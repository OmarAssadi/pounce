/* Copyright (C) 2019  C. McEnroe <june@causal.agency>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <time.h>

#include "bounce.h"

enum { RingLen = 4096 };
static_assert(!(RingLen & (RingLen - 1)), "power of two RingLen");

static struct {
	char *lines[RingLen];
	time_t times[RingLen];
} ring;

size_t producer;

void ringProduce(const char *line) {
	size_t i = producer++ % RingLen;
	if (ring.lines[i]) free(ring.lines[i]);
	ring.times[i] = time(NULL);
	ring.lines[i] = strdup(line);
	if (!ring.lines[i]) err(EX_OSERR, "strdup");
}

struct Consumer {
	char *name;
	size_t pos;
};

static struct {
	struct Consumer *ptr;
	size_t cap, len;
} consumers;

size_t ringConsumer(const char *name) {
	for (size_t i = 0; i < consumers.len; ++i) {
		if (!strcmp(consumers.ptr[i].name, name)) return i;
	}

	if (consumers.len == consumers.cap) {
		consumers.cap = (consumers.cap ? consumers.cap * 2 : 8);
		// FIXME: Keep old pointer around for saving when exiting for error.
		consumers.ptr = realloc(
			consumers.ptr, sizeof(*consumers.ptr) * consumers.cap
		);
		if (!consumers.ptr) err(EX_OSERR, "realloc");
	}

	struct Consumer *consumer = &consumers.ptr[consumers.len];
	consumer->pos = 0;
	consumer->name = strdup(name);
	if (!consumer->name) err(EX_OSERR, "strdup");
	return consumers.len++;
}

size_t ringDiff(size_t consumer) {
	assert(consumer < consumers.len);
	return producer - consumers.ptr[consumer].pos;
}

const char *ringPeek(time_t *time, size_t consumer) {
	if (!ringDiff(consumer)) return NULL;
	if (ringDiff(consumer) > RingLen) {
		consumers.ptr[consumer].pos = producer - RingLen;
	}
	size_t i = consumers.ptr[consumer].pos % RingLen;
	if (time) *time = ring.times[i];
	return ring.lines[i];
}

const char *ringConsume(time_t *time, size_t consumer) {
	const char *line = ringPeek(time, consumer);
	consumers.ptr[consumer].pos++;
	return line;
}

void ringInfo(void) {
	fprintf(stderr, "producer: %zu\n", producer);
	for (size_t i = 0; i < consumers.len; ++i) {
		fprintf(
			stderr, "consumer %s: %zu (%zu)\n",
			consumers.ptr[i].name,
			consumers.ptr[i].pos, producer - consumers.ptr[i].pos
		);
	}
}

static const size_t FileVersion = 0x0165636E756F70;

static int writeSize(FILE *file, size_t value) {
	return (fwrite(&value, sizeof(value), 1, file) ? 0 : -1);
}
static int writeTime(FILE *file, time_t time) {
	return (fwrite(&time, sizeof(time), 1, file) ? 0 : -1);
}
static int writeString(FILE *file, const char *str) {
	return (fwrite(str, strlen(str) + 1, 1, file) ? 0 : -1);
}

int ringSave(FILE *file) {
	if (writeSize(file, FileVersion)) return -1;
	if (writeSize(file, producer)) return -1;
	if (writeSize(file, consumers.len)) return -1;
	for (size_t i = 0; i < consumers.len; ++i) {
		if (writeString(file, consumers.ptr[i].name)) return -1;
		if (writeSize(file, consumers.ptr[i].pos)) return -1;
	}
	for (size_t i = 0; i < RingLen; ++i) {
		if (writeTime(file, ring.times[i])) return -1;
	}
	for (size_t i = 0; i < RingLen; ++i) {
		if (!ring.lines[i]) break;
		if (writeString(file, ring.lines[i])) return -1;
	}
	return 0;
}

static void readSize(FILE *file, size_t *value) {
	fread(value, sizeof(*value), 1, file);
	if (ferror(file)) err(EX_IOERR, "fread");
	if (feof(file)) err(EX_DATAERR, "unexpected eof");
}
static void readTime(FILE *file, time_t *time) {
	fread(time, sizeof(*time), 1, file);
	if (ferror(file)) err(EX_IOERR, "fread");
	if (feof(file)) err(EX_DATAERR, "unexpected eof");
}
static void readString(FILE *file, char **buf, size_t *cap) {
	ssize_t len = getdelim(buf, cap, '\0', file);
	if (len < 0 && !feof(file)) err(EX_IOERR, "getdelim");
}

void ringLoad(FILE *file) {
	size_t version;
	fread(&version, sizeof(version), 1, file);
	if (ferror(file)) err(EX_IOERR, "fread");
	if (feof(file)) return;

	if (version != FileVersion) errx(EX_DATAERR, "unknown file version");
	readSize(file, &producer);

	char *buf = NULL;
	size_t cap = 0;

	size_t len;
	readSize(file, &len);
	for (size_t i = 0; i < len; ++i) {
		readString(file, &buf, &cap);
		size_t consumer = ringConsumer(buf);
		readSize(file, &consumers.ptr[consumer].pos);
	}

	for (size_t i = 0; i < RingLen; ++i) {
		readTime(file, &ring.times[i]);
	}
	for (size_t i = 0; i < RingLen; ++i) {
		readString(file, &buf, &cap);
		if (feof(file)) break;
		ring.lines[i] = strdup(buf);
		if (!ring.lines[i]) err(EX_OSERR, "strdup");
	}

	free(buf);
}
