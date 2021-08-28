/* Copyright (C) 2019  C. McEnroe <june@causal.agency>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify this Program, or any covered work, by linking or
 * combining it with OpenSSL (or a modified version of that library),
 * containing parts covered by the terms of the OpenSSL License and the
 * original SSLeay license, the licensors of this Program grant you
 * additional permission to convey the resulting work. Corresponding
 * Source for a non-source form of such a combination shall include the
 * source code for the parts of OpenSSL used as well as that of the
 * covered work.
 */

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sysexits.h>

#include "bounce.h"

static struct {
	size_t len;
	char **lines;
	struct timeval *times;
} ring;

void ringAlloc(size_t len) {
	if (len & (len - 1)) {
		errx(EX_CONFIG, "ring length must be power of two: %zu", len);
	}
	ring.lines = calloc(len, sizeof(*ring.lines));
	if (!ring.lines) err(EX_OSERR, "calloc");
	ring.times = calloc(len, sizeof(*ring.times));
	if (!ring.times) err(EX_OSERR, "calloc");
	ring.len = len;
}

static size_t producer;

void ringProduce(const char *line) {
	size_t i = producer++ & (ring.len - 1);
	if (ring.lines[i]) free(ring.lines[i]);
	gettimeofday(&ring.times[i], NULL);
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
		void *ptr = realloc(
			consumers.ptr, sizeof(*consumers.ptr) * consumers.cap
		);
		if (!ptr) err(EX_OSERR, "realloc");
		consumers.ptr = ptr;
	}

	struct Consumer *consumer = &consumers.ptr[consumers.len];
	consumer->pos = 0;
	consumer->name = strdup(name);
	if (!consumer->name) err(EX_OSERR, "strdup");
	return consumers.len++;
}

void ringSet(size_t consumer, size_t pos) {
	assert(consumer < consumers.len);
	if (pos <= producer) consumers.ptr[consumer].pos = pos;
}

size_t ringPos(size_t consumer) {
	assert(consumer < consumers.len);
	return consumers.ptr[consumer].pos;
}

size_t ringDiff(size_t consumer) {
	assert(consumer < consumers.len);
	return producer - consumers.ptr[consumer].pos;
}

const char *ringPeek(struct timeval *time, size_t consumer) {
	if (!ringDiff(consumer)) return NULL;
	if (ringDiff(consumer) > ring.len) {
		warnx(
			"consumer %s dropped %zu messages",
			consumers.ptr[consumer].name, ringDiff(consumer) - ring.len
		);
		consumers.ptr[consumer].pos = producer - ring.len;
	}
	size_t i = consumers.ptr[consumer].pos & (ring.len - 1);
	if (time) *time = ring.times[i];
	assert(ring.lines[i]);
	return ring.lines[i];
}

const char *ringConsume(struct timeval *time, size_t consumer) {
	const char *line = ringPeek(time, consumer);
	if (line) consumers.ptr[consumer].pos++;
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

static const uint64_t Signatures[] = {
	0x0165636E756F70, // no ring size
	0x0265636E756F70, // time_t only
	0x0365636E756F70,
};

static size_t signatureVersion(uint64_t signature) {
	for (size_t i = 0; i < ARRAY_LEN(Signatures); ++i) {
		if (signature == Signatures[i]) return i;
	}
	errx(EX_DATAERR, "unknown file signature %" PRIX64, signature);
}

static int writeSize(FILE *file, size_t value) {
	return (fwrite(&value, sizeof(value), 1, file) ? 0 : -1);
}
static int writeTime(FILE *file, struct timeval time) {
	return (fwrite(&time, sizeof(time), 1, file) ? 0 : -1);
}
static int writeString(FILE *file, const char *str) {
	return (fwrite(str, strlen(str) + 1, 1, file) ? 0 : -1);
}

int ringSave(FILE *file) {
	if (!fwrite(&Signatures[2], sizeof(*Signatures), 1, file)) return -1;
	if (writeSize(file, ring.len)) return -1;
	if (writeSize(file, producer)) return -1;
	if (writeSize(file, consumers.len)) return -1;
	for (size_t i = 0; i < consumers.len; ++i) {
		if (writeString(file, consumers.ptr[i].name)) return -1;
		if (writeSize(file, consumers.ptr[i].pos)) return -1;
	}
	for (size_t i = 0; i < ring.len; ++i) {
		if (writeTime(file, ring.times[i])) return -1;
	}
	for (size_t i = 0; i < ring.len; ++i) {
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
static void readTime(FILE *file, struct timeval *time) {
	fread(time, sizeof(*time), 1, file);
	if (ferror(file)) err(EX_IOERR, "fread");
	if (feof(file)) err(EX_DATAERR, "unexpected eof");
}
static void readTimeT(FILE *file, time_t *time) {
	fread(time, sizeof(*time), 1, file);
	if (ferror(file)) err(EX_IOERR, "fread");
	if (feof(file)) err(EX_DATAERR, "unexpected eof");
}
static void readString(FILE *file, char **buf, size_t *cap) {
	ssize_t len = getdelim(buf, cap, '\0', file);
	if (len < 0 && !feof(file)) err(EX_IOERR, "getdelim");
}

void ringLoad(FILE *file) {
	uint64_t signature;
	fread(&signature, sizeof(signature), 1, file);
	if (ferror(file)) err(EX_IOERR, "fread");
	if (feof(file)) return;
	size_t version = signatureVersion(signature);

	size_t saveLen = 4096;
	if (version > 0) readSize(file, &saveLen);
	if (saveLen > ring.len) {
		errx(EX_DATAERR, "cannot load save with larger ring");
	}

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

	for (size_t i = 0; i < saveLen; ++i) {
		if (version < 2) {
			readTimeT(file, &ring.times[i].tv_sec);
		} else {
			readTime(file, &ring.times[i]);
		}
	}
	for (size_t i = 0; i < saveLen; ++i) {
		readString(file, &buf, &cap);
		if (feof(file)) break;
		ring.lines[i] = strdup(buf);
		if (!ring.lines[i]) err(EX_OSERR, "strdup");
	}
	free(buf);

	if (ring.len > saveLen) {
		producer %= saveLen;
		for (size_t i = 0; i < consumers.len; ++i) {
			struct Consumer *consumer = &consumers.ptr[i];
			consumer->pos %= saveLen;
			if (consumer->pos > producer) consumer->pos = 0;
		}
	}
}
