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
