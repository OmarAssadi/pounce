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
	size_t write;
} ring;

void ringProduce(const char *line) {
	size_t i = ring.write++ % RingLen;
	if (ring.lines[i]) free(ring.lines[i]);
	ring.times[i] = time(NULL);
	ring.lines[i] = strdup(line);
	if (!ring.lines[i]) err(EX_OSERR, "strdup");
}

static struct {
	char **names;
	size_t *ptrs;
	size_t cap, len;
} read;

size_t ringConsumer(const char *name) {
	for (size_t i = 0; i < read.len; ++i) {
		if (!strcmp(read.names[i], name)) return i;
	}

	if (read.len == read.cap) {
		read.cap = (read.cap ? read.cap * 2 : 8);
		read.names = realloc(read.names, sizeof(*read.names) * read.cap);
		if (!read.names) err(EX_OSERR, "realloc");
		read.ptrs = realloc(read.ptrs, sizeof(*read.ptrs) * read.cap);
		if (!read.ptrs) err(EX_OSERR, "realloc");
	}

	read.names[read.len] = strdup(name);
	if (!read.names[read.len]) err(EX_OSERR, "strdup");
	read.ptrs[read.len] = 0;
	return read.len++;
}

size_t ringDiff(size_t consumer) {
	assert(consumer < read.len);
	return ring.write - read.ptrs[consumer];
}

const char *ringConsume(time_t *time, size_t consumer) {
	assert(consumer < read.len);
	if (!ringDiff(consumer)) return NULL;
	if (ringDiff(consumer) > RingLen) {
		read.ptrs[consumer] = ring.write - RingLen;
	}
	size_t i = read.ptrs[consumer]++ % RingLen;
	if (time) *time = ring.times[i];
	return ring.lines[i];
}

void ringInfo(void) {
	fprintf(stderr, "producer: %zu\n", ring.write);
	for (size_t i = 0; i < read.len; ++i) {
		fprintf(
			stderr, "consumer %s: %zu (%zu)\n",
			read.names[i], read.ptrs[i], ring.write - read.ptrs[i]
		);
	}
}
