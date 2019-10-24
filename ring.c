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

void ringWrite(const char *line) {
	size_t i = ring.write++ % RingLen;
	if (ring.lines[i]) free(ring.lines[i]);
	ring.times[i] = time(NULL);
	ring.lines[i] = strdup(line);
	if (!ring.lines[i]) err(EX_OSERR, "strdup");
}

static struct {
	char **names;
	size_t *reads;
	size_t cap, len;
} reader;

size_t ringReader(const char *name) {
	for (size_t i = 0; i < reader.len; ++i) {
		if (!strcmp(reader.names[i], name)) return i;
	}

	if (reader.len == reader.cap) {
		reader.cap = (reader.cap ? reader.cap * 2 : 8);
		reader.names = realloc(reader.names, sizeof(*reader.names) * reader.cap);
		if (!reader.names) err(EX_OSERR, "realloc");
		reader.reads = realloc(reader.reads, sizeof(*reader.reads) * reader.cap);
		if (!reader.reads) err(EX_OSERR, "realloc");
	}

	reader.names[reader.len] = strdup(name);
	if (!reader.names[reader.len]) err(EX_OSERR, "strdup");
	reader.reads[reader.len] = 0;
	return reader.len++;
}
