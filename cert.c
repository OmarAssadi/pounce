/* Copyright (C) 2020  C. McEnroe <june@causal.agency>
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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "bounce.h"

// This basically exists to work around certbot's symlinks from "live" into
// "archive" under capsicum.

int certOpen(struct Cert *cert, const char *path) {
	char buf[PATH_MAX];
	snprintf(buf, sizeof(buf), "%s", path);

	char *base = strrchr(buf, '/');
	if (base) {
		*base = '\0';
		snprintf(cert->name, sizeof(cert->name), "%s", &base[1]);
		cert->parent = open(buf, O_DIRECTORY);
	} else {
		snprintf(cert->name, sizeof(cert->name), "%s", path);
		cert->parent = open(".", O_DIRECTORY);
	}
	if (cert->parent < 0) return -1;

	cert->target = cert->parent;
	ssize_t len = readlinkat(cert->parent, cert->name, buf, sizeof(buf) - 1);
	if (len < 0 && errno == EINVAL) return 0;
	if (len < 0) return -1;
	buf[len] = '\0';

	base = strrchr(buf, '/');
	if (base) {
		*base = '\0';
		cert->target = openat(cert->parent, buf, O_DIRECTORY);
		if (cert->target < 0) return -1;
	}
	return 0;
}

FILE *certFile(const struct Cert *cert) {
	const char *name = cert->name;

	char buf[PATH_MAX];
	ssize_t len = readlinkat(cert->parent, cert->name, buf, sizeof(buf) - 1);
	if (len < 0) {
		if (errno != EINVAL) return NULL;
	} else {
		// XXX: Assume only the target base name has changed.
		buf[len] = '\0';
		name = strrchr(buf, '/');
		if (name) {
			name = &name[1];
		} else {
			name = buf;
		}
	}

	int fd = openat(cert->target, name, O_RDONLY);
	if (fd < 0) return NULL;

	return fdopen(fd, "r");
}
