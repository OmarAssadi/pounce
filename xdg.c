/* Copyright (C) 2019, 2020  C. McEnroe <june@causal.agency>
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>

#include "bounce.h"

#define SUBDIR "pounce"

struct Base {
	const char *envHome;
	const char *envDirs;
	const char *defHome;
	const char *defDirs;
};

static const struct Base Config = {
	.envHome = "XDG_CONFIG_HOME",
	.envDirs = "XDG_CONFIG_DIRS",
	.defHome = ".config",
	.defDirs = "/etc/xdg",
};

static const struct Base Data = {
	.envHome = "XDG_DATA_HOME",
	.envDirs = "XDG_DATA_DIRS",
	.defHome = ".local/share",
	.defDirs = "/usr/local/share:/usr/share",
};

static char *basePath(
	struct Base base, char *buf, size_t cap, const char *path, int i
) {
	if (path[strspn(path, ".")] == '/') {
		if (i > 0) return NULL;
		snprintf(buf, cap, "%s", path);
		return buf;
	}

	if (i > 0) {
		const char *dirs = getenv(base.envDirs);
		if (!dirs) dirs = base.defDirs;
		for (; i > 1; --i) {
			dirs += strcspn(dirs, ":");
			dirs += (*dirs == ':');
		}
		if (!*dirs) return NULL;
		snprintf(
			buf, cap, "%.*s/" SUBDIR "/%s",
			(int)strcspn(dirs, ":"), dirs, path
		);
		return buf;
	}

	const char *home = getenv("HOME");
	const char *baseHome = getenv(base.envHome);
	if (baseHome) {
		snprintf(buf, cap, "%s/" SUBDIR "/%s", baseHome, path);
	} else if (home) {
		snprintf(buf, cap, "%s/%s/" SUBDIR "/%s", home, base.defHome, path);
	} else {
		errx(EX_USAGE, "HOME unset");
	}
	return buf;
}

char *configPath(char *buf, size_t cap, const char *path, int i) {
	return basePath(Config, buf, cap, path, i);
}

char *dataPath(char *buf, size_t cap, const char *path, int i) {
	return basePath(Data, buf, cap, path, i);
}

FILE *configOpen(const char *path, const char *mode) {
	char buf[PATH_MAX];
	for (int i = 0; configPath(buf, sizeof(buf), path, i); ++i) {
		FILE *file = fopen(buf, mode);
		if (file) return file;
		if (errno != ENOENT) warn("%s", buf);
	}
	warn("%s", configPath(buf, sizeof(buf), path, 0));
	return NULL;
}

FILE *dataOpen(const char *path, const char *mode) {
	char buf[PATH_MAX];
	for (int i = 0; dataPath(buf, sizeof(buf), path, i); ++i) {
		FILE *file = fopen(buf, mode);
		if (file) return file;
		if (errno != ENOENT) warn("%s", buf);
	}
	if (mode[0] != 'r') {
		int error = mkdir(dataPath(buf, sizeof(buf), "", 0), S_IRWXU);
		if (error && errno != EEXIST) warn("%s", buf);
	}
	FILE *file = fopen(dataPath(buf, sizeof(buf), path, 0), mode);
	if (!file) warn("%s", buf);
	return file;
}
