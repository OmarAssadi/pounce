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

static const char *
basePath(struct Base base, const char **dirs, const char *path) {
	static char buf[PATH_MAX];

	if (*dirs) {
		if (!**dirs) return NULL;
		size_t len = strcspn(*dirs, ":");
		snprintf(buf, sizeof(buf), "%.*s/" SUBDIR "/%s", (int)len, *dirs, path);
		*dirs += len;
		if (**dirs) *dirs += 1;
		return buf;
	}

	if (path[strspn(path, ".")] == '/') {
		*dirs = "";
		return path;
	}

	*dirs = getenv(base.envDirs);
	if (!*dirs) *dirs = base.defDirs;

	const char *home = getenv("HOME");
	const char *baseHome = getenv(base.envHome);
	if (baseHome) {
		snprintf(buf, sizeof(buf), "%s/" SUBDIR "/%s", baseHome, path);
	} else if (home) {
		snprintf(
			buf, sizeof(buf), "%s/%s/" SUBDIR "/%s",
			home, base.defHome, path
		);
	} else {
		errx(EX_CONFIG, "HOME unset");
	}
	return buf;
}

const char *configPath(const char **dirs, const char *path) {
	return basePath(Config, dirs, path);
}

const char *dataPath(const char **dirs, const char *path) {
	return basePath(Data, dirs, path);
}

FILE *configOpen(const char *path, const char *mode) {
	const char *dirs = NULL;
	for (const char *abs; NULL != (abs = configPath(&dirs, path));) {
		FILE *file = fopen(abs, mode);
		if (file) return file;
		if (errno != ENOENT) warn("%s", abs);
	}
	dirs = NULL;
	warn("%s", configPath(&dirs, path));
	return NULL;
}

static void dataMkdir(const char *path) {
	const char *dirs = NULL;
	path = dataPath(&dirs, path);
	int error = mkdir(path, S_IRWXU);
	if (error && errno != EEXIST) warn("%s", path);
}

FILE *dataOpen(const char *path, const char *mode) {
	const char *dirs = NULL;
	for (const char *abs; NULL != (abs = dataPath(&dirs, path));) {
		FILE *file = fopen(abs, mode);
		if (file) return file;
		if (errno != ENOENT) warn("%s", abs);
	}
	if (mode[0] != 'r') dataMkdir("");
	dirs = NULL;
	path = dataPath(&dirs, path);
	FILE *file = fopen(path, mode);
	if (!file) warn("%s", path);
	return file;
}
