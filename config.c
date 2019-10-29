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

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WS "\t "

static const char *path;
static FILE *file;
static size_t num;
static char *line;
static size_t cap;

static int clean(int opt) {
	if (file) fclose(file);
	free(line);
	line = NULL;
	cap = 0;
	return opt;
}

int getopt_config(
	int argc, char *const *argv,
	const char *optstring, const struct option *longopts, int *longindex
) {
	int opt = getopt_long(argc, argv, optstring, longopts, longindex);
	if (opt >= 0) return opt;

	for (;;) {
		if (!file) {
			if (optind < argc) {
				num = 0;
				path = argv[optind++];
				file = fopen(path, "r");
				if (!file) {
					warn("%s", path);
					return clean('?');
				}
			} else {
				return clean(-1);
			}
		}

		for (;;) {
			ssize_t llen = getline(&line, &cap, file);
			if (ferror(file)) {
				warn("%s", path);
				return clean('?');
			}
			if (llen <= 0) break;
			if (line[llen - 1] == '\n') line[llen - 1] = '\0';
			num++;

			char *name = line + strspn(line, WS);
			size_t len = strcspn(name, WS "=");
			if (!name[0] || name[0] == '#') continue;

			const struct option *option;
			for (option = longopts; option->name; ++option) {
				if (strlen(option->name) != len) continue;
				if (!strncmp(option->name, name, len)) break;
			}
			if (!option->name) {
				warnx(
					"%s:%zu: unrecognized option `%.*s'",
					path, num, (int)len, name
				);
				return clean('?');
			}

			char *equal = &name[len] + strspn(&name[len], WS);
			if (*equal && *equal != '=') {
				warnx(
					"%s:%zu: option `%s' missing equals sign",
					path, num, option->name
				);
				return clean('?');
			}
			if (option->has_arg == no_argument && *equal) {
				warnx(
					"%s:%zu: option `%s' doesn't allow an argument",
					path, num, option->name
				);
				return clean('?');
			}
			if (option->has_arg == required_argument && !*equal) {
				warnx(
					"%s:%zu: option `%s' requires an argument",
					path, num, option->name
				);
				return clean(':');
			}

			optarg = NULL;
			if (*equal) {
				char *arg = &equal[1] + strspn(&equal[1], WS);
				optarg = strdup(arg);
				if (!optarg) {
					warn("getopt_config");
					return clean('?');
				}
			}

			if (longindex) *longindex = option - longopts;
			if (option->flag) {
				*option->flag = option->val;
				return 0;
			} else {
				return option->val;
			}
		}

		fclose(file);
		file = NULL;
	}
}
