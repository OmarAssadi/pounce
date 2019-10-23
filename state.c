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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "bounce.h"

enum { ISupportCap = 32 };
static struct {
	char *origin;
	char *nick;
	char *welcome;
	char *yourHost;
	char *created;
	char *myInfo[4];
	struct {
		char *values[ISupportCap];
		size_t len;
	} iSupport;
} state;

bool stateReady(void) {
	return state.origin
		&& state.nick
		&& state.welcome
		&& state.yourHost
		&& state.created
		&& state.myInfo[0]
		&& state.iSupport.len;
}

static void set(char **field, const char *value) {
	if (*field) free(*field);
	*field = NULL;
	if (value) {
		*field = strdup(value);
		if (!*field) err(EX_OSERR, "strdup");
	}
}

enum { ParamCap = 15 };
struct Command {
	const char *origin;
	const char *name;
	const char *target;
	const char *params[ParamCap];
};
typedef void Handler(struct Command);

static void cap(struct Command cmd) {
	bool ack = cmd.params[0] && !strcmp(cmd.params[0], "ACK");
	bool sasl = cmd.params[1] && !strcmp(cmd.params[1], "sasl");
	if (!ack || !sasl) errx(EX_CONFIG, "server does not support SASL");
	serverAuth();
}

static void replyWelcome(struct Command cmd) {
	set(&state.origin, cmd.origin);
	set(&state.nick, cmd.target);
	set(&state.welcome, cmd.params[0]);
}

static void replyYourHost(struct Command cmd) {
	set(&state.yourHost, cmd.params[0]);
}

static void replyCreated(struct Command cmd) {
	set(&state.created, cmd.params[0]);
}

static void replyMyInfo(struct Command cmd) {
	set(&state.myInfo[0], cmd.params[0]);
	set(&state.myInfo[1], cmd.params[1]);
	set(&state.myInfo[2], cmd.params[2]);
	set(&state.myInfo[3], cmd.params[3]);
}

static void replyISupport(struct Command cmd) {
	for (size_t i = 0; i < ParamCap; ++i) {
		if (!cmd.params[i] || strchr(cmd.params[i], ' ')) break;
		if (state.iSupport.len == ISupportCap) break;
		set(&state.iSupport.values[state.iSupport.len++], cmd.params[i]);
	}
}

static const struct {
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ "001", replyWelcome },
	{ "002", replyYourHost },
	{ "003", replyCreated },
	{ "004", replyMyInfo },
	{ "005", replyISupport },
	{ "CAP", cap },
};
static const size_t HandlersLen = sizeof(Handlers) / sizeof(Handlers[0]);

void stateParse(char *line) {
	struct Command cmd = {0};
	if (line[0] == ':') {
		cmd.origin = 1 + strsep(&line, " ");
		if (!line) errx(EX_PROTOCOL, "eof after origin");
	}

	cmd.name = strsep(&line, " ");
	cmd.target = strsep(&line, " ");
	for (size_t i = 0; line && i < ParamCap; ++i) {
		if (line[0] == ':') {
			cmd.params[i] = line;
			break;
		}
		cmd.params[i] = strsep(&line, " ");
	}

	for (size_t i = 0; i < HandlersLen; ++i) {
		if (strcmp(cmd.name, Handlers[i].cmd)) continue;
		Handlers[i].fn(cmd);
		break;
	}
}
