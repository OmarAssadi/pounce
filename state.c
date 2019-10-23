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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "bounce.h"

static char *nick;

// TODO: Channels.

static struct {
	char *origin;
	char *welcome;
	char *yourHost;
	char *created;
	char *myInfo[4];
} intro;

enum { SupportCap = 32 };
static struct {
	char *tokens[SupportCap];
	size_t len;
} support;

bool stateReady(void) {
	return nick
		&& intro.origin
		&& intro.welcome
		&& intro.yourHost
		&& intro.created
		&& intro.myInfo[0]
		&& support.len;
}

static void set(char **field, const char *value) {
	if (*field) free(*field);
	*field = strdup(value);
	if (!*field) err(EX_OSERR, "strdup");
}

static void supportSet(const char *token) {
	if (support.len == SupportCap) {
		warnx("dropping ISUPPORT token %s", token);
		return;
	}
	set(&support.tokens[support.len++], token);
}

typedef void Handler(struct Message);

static void handleCap(struct Message msg) {
	bool ack = msg.params[1] && !strcmp(msg.params[1], "ACK");
	bool sasl = msg.params[2] && !strcmp(msg.params[2], "sasl");
	if (!ack || !sasl) errx(EX_CONFIG, "server does not support SASL");
	serverAuth();
}

static void handleReplyWelcome(struct Message msg) {
	if (!msg.params[1]) errx(EX_PROTOCOL, "RPL_WELCOME without message");
	set(&intro.origin, msg.origin);
	set(&nick, msg.params[0]);
	set(&intro.welcome, msg.params[1]);
}
static void handleReplyYourHost(struct Message msg) {
	if (!msg.params[1]) errx(EX_PROTOCOL, "RPL_YOURHOST without message");
	set(&intro.yourHost, msg.params[1]);
}
static void handleReplyCreated(struct Message msg) {
	if (!msg.params[1]) errx(EX_PROTOCOL, "RPL_CREATED without message");
	set(&intro.created, msg.params[1]);
}
static void handleReplyMyInfo(struct Message msg) {
	if (!msg.params[4]) errx(EX_PROTOCOL, "RPL_MYINFO without 4 parameters");
	set(&intro.myInfo[0], msg.params[1]);
	set(&intro.myInfo[1], msg.params[2]);
	set(&intro.myInfo[2], msg.params[3]);
	set(&intro.myInfo[3], msg.params[4]);
}

static void handleReplyISupport(struct Message msg) {
	for (size_t i = 1; i < ParamCap; ++i) {
		if (!msg.params[i] || strchr(msg.params[i], ' ')) break;
		supportSet(msg.params[i]);
	}
}

static bool self(struct Message msg) {
	assert(nick);
	size_t len = strlen(nick);
	if (strncmp(msg.origin, nick, len)) return false;
	if (strlen(msg.origin) < len || msg.origin[len] != '!') return false;
	return true;
}

static void handleNick(struct Message msg) {
	if (!msg.origin) errx(EX_PROTOCOL, "NICK without origin");
	if (!msg.params[0]) errx(EX_PROTOCOL, "NICK without new nick");
	if (self(msg)) set(&nick, msg.params[0]);
}

static void handleError(struct Message msg) {
	errx(EX_UNAVAILABLE, "%s", msg.params[0]);
}

static const struct {
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ "001", handleReplyWelcome },
	{ "002", handleReplyYourHost },
	{ "003", handleReplyCreated },
	{ "004", handleReplyMyInfo },
	{ "005", handleReplyISupport },
	{ "CAP", handleCap },
	{ "ERROR", handleError },
	{ "NICK", handleNick },
};

void stateParse(char *line) {
	struct Message msg = parse(line);
	if (!msg.cmd) errx(EX_PROTOCOL, "no command");
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg.cmd, Handlers[i].cmd)) continue;
		Handlers[i].fn(msg);
		break;
	}
}

void stateSync(struct Client *client) {
	char buf[4096];
	int len = snprintf(
		buf, sizeof(buf),
		":%s 001 %s :%s\r\n"
		":%s 002 %s :%s\r\n"
		":%s 003 %s :%s\r\n"
		":%s 004 %s %s %s %s %s\r\n",
		intro.origin, nick, intro.welcome,
		intro.origin, nick, intro.yourHost,
		intro.origin, nick, intro.created,
		intro.origin, nick,
		intro.myInfo[0], intro.myInfo[1], intro.myInfo[2], intro.myInfo[3]
	);
	assert(len > 0 && (size_t)len < sizeof(buf));

	// TODO: Send ISUPPORT.

	clientSend(client, buf, len);
}
