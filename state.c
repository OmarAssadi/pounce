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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "bounce.h"

static struct {
	char *origin;
	char *welcome;
	char *yourHost;
	char *created;
	char *myInfo[4];
} intro;

static char *nick;

static void set(char **field, const char *value) {
	if (*field) free(*field);
	*field = strdup(value);
	if (!*field) err(EX_OSERR, "strdup");
}

static struct {
	char **names;
	size_t cap, len;
} chan;

static void chanAdd(const char *name) {
	if (chan.len == chan.cap) {
		chan.cap = (chan.cap ? chan.cap * 2 : 8);
		chan.names = realloc(chan.names, sizeof(char *) * chan.cap);
		if (!chan.names) err(EX_OSERR, "realloc");
	}
	chan.names[chan.len] = strdup(name);
	if (!chan.names[chan.len]) err(EX_OSERR, "strdup");
	chan.len++;
}

static void chanRemove(const char *name) {
	for (size_t i = 0; i < chan.len; ++i) {
		if (strcmp(chan.names[i], name)) continue;
		free(chan.names[i]);
		chan.names[i] = chan.names[--chan.len];
		return;
	}
}

static struct {
	char **tokens;
	size_t cap, len;
} support;

static void supportAdd(const char *token) {
	if (support.len == support.cap) {
		support.cap = (support.cap ? support.cap * 2 : 8);
		support.tokens = realloc(support.tokens, sizeof(char *) * support.cap);
		if (!support.tokens) err(EX_OSERR, "realloc");
	}
	support.tokens[support.len] = strdup(token);
	if (!support.tokens[support.len]) err(EX_OSERR, "strdup");
	support.len++;
}

bool stateReady(void) {
	return nick
		&& intro.origin
		&& intro.welcome
		&& intro.yourHost
		&& intro.created
		&& intro.myInfo[0]
		&& support.len;
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
		supportAdd(msg.params[i]);
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

static void handleJoin(struct Message msg) {
	if (!msg.origin) errx(EX_PROTOCOL, "JOIN without origin");
	if (!msg.params[0]) errx(EX_PROTOCOL, "JOIN without channel");
	if (self(msg)) chanAdd(msg.params[0]);
}

static void handlePart(struct Message msg) {
	if (!msg.origin) errx(EX_PROTOCOL, "PART without origin");
	if (!msg.params[0]) errx(EX_PROTOCOL, "PART without channel");
	if (self(msg)) chanRemove(msg.params[0]);
}

static void handleKick(struct Message msg) {
	if (!msg.params[0]) errx(EX_PROTOCOL, "KICK without channel");
	if (!msg.params[1]) errx(EX_PROTOCOL, "KICK without nick");
	if (!strcmp(msg.params[1], nick)) chanRemove(msg.params[0]);
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
	{ "JOIN", handleJoin },
	{ "KICK", handleKick },
	{ "NICK", handleNick },
	{ "PART", handlePart },
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

// FIXME: Deduplicate this.
static void format(struct Client *client, const char *format, ...) {
	char buf[513];
	va_list ap;
	va_start(ap, format);
	int len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	assert(len > 0 && (size_t)len < sizeof(buf));
	clientSend(client, buf, len);
}

void stateSync(struct Client *client) {
	format(client, ":%s 001 %s :%s\r\n", intro.origin, nick, intro.welcome);
	format(client, ":%s 002 %s :%s\r\n", intro.origin, nick, intro.yourHost);
	format(client, ":%s 003 %s :%s\r\n", intro.origin, nick, intro.created);
	format(
		client, ":%s 004 %s %s %s %s\r\n",
		intro.origin, nick,
		intro.myInfo[0], intro.myInfo[1], intro.myInfo[2], intro.myInfo[3]
	);

	size_t i;
	for (i = 0; support.len - i >= 13; i += 13) {
		format(
			client,
			":%s 005 %s"
			" %s %s %s %s %s %s %s %s %s %s %s %s %s"
			" :are supported by this server\r\n",
			intro.origin, nick,
			support.tokens[i + 0], support.tokens[i + 1],
			support.tokens[i + 2], support.tokens[i + 3],
			support.tokens[i + 4], support.tokens[i + 5],
			support.tokens[i + 6], support.tokens[i + 7],
			support.tokens[i + 8], support.tokens[i + 9],
			support.tokens[i + 10], support.tokens[i + 11],
			support.tokens[i + 12]
		);
	}
	// FIXME: Do something about this?
	if (i < support.len) {
		format(client, ":%s 005 %s", intro.origin, nick);
		for (; i < support.len; ++i) {
			format(client, " %s", support.tokens[i]);
		}
		format(client, " :are supported by this server\r\n");
	}

	// FIXME: Send a proper self origin.
	for (size_t i = 0; i < chan.len; ++i) {
		format(client, ":%s JOIN %s\r\n", nick, chan.names[i]);
	}
}
