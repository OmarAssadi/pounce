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
#include <strings.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "bounce.h"

enum Need {
	NeedNick = 1 << 0,
	NeedUser = 1 << 1,
	NeedPass = 1 << 2,
	NeedCapEnd = 1 << 3,
};

struct Client {
	struct tls *tls;
	enum Need need;
	size_t consumer;
	bool serverTime;
	char buf[1024];
	size_t len;
	bool error;
};

struct Client *clientAlloc(struct tls *tls) {
	struct Client *client = calloc(1, sizeof(*client));
	if (!client) err(EX_OSERR, "calloc");
	client->tls = tls;
	client->need = NeedNick | NeedUser | (clientPass ? NeedPass : 0);
	return client;
}

void clientFree(struct Client *client) {
	tls_close(client->tls);
	tls_free(client->tls);
	free(client);
}

bool clientError(const struct Client *client) {
	return client->error;
}

void clientSend(struct Client *client, const char *ptr, size_t len) {
	if (verbose) fprintf(stderr, "\x1B[34m%.*s\x1B[m", (int)len, ptr);
	while (len) {
		ssize_t ret = tls_write(client->tls, ptr, len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) {
			warnx("client tls_write: %s", tls_error(client->tls));
			client->error = true;
			return;
		}
		ptr += ret;
		len -= ret;
	}
}

void clientFormat(struct Client *client, const char *format, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, format);
	int len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	assert((size_t)len < sizeof(buf));
	clientSend(client, buf, len);
}

static void passRequired(struct Client *client) {
	clientFormat(
		client,
		":%s 464 * :Password incorrect\r\n"
		"ERROR :Password incorrect\r\n",
		Origin
	);
	client->error = true;
}

static void maybeSync(struct Client *client) {
	if (client->need == NeedPass) passRequired(client);
	if (!client->need) stateSync(client);
}

typedef void Handler(struct Client *client, struct Message *msg);

static void handleNick(struct Client *client, struct Message *msg) {
	(void)msg;
	client->need &= ~NeedNick;
	maybeSync(client);
}

static void handleUser(struct Client *client, struct Message *msg) {
	if (!msg->params[0]) {
		client->error = true;
		return;
	}
	if (client->need & NeedPass) {
		passRequired(client);
	} else {
		client->need &= ~NeedUser;
		client->consumer = ringConsumer(msg->params[0]);
		maybeSync(client);
	}
}

static void handlePass(struct Client *client, struct Message *msg) {
	if (!clientPass) return;
	if (!msg->params[0]) {
		client->error = true;
		return;
	}
	if (!strcmp(crypt(msg->params[0], clientPass), clientPass)) {
		client->need &= ~NeedPass;
		maybeSync(client);
	} else {
		passRequired(client);
	}
	explicit_bzero(msg->params[0], strlen(msg->params[0]));
}

static void handleCap(struct Client *client, struct Message *msg) {
	if (!msg->params[0]) msg->params[0] = "";

	if (!strcmp(msg->params[0], "END")) {
		if (!client->need) return;
		client->need &= ~NeedCapEnd;
		maybeSync(client);

	} else if (!strcmp(msg->params[0], "LS")) {
		if (client->need) client->need |= NeedCapEnd;
		clientFormat(client, ":%s CAP * LS :server-time\r\n", Origin);

	} else if (!strcmp(msg->params[0], "REQ") && msg->params[1]) {
		if (client->need) client->need |= NeedCapEnd;
		if (!strcmp(msg->params[1], "server-time")) {
			client->serverTime = true;
			clientFormat(client, ":%s CAP * ACK :server-time\r\n", Origin);
		} else {
			clientFormat(client, ":%s CAP * NAK :%s\r\n", Origin, msg->params[1]);
		}

	} else if (!strcmp(msg->params[0], "LIST")) {
		clientFormat(
			client, ":%s CAP * LIST :%s\r\n",
			Origin, (client->serverTime ? "server-time" : "")
		);

	} else {
		clientFormat(client, ":%s 410 * :Invalid CAP subcommand\r\n", Origin);
	}
}

static void handleQuit(struct Client *client, struct Message *msg) {
	(void)msg;
	clientFormat(client, "ERROR :Detaching\r\n");
	client->error = true;
}

static void handlePrivmsg(struct Client *client, struct Message *msg) {
	if (!msg->params[0] || !msg->params[1]) return;
	char line[1024];
	snprintf(
		line, sizeof(line), ":%s %s %s :%s",
		stateEcho(), msg->cmd, msg->params[0], msg->params[1]
	);
	size_t diff = ringDiff(client->consumer);
	ringProduce(line);
	if (!diff) ringConsume(NULL, client->consumer);

	serverFormat("%s %s :%s\r\n", msg->cmd, msg->params[0], msg->params[1]);
}

static const struct {
	const char *cmd;
	Handler *fn;
	bool need;
} Handlers[] = {
	{ "CAP", handleCap, false },
	{ "NICK", handleNick, false },
	{ "NOTICE", handlePrivmsg, true },
	{ "PASS", handlePass, false },
	{ "PRIVMSG", handlePrivmsg, true },
	{ "QUIT", handleQuit, true },
	{ "USER", handleUser, false },
};

static void clientParse(struct Client *client, char *line) {
	struct Message msg = parse(line);
	if (!msg.cmd) return;
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg.cmd, Handlers[i].cmd)) continue;
		if (Handlers[i].need && client->need) break;
		Handlers[i].fn(client, &msg);
		return;
	}
	client->error = true;
}

static bool intercept(const char *line, size_t len) {
	if (len >= 4 && !memcmp(line, "CAP ", 4)) return true;
	if (len >= 5 && !memcmp(line, "QUIT ", 5)) return true;
	if (len >= 7 && !memcmp(line, "NOTICE ", 7)) return true;
	if (len >= 8 && !memcmp(line, "PRIVMSG ", 8)) return true;
	return false;
}

void clientRecv(struct Client *client) {
	assert(client->len < sizeof(client->buf));
	ssize_t read = tls_read(
		client->tls,
		&client->buf[client->len], sizeof(client->buf) - client->len
	);
	if (read == TLS_WANT_POLLIN || read == TLS_WANT_POLLOUT) return;
	if (read <= 0) {
		if (read < 0) warnx("client tls_read: %s", tls_error(client->tls));
		client->error = true;
		return;
	}
	client->len += read;

	char *crlf;
	char *line = client->buf;
	for (;;) {
		crlf = memmem(line, &client->buf[client->len] - line, "\r\n", 2);
		if (!crlf) break;
		if (verbose) {
			fprintf(stderr, "\x1B[33m%.*s\x1B[m\n", (int)(crlf - line), line);
		}
		if (client->need || intercept(line, crlf - line)) {
			crlf[0] = '\0';
			clientParse(client, line);
		} else {
			serverSend(line, crlf + 2 - line);
		}
		line = crlf + 2;
	}
	client->len -= line - client->buf;
	memmove(client->buf, line, client->len);
}

size_t clientDiff(const struct Client *client) {
	if (client->need) return 0;
	return ringDiff(client->consumer);
}

void clientConsume(struct Client *client) {
	time_t time;
	const char *line = ringPeek(&time, client->consumer);
	if (!line) return;
	if (client->serverTime) {
		char ts[sizeof("YYYY-MM-DDThh:mm:ss.sssZ")];
		struct tm *tm = gmtime(&time);
		strftime(ts, sizeof(ts), "%FT%T.000Z", tm);
		clientFormat(client, "@time=%s %s\r\n", ts, line);
	} else {
		clientFormat(client, "%s\r\n", line);
	}
	if (!client->error) ringConsume(NULL, client->consumer);
}
