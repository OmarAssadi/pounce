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
#include <tls.h>

#include "bounce.h"

enum Need {
	NeedNick = 1 << 0,
	NeedUser = 1 << 1,
	NeedPass = 1 << 2,
	NeedCapEnd = 1 << 3,
};

struct Client {
	bool error;
	struct tls *tls;
	enum Need need;
	char buf[4096];
	size_t len;
};

struct Client *clientAlloc(struct tls *tls) {
	struct Client *client = malloc(sizeof(*client));
	if (!client) err(EX_OSERR, "malloc");

	client->error = false;
	client->tls = tls;
	client->need = NeedNick | NeedUser | (clientPass ? NeedPass : 0);
	client->len = 0;

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
		// FIXME: Handle non-blocking?
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) {
			warnx("tls_write: %s", tls_error(client->tls));
			client->error = true;
			return;
		}
		ptr += ret;
		len -= ret;
	}
}

static void format(struct Client *client, const char *format, ...) {
	char buf[513];
	va_list ap;
	va_start(ap, format);
	int len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	assert(len > 0 && (size_t)len < sizeof(buf));
	clientSend(client, buf, len);
}

static void passRequired(struct Client *client) {
	format(
		client,
		":invalid 464 * :Password incorrect\r\n"
		"ERROR :Password incorrect\r\n"
	);
	client->error = true;
}

typedef void Handler(struct Client *client, struct Message msg);

static void handleNick(struct Client *client, struct Message msg) {
	(void)msg;
	client->need &= ~NeedNick;
	if (!client->need) stateSync(client);
	if (client->need == NeedPass) passRequired(client);
}

static void handleUser(struct Client *client, struct Message msg) {
	(void)msg;
	// TODO: Identify client by username.
	client->need &= ~NeedUser;
	if (!client->need) stateSync(client);
	if (client->need == NeedPass) passRequired(client);
}

static void handlePass(struct Client *client, struct Message msg) {
	if (!msg.params[0] || strcmp(clientPass, msg.params[0])) {
		passRequired(client);
	} else {
		client->need &= ~NeedPass;
		if (!client->need) stateSync(client);
	}
}

static void handleCap(struct Client *client, struct Message msg) {
	// TODO...
}

static const struct {
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ "CAP", handleCap },
	{ "NICK", handleNick },
	{ "PASS", handlePass },
	{ "USER", handleUser },
};

static void clientParse(struct Client *client, char *line) {
	struct Message msg = parse(line);
	if (!msg.cmd) {
		// FIXME: Identify client in message.
		warnx("no command");
		client->error = true;
		return;
	}
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg.cmd, Handlers[i].cmd)) continue;
		Handlers[i].fn(client, msg);
		break;
	}
}

void clientRecv(struct Client *client) {
	ssize_t read = tls_read(
		client->tls,
		&client->buf[client->len], sizeof(client->buf) - client->len
	);
	if (read == TLS_WANT_POLLIN || read == TLS_WANT_POLLOUT) return;
	if (read < 0) warnx("tls_read: %s", tls_error(client->tls));
	if (read < 1) {
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
		if (client->need) {
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
