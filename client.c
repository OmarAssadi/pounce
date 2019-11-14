/* Copyright (C) 2019  C. McEnroe <june@causal.agency>
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
 */

#include <assert.h>
#include <err.h>
#include <regex.h>
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

static size_t count;

enum Need {
	BIT(NeedNick),
	BIT(NeedUser),
	BIT(NeedPass),
	BIT(NeedCapEnd),
};

struct Client {
	struct tls *tls;
	enum Need need;
	size_t consumer;
	enum Cap caps;
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
	if (!client->need) {
		if (!--count) serverFormat("AWAY :%s\r\n", clientAway);
	}
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
		ORIGIN
	);
	client->error = true;
}

static void maybeSync(struct Client *client) {
	if (client->need == NeedPass) passRequired(client);
	if (!client->need) {
		stateSync(client);
		if (!count++) serverFormat("AWAY\r\n");
	}
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
	enum Cap avail = CapServerTime | (stateCaps & ~CapSASL);

	if (!strcmp(msg->params[0], "END")) {
		if (!client->need) return;
		client->need &= ~NeedCapEnd;
		maybeSync(client);

	} else if (!strcmp(msg->params[0], "LS")) {
		if (client->need) client->need |= NeedCapEnd;
		clientFormat(client, ":%s CAP * LS :%s\r\n", ORIGIN, capList(avail));

	} else if (!strcmp(msg->params[0], "REQ") && msg->params[1]) {
		if (client->need) client->need |= NeedCapEnd;
		enum Cap caps = capParse(msg->params[1]);
		if (caps == (avail & caps)) {
			client->caps |= caps;
			clientFormat(client, ":%s CAP * ACK :%s\r\n", ORIGIN, msg->params[1]);
		} else {
			clientFormat(client, ":%s CAP * NAK :%s\r\n", ORIGIN, msg->params[1]);
		}

	} else if (!strcmp(msg->params[0], "LIST")) {
		clientFormat(
			client, ":%s CAP * LIST :%s\r\n",
			ORIGIN, capList(client->caps)
		);

	} else {
		clientFormat(client, ":%s 410 * :Invalid CAP subcommand\r\n", ORIGIN);
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

static int wordcmp(const char *line, size_t i, const char *word) {
	while (i--) {
		line += strcspn(line, " ");
		if (*line) line++;
	}
	size_t len = strcspn(line, " ");
	return len == strlen(word)
		? strncmp(line, word, len)
		: len - strlen(word);
}

static size_t strlcpyn(char *dst, const char *src, size_t cap, size_t len) {
	if (len < cap) {
		memcpy(dst, src, len);
		dst[len] = '\0';
	} else {
		memcpy(dst, src, cap - 1);
		dst[cap - 1] = '\0';
	}
	return len;
}

// s/..(..)../\1/g
static char *snip(char *dst, size_t cap, const char *src, const regex_t *regex) {
	size_t len = 0;
	regmatch_t match[2];
	assert(regex->re_nsub);
	for (; *src; src += match[0].rm_eo) {
		if (regexec(regex, src, 2, match, 0)) break;
		len += strlcpyn(&dst[len], src, cap - len, match[0].rm_so);
		if (len >= cap) return NULL;
		len += strlcpyn(
			&dst[len], &src[match[1].rm_so],
			cap - len, match[1].rm_eo - match[1].rm_so
		);
		if (len >= cap) return NULL;
	}
	len += strlcpy(&dst[len], src, cap - len);
	return (len < cap ? dst : NULL);
}

static regex_t *compile(regex_t *regex, const char *pattern) {
	if (regex->re_nsub) return regex;
	int error = regcomp(regex, pattern, REG_EXTENDED);
	if (error) {
		char buf[256];
		regerror(error, regex, buf, sizeof(buf));
		errx(EX_SOFTWARE, "regcomp: %s: %s", buf, pattern);
	}
	return regex;
}

typedef const char *Filter(const char *line);

static const char *filterAccountNotify(const char *line) {
	return (wordcmp(line, 1, "ACCOUNT") ? line : NULL);
}

static const char *filterAwayNotify(const char *line) {
	return (wordcmp(line, 1, "AWAY") ? line : NULL);
}

static const char *filterChghost(const char *line) {
	return (wordcmp(line, 1, "CHGHOST") ? line : NULL);
}

static const char *filterExtendedJoin(const char *line) {
	if (wordcmp(line, 1, "JOIN")) return line;
	static regex_t regex;
	static char buf[512];
	return snip(buf, sizeof(buf), line, compile(&regex, "(JOIN [^ ]+).+"));
}

static const char *filterInviteNotify(const char *line) {
	if (wordcmp(line, 1, "INVITE")) return line;
	return (wordcmp(line, 2, stateNick()) ? NULL : line);
}

static const char *filterMultiPrefix(const char *line) {
	static char buf[512];
	if (!wordcmp(line, 1, "352")) {
		static regex_t regex;
		return snip(
			buf, sizeof(buf), line,
			compile(&regex, "( [HG][*]?[~!@%&+])[~!@%&+]+")
		);
	} else if (!wordcmp(line, 1, "353")) {
		static regex_t regex;
		return snip(
			buf, sizeof(buf), line,
			compile(&regex, "( :?[~!@%&+])[~!@%&+]+")
		);
	} else {
		return line;
	}
}

static const char *filterUserhostInNames(const char *line) {
	if (wordcmp(line, 1, "353")) return line;
	static regex_t regex;
	static char buf[512];
	return snip(
		buf, sizeof(buf), line,
		compile(&regex, "( :?[^!]+)![^ ]+")
	);
}

static Filter *Filters[] = {
	[CapAccountNotifyBit] = filterAccountNotify,
	[CapAwayNotifyBit] = filterAwayNotify,
	[CapChghostBit] = filterChghost,
	[CapExtendedJoinBit] = filterExtendedJoin,
	[CapInviteNotifyBit] = filterInviteNotify,
	[CapMultiPrefixBit] = filterMultiPrefix,
	[CapUserhostInNamesBit] = filterUserhostInNames,
};

void clientConsume(struct Client *client) {
	time_t time;
	const char *line = ringPeek(&time, client->consumer);
	if (!line) return;

	enum Cap diff = client->caps ^ stateCaps;
	for (size_t i = 0; line && i < ARRAY_LEN(Filters); ++i) {
		if (!Filters[i]) continue;
		if (diff & (1 << i)) line = Filters[i](line);
	}
	if (!line) {
		ringConsume(NULL, client->consumer);
		return;
	}

	// TODO: Move into a filter?
	if (client->caps & CapServerTime) {
		char ts[sizeof("YYYY-MM-DDThh:mm:ss.sssZ")];
		struct tm *tm = gmtime(&time);
		strftime(ts, sizeof(ts), "%FT%T.000Z", tm);
		clientFormat(client, "@time=%s %s\r\n", ts, line);
	} else {
		clientFormat(client, "%s\r\n", line);
	}
	if (!client->error) ringConsume(NULL, client->consumer);
}
