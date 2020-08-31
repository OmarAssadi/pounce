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
#include <time.h>
#include <tls.h>
#include <unistd.h>

#include "bounce.h"

enum Cap clientCaps = CapServerTime | CapConsumer | CapPassive | CapSTS;
char *clientPass;
char *clientAway;

static size_t active;

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
	size_t setPos;
	enum Cap caps;
	char buf[MessageCap];
	size_t len;
	bool error;
};

struct Client *clientAlloc(struct tls *tls) {
	struct Client *client = calloc(1, sizeof(*client));
	if (!client) err(EX_OSERR, "calloc");
	client->tls = tls;
	client->need = NeedNick | NeedUser | (clientPass ? NeedPass : 0);
	if ((clientCaps & CapSASL) && tls_peer_cert_provided(tls)) {
		client->need &= ~NeedPass;
	}
	return client;
}

void clientFree(struct Client *client) {
	if (!client->need) {
		if (!(client->caps & CapPassive) && !--active) {
			serverEnqueue("AWAY :%s\r\n", clientAway);
		}
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
	char buf[MessageCap];
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
		if (client->setPos) ringSet(client->consumer, client->setPos);
		if (!(client->caps & CapPassive) && !active++) {
			serverEnqueue("AWAY\r\n");
		}
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
		if (msg->params[0][0] == '-') client->caps |= CapPassive;
		maybeSync(client);
	}
}

static void handlePass(struct Client *client, struct Message *msg) {
	if (!clientPass) return;
	if (!msg->params[0]) {
		client->error = true;
		return;
	}
#ifdef __OpenBSD__
	int error = crypt_checkpass(msg->params[0], clientPass);
#else
	int error = strcmp(crypt(msg->params[0], clientPass), clientPass);
#endif
	if (error) {
		passRequired(client);
	} else {
		client->need &= ~NeedPass;
		maybeSync(client);
	}
	explicit_bzero(msg->params[0], strlen(msg->params[0]));
}

static void handleCap(struct Client *client, struct Message *msg) {
	if (!msg->params[0]) msg->params[0] = "";

	enum Cap avail = clientCaps | (stateCaps & ~CapSASL);
	const char *values[CapBits] = {
		[CapSASLBit] = "EXTERNAL",
		[CapSTSBit] = "duration=2147483647",
	};

	if (!strcmp(msg->params[0], "END")) {
		if (!client->need) return;
		client->need &= ~NeedCapEnd;
		maybeSync(client);

	} else if (!strcmp(msg->params[0], "LS")) {
		if (client->need) client->need |= NeedCapEnd;
		int version = 0;
		if (msg->params[1]) version = strtol(msg->params[1], NULL, 10);
		if (version >= 302) {
			if (avail & CapCapNotify) client->caps |= CapCapNotify;
			clientFormat(
				client, ":%s CAP * LS :%s\r\n",
				ORIGIN, capList(avail, values)
			);
		} else {
			clientFormat(
				client, ":%s CAP * LS :%s\r\n",
				ORIGIN, capList(avail, NULL)
			);
		}

	} else if (!strcmp(msg->params[0], "REQ") && msg->params[1]) {
		if (client->need) client->need |= NeedCapEnd;
		enum Cap caps = capParse(msg->params[1], values);
		if (caps == (avail & caps)) {
			client->caps |= caps;
			if (caps & CapConsumer && values[CapConsumerBit]) {
				client->setPos = strtoull(values[CapConsumerBit], NULL, 10);
			}
			clientFormat(client, ":%s CAP * ACK :%s\r\n", ORIGIN, msg->params[1]);
		} else {
			clientFormat(client, ":%s CAP * NAK :%s\r\n", ORIGIN, msg->params[1]);
		}

	} else if (!strcmp(msg->params[0], "LIST")) {
		clientFormat(
			client, ":%s CAP * LIST :%s\r\n",
			ORIGIN, capList(client->caps, NULL)
		);

	} else {
		clientFormat(client, ":%s 410 * :Invalid CAP subcommand\r\n", ORIGIN);
	}
}

static void handleAuthenticate(struct Client *client, struct Message *msg) {
	if (!msg->params[0]) msg->params[0] = "";
	if (!strcmp(msg->params[0], "EXTERNAL")) {
		clientFormat(client, "AUTHENTICATE +\r\n");
	} else if (!strcmp(msg->params[0], "+")) {
		clientFormat(
			client, ":%s 900 * %s * :You are now logged in as *\r\n",
			ORIGIN, stateEcho()
		);
		clientFormat(
			client, ":%s 903 * :SASL authentication successful\r\n",
			ORIGIN
		);
	} else {
		clientFormat(
			client, ":%s 904 * :SASL authentication failed\r\n",
			ORIGIN
		);
	}
}

static void handleQuit(struct Client *client, struct Message *msg) {
	(void)msg;
	clientFormat(client, "ERROR :Detaching\r\n");
	client->error = true;
}

static void reserialize(
	char *buf, size_t cap, const char *origin, const struct Message *msg
) {
	size_t len = 0;
	if (msg->tags) {
		len += snprintf(&buf[len], cap - len, "@%s ", msg->tags);
		if (len >= cap) return;
	}
	if (!origin) origin = msg->origin;
	if (origin) {
		len += snprintf(&buf[len], cap - len, ":%s ", origin);
		if (len >= cap) return;
	}
	len += snprintf(&buf[len], cap - len, "%s", msg->cmd);
	if (len >= cap) return;
	for (size_t i = 0; i < ParamCap && msg->params[i]; ++i) {
		if (i + 1 == ParamCap || !msg->params[i + 1]) {
			len += snprintf(&buf[len], cap - len, " :%s", msg->params[i]);
		} else {
			len += snprintf(&buf[len], cap - len, " %s", msg->params[i]);
		}
		if (len >= cap) return;
	}
}

static void clientProduce(struct Client *client, const char *line) {
	size_t diff = ringDiff(client->consumer);
	ringProduce(line);
	if (!diff) ringConsume(NULL, client->consumer);
}

static void handlePrivmsg(struct Client *client, struct Message *msg) {
	if (!msg->params[0]) return;
	char buf[MessageCap];
	reserialize(buf, sizeof(buf), stateEcho(), msg);
	clientProduce(client, buf);
	if (!strcmp(msg->params[0], stateNick())) return;
	reserialize(buf, sizeof(buf), NULL, msg);
	serverFormat("%s\r\n", buf);
}

static void handleTagmsg(struct Client *client, struct Message *msg) {
	if (!msg->params[0]) return;
	char buf[MessageCap];
	reserialize(buf, sizeof(buf), stateEcho(), msg);
	clientProduce(client, buf);
	if (!strcmp(msg->params[0], stateNick())) return;
	reserialize(buf, sizeof(buf), NULL, msg);
	serverFormat("%s\r\n", buf);
}

static void handlePalaver(struct Client *client, struct Message *msg) {
	if (client->need & NeedPass) return;
	char buf[MessageCap];
	reserialize(buf, sizeof(buf), NULL, msg);
	clientProduce(client, buf);
}

static const struct {
	bool intercept;
	bool need;
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ false, false, "AUTHENTICATE", handleAuthenticate },
	{ false, false, "NICK", handleNick },
	{ false, false, "PASS", handlePass },
	{ false, false, "USER", handleUser },
	{ true, false, "CAP", handleCap },
	{ true, false, "PALAVER", handlePalaver },
	{ true, true, "NOTICE", handlePrivmsg },
	{ true, true, "PRIVMSG", handlePrivmsg },
	{ true, true, "QUIT", handleQuit },
	{ true, true, "TAGMSG", handleTagmsg },
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
	if (line[0] == '@') {
		const char *sp = memchr(line, ' ', len);
		if (!sp) return false;
		sp++;
		len -= sp - line;
		line = sp;
	}
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (!Handlers[i].intercept) continue;
		size_t n = strlen(Handlers[i].cmd);
		if (len < n) continue;
		if (memcmp(line, Handlers[i].cmd, n)) continue;
		if (len == n || line[n] == ' ' || line[n] == '\r') return true;
	}
	return false;
}

void clientRecv(struct Client *client) {
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

	char *lf;
	char *line = client->buf;
	for (;;) {
		lf = memchr(line, '\n', &client->buf[client->len] - line);
		if (!lf) break;
		if (verbose) {
			fprintf(stderr, "\x1B[33m%.*s\x1B[m\n", (int)(lf - line), line);
		}
		if (client->need || intercept(line, lf - line)) {
			lf[0] = '\0';
			if (lf - line && lf[-1] == '\r') lf[-1] = '\0';
			clientParse(client, line);
		} else {
			serverSend(line, lf + 1 - line);
		}
		line = lf + 1;
	}
	client->len -= line - client->buf;
	memmove(client->buf, line, client->len);
}

size_t clientDiff(const struct Client *client) {
	if (client->need) return 0;
	return ringDiff(client->consumer);
}

static int wordcmp(const char *line, size_t i, const char *word) {
	if (line[0] == '@') {
		line += strcspn(line, " ");
		if (*line) line++;
	}
	if (line[0] == ':') {
		line += strcspn(line, " ");
		if (*line) line++;
	}
	while (i--) {
		line += strcspn(line, " ");
		if (*line) line++;
	}
	size_t len = strcspn(line, " ");
	return len == strlen(word)
		? strncmp(line, word, len)
		: (int)len - (int)strlen(word);
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
	len += snprintf(&dst[len], cap - len, "%s", src);
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
	return (wordcmp(line, 0, "ACCOUNT") ? line : NULL);
}

static const char *filterAwayNotify(const char *line) {
	return (wordcmp(line, 0, "AWAY") ? line : NULL);
}

static const char *filterBatch(const char *line) {
	return (wordcmp(line, 0, "BATCH") ? line : NULL);
}

static const char *filterCapNotify(const char *line) {
	if (wordcmp(line, 0, "CAP")) return line;
	if (!wordcmp(line, 1, "NEW")) return NULL;
	if (!wordcmp(line, 1, "DEL")) return NULL;
	return line;
}

static const char *filterChghost(const char *line) {
	return (wordcmp(line, 0, "CHGHOST") ? line : NULL);
}

static const char *filterExtendedJoin(const char *line) {
	if (wordcmp(line, 0, "JOIN")) return line;
	static regex_t regex;
	static char buf[MessageCap];
	return snip(buf, sizeof(buf), line, compile(&regex, "(JOIN [^ ]+).+"));
}

static const char *filterInviteNotify(const char *line) {
	if (wordcmp(line, 0, "INVITE")) return line;
	return (wordcmp(line, 1, stateNick()) ? NULL : line);
}

static const char *filterLabeledResponse(const char *line) {
	return (wordcmp(line, 0, "ACK") ? line : NULL);
}

static const char *filterMessageTags(const char *line) {
	return (wordcmp(line, 0, "TAGMSG") ? line : NULL);
}

static const char *filterMultiPrefix(const char *line) {
	static char buf[MessageCap];
	if (!wordcmp(line, 0, "352")) {
		static regex_t regex;
		return snip(
			buf, sizeof(buf), line,
			compile(&regex, "( [HG][*]?[~!@%&+])[~!@%&+]+")
		);
	} else if (!wordcmp(line, 0, "353")) {
		static regex_t regex;
		return snip(
			buf, sizeof(buf), line,
			compile(&regex, "( :?[~!@%&+])[~!@%&+]+")
		);
	} else {
		return line;
	}
}

static const char *filterPalaverApp(const char *line) {
	return (wordcmp(line, 0, "PALAVER") ? line : NULL);
}

static const char *filterSetname(const char *line) {
	return (wordcmp(line, 0, "SETNAME") ? line : NULL);
}

static const char *filterUserhostInNames(const char *line) {
	if (wordcmp(line, 0, "353")) return line;
	static regex_t regex;
	static char buf[MessageCap];
	return snip(
		buf, sizeof(buf), line,
		compile(&regex, "( :?[^!]+)![^ ]+")
	);
}

static const char *filterTags(const char *line) {
	if (line[0] != '@') return line;
	const char *sp = strchr(line, ' ');
	return (sp ? sp + 1 : NULL);
}

static Filter *Filters[] = {
	[CapAccountNotifyBit] = filterAccountNotify,
	[CapAwayNotifyBit] = filterAwayNotify,
	[CapBatchBit] = filterBatch,
	[CapCapNotifyBit] = filterCapNotify,
	[CapChghostBit] = filterChghost,
	[CapExtendedJoinBit] = filterExtendedJoin,
	[CapInviteNotifyBit] = filterInviteNotify,
	[CapLabeledResponseBit] = filterLabeledResponse,
	[CapMessageTagsBit] = filterMessageTags,
	[CapMultiPrefixBit] = filterMultiPrefix,
	[CapPalaverAppBit] = filterPalaverApp,
	[CapSetnameBit] = filterSetname,
	[CapUserhostInNamesBit] = filterUserhostInNames,
};

static bool hasTime(const char *line) {
	if (!strncmp(line, "@time=", 6)) return true;
	while (*line && *line != ' ') {
		line += strcspn(line, "; ");
		if (!strncmp(line, ";time=", 6)) return true;
		if (*line == ';') line++;
	}
	return false;
}

void clientConsume(struct Client *client) {
	struct timeval time;
	const char *line = ringPeek(&time, client->consumer);
	if (!line) return;

	if (stateCaps & TagCaps && !(client->caps & TagCaps)) {
		line = filterTags(line);
	}
	enum Cap diff = client->caps ^ (clientCaps | stateCaps);
	for (size_t i = 0; line && i < ARRAY_LEN(Filters); ++i) {
		if (!Filters[i]) continue;
		if (diff & (1 << i)) line = Filters[i](line);
	}
	if (!line) {
		ringConsume(NULL, client->consumer);
		return;
	}

	if (client->caps & CapServerTime && !hasTime(line)) {
		char ts[sizeof("YYYY-MM-DDThh:mm:ss")];
		struct tm *tm = gmtime(&time.tv_sec);
		strftime(ts, sizeof(ts), "%FT%T", tm);
		clientFormat(
			client, "@time=%s.%03dZ;causal.agency/pos=%zu%c%s\r\n",
			ts, (int)(time.tv_usec / 1000),
			ringPos(client->consumer) + 1,
			(line[0] == '@' ? ';' : ' '),
			(line[0] == '@' ? &line[1] : line)
		);
	} else if (client->caps & CapConsumer) {
		clientFormat(
			client, "@causal.agency/pos=%zu%c%s\r\n",
			ringPos(client->consumer) + 1,
			(line[0] == '@' ? ';' : ' '),
			(line[0] == '@' ? &line[1] : line)
		);
	} else {
		clientFormat(client, "%s\r\n", line);
	}
	if (!client->error) ringConsume(NULL, client->consumer);
}
