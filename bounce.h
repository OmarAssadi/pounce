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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <tls.h>

#ifndef CERTBOT_PATH
#define CERTBOT_PATH "/etc/letsencrypt"
#endif

#ifndef OPENSSL_BIN
#define OPENSSL_BIN "openssl"
#endif

#define SOURCE_URL "https://git.causal.agency/pounce"
#define ORIGIN "irc.invalid"

#define BIT(x) x##Bit, x = 1 << x##Bit, x##Bit_ = x##Bit
#define ARRAY_LEN(a) (sizeof(a) / sizeof(a[0]))

typedef unsigned char byte;

enum { MessageCap = 8191 + 512 };

enum { ParamCap = 15 };
struct Message {
	char *tags;
	char *origin;
	char *cmd;
	char *params[ParamCap];
};

static inline struct Message parse(char *line) {
	struct Message msg = {0};
	if (line[0] == '@') msg.tags = 1 + strsep(&line, " ");
	if (line[0] == ':') msg.origin = 1 + strsep(&line, " ");
	msg.cmd = strsep(&line, " ");
	for (size_t i = 0; line && i < ParamCap; ++i) {
		if (line[0] == ':') {
			msg.params[i] = &line[1];
			break;
		}
		msg.params[i] = strsep(&line, " ");
	}
	return msg;
}

#define ENUM_CAP \
	X("account-notify", CapAccountNotify) \
	X("account-tag", CapAccountTag) \
	X("away-notify", CapAwayNotify) \
	X("batch", CapBatch) \
	X("cap-notify", CapCapNotify) \
	X("causal.agency/consumer", CapConsumer) \
	X("causal.agency/passive", CapPassive) \
	X("chghost", CapChghost) \
	X("extended-join", CapExtendedJoin) \
	X("invite-notify", CapInviteNotify) \
	X("labeled-response", CapLabeledResponse) \
	X("message-tags", CapMessageTags) \
	X("multi-prefix", CapMultiPrefix) \
	X("palaverapp.com", CapPalaverApp) \
	X("sasl", CapSASL) \
	X("server-time", CapServerTime) \
	X("setname", CapSetname) \
	X("sts", CapSTS) \
	X("userhost-in-names", CapUserhostInNames) \
	X("", CapUnsupported)

enum Cap {
#define X(name, id) BIT(id),
	ENUM_CAP
#undef X
	CapBits,
	TagCaps = 0
		| CapAccountTag
		| CapBatch
		| CapConsumer
		| CapLabeledResponse
		| CapMessageTags
		| CapServerTime,
};

static const char *CapNames[] = {
#define X(name, id) [id##Bit] = name,
	ENUM_CAP
#undef X
};

static inline enum Cap capParse(const char *list, const char *values[CapBits]) {
	enum Cap caps = 0;
	while (*list) {
		enum Cap cap = CapUnsupported;
		size_t len = strcspn(list, "= ");
		for (size_t i = 0; i < ARRAY_LEN(CapNames); ++i) {
			if (len != strlen(CapNames[i])) continue;
			if (strncmp(list, CapNames[i], len)) continue;
			cap = 1 << i;
			if (list[len] == '=' && values) values[i] = &list[len + 1];
			break;
		}
		caps |= cap;
		list += strcspn(list, " ");
		if (*list) list++;
	}
	return caps;
}

static inline const char *capList(enum Cap caps, const char *values[CapBits]) {
	static char buf[1024];
	buf[0] = '\0';
	size_t len = 0;
	for (size_t i = 0; i < ARRAY_LEN(CapNames); ++i) {
		if (caps & (1 << i)) {
			len += snprintf(
				&buf[len], sizeof(buf) - len,
				"%s%s%s%s",
				(len ? " " : ""), CapNames[i],
				(values && values[i] ? "=" : ""),
				(values && values[i] ? values[i] : "")
			);
			if (len >= sizeof(buf)) break;
		}
	}
	return buf;
}

extern bool verbose;

void ringAlloc(size_t len);
void ringProduce(const char *line);
size_t ringConsumer(const char *name);
void ringSet(size_t consumer, size_t pos);
size_t ringPos(size_t consumer);
size_t ringDiff(size_t consumer);
const char *ringPeek(struct timeval *time, size_t consumer);
const char *ringConsume(struct timeval *time, size_t consumer);
void ringInfo(void);
int ringSave(FILE *file);
void ringLoad(FILE *file);

void localConfig(FILE *cert, FILE *priv, FILE *ca, bool require);
size_t localBind(int fds[], size_t cap, const char *host, const char *port);
size_t localUnix(int fds[], size_t cap, const char *path);
struct tls *localAccept(int *fd, int bind);

extern struct timeval serverQueueInterval;
void serverConfig(bool insecure, const char *cert, const char *priv);
int serverConnect(const char *bindHost, const char *host, const char *port);
void serverRecv(void);
void serverSend(const char *ptr, size_t len);
void serverFormat(const char *format, ...)
	__attribute__((format(printf, 1, 2)));
void serverEnqueue(const char *format, ...)
	__attribute__((format(printf, 1, 2)));
void serverDequeue(void);

extern enum Cap clientCaps;
extern char *clientPass;
extern char *clientAway;
struct Client *clientAlloc(struct tls *tls);
void clientFree(struct Client *client);
bool clientError(const struct Client *client);
void clientRecv(struct Client *client);
void clientSend(struct Client *client, const char *ptr, size_t len);
void clientFormat(struct Client *client, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
size_t clientDiff(const struct Client *client);
void clientConsume(struct Client *client);

extern bool stateNoNames;
extern enum Cap stateCaps;
void stateLogin(
	const char *pass, enum Cap blind, const char *plain,
	const char *nick, const char *user, const char *real
);
bool stateReady(void);
void stateParse(char *line);
void stateSync(struct Client *client);
const char *stateNick(void);
const char *stateEcho(void);

struct option;
int getopt_config(
	int argc, char *const *argv,
	const char *optstring, const struct option *longopts, int *longindex
);

static const char Base64[64] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};

#define BASE64_SIZE(len) (1 + ((len) + 2) / 3 * 4)

static inline void base64(char *dst, const byte *src, size_t len) {
	size_t i = 0;
	while (len > 2) {
		dst[i++] = Base64[0x3F & (src[0] >> 2)];
		dst[i++] = Base64[0x3F & (src[0] << 4 | src[1] >> 4)];
		dst[i++] = Base64[0x3F & (src[1] << 2 | src[2] >> 6)];
		dst[i++] = Base64[0x3F & src[2]];
		src += 3;
		len -= 3;
	}
	if (len) {
		dst[i++] = Base64[0x3F & (src[0] >> 2)];
		if (len > 1) {
			dst[i++] = Base64[0x3F & (src[0] << 4 | src[1] >> 4)];
			dst[i++] = Base64[0x3F & (src[1] << 2)];
		} else {
			dst[i++] = Base64[0x3F & (src[0] << 4)];
			dst[i++] = '=';
		}
		dst[i++] = '=';
	}
	dst[i] = '\0';
}
