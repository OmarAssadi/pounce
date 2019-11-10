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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tls.h>

#include "compat.h"

#ifndef CERTBOT_PATH
#define CERTBOT_PATH "/usr/local/etc/letsencrypt"
#endif

#define SOURCE_URL "https://code.causal.agency/june/pounce"
#define ORIGIN "irc.invalid"

#define BIT(x) x##Bit, x = 1 << x##Bit, x##Bit_ = x##Bit
#define ARRAY_LEN(a) (sizeof(a) / sizeof(a[0]))

typedef unsigned char byte;

enum { ParamCap = 15 };
struct Message {
	char *origin;
	char *cmd;
	char *params[ParamCap];
};

static inline struct Message parse(char *line) {
	struct Message msg = {0};
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
	X("away-notify", CapAwayNotify) \
	X("chghost", CapChghost) \
	X("extended-join", CapExtendedJoin) \
	X("invite-notify", CapInviteNotify) \
	X("sasl", CapSASL) \
	X("server-time", CapServerTime) \
	X("", CapUnsupported)

enum Cap {
#define X(name, id) BIT(id),
	ENUM_CAP
#undef X
};

static const char *CapNames[] = {
#define X(name, id) [id##Bit] = name,
	ENUM_CAP
#undef X
};

static inline enum Cap capParse(const char *list) {
	enum Cap caps = 0;
	while (*list) {
		enum Cap cap = CapUnsupported;
		size_t len = strcspn(list, " ");
		for (size_t i = 0; i < ARRAY_LEN(CapNames); ++i) {
			if (len != strlen(CapNames[i])) continue;
			if (strncmp(list, CapNames[i], len)) continue;
			cap = 1 << i;
			break;
		}
		caps |= cap;
		list += len;
		if (*list) list++;
	}
	return caps;
}

static inline const char *capList(enum Cap caps) {
	static char buf[1024];
	buf[0] = '\0';
	for (size_t i = 0; i < ARRAY_LEN(CapNames); ++i) {
		if (caps & (1 << i)) {
			if (buf[0]) strlcat(buf, " ", sizeof(buf));
			strlcat(buf, CapNames[i], sizeof(buf));
		}
	}
	return buf;
}

bool verbose;

void ringAlloc(size_t len);
void ringProduce(const char *line);
size_t ringConsumer(const char *name);
size_t ringDiff(size_t consumer);
const char *ringPeek(time_t *time, size_t consumer);
const char *ringConsume(time_t *time, size_t consumer);
void ringInfo(void);
int ringSave(FILE *file);
void ringLoad(FILE *file);

void listenConfig(FILE *cert, FILE *priv);
size_t listenBind(int fds[], size_t cap, const char *host, const char *port);
size_t listenUnix(int fds[], size_t cap, const char *path);
struct tls *listenAccept(int *fd, int bind);

void serverConfig(bool insecure, const char *cert, const char *priv);
int serverConnect(const char *host, const char *port);
void serverRecv(void);
void serverSend(const char *ptr, size_t len);
void serverFormat(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

char *clientPass;
char *clientAway;
struct Client *clientAlloc(struct tls *tls);
void clientFree(struct Client *client);
bool clientError(const struct Client *client);
void clientRecv(struct Client *client);
void clientSend(struct Client *client, const char *ptr, size_t len);
void clientFormat(struct Client *client, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
size_t clientDiff(const struct Client *client);
void clientConsume(struct Client *client);

bool stateJoinNames;
enum Cap stateCaps;
void stateLogin(
	const char *pass, bool sasl, const char *plain,
	const char *nick, const char *user, const char *real
);
bool stateReady(void);
void stateParse(char *line);
void stateSync(struct Client *client);
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
