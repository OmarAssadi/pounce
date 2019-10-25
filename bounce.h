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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tls.h>

#ifndef DEFAULT_CERT_PATH
#define DEFAULT_CERT_PATH "/usr/local/etc/letsencrypt/live/%s/fullchain.pem"
#endif

#ifndef DEFAULT_PRIV_PATH
#define DEFAULT_PRIV_PATH "/usr/local/etc/letsencrypt/live/%s/privkey.pem"
#endif

#define ARRAY_LEN(a) (sizeof(a) / sizeof(a[0]))

bool verbose;

enum { ParamCap = 15 };
struct Message {
	const char *origin;
	const char *cmd;
	const char *params[ParamCap];
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

void listenConfig(const char *cert, const char *priv);
size_t listenBind(int fds[], size_t cap, const char *host, const char *port);
int listenAccept(struct tls **client, int fd);

int serverConnect(const char *host, const char *port);
void serverLogin(
	const char *pass, const char *auth,
	const char *nick, const char *user, const char *real
);
void serverAuth(void);
void serverRecv(void);
void serverSend(const char *ptr, size_t len);
void serverFormat(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

char *clientPass;
struct Client *clientAlloc(struct tls *tls);
void clientFree(struct Client *client);
bool clientError(const struct Client *client);
void clientRecv(struct Client *client);
void clientSend(struct Client *client, const char *ptr, size_t len);
void clientFormat(struct Client *client, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

bool stateReady(void);
void stateParse(char *line);
void stateSync(struct Client *client);

void ringWrite(const char *line);
size_t ringReader(const char *name);
size_t ringDiff(size_t reader);
const char *ringRead(time_t *time, size_t reader);
