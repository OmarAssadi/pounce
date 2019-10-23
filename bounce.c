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
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "bounce.h"

static struct {
	size_t cap, len;
	struct pollfd *fds;
	struct Client **clients;
} loop;

static void loopAdd(int fd, struct Client *client) {
	if (loop.len == loop.cap) {
		loop.cap = (loop.cap ? loop.cap * 2 : 4);
		loop.fds = realloc(loop.fds, sizeof(struct pollfd) * loop.cap);
		loop.clients = realloc(loop.clients, sizeof(struct Client *) * loop.cap);
		if (!loop.fds || !loop.clients) err(EX_OSERR, "realloc");
	}

	loop.fds[loop.len].fd = fd;
	loop.fds[loop.len].events = POLLIN;
	loop.clients[loop.len] = client;
	loop.len++;
}

static void loopRemove(size_t i) {
	loop.len--;
	loop.fds[i] = loop.fds[loop.len];
	loop.clients[i] = loop.clients[loop.len];
}

static char *censor(char *arg) {
	char *dup = strdup(arg);
	if (!dup) err(EX_OSERR, "strdup");
	memset(arg, '\0', strlen(dup));
	arg[0] = '*';
	return dup;
}

int main(int argc, char *argv[]) {
	const char *localHost = "localhost";
	const char *localPort = "6697";
	const char *localPass = NULL;
	char certPath[PATH_MAX] = "";
	char privPath[PATH_MAX] = "";

	const char *host = NULL;
	const char *port = "6697";
	const char *pass = NULL;
	const char *auth = NULL;
	const char *nick = NULL;
	const char *user = NULL;
	const char *real = NULL;
	const char *join = NULL;

	int opt;
	while (0 < (opt = getopt(argc, argv, "C:H:K:P:W:a:h:j:n:p:r:u:w:"))) {
		switch (opt) {
			break; case 'C': strlcpy(certPath, optarg, sizeof(certPath));
			break; case 'H': localHost = optarg;
			break; case 'K': strlcpy(privPath, optarg, sizeof(privPath));
			break; case 'P': localPort = optarg;
			break; case 'W': localPass = censor(optarg);
			break; case 'a': auth = censor(optarg);
			break; case 'h': host = optarg;
			break; case 'j': join = optarg;
			break; case 'n': nick = optarg;
			break; case 'p': port = optarg;
			break; case 'r': real = optarg;
			break; case 'u': user = optarg;
			break; case 'w': pass = censor(optarg);
			break; default:  return EX_USAGE;
		}
	}

	if (!certPath[0]) {
		snprintf(certPath, sizeof(certPath), DEFAULT_CERT_PATH, localHost);
	}
	if (!privPath[0]) {
		snprintf(privPath, sizeof(privPath), DEFAULT_PRIV_PATH, localHost);
	}

	if (!host) errx(EX_USAGE, "no host");
	if (!nick) {
		nick = getenv("USER");
		if (!nick) errx(EX_CONFIG, "USER unset");
	}
	if (!user) user = nick;
	if (!real) real = nick;

	listenConfig(certPath, privPath);

	enum { BindCap = 8 };
	int bind[BindCap];
	size_t bindLen = listenBind(bind, BindCap, localHost, localPort);

	int server = serverConnect(host, port);
	serverLogin(pass, auth, nick, user, real);

	while (!stateReady()) {
		serverRecv();
	}
	if (join) serverJoin(join);

	for (size_t i = 0; i < bindLen; ++i) {
		int error = listen(bind[i], 1);
		if (error) err(EX_IOERR, "listen");
		loopAdd(bind[i], NULL);
	}
	loopAdd(server, NULL);

	while (0 < poll(loop.fds, loop.len, -1)) {
		for (size_t i = 0; i < loop.len; ++i) {
			if (!loop.fds[i].revents) continue;
			if (i < bindLen) {
				struct Client *client = clientAlloc();
				loopAdd(listenAccept(&client->tls, loop.fds[i].fd), client);
			} else if (!loop.clients[i]) {
				serverRecv();
			} else if (loop.fds[i].revents & POLLERR) {
				close(loop.fds[i].fd);
				clientFree(loop.clients[i]);
				loopRemove(i);
			} else {
				clientRecv(loop.clients[i]);
			}
		}
	}
}
