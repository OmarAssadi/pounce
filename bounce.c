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
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "bounce.h"

static volatile sig_atomic_t signals[NSIG];
static void signalHandler(int signal) {
	signals[signal] = 1;
}

static struct {
	struct pollfd *fds;
	struct Client **clients;
	size_t cap, len;
} event;

static void eventAdd(int fd, struct Client *client) {
	if (event.len == event.cap) {
		event.cap = (event.cap ? event.cap * 2 : 8);
		event.fds = realloc(event.fds, sizeof(*event.fds) * event.cap);
		if (!event.fds) err(EX_OSERR, "realloc");
		event.clients = realloc(
			event.clients, sizeof(*event.clients) * event.cap
		);
		if (!event.clients) err(EX_OSERR, "realloc");
	}
	event.fds[event.len] = (struct pollfd) { .fd = fd, .events = POLLIN };
	event.clients[event.len] = client;
	event.len++;
}

static void eventRemove(size_t i) {
	event.len--;
	event.fds[i] = event.fds[event.len];
	event.clients[i] = event.clients[event.len];
}

static char *sensitive(char *arg) {
	char *value = NULL;
	if (arg[0] == '@') {
		FILE *file = fopen(&arg[1], "r");
		if (!file) err(EX_NOINPUT, "%s", &arg[1]);

		size_t cap = 0;
		ssize_t len = getline(&value, &cap, file);
		if (len < 0) err(EX_IOERR, "%s", &arg[1]);

		if (len && value[len - 1] == '\n') value[len - 1] = '\0';
		fclose(file);

	} else {
		value = strdup(arg);
		if (!value) err(EX_OSERR, "strdup");
	}
	memset(arg, '\0', strlen(arg));
	arg[0] = '*';
	return value;
}

int main(int argc, char *argv[]) {
	const char *localHost = "localhost";
	const char *localPort = "6697";
	char certPath[PATH_MAX] = "";
	char privPath[PATH_MAX] = "";

	bool insecure = false;
	const char *host = NULL;
	const char *port = "6697";
	const char *pass = NULL;
	const char *auth = NULL;
	const char *nick = NULL;
	const char *user = NULL;
	const char *real = NULL;
	const char *join = NULL;
	const char *away = "pounced :3";

	int opt;
	while (0 < (opt = getopt(argc, argv, "!A:C:H:K:NP:W:a:h:j:n:p:r:u:vw:"))) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'A': away = optarg;
			break; case 'C': strlcpy(certPath, optarg, sizeof(certPath));
			break; case 'H': localHost = optarg;
			break; case 'K': strlcpy(privPath, optarg, sizeof(privPath));
			break; case 'N': stateJoinNames = true;
			break; case 'P': localPort = optarg;
			break; case 'W': clientPass = sensitive(optarg);
			break; case 'a': auth = sensitive(optarg);
			break; case 'h': host = optarg;
			break; case 'j': join = optarg;
			break; case 'n': nick = optarg;
			break; case 'p': port = optarg;
			break; case 'r': real = optarg;
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
			break; case 'w': pass = sensitive(optarg);
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

	int bind[8];
	size_t binds = listenBind(bind, 8, localHost, localPort);

	int server = serverConnect(insecure, host, port);
	serverLogin(pass, auth, nick, user, real);
	while (!stateReady()) serverRecv();
	if (join) serverFormat("JOIN :%s\r\n", join);

	for (size_t i = 0; i < binds; ++i) {
		int error = listen(bind[i], 1);
		if (error) err(EX_IOERR, "listen");
		eventAdd(bind[i], NULL);
	}
	eventAdd(server, NULL);

	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);

	size_t clients = 0;
	for (;;) {
		int nfds = poll(event.fds, event.len, -1);
		if (nfds < 0 && errno != EINTR) err(EX_IOERR, "poll");
		if (signals[SIGINT] || signals[SIGTERM]) break;
		if (nfds < 0) continue;

		for (size_t i = 0; i < event.len; ++i) {
			short revents = event.fds[i].revents;
			if (!revents) continue;

			if (i < binds) {
				int fd;
				struct tls *tls = listenAccept(&fd, event.fds[i].fd);
				eventAdd(fd, clientAlloc(tls));
				// FIXME: This should only be done after a successful client
				// registration.
				if (!clients++) serverFormat("AWAY\r\n");
				continue;
			}

			if (!event.clients[i]) {
				if (revents & POLLIN) {
					serverRecv();
				} else {
					errx(EX_UNAVAILABLE, "server hung up");
				}
				continue;
			}

			struct Client *client = event.clients[i];
			if (revents & POLLIN) clientRecv(client);
			if (revents & POLLOUT) clientConsume(client);
			if (clientError(client) || revents & (POLLHUP | POLLERR)) {
				clientFree(client);
				close(event.fds[i].fd);
				eventRemove(i);
				if (!--clients) serverFormat("AWAY :%s\r\n", away);
				break;
			}
		}

		for (size_t i = binds + 1; i < event.len; ++i) {
			assert(event.clients[i]);
			if (clientDiff(event.clients[i])) {
				event.fds[i].events |= POLLOUT;
			} else {
				event.fds[i].events &= ~POLLOUT;
			}
		}
	}

	serverFormat("QUIT\r\n");
	for (size_t i = 0; i < event.len; ++i) {
		if (event.clients[i]) {
			clientFormat(event.clients[i], "ERROR :Disconnecting\r\n");
			clientFree(event.clients[i]);
		}
		close(event.fds[i].fd);
	}
}
