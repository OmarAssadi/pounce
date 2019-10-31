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

#define __STDC_WANT_LIB_EXT1__ 1

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "bounce.h"

#ifndef SIGINFO
#define SIGINFO SIGUSR2
#endif

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

static FILE *saveFile;

static void saveExit(void) {
	int error = ringSave(saveFile);
	if (error) warn("fwrite");
	error = fclose(saveFile);
	if (error) warn("fclose");
}

static void saveLoad(const char *path) {
	umask(0066);
	saveFile = fopen(path, "a+");
	if (!saveFile) err(EX_CANTCREAT, "%s", path);

	int error = flock(fileno(saveFile), LOCK_EX | LOCK_NB);
	if (error && errno != EWOULDBLOCK) err(EX_OSERR, "flock");
	if (error) errx(EX_CANTCREAT, "%s: lock held by other process", path);

	rewind(saveFile);
	ringLoad(saveFile);

	error = ftruncate(fileno(saveFile), 0);
	if (error) err(EX_IOERR, "ftruncate");

	atexit(saveExit);
}

int main(int argc, char *argv[]) {
	const char *bindHost = "localhost";
	const char *bindPort = "6697";
	char certPath[PATH_MAX] = "";
	char privPath[PATH_MAX] = "";
	const char *save = NULL;
	size_t ring = 4096;

	bool insecure = false;
	const char *host = NULL;
	const char *port = "6697";
	char *pass = NULL;
	char *auth = NULL;
	const char *nick = NULL;
	const char *user = NULL;
	const char *real = NULL;
	const char *join = NULL;
	const char *away = "pounced :3";
	const char *quit = "connection reset by purr";

	const char *Opts = "!A:C:H:K:NP:Q:W:a:f:h:j:n:p:r:s:u:vw:";
	const struct option LongOpts[] = {
		{ "insecure", no_argument, NULL, '!' },
		{ "away", required_argument, NULL, 'A' },
		{ "cert", required_argument, NULL, 'C' },
		{ "bind-host", required_argument, NULL, 'H' },
		{ "key", required_argument, NULL, 'K' },
		{ "names", no_argument, NULL, 'N' },
		{ "bind-port", required_argument, NULL, 'P' },
		{ "quit", required_argument, NULL, 'Q' },
		{ "client-pass", required_argument, NULL, 'W' },
		{ "sasl", required_argument, NULL, 'a' },
		{ "save", required_argument, NULL, 'f' },
		{ "host", required_argument, NULL, 'h' },
		{ "join", required_argument, NULL, 'j' },
		{ "nick", required_argument, NULL, 'n' },
		{ "port", required_argument, NULL, 'p' },
		{ "real", required_argument, NULL, 'r' },
		{ "size", required_argument, NULL, 's' },
		{ "user", required_argument, NULL, 'u' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "pass", required_argument, NULL, 'w' },
		{0},
	};

	int opt;
	while (0 < (opt = getopt_config(argc, argv, Opts, LongOpts, NULL))) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'A': away = optarg;
			break; case 'C': strlcpy(certPath, optarg, sizeof(certPath));
			break; case 'H': bindHost = optarg;
			break; case 'K': strlcpy(privPath, optarg, sizeof(privPath));
			break; case 'N': stateJoinNames = true;
			break; case 'P': bindPort = optarg;
			break; case 'Q': quit = optarg;
			break; case 'W': clientPass = optarg;
			break; case 'a': auth = optarg;
			break; case 'f': save = optarg;
			break; case 'h': host = optarg;
			break; case 'j': join = optarg;
			break; case 'n': nick = optarg;
			break; case 'p': port = optarg;
			break; case 'r': real = optarg;
			break; case 's': {
				char *rest;
				ring = strtoull(optarg, &rest, 0);
				if (*rest) errx(EX_USAGE, "invalid size: %s", optarg);
			}
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
			break; case 'w': pass = optarg;
			break; default:  return EX_USAGE;
		}
	}

	if (!certPath[0]) {
		snprintf(certPath, sizeof(certPath), DEFAULT_CERT_PATH, bindHost);
	}
	if (!privPath[0]) {
		snprintf(privPath, sizeof(privPath), DEFAULT_PRIV_PATH, bindHost);
	}
	if (!host) errx(EX_USAGE, "no host");
	if (!nick) {
		nick = getenv("USER");
		if (!nick) errx(EX_CONFIG, "USER unset");
	}
	if (!user) user = nick;
	if (!real) real = nick;

	ringAlloc(ring);
	if (save) saveLoad(save);

	int bind[8];
	listenConfig(certPath, privPath);
	size_t binds = listenBind(bind, 8, bindHost, bindPort);

	int server = serverConnect(insecure, host, port);
	stateLogin(pass, auth, nick, user, real);
	if (pass) memset_s(pass, strlen(pass), 0, strlen(pass));
	if (auth) memset_s(auth, strlen(auth), 0, strlen(auth));

	while (!stateReady()) serverRecv();
	serverFormat("AWAY :%s\r\n", away);
	if (join) serverFormat("JOIN :%s\r\n", join);

	for (size_t i = 0; i < binds; ++i) {
		int error = listen(bind[i], 1);
		if (error) err(EX_IOERR, "listen");
		eventAdd(bind[i], NULL);
	}
	eventAdd(server, NULL);

	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	signal(SIGINFO, signalHandler);
	signal(SIGUSR1, signalHandler);

	size_t clients = 0;
	for (;;) {
		int nfds = poll(event.fds, event.len, -1);
		if (nfds < 0 && errno != EINTR) err(EX_IOERR, "poll");

		if (signals[SIGINT] || signals[SIGTERM]) break;
		if (signals[SIGINFO]) {
			ringInfo();
			signals[SIGINFO] = 0;
		}
		if (signals[SIGUSR1]) {
			listenConfig(certPath, privPath);
			signals[SIGUSR1] = 0;
		}

		if (nfds < 0) continue;
		for (size_t i = event.len - 1; i < event.len; --i) {
			short revents = event.fds[i].revents;
			if (!revents) continue;

			if (i < binds) {
				int fd;
				struct tls *tls = listenAccept(&fd, event.fds[i].fd);
				int error = tls_handshake(tls);
				if (error) {
					warnx("tls_handshake: %s", tls_error(tls));
					tls_free(tls);
					close(fd);
				} else {
					eventAdd(fd, clientAlloc(tls));
					if (!clients++) serverFormat("AWAY\r\n");
				}
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

	serverFormat("QUIT :%s\r\n", quit);
	for (size_t i = 0; i < event.len; ++i) {
		if (event.clients[i]) {
			clientFormat(event.clients[i], "ERROR :Disconnecting\r\n");
			clientFree(event.clients[i]);
		}
		close(event.fds[i].fd);
	}
}
