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

	// TODO: Wait for successful login before listening.
	for (size_t i = 0; i < bindLen; ++i) {
		int error = listen(bind[i], 1);
		if (error) err(EX_IOERR, "listen");
	}

	// Wishing for struct-of-arrays...
	struct pollfd fds[BindCap];
	for (size_t i = 0; i < bindLen; ++i) {
		fds[i].fd = bind[i];
		fds[i].events = POLLIN;
	}

	while (0 < poll(fds, bindLen, -1)) {
		for (size_t i = 0; i < bindLen; ++i) {
			if (!fds[i].revents) continue;
			struct tls *client;
			int fd = listenAccept(&client, fds[i].fd);
		}
	}
}
