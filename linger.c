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
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#ifndef DEFAULT_CERT_PATH
#define DEFAULT_CERT_PATH "/usr/local/etc/letsencrypt/live/%s/fullchain.pem"
#endif

#ifndef DEFAULT_PRIV_PATH
#define DEFAULT_PRIV_PATH "/usr/local/etc/letsencrypt/live/%s/privkey.pem"
#endif

static char *censor(char *arg) {
	char *dup = strdup(arg);
	if (!dup) err(EX_OSERR, "strdup");
	memset(arg, '*', strlen(dup));
	return dup;
}

int main(int argc, char *argv[]) {
	int error;

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

	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	error = tls_config_set_keypair_file(config, certPath, privPath);
	if (error) {
		errx(
			EX_CONFIG, "tls_config_set_keypair_file: %s",
			tls_config_error(config)
		);
	}

	struct tls *server = tls_server();
	if (!server) errx(EX_SOFTWARE, "tls_server");

	error = tls_configure(server, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(server));
	tls_config_free(config);

	struct addrinfo *head;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	error = getaddrinfo(localHost, localPort, &hints, &head);
	if (error) {
		errx(EX_NOHOST, "%s:%s: %s", localHost, localPort, gai_strerror(error));
	}

	enum { PollCap = 64 };
	struct pollfd fds[PollCap];

	size_t binds = 0;
	for (struct addrinfo *ai = head; ai; ai = ai->ai_next) {
		fds[binds].fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fds[binds].fd < 0) err(EX_OSERR, "socket");

		error = bind(fds[binds].fd, ai->ai_addr, ai->ai_addrlen);
		if (error) {
			warn("%s:%s", localHost, localPort);
			close(fds[binds].fd);
			continue;
		}

		if (++binds == PollCap) errx(EX_CONFIG, "too many sockets to bind");
	}
	if (!binds) return EX_UNAVAILABLE;
	freeaddrinfo(head);

	for (size_t i = 0; i < binds; ++i) {
		fds[i].events = POLLIN;
		error = listen(fds[i].fd, 1);
		if (error) err(EX_IOERR, "listen");
	}

	while (0 < poll(fds, binds, -1)) {
		for (size_t i = 0; i < binds; ++i) {
			if (!fds[i].revents) continue;

			int sock = accept(fds[i].fd, NULL, NULL);
			if (sock < 0) err(EX_IOERR, "accept");

			struct tls *client;
			error = tls_accept_socket(server, &client, sock);
			if (error) {
				errx(EX_SOFTWARE, "tls_accept_socket: %s", tls_error(server));
			}
		}
	}
}
