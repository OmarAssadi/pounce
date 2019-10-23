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
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "bounce.h"

static struct tls *server;

void listenConfig(const char *cert, const char *priv) {
	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	int error = tls_config_set_keypair_file(config, cert, priv);
	if (error) {
		errx(
			EX_CONFIG, "tls_config_set_keypair_file: %s",
			tls_config_error(config)
		);
	}

	server = tls_server();
	if (!server) errx(EX_SOFTWARE, "tls_server");

	error = tls_configure(server, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(server));
	tls_config_free(config);
}

size_t listenBind(int fds[], size_t cap, const char *host, const char *port) {
	struct addrinfo *head;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	int error = getaddrinfo(host, port, &hints, &head);
	if (error) errx(EX_NOHOST, "%s:%s: %s", host, port, gai_strerror(error));

	size_t len = 0;
	for (struct addrinfo *ai = head; ai && len < cap; ai = ai->ai_next) {
		fds[len] = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fds[len] < 0) err(EX_OSERR, "socket");

		error = bind(fds[len], ai->ai_addr, ai->ai_addrlen);
		if (error) {
			warn("%s:%s", host, port);
			close(fds[len]);
			continue;
		}

		error = listen(fds[len], 1);
		if (error) err(EX_IOERR, "listen");

		len++;
	}
	freeaddrinfo(head);

	if (!len) errx(EX_UNAVAILABLE, "could not bind any sockets");
	return len;
}

int listenAccept(struct tls **client, int fd) {
	int sock = accept(fd, NULL, NULL);
	if (sock < 0) err(EX_IOERR, "accept");

	int yes = 1;
	int error = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
	if (error) err(EX_OSERR, "setsockopt");

	error = tls_accept_socket(server, client, sock);
	if (error) errx(EX_SOFTWARE, "tls_accept_socket: %s", tls_error(server));

	return sock;
}
