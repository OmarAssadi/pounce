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
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "bounce.h"

static struct tls *server;

static byte *reread(size_t *len, FILE *file) {
	struct stat stat;
	int error = fstat(fileno(file), &stat);
	if (error) err(EX_IOERR, "fstat");

	byte *buf = malloc(stat.st_size);
	if (!buf) err(EX_OSERR, "malloc");

	fpurge(file);
	rewind(file);
	*len = fread(buf, 1, stat.st_size, file);
	if (ferror(file)) err(EX_IOERR, "fread");

	return buf;
}

void listenConfig(FILE *cert, FILE *priv) {
	tls_free(server);
	server = tls_server();
	if (!server) errx(EX_SOFTWARE, "tls_server");

	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	size_t len;
	byte *buf = reread(&len, cert);
	int error = tls_config_set_cert_mem(config, buf, len);
	if (error) {
		errx(EX_CONFIG, "tls_config_set_cert_mem: %s", tls_config_error(config));
	}
	free(buf);

	buf = reread(&len, priv);
	error = tls_config_set_key_mem(config, buf, len);
	if (error) {
		errx(EX_CONFIG, "tls_config_set_key_mem: %s", tls_config_error(config));
	}
	free(buf);

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

		int yes = 1;
		error = setsockopt(fds[len], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		if (error) err(EX_OSERR, "setsockopt");

		error = bind(fds[len], ai->ai_addr, ai->ai_addrlen);
		if (error) {
			warn("%s:%s", host, port);
			close(fds[len]);
			continue;
		}

		len++;
	}
	freeaddrinfo(head);

	if (!len) errx(EX_UNAVAILABLE, "could not bind any sockets");
	return len;
}

struct tls *listenAccept(int *fd, int bind) {
	*fd = accept(bind, NULL, NULL);
	if (*fd < 0) err(EX_IOERR, "accept");

	int yes = 1;
	int error = setsockopt(*fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
	if (error) err(EX_OSERR, "setsockopt");

	struct tls *client;
	error = tls_accept_socket(server, &client, *fd);
	if (error) errx(EX_SOFTWARE, "tls_accept_socket: %s", tls_error(server));
	return client;
}
