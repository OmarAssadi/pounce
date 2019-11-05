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

#include "bounce.h"

#include <assert.h>
#include <err.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

static struct tls *client;

void serverConfig(bool insecure, const char *cert, const char *priv) {
	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	int error = tls_config_set_ciphers(config, "compat");
	if (error) {
		errx(EX_SOFTWARE, "tls_config_set_ciphers: %s", tls_config_error(config));
	}

	if (insecure) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
	}

	if (cert) {
		error = tls_config_set_cert_file(config, cert);
		if (error) {
			errx(
				EX_SOFTWARE, "tls_config_set_cert_file: %s",
				tls_config_error(config)
			);
		}
	}

	if (cert && !priv) priv = cert;
	if (priv) {
		error = tls_config_set_key_file(config, priv);
		if (error) {
			errx(
				EX_SOFTWARE, "tls_config_set_key_file: %s",
				tls_config_error(config)
			);
		}
	}

	client = tls_client();
	if (!client) errx(EX_SOFTWARE, "tls_client");

	error = tls_configure(client, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(client));
	tls_config_free(config);
}

int serverConnect(const char *host, const char *port) {
	assert(client);

	struct addrinfo *head;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	int error = getaddrinfo(host, port, &hints, &head);
	if (error) errx(EX_NOHOST, "%s:%s: %s", host, port, gai_strerror(error));

	int sock = -1;
	for (struct addrinfo *ai = head; ai; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) err(EX_OSERR, "socket");

		error = connect(sock, ai->ai_addr, ai->ai_addrlen);
		if (!error) break;

		close(sock);
		sock = -1;
	}
	if (sock < 0) err(EX_UNAVAILABLE, "%s:%s", host, port);
	freeaddrinfo(head);

	int yes = 1;
	error = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
	if (error) err(EX_OSERR, "setsockopt");

	error = tls_connect_socket(client, sock, host);
	if (error) errx(EX_PROTOCOL, "tls_connect: %s", tls_error(client));

	error = tls_handshake(client);
	if (error) errx(EX_PROTOCOL, "tls_handshake: %s", tls_error(client));

	return sock;
}

void serverSend(const char *ptr, size_t len) {
	if (verbose) fprintf(stderr, "\x1B[31m%.*s\x1B[m", (int)len, ptr);
	while (len) {
		ssize_t ret = tls_write(client, ptr, len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "server tls_write: %s", tls_error(client));
		ptr += ret;
		len -= ret;
	}
}

void serverFormat(const char *format, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, format);
	int len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	assert((size_t)len < sizeof(buf));
	serverSend(buf, len);
}

void serverRecv(void) {
	static char buf[4096];
	static size_t len;

	ssize_t read = tls_read(client, &buf[len], sizeof(buf) - len);
	if (read == TLS_WANT_POLLIN || read == TLS_WANT_POLLOUT) return;
	if (read < 0) errx(EX_IOERR, "server tls_read: %s", tls_error(client));
	len += read;

	char *crlf;
	char *line = buf;
	for (;;) {
		crlf = memmem(line, &buf[len] - line, "\r\n", 2);
		if (!crlf) break;
		crlf[0] = '\0';
		if (verbose) fprintf(stderr, "\x1B[32m%s\x1B[m\n", line);
		if (!strncmp(line, "PING ", 5)) {
			serverFormat("PONG %s\r\n", &line[5]);
		} else {
			if (stateReady()) ringProduce(line);
			stateParse(line);
		}
		line = crlf + 2;
	}
	len -= line - buf;
	memmove(buf, line, len);
}
