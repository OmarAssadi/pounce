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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "bounce.h"

typedef unsigned char byte;

static struct tls *client;

int serverConnect(const char *host, const char *port) {
	int error;

	struct tls_config *config = tls_config_new();
	error = tls_config_set_ciphers(config, "compat");
	if (error) errx(EX_SOFTWARE, "tls_config");

	client = tls_client();
	if (!client) errx(EX_SOFTWARE, "tls_client");

	error = tls_configure(client, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(client));
	tls_config_free(config);

	struct addrinfo *head;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	error = getaddrinfo(host, port, &hints, &head);
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

	error = tls_connect_socket(client, sock, host);
	if (error) errx(EX_PROTOCOL, "tls_connect: %s", tls_error(client));

	return sock;
}

void serverSend(const char *ptr, size_t len) {
	while (len) {
		ssize_t ret = tls_write(client, ptr, len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "tls_write: %s", tls_error(client));
		ptr += ret;
		len -= ret;
	}
}

static void format(const char *format, ...) {
	char *buf;
	va_list ap;
	va_start(ap, format);
	int len = vasprintf(&buf, format, ap);
	va_end(ap);
	if (!buf) err(EX_OSERR, "vasprintf");
	serverSend(format, len);
	free(buf);
}

static const char Base64[64] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};

static char *base64(const byte *src, size_t len) {
	char *dst = malloc(1 + (len + 2) / 3 * 4);
	if (!dst) err(EX_OSERR, "malloc");

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
	return dst;
}

static char *authBase64;

void serverLogin(
	const char *pass, const char *auth,
	const char *nick, const char *user, const char *real
) {
	if (pass) format("PASS :%s\r\n", pass);
	if (auth) {
		byte plain[1 + strlen(auth)];
		plain[0] = 0;
		for (size_t i = 0; auth[i]; ++i) {
			plain[1 + i] = (auth[i] == ':' ? 0 : auth[i]);
		}
		authBase64 = base64(plain, sizeof(plain));
		format("CAP REQ :sasl\r\n");
	}
	format("NICK %s\r\nUSER %s 0 * :%s\r\n", nick, user, real);
}
