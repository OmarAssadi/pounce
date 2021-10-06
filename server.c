/* Copyright (C) 2019  C. McEnroe <june@causal.agency>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify this Program, or any covered work, by linking or
 * combining it with OpenSSL (or a modified version of that library),
 * containing parts covered by the terms of the OpenSSL License and the
 * original SSLeay license, the licensors of this Program grant you
 * additional permission to convey the resulting work. Corresponding
 * Source for a non-source form of such a combination shall include the
 * source code for the parts of OpenSSL used as well as that of the
 * covered work.
 */

#include <assert.h>
#include <err.h>
#include <limits.h>
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

static struct tls *client;
static struct tls_config *config;

void serverConfig(
	bool insecure, const char *trust, const char *cert, const char *priv
) {
	int error = 0;
	char buf[PATH_MAX];
	config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	if (insecure) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
	}

	if (trust) {
		tls_config_insecure_noverifyname(config);
		for (int i = 0; configPath(buf, sizeof(buf), trust, i); ++i) {
			error = tls_config_set_ca_file(config, buf);
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", trust, tls_config_error(config));
	}

	if (cert) {
		for (int i = 0; configPath(buf, sizeof(buf), cert, i); ++i) {
			if (priv) {
				error = tls_config_set_cert_file(config, buf);
			} else {
				error = tls_config_set_keypair_file(config, buf, buf);
			}
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", cert, tls_config_error(config));
	}
	if (priv) {
		for (int i = 0; configPath(buf, sizeof(buf), priv, i); ++i) {
			error = tls_config_set_key_file(config, buf);
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", priv, tls_config_error(config));
	}

	client = tls_client();
	if (!client) errx(EX_SOFTWARE, "tls_client");

	error = tls_configure(client, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(client));
}

int serverConnect(const char *bindHost, const char *host, const char *port) {
	assert(client);

	int error;
	int sock = -1;
	struct addrinfo *head;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};

	if (bindHost) {
		error = getaddrinfo(bindHost, NULL, &hints, &head);
		if (error) errx(EX_NOHOST, "%s: %s", bindHost, gai_strerror(error));

		for (struct addrinfo *ai = head; ai; ai = ai->ai_next) {
			sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
			if (sock < 0) err(EX_OSERR, "socket");

			error = bind(sock, ai->ai_addr, ai->ai_addrlen);
			if (!error) {
				hints.ai_family = ai->ai_family;
				break;
			}

			close(sock);
			sock = -1;
		}
		if (sock < 0) err(EX_UNAVAILABLE, "%s", bindHost);
		freeaddrinfo(head);
	}

	error = getaddrinfo(host, port, &hints, &head);
	if (error) errx(EX_NOHOST, "%s:%s: %s", host, port, gai_strerror(error));

	for (struct addrinfo *ai = head; ai; ai = ai->ai_next) {
		if (sock < 0) {
			sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
			if (sock < 0) err(EX_OSERR, "socket");
		}

		error = connect(sock, ai->ai_addr, ai->ai_addrlen);
		if (!error) break;

		close(sock);
		sock = -1;
	}
	if (sock < 0) err(EX_UNAVAILABLE, "%s:%s", host, port);
	freeaddrinfo(head);

	error = tls_connect_socket(client, sock, host);
	if (error) errx(EX_PROTOCOL, "tls_connect: %s", tls_error(client));

	do {
		error = tls_handshake(client);
	} while (error == TLS_WANT_POLLIN || error == TLS_WANT_POLLOUT);
	if (error) errx(EX_PROTOCOL, "tls_handshake: %s", tls_error(client));
	tls_config_clear_keys(config);

	return sock;
}

void serverClose(void) {
	tls_close(client);
	tls_free(client);
}

void serverPrintCert(void) {
	size_t len;
	const byte *pem = tls_peer_cert_chain_pem(client, &len);
	printf("subject= %s\n", tls_peer_cert_subject(client));
	fwrite(pem, len, 1, stdout);
}

void serverSend(const char *ptr, size_t len) {
	verboseLog("<<", ptr, len);
	while (len) {
		ssize_t ret = tls_write(client, ptr, len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "server tls_write: %s", tls_error(client));
		ptr += ret;
		len -= ret;
	}
}

void serverFormat(const char *format, ...) {
	char buf[MessageCap + 1];
	va_list ap;
	va_start(ap, format);
	int len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	assert((size_t)len < sizeof(buf));
	serverSend(buf, len);
}

enum { QueueCap = 256 };
static struct {
	size_t enq;
	size_t deq;
	char *msgs[QueueCap];
} queue;

void serverDequeue(void) {
	if (queue.enq - queue.deq) {
		char *msg = queue.msgs[queue.deq++ % QueueCap];
		serverSend(msg, strlen(msg));
		free(msg);
	} else {
		struct itimerval timer = { .it_value = {0} };
		int error = setitimer(ITIMER_REAL, &timer, NULL);
		if (error) err(EX_OSERR, "setitimer");
	}
}

struct timeval serverQueueInterval = { .tv_usec = 1000 * 200 };

void serverEnqueue(const char *format, ...) {
	if (queue.enq - queue.deq == QueueCap) {
		warnx("server send queue full");
		serverDequeue();
	} else if (queue.enq == queue.deq) {
		struct itimerval timer = {
			.it_interval = serverQueueInterval,
			.it_value = { .tv_usec = 1 },
		};
		int error = setitimer(ITIMER_REAL, &timer, NULL);
		if (error) err(EX_OSERR, "setitimer");
	}
	va_list ap;
	va_start(ap, format);
	int len = vasprintf(&queue.msgs[queue.enq++ % QueueCap], format, ap);
	va_end(ap);
	if (len < 0) err(EX_OSERR, "vasprintf");
}

void serverRecv(void) {
	static char buf[MessageCap];
	static size_t len;

	ssize_t read = tls_read(client, &buf[len], sizeof(buf) - len);
	if (read == TLS_WANT_POLLIN || read == TLS_WANT_POLLOUT) return;
	if (read < 0) errx(EX_IOERR, "server tls_read: %s", tls_error(client));
	if (!read) errx(EX_PROTOCOL, "server closed connection");
	len += read;

	char *crlf;
	char *line = buf;
	for (;;) {
		crlf = memmem(line, &buf[len] - line, "\r\n", 2);
		if (!crlf) break;
		crlf[0] = '\0';
		verboseLog(">>", line, crlf - line);
		const char *ping = line;
		if (ping[0] == '@') {
			ping += strcspn(ping, " ");
			if (*ping) ping++;
		}
		if (!strncmp(ping, "PING ", 5)) {
			serverFormat("PONG %s\r\n", &ping[5]);
		} else {
			if (stateReady()) ringProduce(line);
			stateParse(line);
		}
		line = crlf + 2;
	}
	len -= line - buf;
	memmove(buf, line, len);
}
