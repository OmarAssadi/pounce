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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <sys/capsicum.h>
#endif

#include "bounce.h"

#ifdef __APPLE__
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif

static struct tls *server;

static byte *readFile(size_t *len, FILE *file) {
	struct stat stat;
	int error = fstat(fileno(file), &stat);
	if (error) err(EX_IOERR, "fstat");

	byte *buf = malloc(stat.st_size);
	if (!buf) err(EX_OSERR, "malloc");

	rewind(file);
	*len = fread(buf, 1, stat.st_size, file);
	if (ferror(file)) err(EX_IOERR, "fread");

	return buf;
}

void localConfig(FILE *cert, FILE *priv, FILE *ca, bool require) {
	tls_free(server);
	server = tls_server();
	if (!server) errx(EX_SOFTWARE, "tls_server");

	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	size_t len;
	byte *buf = readFile(&len, cert);
	int error = tls_config_set_cert_mem(config, buf, len);
	if (error) {
		errx(EX_CONFIG, "tls_config_set_cert_mem: %s", tls_config_error(config));
	}
	free(buf);

	buf = readFile(&len, priv);
	error = tls_config_set_key_mem(config, buf, len);
	if (error) {
		errx(EX_CONFIG, "tls_config_set_key_mem: %s", tls_config_error(config));
	}
	free(buf);

	if (ca) {
		buf = readFile(&len, ca);
		error = tls_config_set_ca_mem(config, buf, len);
		if (error) {
			errx(
				EX_CONFIG, "tls_config_set_ca_mem: %s",
				tls_config_error(config)
			);
		}
		free(buf);
		if (require) {
			tls_config_verify_client(config);
		} else {
			tls_config_verify_client_optional(config);
		}
	}

	error = tls_configure(server, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(server));
	tls_config_free(config);
}

size_t localBind(int fds[], size_t cap, const char *host, const char *port) {
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

static bool unix;
static int unixDir = -1;
static char unixFile[PATH_MAX];

static void unixUnlink(void) {
	int error = unlinkat(unixDir, unixFile, 0);
	if (error) warn("unlinkat");
}

size_t localUnix(int fds[], size_t cap, const char *path) {
	if (!cap) return 0;

	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) err(EX_OSERR, "socket");

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int len = snprintf(
		addr.sun_path, sizeof(addr.sun_path), "%s", path
	);
	if ((size_t)len >= sizeof(addr.sun_path)) {
		errx(EX_CONFIG, "path too long: %s", path);
	}

	int error = bind(sock, (struct sockaddr *)&addr, SUN_LEN(&addr));
	if (error) err(EX_UNAVAILABLE, "%s", path);

	char dir[PATH_MAX] = ".";
	const char *base = strrchr(path, '/');
	if (base) {
		snprintf(dir, sizeof(dir), "%.*s", (int)(base - path), path);
		base++;
	} else {
		base = path;
	}
	snprintf(unixFile, sizeof(unixFile), "%s", base);

	unixDir = open(dir, O_DIRECTORY);
	if (unixDir < 0) err(EX_UNAVAILABLE, "%s", dir);
	atexit(unixUnlink);

#ifdef __FreeBSD__
	cap_rights_t rights;
	error = cap_rights_limit(unixDir, cap_rights_init(&rights, CAP_UNLINKAT));
	if (error) err(EX_OSERR, "cap_rights_limit");
#endif

	unix = true;
	fds[0] = sock;
	return 1;
}

static int recvfd(int sock) {
	char buf[CMSG_SPACE(sizeof(int))];

	char x;
	struct iovec iov = { .iov_base = &x, .iov_len = 1 };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
	};
	if (0 > recvmsg(sock, &msg, 0)) return -1;

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
		errno = ENOMSG;
		return -1;
	}
	return *(int *)CMSG_DATA(cmsg);
}

struct tls *localAccept(int *fd, int bind) {
	*fd = accept(bind, NULL, NULL);
	if (*fd < 0) return NULL;

	if (unix) {
		int sent = recvfd(*fd);
		if (sent < 0) err(EX_IOERR, "recvfd");
		close(*fd);
		*fd = sent;
	}

	int on = 1;
	int error = setsockopt(*fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	if (error) err(EX_OSERR, "setsockopt");

#ifdef TCP_KEEPIDLE
	int idle = 15 * 60;
	error = setsockopt(*fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
	if (error) err(EX_OSERR, "setsockopt");
#endif

	struct tls *client;
	error = tls_accept_socket(server, &client, *fd);
	if (error) errx(EX_SOFTWARE, "tls_accept_socket: %s", tls_error(server));
	return client;
}
