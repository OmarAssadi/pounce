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
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <unistd.h>

static struct {
	uint8_t buf[4096];
	uint8_t *ptr;
	size_t len;
} peek;

static void skip(size_t skip) {
	if (peek.len < skip) skip = peek.len;
	peek.ptr += skip;
	peek.len -= skip;
}
static uint8_t uint8(void) {
	if (peek.len < 1) return 0;
	peek.len--;
	return *peek.ptr++;
}
static uint16_t uint16(void) {
	uint16_t val = uint8();
	return val << 8 | uint8();
}

static char *serverName(void) {
	peek.ptr = peek.buf;
	// TLSPlaintext
	if (uint8() != 22) return NULL;
	skip(4);
	// Handshake
	if (uint8() != 1) return NULL;
	skip(3);
	// ClientHello
	skip(34);
	skip(uint8());
	skip(uint16());
	skip(uint8());
	uint16_t len = uint16();
	if (len > peek.len) return NULL;
	peek.len = len;
	while (peek.len) {
		// Extension
		uint16_t type = uint16();
		uint16_t len = uint16();
		if (type != 0) {
			skip(len);
			continue;
		}
		// ServerNameList
		skip(2);
		// ServerName
		if (uint8() != 0) return NULL;
		// HostName
		len = uint16();
		char *name = (char *)peek.ptr;
		skip(len);
		*peek.ptr = '\0';
		return name;
	}
	return NULL;
}

static const uint8_t Alert[] = {
	0x15, 0x03, 0x03, 0x00, 0x02, // TLSPlaintext
	0x02, 0x70, // Alert fatal unrecognized_name
};

static void alert(int sock) {
	ssize_t len = send(sock, Alert, sizeof(Alert), 0);
	if (len < 0) warn("send");
}

static ssize_t sendfd(int sock, int fd) {
	char buf[CMSG_SPACE(sizeof(int))];

	char x = 0;
	struct iovec iov = { .iov_base = &x, .iov_len = 1 };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = fd;

	return sendmsg(sock, &msg, 0);
}

int main(int argc, char *argv[]) {
	int error;

	const char *host = "localhost";
	const char *port = "6697";
	const char *path = NULL;
	int timeout = 1000;

	for (int opt; 0 < (opt = getopt(argc, argv, "H:P:t:"));) {
		switch (opt) {
			break; case 'H': host = optarg;
			break; case 'P': port = optarg;
			break; case 't': {
				char *rest;
				timeout = strtol(optarg, &rest, 0);
				if (*rest) errx(EX_USAGE, "invalid timeout: %s", optarg);
			}
			break; default:  return EX_USAGE;
		}
	}
	if (optind < argc) {
		path = argv[optind];
	} else {
		errx(EX_USAGE, "directory required");
	}

#ifdef __OpenBSD__
	error = unveil(path, "r");
	if (error) err(EX_OSERR, "unveil");

	error = pledge("stdio rpath inet unix dns sendfd", NULL);
	if (error) err(EX_OSERR, "pledge");
#endif

	error = chdir(path);
	if (error) err(EX_NOINPUT, "%s", path);

	enum { Cap = 1024 };
	struct pollfd fds[Cap];
	size_t nfds = 0;

	struct addrinfo *head;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	error = getaddrinfo(host, port, &hints, &head);
	if (error) errx(EX_NOHOST, "%s:%s: %s", host, port, gai_strerror(error));

	size_t binds = 0;
	for (struct addrinfo *ai = head; ai && binds < Cap - 1; ai = ai->ai_next) {
		int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) err(EX_OSERR, "socket");

		int yes = 1;
		error = setsockopt(
			sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)
		);
		if (error) err(EX_OSERR, "setsockopt");

		error = bind(sock, ai->ai_addr, ai->ai_addrlen);
		if (error) {
			warn("%s:%s", host, port);
			close(sock);
			continue;
		}

		fds[nfds++] = (struct pollfd) { .fd = sock, .events = POLLIN };
		binds++;
	}
	if (!binds) errx(EX_UNAVAILABLE, "could not bind any sockets");
	freeaddrinfo(head);

	for (size_t i = 0; i < binds; ++i) {
		error = listen(fds[i].fd, -1);
		if (error) err(EX_IOERR, "listen");
	}

	signal(SIGPIPE, SIG_IGN);
	for (;;) {
		for (size_t i = 0; i < binds; ++i) {
			fds[i].events = (nfds < Cap ? POLLIN : 0);
		}

		int ready = poll(fds, nfds, (nfds > binds ? timeout : -1));
		if (ready < 0) err(EX_IOERR, "poll");

		if (!ready) {
			for (size_t i = binds; i < nfds; ++i) {
				close(fds[i].fd);
			}
			nfds = binds;
			continue;
		}

		for (size_t i = nfds - 1; i < nfds; --i) {
			if (!fds[i].revents) continue;

			if (i < binds) {
				int sock = accept(fds[i].fd, NULL, NULL);
				if (sock < 0) {
					warn("accept");
					continue;
				}
				assert(nfds < Cap);
				fds[nfds++] = (struct pollfd) { .fd = sock, .events = POLLIN };
				continue;
			}

			if (fds[i].revents & (POLLHUP | POLLERR)) goto remove;

			ssize_t len = recv(
				fds[i].fd, peek.buf, sizeof(peek.buf) - 1, MSG_PEEK
			);
			if (len < 0) {
				warn("recv");
				goto remove;
			}
			peek.len = len;

			char *name = serverName();
			if (!name || name[0] == '.' || strchr(name, '/')) {
				alert(fds[i].fd);
				goto remove;
			}

			struct sockaddr_un addr = { .sun_family = AF_UNIX };
			snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", name);

			int sock = socket(PF_UNIX, SOCK_STREAM, 0);
			if (sock < 0) err(EX_OSERR, "socket");

			error = connect(sock, (struct sockaddr *)&addr, SUN_LEN(&addr));
			if (error) {
				warn("%s", name);
				alert(fds[i].fd);
			} else {
				len = sendfd(sock, fds[i].fd);
				if (len < 0) {
					warn("%s", name);
					alert(fds[i].fd);
				}
			}
			close(sock);

remove:
			close(fds[i].fd);
			fds[i] = fds[--nfds];
		}
	}
}
