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
 */

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

#ifdef __FreeBSD__
#include <sys/capsicum.h>
#endif

#include "compat.h"

static struct {
	struct pollfd *ptr;
	size_t len, cap;
} event;

static void eventAdd(int fd) {
	if (event.len == event.cap) {
		event.cap = (event.cap ? event.cap * 2 : 8);
		event.ptr = realloc(event.ptr, sizeof(*event.ptr) * event.cap);
		if (!event.ptr) err(EX_OSERR, "malloc");
	}
	event.ptr[event.len++] = (struct pollfd) {
		.fd = fd,
		.events = POLLIN,
	};
}

static void eventRemove(size_t i) {
	close(event.ptr[i].fd);
	event.ptr[i] = event.ptr[--event.len];
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
	peek.len = uint16();
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

int main(int argc, char *argv[]) {
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

	int dir = open(path, O_DIRECTORY);
	if (dir < 0) err(EX_NOINPUT, "%s", path);

	int error = fchdir(dir);
	if (error) err(EX_NOINPUT, "%s", path);

	struct addrinfo *head;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	error = getaddrinfo(host, port, &hints, &head);
	if (error) errx(EX_NOHOST, "%s:%s: %s", host, port, gai_strerror(error));

	size_t binds = 0;
	for (struct addrinfo *ai = head; ai; ai = ai->ai_next) {
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

		eventAdd(sock);
		binds++;
	}
	if (!binds) errx(EX_UNAVAILABLE, "could not bind any sockets");
	freeaddrinfo(head);

#ifdef __FreeBSD__
	error = cap_enter();
	if (error) err(EX_OSERR, "cap_enter");

	cap_rights_t dirRights, sockRights, unixRights, bindRights;
	cap_rights_init(&dirRights, CAP_CONNECTAT);
	cap_rights_init(&sockRights, CAP_EVENT, CAP_RECV, CAP_SEND, CAP_SETSOCKOPT);
	cap_rights_init(&unixRights, CAP_CONNECT, CAP_SEND);
	cap_rights_init(&bindRights, CAP_LISTEN, CAP_ACCEPT);
	cap_rights_merge(&bindRights, &sockRights);

	error = cap_rights_limit(dir, &dirRights);
	if (error) err(EX_OSERR, "cap_rights_limit");
	for (size_t i = 0; i < binds; ++i) {
		error = cap_rights_limit(event.ptr[i].fd, &bindRights);
		if (error) err(EX_OSERR, "cap_rights_limit");
	}
#endif

	for (size_t i = 0; i < binds; ++i) {
		error = listen(event.ptr[i].fd, 1);
		if (error) err(EX_IOERR, "listen");
	}

	signal(SIGPIPE, SIG_IGN);
	for (;;) {
		int nfds = poll(
			event.ptr, event.len, (event.len > binds ? timeout : -1)
		);
		if (nfds < 0) err(EX_IOERR, "poll");

		if (!nfds) {
			for (size_t i = event.len - 1; i >= binds; --i) {
				eventRemove(i);
			}
			continue;
		}

		for (size_t i = event.len - 1; i < event.len; --i) {
			if (!event.ptr[i].revents) continue;

			if (i < binds) {
				int sock = accept(event.ptr[i].fd, NULL, NULL);
				if (sock < 0) {
					warn("accept");
					continue;
				}

				int yes = 1;
				error = setsockopt(
					sock, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)
				);
				if (error) err(EX_OSERR, "setsockopt");

				eventAdd(sock);
				continue;
			}

			if (event.ptr[i].revents & (POLLHUP | POLLERR)) {
				eventRemove(i);
				continue;
			}

			ssize_t len = recv(
				event.ptr[i].fd, peek.buf, sizeof(peek.buf) - 1, MSG_PEEK
			);
			if (len < 0) {
				warn("recv");
				eventRemove(i);
				continue;
			}
			peek.len = len;

			char *name = serverName();
			if (!name || name[0] == '.' || name[0] == '/') {
				alert(event.ptr[i].fd);
				eventRemove(i);
				continue;
			}

			struct sockaddr_un addr = { .sun_family = AF_UNIX };
			strlcpy(addr.sun_path, name, sizeof(addr.sun_path));

			int sock = socket(PF_UNIX, SOCK_STREAM, 0);
			if (sock < 0) err(EX_OSERR, "socket");

#ifdef __FreeBSD__
			error = cap_rights_limit(sock, &unixRights);
			if (error) err(EX_OSERR, "cap_rights_limit");

			error = connectat(
				dir, sock, (struct sockaddr *)&addr, SUN_LEN(&addr)
			);
#else
			error = connect(sock, (struct sockaddr *)&addr, SUN_LEN(&addr));
#endif

			if (error) {
				warn("%s", name);
				alert(event.ptr[i].fd);
			} else {
				len = sendfd(sock, event.ptr[i].fd);
				if (len < 0) {
					warn("%s", name);
					alert(event.ptr[i].fd);
				}
			}

			close(sock);
			eventRemove(i);
		}
	}
}
