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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <sys/capsicum.h>
#endif

#ifndef SIGINFO
#define SIGINFO SIGUSR2
#endif

static void hashPass(void) {
	char *pass = getpass("Password: ");
	byte rand[12];
	ssize_t len = getrandom(rand, sizeof(rand), 0);
	if (len < 0) err(EX_OSERR, "getrandom");
	char salt[3 + BASE64_SIZE(sizeof(rand))] = "$6$";
	base64(&salt[3], rand, sizeof(rand));
	printf("%s\n", crypt(pass, salt));
}

static FILE *saveFile;

static void saveExit(void) {
	int error = ringSave(saveFile);
	if (error) warn("fwrite");
	error = fclose(saveFile);
	if (error) warn("fclose");
}

static void saveLoad(const char *path) {
	umask(0066);
	saveFile = fopen(path, "a+");
	if (!saveFile) err(EX_CANTCREAT, "%s", path);

	int error = flock(fileno(saveFile), LOCK_EX | LOCK_NB);
	if (error && errno != EWOULDBLOCK) err(EX_OSERR, "flock");
	if (error) errx(EX_CANTCREAT, "%s: lock held by other process", path);

	rewind(saveFile);
	ringLoad(saveFile);

	error = ftruncate(fileno(saveFile), 0);
	if (error) err(EX_IOERR, "ftruncate");

	atexit(saveExit);
}

struct SplitPath {
	int dir;
	const char *file;
	int targetDir;
};

#ifdef __FreeBSD__
static void splitLimit(struct SplitPath split, const cap_rights_t *rights) {
	int error = cap_rights_limit(split.dir, rights);
	if (error) err(EX_OSERR, "cap_rights_limit");
	if (split.targetDir < 0) return;
	error = cap_rights_limit(split.targetDir, rights);
	if (error) err(EX_OSERR, "cap_rights_limit");
}
#endif

static struct SplitPath splitPath(char *path) {
	struct SplitPath split = { .targetDir = -1 };
	char *base = strrchr(path, '/');
	if (base) {
		*base++ = '\0';
		split.dir = open(path, O_DIRECTORY);
	} else {
		base = path;
		split.dir = open(".", O_DIRECTORY);
	}
	if (split.dir < 0) err(EX_NOINPUT, "%s", path);
	split.file = base;

	// Capsicum workaround for certbot "live" symlinks to "../../archive".
	char target[PATH_MAX];
	ssize_t len = readlinkat(split.dir, split.file, target, sizeof(target) - 1);
	if (len < 0 && errno == EINVAL) return split;
	if (len < 0) err(EX_IOERR, "readlinkat");
	target[len] = '\0';

	base = strrchr(target, '/');
	if (base) {
		*base = '\0';
		split.targetDir = openat(split.dir, target, O_DIRECTORY);
		if (split.targetDir < 0) err(EX_NOINPUT, "%s", target);
	}
	return split;
}

static FILE *splitOpen(struct SplitPath split) {
	if (split.targetDir >= 0) {
		char target[PATH_MAX];
		ssize_t len = readlinkat(
			split.dir, split.file, target, sizeof(target) - 1
		);
		if (len < 0) err(EX_IOERR, "readlinkat");
		target[len] = '\0';

		split.dir = split.targetDir;
		split.file = strrchr(target, '/');
		if (!split.file) errx(EX_CONFIG, "symlink no longer targets directory");
		split.file++;
	}

	int fd = openat(split.dir, split.file, O_RDONLY);
	if (fd < 0) err(EX_NOINPUT, "%s", split.file);
	FILE *file = fdopen(fd, "r");
	if (!file) err(EX_IOERR, "fdopen");
	return file;
}

static struct {
	struct pollfd *fds;
	struct Client **clients;
	size_t cap, len;
} event;

static void eventAdd(int fd, struct Client *client) {
	if (event.len == event.cap) {
		event.cap = (event.cap ? event.cap * 2 : 8);
		event.fds = realloc(event.fds, sizeof(*event.fds) * event.cap);
		if (!event.fds) err(EX_OSERR, "realloc");
		event.clients = realloc(
			event.clients, sizeof(*event.clients) * event.cap
		);
		if (!event.clients) err(EX_OSERR, "realloc");
	}
	event.fds[event.len] = (struct pollfd) { .fd = fd, .events = POLLIN };
	event.clients[event.len] = client;
	event.len++;
}

static void eventRemove(size_t i) {
	event.len--;
	event.fds[i] = event.fds[event.len];
	event.clients[i] = event.clients[event.len];
}

static volatile sig_atomic_t signals[NSIG];
static void signalHandler(int signal) {
	signals[signal] = 1;
}

int main(int argc, char *argv[]) {
	const char *bindHost = "localhost";
	const char *bindPort = "6697";
	char bindPath[PATH_MAX] = "";
	char certPath[PATH_MAX] = "";
	char privPath[PATH_MAX] = "";
	const char *save = NULL;
	size_t ring = 4096;

	bool insecure = false;
	const char *clientCert = NULL;
	const char *clientPriv = NULL;
	const char *host = NULL;
	const char *port = "6697";
	char *pass = NULL;
	bool sasl = false;
	char *plain = NULL;
	const char *nick = NULL;
	const char *user = NULL;
	const char *real = NULL;
	const char *join = NULL;
	const char *away = "pounced :3";
	const char *quit = "connection reset by purr";

	const char *Opts = "!A:C:H:K:NP:Q:U:W:a:c:ef:h:j:k:n:p:r:s:u:vw:x";
	const struct option LongOpts[] = {
		{ "insecure", no_argument, NULL, '!' },
		{ "away", required_argument, NULL, 'A' },
		{ "cert", required_argument, NULL, 'C' },
		{ "bind-host", required_argument, NULL, 'H' },
		{ "key", required_argument, NULL, 'K' },
		{ "names", no_argument, NULL, 'N' },
		{ "bind-port", required_argument, NULL, 'P' },
		{ "quit", required_argument, NULL, 'Q' },
		{ "bind-path", required_argument, NULL, 'U' },
		{ "client-pass", required_argument, NULL, 'W' },
		{ "sasl-plain", required_argument, NULL, 'a' },
		{ "client-cert", required_argument, NULL, 'c' },
		{ "sasl-external", no_argument, NULL, 'e' },
		{ "save", required_argument, NULL, 'f' },
		{ "host", required_argument, NULL, 'h' },
		{ "join", required_argument, NULL, 'j' },
		{ "client-key", required_argument, NULL, 'k' },
		{ "nick", required_argument, NULL, 'n' },
		{ "port", required_argument, NULL, 'p' },
		{ "real", required_argument, NULL, 'r' },
		{ "size", required_argument, NULL, 's' },
		{ "user", required_argument, NULL, 'u' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "pass", required_argument, NULL, 'w' },
		{0},
	};

	int opt;
	while (0 < (opt = getopt_config(argc, argv, Opts, LongOpts, NULL))) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'A': away = optarg;
			break; case 'C': strlcpy(certPath, optarg, sizeof(certPath));
			break; case 'H': bindHost = optarg;
			break; case 'K': strlcpy(privPath, optarg, sizeof(privPath));
			break; case 'N': stateJoinNames = true;
			break; case 'P': bindPort = optarg;
			break; case 'Q': quit = optarg;
			break; case 'U': strlcpy(bindPath, optarg, sizeof(bindPath));
			break; case 'W': clientPass = optarg;
			break; case 'a': sasl = true; plain = optarg;
			break; case 'c': clientCert = optarg;
			break; case 'e': sasl = true;
			break; case 'f': save = optarg;
			break; case 'h': host = optarg;
			break; case 'j': join = optarg;
			break; case 'k': clientPriv = optarg;
			break; case 'n': nick = optarg;
			break; case 'p': port = optarg;
			break; case 'r': real = optarg;
			break; case 's': {
				char *rest;
				ring = strtoull(optarg, &rest, 0);
				if (*rest) errx(EX_USAGE, "invalid size: %s", optarg);
			}
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
			break; case 'w': pass = optarg;
			break; case 'x': hashPass(); return EX_OK;
			break; default:  return EX_USAGE;
		}
	}

	if (bindPath[0]) {
		struct stat st;
		int error = stat(bindPath, &st);
		if (error && errno != ENOENT) err(EX_CANTCREAT, "%s", bindPath);
		if (S_ISDIR(st.st_mode)) {
			strlcat(bindPath, "/", sizeof(bindPath));
			strlcat(bindPath, bindHost, sizeof(bindPath));
		}
	}
	if (!certPath[0]) {
		snprintf(certPath, sizeof(certPath), DEFAULT_CERT_PATH, bindHost);
	}
	if (!privPath[0]) {
		snprintf(privPath, sizeof(privPath), DEFAULT_PRIV_PATH, bindHost);
	}
	if (!host) errx(EX_USAGE, "no host");
	if (!nick) {
		nick = getenv("USER");
		if (!nick) errx(EX_CONFIG, "USER unset");
	}
	if (!user) user = nick;
	if (!real) real = nick;

	ringAlloc(ring);
	if (save) saveLoad(save);

	struct SplitPath certSplit = splitPath(certPath);
	struct SplitPath privSplit = splitPath(privPath);
	FILE *cert = splitOpen(certSplit);
	FILE *priv = splitOpen(privSplit);
	listenConfig(cert, priv);
	fclose(cert);
	fclose(priv);

	int bind[8];
	size_t binds = bindPath[0]
		? listenUnix(bind, ARRAY_LEN(bind), bindPath)
		: listenBind(bind, ARRAY_LEN(bind), bindHost, bindPort);

	serverConfig(insecure, clientCert, clientPriv);
	int server = serverConnect(host, port);

#ifdef __FreeBSD__
	int error = cap_enter();
	if (error) err(EX_OSERR, "cap_enter");

	cap_rights_t saveRights, fileRights, sockRights, bindRights;
	cap_rights_init(&saveRights, CAP_WRITE);
	cap_rights_init(&fileRights, CAP_FCNTL, CAP_FSTAT, CAP_LOOKUP, CAP_READ);
	cap_rights_init(&sockRights, CAP_EVENT, CAP_RECV, CAP_SEND, CAP_SETSOCKOPT);
	cap_rights_init(&bindRights, CAP_LISTEN, CAP_ACCEPT);
	cap_rights_merge(&bindRights, &sockRights);

	if (saveFile) {
		error = cap_rights_limit(fileno(saveFile), &saveRights);
		if (error) err(EX_OSERR, "cap_rights_limit");
	}
	splitLimit(certSplit, &fileRights);
	splitLimit(privSplit, &fileRights);
	for (size_t i = 0; i < binds; ++i) {
		error = cap_rights_limit(bind[i], &bindRights);
		if (error) err(EX_OSERR, "cap_rights_limit");
	}
	error = cap_rights_limit(server, &sockRights);
	if (error) err(EX_OSERR, "cap_rights_limit");
#endif

	stateLogin(pass, sasl, plain, nick, user, real);
	if (pass) explicit_bzero(pass, strlen(pass));
	if (plain) explicit_bzero(plain, strlen(plain));

	while (!stateReady()) serverRecv();
	serverFormat("AWAY :%s\r\n", away);
	if (join) serverFormat("JOIN :%s\r\n", join);

	for (size_t i = 0; i < binds; ++i) {
		int error = listen(bind[i], 1);
		if (error) err(EX_IOERR, "listen");
		eventAdd(bind[i], NULL);
	}
	eventAdd(server, NULL);

	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	signal(SIGINFO, signalHandler);
	signal(SIGUSR1, signalHandler);

	size_t clients = 0;
	for (;;) {
		int nfds = poll(event.fds, event.len, -1);
		if (nfds < 0 && errno != EINTR) err(EX_IOERR, "poll");

		if (signals[SIGINT] || signals[SIGTERM]) break;
		if (signals[SIGINFO]) {
			ringInfo();
			signals[SIGINFO] = 0;
		}
		if (signals[SIGUSR1]) {
			cert = splitOpen(certSplit);
			priv = splitOpen(privSplit);
			listenConfig(cert, priv);
			fclose(cert);
			fclose(priv);
			signals[SIGUSR1] = 0;
		}

		if (nfds < 0) continue;
		for (size_t i = event.len - 1; i < event.len; --i) {
			short revents = event.fds[i].revents;
			if (!revents) continue;

			if (i < binds) {
				int fd;
				struct tls *tls = listenAccept(&fd, event.fds[i].fd);
				int error = tls_handshake(tls);
				if (error) {
					warnx("tls_handshake: %s", tls_error(tls));
					tls_free(tls);
					close(fd);
				} else {
					eventAdd(fd, clientAlloc(tls));
					if (!clients++) serverFormat("AWAY\r\n");
				}
				continue;
			}

			if (!event.clients[i]) {
				if (revents & POLLIN) {
					serverRecv();
				} else {
					errx(EX_UNAVAILABLE, "server hung up");
				}
				continue;
			}

			struct Client *client = event.clients[i];
			if (revents & POLLIN) clientRecv(client);
			if (revents & POLLOUT) clientConsume(client);
			if (clientError(client) || revents & (POLLHUP | POLLERR)) {
				clientFree(client);
				close(event.fds[i].fd);
				eventRemove(i);
				if (!--clients) serverFormat("AWAY :%s\r\n", away);
			}
		}

		for (size_t i = binds + 1; i < event.len; ++i) {
			assert(event.clients[i]);
			if (clientDiff(event.clients[i])) {
				event.fds[i].events |= POLLOUT;
			} else {
				event.fds[i].events &= ~POLLOUT;
			}
		}
	}

	serverFormat("QUIT :%s\r\n", quit);
	for (size_t i = 0; i < event.len; ++i) {
		if (event.clients[i]) {
			clientFormat(
				event.clients[i], ":%s QUIT :%s\r\nERROR :Disconnecting\r\n",
				stateEcho(), quit
			);
			clientFree(event.clients[i]);
		}
		close(event.fds[i].fd);
	}
}
