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
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sysexits.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <sys/capsicum.h>
#endif

#ifndef SIGINFO
#define SIGINFO SIGUSR2
#endif

#include "bounce.h"

bool verbose;

static volatile sig_atomic_t signals[NSIG];
static void signalHandler(int signal) {
	signals[signal] = 1;
}
static void justExit(int signal) {
	exit(128 + signal);
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
	close(event.fds[i].fd);
	event.len--;
	event.fds[i] = event.fds[event.len];
	event.clients[i] = event.clients[event.len];
}

static FILE *saveFile;

static void saveSave(void) {
	int error = ringSave(saveFile);
	if (error) warn("fwrite");
	error = fclose(saveFile);
	if (error) warn("fclose");
}

static void saveLoad(const char *path) {
	umask(0066);
	saveFile = dataOpen(path, "a+");
	if (!saveFile) exit(EX_CANTCREAT);

	int error = flock(fileno(saveFile), LOCK_EX | LOCK_NB);
	if (error && errno != EWOULDBLOCK) err(EX_OSERR, "flock");
	if (error) errx(EX_CANTCREAT, "lock held by other process: %s", path);

	rewind(saveFile);
	ringLoad(saveFile);
	error = ftruncate(fileno(saveFile), 0);
	if (error) err(EX_IOERR, "ftruncate");

	atexit(saveSave);
}

#ifdef __FreeBSD__
static void capLimit(int fd, const cap_rights_t *rights) {
	int error = cap_rights_limit(fd, rights);
	if (error) err(EX_OSERR, "cap_rights_limit");
}
#endif

#ifdef __OpenBSD__
static void unveilParent(const char *path, const char *mode) {
	char buf[PATH_MAX];
	strlcpy(buf, path, sizeof(buf));
	char *base = strrchr(buf, '/');
	if (base) *base = '\0';
	int error = unveil((base ? buf : "."), mode);
	if (error && errno != ENOENT) err(EX_NOINPUT, "%s", path);
}

static void unveilTarget(const char *path, const char *mode) {
	char buf[PATH_MAX];
	strlcpy(buf, path, sizeof(buf));
	char *base = strrchr(buf, '/');
	base = (base ? base + 1 : buf);
	ssize_t len = readlink(path, base, sizeof(buf) - (base - buf) - 1);
	if (len < 0) return;
	base[len] = '\0';
	unveilParent(buf, mode);
}

static void unveilConfig(const char *path) {
	const char *dirs = NULL;
	for (const char *abs; NULL != (abs = configPath(&dirs, path));) {
		unveilParent(abs, "r");
		unveilTarget(abs, "r");
	}
}
#endif /* __OpenBSD__ */

static size_t parseSize(const char *str) {
	char *rest;
	size_t size = strtoull(str, &rest, 0);
	if (*rest) errx(EX_USAGE, "invalid size: %s", str);
	return size;
}

static struct timeval parseInterval(const char *str) {
	char *rest;
	long ms = strtol(str, &rest, 0);
	if (*rest) errx(EX_USAGE, "invalid interval: %s", str);
	return (struct timeval) {
		.tv_sec = ms / 1000,
		.tv_usec = 1000 * (ms % 1000),
	};
}

static void hashPass(void);
static void genCert(const char *path, const char *ca);

int main(int argc, char *argv[]) {
	int error;

	size_t ringSize = 4096;
	const char *savePath = NULL;

	const char *bindHost = "localhost";
	const char *bindPort = "6697";
	char bindPath[PATH_MAX] = "";
	char certPath[PATH_MAX] = "";
	char privPath[PATH_MAX] = "";
	const char *caPath = NULL;
	const char *genPath = NULL;

	bool insecure = false;
	bool printCert = false;
	const char *trust = NULL;
	const char *clientCert = NULL;
	const char *clientPriv = NULL;
	const char *serverBindHost = NULL;

	const char *host = NULL;
	const char *port = "6697";
	char *pass = NULL;
	char *plain = NULL;
	enum Cap blindReq = 0;
	const char *nick = NULL;
	const char *user = NULL;
	const char *real = NULL;

	const char *mode = NULL;
	const char *join = NULL;
	const char *quit = "connection reset by purr";

	struct option options[] = {
		{ .val = '!', .name = "insecure", no_argument },
		{ .val = 'A', .name = "local-ca", required_argument },
		{ .val = 'C', .name = "local-cert", required_argument },
		{ .val = 'H', .name = "local-host", required_argument },
		{ .val = 'K', .name = "local-priv", required_argument },
		{ .val = 'L', .name = "palaver", no_argument },
		{ .val = 'N', .name = "no-names", no_argument },
		{ .val = 'P', .name = "local-port", required_argument },
		{ .val = 'Q', .name = "queue-interval", required_argument },
		{ .val = 'R', .name = "blind-req", required_argument },
		{ .val = 'S', .name = "bind", required_argument },
		{ .val = 'T', .name = "no-sts", no_argument },
		{ .val = 'U', .name = "local-path", required_argument },
		{ .val = 'W', .name = "local-pass", required_argument },
		{ .val = 'a', .name = "sasl-plain", required_argument },
		{ .val = 'c', .name = "client-cert", required_argument },
		{ .val = 'e', .name = "sasl-external", no_argument },
		{ .val = 'f', .name = "save", required_argument },
		{ .val = 'g', .name = "generate", required_argument },
		{ .val = 'h', .name = "host", required_argument },
		{ .val = 'j', .name = "join", required_argument },
		{ .val = 'k', .name = "client-priv", required_argument },
		{ .val = 'm', .name = "mode", required_argument },
		{ .val = 'n', .name = "nick", required_argument },
		{ .val = 'o', .name = "print-cert", no_argument },
		{ .val = 'p', .name = "port", required_argument },
		{ .val = 'q', .name = "quit", required_argument },
		{ .val = 'r', .name = "real", required_argument },
		{ .val = 's', .name = "size", required_argument },
		{ .val = 't', .name = "trust", required_argument },
		{ .val = 'u', .name = "user", required_argument },
		{ .val = 'v', .name = "verbose", no_argument },
		{ .val = 'w', .name = "pass", required_argument },
		{ .val = 'x', .name = "hash", no_argument },
		{ .val = 'y', .name = "away", required_argument },
		{0},
	};
	char opts[2 * ARRAY_LEN(options)];
	for (size_t i = 0, j = 0; i < ARRAY_LEN(options); ++i) {
		opts[j++] = options[i].val;
		if (options[i].has_arg) opts[j++] = ':';
	}

	for (int opt; 0 < (opt = getopt_config(argc, argv, opts, options, NULL));) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'A': caPath = optarg; clientCaps |= CapSASL;
			break; case 'C': snprintf(certPath, sizeof(certPath), "%s", optarg);
			break; case 'H': bindHost = optarg;
			break; case 'K': snprintf(privPath, sizeof(privPath), "%s", optarg);
			break; case 'N': stateNoNames = true;
			break; case 'L': clientCaps |= CapPalaverApp;
			break; case 'P': bindPort = optarg;
			break; case 'Q': serverQueueInterval = parseInterval(optarg);
			break; case 'R': blindReq |= capParse(optarg, NULL);
			break; case 'S': serverBindHost = optarg;
			break; case 'T': clientCaps &= ~CapSTS;
			break; case 'U': snprintf(bindPath, sizeof(bindPath), "%s", optarg);
			break; case 'W': clientPass = optarg;
			break; case 'a': blindReq |= CapSASL; plain = optarg;
			break; case 'c': clientCert = optarg;
			break; case 'e': blindReq |= CapSASL;
			break; case 'f': savePath = optarg;
			break; case 'g': genPath = optarg;
			break; case 'h': host = optarg;
			break; case 'j': join = optarg;
			break; case 'k': clientPriv = optarg;
			break; case 'm': mode = optarg;
			break; case 'n': nick = optarg;
			break; case 'o': printCert = true;
			break; case 'p': port = optarg;
			break; case 'q': quit = optarg;
			break; case 'r': real = optarg;
			break; case 's': ringSize = parseSize(optarg);
			break; case 't': trust = optarg;
			break; case 'u': user = optarg;
			break; case 'v': verbose = true; setlinebuf(stdout);
			break; case 'w': pass = optarg;
			break; case 'x': hashPass(); return EX_OK;
			break; case 'y': clientAway = optarg;
			break; default:  return EX_USAGE;
		}
	}
	if (blindReq & CapUnsupported) errx(EX_USAGE, "unsupported capability");
	if (genPath) genCert(genPath, caPath);

	if (bindPath[0]) {
		struct stat st;
		int error = stat(bindPath, &st);
		if (error && errno != ENOENT) err(EX_CANTCREAT, "%s", bindPath);
		if (S_ISDIR(st.st_mode)) {
			size_t len = strlen(bindPath);
			snprintf(&bindPath[len], sizeof(bindPath) - len, "/%s", bindHost);
		}
	}
	if (!certPath[0]) {
		snprintf(
			certPath, sizeof(certPath), CERTBOT_PATH "/live/%s/fullchain.pem",
			bindHost
		);
	}
	if (!privPath[0]) {
		snprintf(
			privPath, sizeof(privPath), CERTBOT_PATH "/live/%s/privkey.pem",
			bindHost
		);
	}

	if (!host) errx(EX_USAGE, "host required");
	if (!nick) {
		nick = getenv("USER");
		if (!nick) errx(EX_CONFIG, "USER unset");
	}
	if (!user) user = nick;
	if (!real) real = nick;
	if (!clientAway) clientAway = "pounced :3";
	if (clientPass && clientPass[0] != '$') {
		errx(EX_USAGE, "password must be hashed with -x");
	}

	if (printCert) {
#ifdef __OpenBSD__
		error = pledge("stdio inet dns", NULL);
		if (error) err(EX_OSERR, "pledge");
#endif
		serverConfig(true, NULL, NULL, NULL);
		serverConnect(serverBindHost, host, port);
		serverPrintCert();
		serverClose();
		return EX_OK;
	}

	// Either exit with cleanup or ignore signals until entering the main loop.
	signal(SIGINT, justExit);
	signal(SIGTERM, justExit);
	signal(SIGINFO, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);

	ringAlloc(ringSize);
	if (savePath) saveLoad(savePath);
	serverConfig(insecure, trust, clientCert, clientPriv);

#ifdef __OpenBSD__
	unveilConfig(certPath);
	unveilConfig(privPath);
	if (caPath) unveilConfig(caPath);
	if (bindPath[0]) unveilParent(bindPath, "rwc");
	error = unveil(tls_default_ca_cert_file(), "r");
	if (error) err(EX_OSFILE, "%s", tls_default_ca_cert_file());

	if (bindPath[0]) {
		error = pledge("stdio rpath inet dns cpath unix recvfd", NULL);
	} else {
		error = pledge("stdio rpath inet dns", NULL);
	}
	if (error) err(EX_OSERR, "pledge");
#endif

	struct Cert localCA = { -1, -1, "" };
	if (caPath) {
		error = 0;
		const char *dirs = NULL;
		for (const char *path; NULL != (path = configPath(&dirs, caPath));) {
			error = certOpen(&localCA, path);
			if (!error) break;
		}
		if (error) err(EX_NOINPUT, "%s", caPath);
	}

	const char *dirs;
	struct Cert cert;
	struct Cert priv;
	dirs = NULL;
	for (const char *path; NULL != (path = configPath(&dirs, certPath));) {
		error = certOpen(&cert, path);
		if (!error) break;
	}
	if (error) err(EX_NOINPUT, "%s", certPath);
	dirs = NULL;
	for (const char *path; NULL != (path = configPath(&dirs, privPath));) {
		error = certOpen(&priv, path);
		if (!error) break;
	}
	if (error) err(EX_NOINPUT, "%s", privPath);

	FILE *certRead = certFile(&cert);
	if (!certRead) err(EX_NOINPUT, "%s", certPath);
	FILE *privRead = certFile(&priv);
	if (!privRead) err(EX_NOINPUT, "%s", privPath);
	FILE *caRead = (caPath ? certFile(&localCA) : NULL);
	if (caPath && !caRead) err(EX_NOINPUT, "%s", caPath);

	localConfig(certRead, privRead, caRead, !clientPass);
	fclose(certRead);
	fclose(privRead);
	if (caPath) fclose(caRead);

	int bind[8];
	size_t binds = bindPath[0]
		? localUnix(bind, ARRAY_LEN(bind), bindPath)
		: localBind(bind, ARRAY_LEN(bind), bindHost, bindPort);
	int server = serverConnect(serverBindHost, host, port);

#ifdef __OpenBSD__
	if (bindPath[0]) {
		error = pledge("stdio rpath cpath unix recvfd", NULL);
	} else {
		error = pledge("stdio rpath inet", NULL);
	}
	if (error) err(EX_OSERR, "pledge");
#endif

#ifdef __FreeBSD__
	error = cap_enter();
	if (error) err(EX_OSERR, "cap_enter");

	cap_rights_t saveRights, fileRights, sockRights, bindRights;
	cap_rights_init(&saveRights, CAP_WRITE);
	cap_rights_init(&fileRights, CAP_FCNTL, CAP_FSTAT, CAP_LOOKUP, CAP_PREAD);
	cap_rights_init(&sockRights, CAP_EVENT, CAP_RECV, CAP_SEND, CAP_SETSOCKOPT);
	cap_rights_init(&bindRights, CAP_LISTEN, CAP_ACCEPT);
	cap_rights_merge(&bindRights, &sockRights);

	if (saveFile) capLimit(fileno(saveFile), &saveRights);
	capLimit(cert.parent, &fileRights);
	capLimit(cert.target, &fileRights);
	capLimit(priv.parent, &fileRights);
	capLimit(priv.target, &fileRights);
	if (caPath) {
		capLimit(localCA.parent, &fileRights);
		capLimit(localCA.target, &fileRights);
	}
	for (size_t i = 0; i < binds; ++i) {
		capLimit(bind[i], &bindRights);
	}
	capLimit(server, &sockRights);
#endif

	stateLogin(pass, blindReq, plain, nick, user, real);
	if (pass) explicit_bzero(pass, strlen(pass));
	if (plain) explicit_bzero(plain, strlen(plain));

	while (!stateReady()) serverRecv();
	serverFormat("AWAY :%s\r\n", clientAway);
	if (mode) serverFormat("MODE %s %s\r\n", stateNick(), mode);
	if (join) serverFormat("JOIN %s\r\n", join);

	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, signalHandler);
	signal(SIGINFO, signalHandler);
	signal(SIGUSR1, signalHandler);

	for (size_t i = 0; i < binds; ++i) {
		error = listen(bind[i], -1);
		if (error) err(EX_IOERR, "listen");
		eventAdd(bind[i], NULL);
	}
	eventAdd(server, NULL);
	size_t clientIndex = event.len;

	for (;;) {
		enum Need needs = 0;
		for (size_t i = clientIndex; i < event.len; ++i) {
			struct Client *client = event.clients[i];
			event.fds[i].events = POLLIN;
			if (!client->need && ringDiff(client->consumer)) {
				event.fds[i].events |= POLLOUT;
			}
			needs |= client->need;
		}

		int timeout = 10000;
		int ready = poll(event.fds, event.len, (needs ? timeout : -1));
		if (ready < 0 && errno != EINTR) err(EX_IOERR, "poll");

		if (needs) {
			time_t now = time(NULL);
			for (size_t i = event.len - 1; i >= clientIndex; --i) {
				struct Client *client = event.clients[i];
				if (!client->need) continue;
				if (now - client->time < timeout / 1000) continue;
				clientFree(client);
				eventRemove(i);
			}
		}

		for (size_t i = event.len - 1; ready > 0 && i < event.len; --i) {
			short revents = event.fds[i].revents;
			if (!revents) continue;

			struct Client *client = event.clients[i];
			if (client) {
				if (revents & POLLOUT) clientConsume(client);
				if (revents & POLLIN) clientRecv(client);
				if (client->error || revents & (POLLHUP | POLLERR)) {
					clientFree(client);
					eventRemove(i);
				}
			} else if (event.fds[i].fd == server) {
				serverRecv();
			} else {
				struct tls *tls = NULL;
				int sock = localAccept(&tls, event.fds[i].fd);
				if (sock < 0) {
					warn("accept");
					continue;
				}
				eventAdd(sock, clientAlloc(sock, tls));
			}
		}

		if (signals[SIGINT] || signals[SIGTERM]) {
			break;
		}
		if (signals[SIGALRM]) {
			signals[SIGALRM] = 0;
			serverDequeue();
		}
		if (signals[SIGINFO]) {
			signals[SIGINFO] = 0;
			ringInfo();
		}
		if (signals[SIGUSR1]) {
			signals[SIGUSR1] = 0;
			certRead = certFile(&cert);
			privRead = certFile(&priv);
			if (caPath) caRead = certFile(&localCA);
			if (!certRead) warn("%s", certPath);
			if (!privRead) warn("%s", privPath);
			if (!caRead && caPath) warn("%s", caPath);
			if (!certRead || !privRead || (!caRead && caPath)) continue;
			localConfig(certRead, privRead, caRead, !clientPass);
			fclose(certRead);
			fclose(privRead);
			if (caPath) fclose(caRead);
		}
	}

	serverFormat("QUIT :%s\r\n", quit);
	serverClose();
	for (size_t i = clientIndex; i < event.len; ++i) {
		struct Client *client = event.clients[i];
		if (!client->need) {
			clientFormat(client, ":%s QUIT :%s\r\n", stateEcho(), quit);
			clientFormat(client, "ERROR :Disconnecting\r\n");
		}
		clientFree(client);
	}
}

#ifdef __OpenBSD__
static void hashPass(void) {
	int error = pledge("stdio tty", NULL);
	if (error) err(EX_OSERR, "pledge");
	char hash[_PASSWORD_LEN];
	char *pass = getpass("Password: ");
	error = crypt_newhash(pass, "bcrypt,a", hash, sizeof(hash));
	if (error) err(EX_OSERR, "crypt_newhash");
	printf("%s\n", hash);
}
#else
static void hashPass(void) {
	byte rand[12];
	FILE *file = fopen("/dev/urandom", "r");
	if (!file) err(EX_OSFILE, "/dev/urandom");
	size_t n = fread(rand, sizeof(rand), 1, file);
	if (!n) err(EX_IOERR, "/dev/urandom");
	fclose(file);
	char salt[3 + BASE64_SIZE(sizeof(rand))] = "$6$";
	base64(&salt[3], rand, sizeof(rand));
	char *pass = getpass("Password: ");
	printf("%s\n", crypt(pass, salt));
}
#endif

static void genReq(const char *path) {
	const char *name = strrchr(path, '/');
	name = (name ? &name[1] : path);
	char subj[256];
	snprintf(subj, sizeof(subj), "/CN=%.*s", (int)strcspn(name, "."), name);
	execlp(
		OPENSSL_BIN, "openssl", "req",
		"-new", "-newkey", "rsa:4096", "-sha256", "-nodes",
		"-subj", subj, "-keyout", path,
		NULL
	);
	err(EX_UNAVAILABLE, "openssl");
}

static void redir(int dst, int src) {
	int fd = dup2(src, dst);
	if (fd < 0) err(EX_OSERR, "dup2");
	close(src);
}

static void genCert(const char *path, const char *ca) {
	int out = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (out < 0) err(EX_CANTCREAT, "%s", path);

	int error;
#ifdef __OpenBSD__
	error = pledge("stdio proc exec", NULL);
	if (error) err(EX_OSERR, "pledge");
#endif

	int rw[2];
	error = pipe(rw);
	if (error) err(EX_OSERR, "pipe");

	pid_t pid = fork();
	if (pid < 0) err(EX_OSERR, "fork");
	if (!pid) {
		close(rw[0]);
		redir(STDOUT_FILENO, rw[1]);
		genReq(path);
	}

	close(rw[1]);
	redir(STDIN_FILENO, rw[0]);
	redir(STDOUT_FILENO, out);
	execlp(
		OPENSSL_BIN, "openssl", "x509",
		"-req", "-days", "3650", "-CAcreateserial",
		(ca ? "-CA" : "-signkey"), (ca ? ca : path),
		NULL
	);
	err(EX_UNAVAILABLE, "openssl");
}
