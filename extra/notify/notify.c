/* Copyright (C) 2021  C. McEnroe <june@causal.agency>
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
#include <ctype.h>
#include <err.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static bool verbose;
static struct tls *client;

static void clientWrite(const char *ptr, size_t len) {
	while (len) {
		ssize_t ret = tls_write(client, ptr, len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "tls_write: %s", tls_error(client));
		ptr += ret;
		len -= ret;
	}
}

static void format(const char *format, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, format);
	int len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	assert((size_t)len < sizeof(buf));
	if (verbose) fprintf(stderr, "%s", buf);
	clientWrite(buf, len);
}

enum { ParamCap = 2 };
struct Message {
	char *time;
	char *nick;
	char *user;
	char *host;
	char *cmd;
	char *params[ParamCap];
};

static struct Message parse(char *line) {
	if (verbose) fprintf(stderr, "%s\n", line);
	struct Message msg = {0};
	if (line[0] == '@') {
		char *tags = 1 + strsep(&line, " ");
		while (tags) {
			char *tag = strsep(&tags, ";");
			char *key = strsep(&tag, "=");
			if (!strcmp(key, "time")) msg.time = tag;
		}
	}
	if (line[0] == ':') {
		char *origin = 1 + strsep(&line, " ");
		msg.nick = strsep(&origin, "!");
		msg.user = strsep(&origin, "@");
		msg.host = origin;
	}
	msg.cmd = strsep(&line, " ");
	for (size_t i = 0; line && i < ParamCap; ++i) {
		if (line[0] == ':') {
			msg.params[i] = &line[1];
			break;
		}
		msg.params[i] = strsep(&line, " ");
	}
	return msg;
}

static void require(const struct Message *msg, bool nick, size_t len) {
	if (nick && !msg->nick) errx(EX_PROTOCOL, "%s missing origin", msg->cmd);
	for (size_t i = 0; i < len; ++i) {
		if (msg->params[i]) continue;
		errx(EX_PROTOCOL, "%s missing parameter %zu", msg->cmd, 1 + i);
	}
}

typedef void Handler(struct Message *msg);

static void handlePing(struct Message *msg) {
	require(msg, false, 1);
	format("PONG :%s\r\n", msg->params[0]);
}

static void handleError(struct Message *msg) {
	require(msg, false, 1);
	errx(EX_UNAVAILABLE, "%s", msg->params[0]);
}

static char *nick;
static bool away;

static void handleReplyWelcome(struct Message *msg) {
	require(msg, false, 1);
	free(nick);
	nick = strdup(msg->params[0]);
	if (!nick) err(EX_OSERR, "strdup");
	format("USERHOST %s\r\n", nick);
}

static void handleNick(struct Message *msg) {
	require(msg, true, 1);
	if (nick && !strcmp(msg->nick, nick)) {
		free(nick);
		nick = strdup(msg->params[0]);
		if (!nick) err(EX_OSERR, "strdup");
	}
}

static void handleReplyUserHost(struct Message *msg) {
	require(msg, false, 2);
	while (msg->params[1]) {
		char *reply = strsep(&msg->params[1], " ");
		char *replyNick = strsep(&reply, "*=");
		if (strcmp(replyNick, nick)) continue;
		if (reply && !reply[0]) strsep(&msg->params[1], "=");
		if (!reply) errx(EX_PROTOCOL, "invalid USERHOST reply");
		away = (reply[0] == '-');
		break;
	}
}

static void handleReplyNowAway(struct Message *msg) {
	(void)msg;
	away = true;
}

static void handleReplyUnaway(struct Message *msg) {
	(void)msg;
	away = false;
}

static const char *command;

static void handlePrivmsg(struct Message *msg) {
	require(msg, true, 2);
	if (!nick || !away) return;

	if (!msg->time) return;
	struct tm tm = {0};
	strptime(msg->time, "%FT%T", &tm);
	time_t then = timegm(&tm);
	if (time(NULL) - then > 60) return;

	bool query = (msg->params[0][0] != '#');
	bool mention = false;
	size_t len = strlen(nick);
	for (
		char *match = msg->params[1];
		NULL != (match = strstr(match, nick));
		match = &match[len]
	) {
		char a = (match > msg->params[1] ? match[-1] : ' ');
		char b = (match[len] ? match[len] : ' ');
		if (b == '\1') b = ' ';
		if ((isspace(a) || ispunct(a)) && (isspace(b) || ispunct(b))) {
			mention = true;
			break;
		}
		match = &match[len];
	}
	if (!query && !mention) return;

	pid_t pid = fork();
	if (pid < 0) err(EX_OSERR, "fork");
	if (pid) return;

	setenv("NOTIFY_TIME", msg->time, 1);
	setenv("NOTIFY_NICK", msg->nick, 1);
	if (msg->user) setenv("NOTIFY_USER", msg->user, 1);
	if (msg->host) setenv("NOTIFY_HOST", msg->host, 1);
	if (!query) setenv("NOTIFY_CHANNEL", msg->params[0], 1);
	setenv("NOTIFY_MESSAGE", msg->params[1], 1);

	const char *shell = getenv("SHELL");
	if (!shell) shell = "/bin/sh";
	execl(shell, "sh", "-c", command, NULL);
	err(EX_OSERR, "%s", shell);
}

static const struct {
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ "001", handleReplyWelcome },
	{ "302", handleReplyUserHost },
	{ "305", handleReplyUnaway },
	{ "306", handleReplyNowAway },
	{ "ERROR", handleError },
	{ "NICK", handleNick },
	{ "PING", handlePing },
	{ "PRIVMSG", handlePrivmsg },
};

static void handle(struct Message *msg) {
	if (!msg->cmd) return;
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg->cmd, Handlers[i].cmd)) continue;
		Handlers[i].fn(msg);
		break;
	}
}

static void reap(int sig) {
	(void)sig;
	int status;
	wait(&status);
}

static void quit(int sig) {
	(void)sig;
	format("QUIT\r\n");
	tls_close(client);
	_exit(EX_OK);
}

int main(int argc, char *argv[]) {
	bool insecure = false;
	const char *cert = NULL;
	const char *priv = NULL;
	const char *host = NULL;
	const char *port = "6697";
	const char *pass = NULL;
	const char *trust = NULL;
	const char *user = "pounce-notify";

	for (int opt; 0 < (opt = getopt(argc, argv, "!c:k:p:t:u:vw:"));) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'c': cert = optarg;
			break; case 'k': priv = optarg;
			break; case 'p': port = optarg;
			break; case 't': trust = optarg;
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
			break; case 'w': pass = optarg;
			break; default:  return EX_USAGE;
		}
	}
	if (argc - optind < 1) errx(EX_USAGE, "host required");
	if (argc - optind < 2) errx(EX_USAGE, "command required");
	host = argv[optind++];
	command = argv[optind];

	setenv("POUNCE_HOST", host, 1);
	setenv("POUNCE_PORT", port, 1);

	client = tls_client();
	if (!client) errx(EX_SOFTWARE, "tls_client");

	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	if (insecure) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
	}

	int error;
	if (trust) {
		tls_config_insecure_noverifyname(config);
		error = tls_config_set_ca_file(config, trust);
		if (error) errx(EX_NOINPUT, "%s: %s", trust, tls_config_error(config));
	}
	if (cert) {
		error = tls_config_set_keypair_file(config, cert, (priv ? priv : cert));
		if (error) {
			errx(
				EX_NOINPUT, "tls_config_set_keypair_file: %s",
				tls_config_error(config)
			);
		}
	}

	error = tls_configure(client, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(client));
	tls_config_free(config);

	error = tls_connect(client, host, port);
	if (error) errx(EX_UNAVAILABLE, "tls_connect: %s", tls_error(client));

	if (pass) format("PASS :%s\r\n", pass);
	format(
		"CAP REQ :causal.agency/passive server-time\r\n"
		"CAP END\r\n"
		"NICK *\r\n"
		"USER %s 0 * :pounce-notify\r\n",
		user
	);

	signal(SIGINT, quit);
	signal(SIGTERM, quit);
	signal(SIGCHLD, reap);

	size_t len = 0;
	char buf[8191 + 512];
	for (;;) {
		ssize_t ret = tls_read(client, &buf[len], sizeof(buf) - len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "tls_read: %s", tls_error(client));
		if (!ret) errx(EX_PROTOCOL, "server closed connection");
		len += ret;

		char *line = buf;
		for (;;) {
			char *crlf = memmem(line, &buf[len] - line, "\r\n", 2);
			if (!crlf) break;
			*crlf = '\0';
			struct Message msg = parse(line);
			handle(&msg);
			line = crlf + 2;
		}
		len -= line - buf;
		memmove(buf, line, len);
	}
}
