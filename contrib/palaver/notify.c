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
#include <ctype.h>
#include <curl/curl.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

// Why must it return (const unsigned char *)?
#define sqlite3_column_text(...) (const char *)sqlite3_column_text(__VA_ARGS__)

#define DATABASE_PATH "pounce-palaver/preferences.sqlite"

#define SQL(...) #__VA_ARGS__
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static bool verbose;
static char curlError[CURL_ERROR_SIZE];

static CURL *curl;
static sqlite3 *db;
static struct tls *client;

static void dbOpen(char *path) {
	char *base = strrchr(path, '/');
	*base = '\0';
	int error = mkdir(path, 0700);
	if (error && errno != EEXIST) err(EX_CANTCREAT, "%s", path);
	*base = '/';

	error = sqlite3_open_v2(
		path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL
	);
	if (error == SQLITE_CANTOPEN) {
		sqlite3_close(db);
		db = NULL;
		return;
	}
	if (error) errx(EX_NOINPUT, "%s: %s", path, sqlite3_errmsg(db));

	sqlite3_busy_timeout(db, 10000);
}

static void dbFind(char *path) {
	if (path) {
		dbOpen(path);
		if (db) return;
		errx(EX_NOINPUT, "%s: database not found", path);
	}

	const char *home = getenv("HOME");
	const char *dataHome = getenv("XDG_DATA_HOME");
	const char *dataDirs = getenv("XDG_DATA_DIRS");

	char buf[PATH_MAX];
	if (dataHome) {
		snprintf(buf, sizeof(buf), "%s/" DATABASE_PATH, dataHome);
	} else {
		if (!home) errx(EX_CONFIG, "HOME unset");
		snprintf(buf, sizeof(buf), "%s/.local/share/" DATABASE_PATH, home);
	}
	dbOpen(buf);
	if (db) return;

	if (!dataDirs) dataDirs = "/usr/local/share:/usr/share";
	while (*dataDirs) {
		size_t len = strcspn(dataDirs, ":");
		snprintf(buf, sizeof(buf), "%.*s/" DATABASE_PATH, (int)len, dataDirs);
		dbOpen(buf);
		if (db) return;
		dataDirs += len;
		if (*dataDirs) dataDirs++;
	}
	errx(EX_NOINPUT, "database not found");
}

static int dbParam(sqlite3_stmt *stmt, const char *param) {
	int index = sqlite3_bind_parameter_index(stmt, param);
	if (index) return index;
	errx(EX_SOFTWARE, "no such parameter %s: %s", param, sqlite3_sql(stmt));
}

static void
dbBindText(sqlite3_stmt *stmt, const char *param, const char *value) {
	if (!sqlite3_bind_text(stmt, dbParam(stmt, param), value, -1, NULL)) return;
	errx(EX_SOFTWARE, "sqlite3_bind_text: %s", sqlite3_errmsg(db));
}

static void
dbBindCopy(sqlite3_stmt *stmt, const char *param, const char *value) {
	int error = sqlite3_bind_text(
		stmt, dbParam(stmt, param), value, -1, SQLITE_TRANSIENT
	);
	if (error) errx(EX_SOFTWARE, "sqlite3_bind_text: %s", sqlite3_errmsg(db));
}

static void dbVerbose(sqlite3_stmt *stmt) {
	if (!verbose) return;
	char *sql = sqlite3_expanded_sql(stmt);
	if (sql) fprintf(stderr, "%s\n", sql);
	sqlite3_free(sql);
}

static void dbInit(void) {
	const char *sql = SQL(
		CREATE TABLE IF NOT EXISTS clients (
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			client TEXT NOT NULL,
			version TEXT NOT NULL,
			network TEXT,
			UNIQUE (host, port, client)
		);
		CREATE TABLE IF NOT EXISTS preferences (
			client TEXT NOT NULL,
			key TEXT NOT NULL,
			value TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS preferencesIndex
		ON preferences (client, key);
	);
	int error = sqlite3_exec(db, sql, NULL, NULL, NULL);
	if (error) errx(EX_SOFTWARE, "%s: %s", sqlite3_errmsg(db), sql);
}

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

enum { ParamCap = 4 };
struct Message {
	char *time;
	char *nick;
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

static void handleCap(struct Message *msg) {
	require(msg, false, 3);
	if (!strcmp(msg->params[1], "NAK")) {
		errx(EX_CONFIG, "pounce palaver option not enabled");
	}
}

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
static int badge;

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

static void keyword(sqlite3_context *ctx, int n, sqlite3_value *args[]) {
	assert(n == 2);
	const char *haystack = (const char *)sqlite3_value_text(args[0]);
	const char *needle = (const char *)sqlite3_value_text(args[1]);
	if (!nick || !haystack || !needle) {
		sqlite3_result_null(ctx);
		return;
	}

	char *copy = NULL;
	const char *replace;
	if (!strcmp(needle, "{nick}")) {
		needle = nick;
	} else if (NULL != (replace = strstr(needle, "{nick}"))) {
		int n = asprintf(
			&copy, "%.*s%s%s",
			(int)(replace - needle), needle, nick, &replace[6]
		);
		if (n < 0) {
			sqlite3_result_error_nomem(ctx);
			return;
		}
		needle = copy;
	}

	size_t len = strlen(needle);
	const char *match = haystack;
	sqlite3_result_int(ctx, false);
	while (NULL != (match = strcasestr(match, needle))) {
		char a = (match > haystack ? match[-1] : ' ');
		char b = (match[len] ? match[len] : ' ');
		if (b == '\1') b = ' ';
		if ((isspace(a) || ispunct(a)) && (isspace(b) || ispunct(b))) {
			sqlite3_result_int(ctx, true);
			break;
		}
		match = &match[len];
	}
	free(copy);
}

enum {
	Identify,
	Begin,
	Set,
	End,
	Clear,
	Notify,
	QueriesLen,
};

static sqlite3_stmt *stmts[QueriesLen];
static const char *Queries[QueriesLen] = {
	[Identify] = SQL(
		SELECT 1 FROM clients
		WHERE host = :host AND port = :port
		AND client = :client AND version = :version;
	),

	[Begin] = SQL(
		DELETE FROM preferences WHERE client = :client;
	),

	[Set] = SQL(
		INSERT INTO preferences (client, key, value)
		VALUES (:client, :key, :value);
	),

	[End] = SQL(
		INSERT INTO clients (host, port, client, version, network)
		VALUES (:host, :port, :client, :version, :network)
		ON CONFLICT (host, port, client) DO
		UPDATE SET version = :version, network = :network
		WHERE host = :host AND port = :port AND client = :client;
	),

	[Clear] = SQL(
		SELECT pushToken.value, pushEndpoint.value
		FROM clients
		JOIN preferences AS pushToken USING (client)
		JOIN preferences AS pushEndpoint USING (client)
		WHERE host = :host AND port = :port
			AND pushToken.key = 'PUSH-TOKEN'
			AND pushEndpoint.key = 'PUSH-ENDPOINT';
	),

	[Notify] = SQL(
		WITH mentions AS (
			SELECT DISTINCT client
			FROM clients
			JOIN preferences USING (client)
			WHERE host = :host AND port = :port AND (
				(key = 'MENTION-KEYWORD' AND keyword(:message, value)) OR
				(key = 'MENTION-CHANNEL' AND value = :channel) OR
				(key = 'MENTION-NICK' AND value = :nick) OR
				:direct
			)
		),
		ignores AS (
			SELECT DISTINCT client
			FROM clients
			JOIN preferences USING (client)
			WHERE host = :host AND port = :port AND (
				(key = 'IGNORE-KEYWORD' AND keyword(:message, value)) OR
				(key = 'IGNORE-CHANNEL' AND value = :channel) OR
				(key = 'IGNORE-NICK' AND value = :nick)
			)
		),
		matches AS (SELECT * FROM mentions EXCEPT SELECT * FROM ignores)
		SELECT
			pushToken.value,
			pushEndpoint.value,
			coalesce(showMessagePreview.value, 'true'),
			clients.network
		FROM clients
		JOIN matches USING (client)
		JOIN preferences AS pushToken USING (client)
		JOIN preferences AS pushEndpoint USING (client)
		LEFT JOIN preferences AS showMessagePreview
			ON showMessagePreview.client = clients.client
			AND showMessagePreview.key = 'SHOW-MESSAGE-PREVIEW'
		WHERE pushToken.key = 'PUSH-TOKEN'
			AND pushEndpoint.key = 'PUSH-ENDPOINT';
	),
};

static void palaverIdentify(struct Message *msg) {
	require(msg, false, 3);
	dbBindText(stmts[Identify], ":client", msg->params[1]);
	dbBindText(stmts[Identify], ":version", msg->params[2]);
	dbVerbose(stmts[Identify]);
	int result = sqlite3_step(stmts[Identify]);
	if (result == SQLITE_DONE) {
		format("PALAVER REQ\r\n");
		dbBindCopy(stmts[End], ":network", msg->params[3]);
	} else if (result != SQLITE_ROW) {
		errx(EX_SOFTWARE, "%s", sqlite3_errmsg(db));
	}
	sqlite3_reset(stmts[Identify]);
}

static void palaverBegin(struct Message *msg) {
	require(msg, false, 3);
	dbBindText(stmts[Begin], ":client", msg->params[1]);
	dbVerbose(stmts[Begin]);
	int result = sqlite3_step(stmts[Begin]);
	if (result != SQLITE_DONE) errx(EX_SOFTWARE, "%s", sqlite3_errmsg(db));
	sqlite3_reset(stmts[Begin]);
	dbBindCopy(stmts[Set], ":client", msg->params[1]);
	dbBindCopy(stmts[End], ":client", msg->params[1]);
	dbBindCopy(stmts[End], ":version", msg->params[2]);
}

static void palaverSet(struct Message *msg) {
	require(msg, false, 3);
	dbBindText(stmts[Set], ":key", msg->params[1]);
	dbBindText(stmts[Set], ":value", msg->params[2]);
	dbVerbose(stmts[Set]);
	int result = sqlite3_step(stmts[Set]);
	if (result != SQLITE_DONE) errx(EX_SOFTWARE, "%s", sqlite3_errmsg(db));
	sqlite3_reset(stmts[Set]);
}

static void palaverEnd(struct Message *msg) {
	(void)msg;
	dbVerbose(stmts[End]);
	int result = sqlite3_step(stmts[End]);
	if (result != SQLITE_DONE) errx(EX_SOFTWARE, "%s", sqlite3_errmsg(db));
	sqlite3_reset(stmts[End]);
}

static void handlePalaver(struct Message *msg) {
	require(msg, false, 1);
	if (!strcmp(msg->params[0], "IDENTIFY")) {
		palaverIdentify(msg);
	} else if (!strcmp(msg->params[0], "BEGIN")) {
		palaverBegin(msg);
	} else if (!strcmp(msg->params[0], "SET")) {
		palaverSet(msg);
	} else if (!strcmp(msg->params[0], "ADD")) {
		palaverSet(msg);
	} else if (!strcmp(msg->params[0], "END")) {
		palaverEnd(msg);
	}
}

static void jsonString(FILE *file, const char *str) {
	fputc('"', file);
	for (const char *ch = str; *ch; ++ch) {
		if (iscntrl(*ch) || *ch == '"' || *ch == '\\') {
			fprintf(file, "\\u%04x", (unsigned)*ch);
		} else {
			fputc(*ch, file);
		}
	}
	fputc('"', file);
}

static void pushNotify(const char *endpoint, const char *token, char *body) {
	CURLcode code = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
	if (code) {
		warnx("%s: %s", endpoint, curlError);
		return;
	}

	char auth[256];
	struct curl_slist *list = NULL;
	snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
	list = curl_slist_append(list, "Content-Type: application/json");
	list = curl_slist_append(list, auth);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

	size_t len = strlen(body);
	FILE *file = fmemopen(body, len, "r");
	if (!file) err(EX_OSERR, "fmemopen");

	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
	curl_easy_setopt(curl, CURLOPT_READDATA, file);

	if (verbose) fprintf(stderr, "%s\n", body);
	code = curl_easy_perform(curl);
	if (code) warnx("%s: %s", endpoint, curlError);

	fclose(file);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(list);
}

static void handleReplyNowAway(struct Message *msg) {
	(void)msg;
	away = true;
}

static void handleReplyUnaway(struct Message *msg) {
	(void)msg;
	away = false;
	if (!badge) return;
	badge = 0;

	dbVerbose(stmts[Clear]);
	int result;
	while (SQLITE_ROW == (result = sqlite3_step(stmts[Clear]))) {
		int i = 0;
		const char *token = sqlite3_column_text(stmts[Clear], i++);
		const char *endpoint = sqlite3_column_text(stmts[Clear], i++);
		pushNotify(endpoint, token, "{\"badge\":0}");
	}
	if (result != SQLITE_DONE) errx(EX_SOFTWARE, "%s", sqlite3_errmsg(db));
	sqlite3_reset(stmts[Clear]);
}

static void jsonBody(
	char *buf, size_t cap,
	struct Message *msg, const char *network, bool preview
) {
	FILE *file = fmemopen(buf, cap, "w");
	if (!file) err(EX_OSERR, "fmemopen");

	fprintf(file, "{\"badge\":%d", badge);
	fprintf(file, ",\"sender\":");
	jsonString(file, msg->nick);
	fprintf(file, ",\"channel\":");
	jsonString(file, msg->params[0]);
	if (network) {
		fprintf(file, ",\"network\":");
		jsonString(file, network);
	}
	if (preview) {
		if (!strncmp(msg->params[1], "\1ACTION ", 8)) {
			size_t len = strlen(msg->params[1]);
			if (msg->params[1][len - 1] == '\1') msg->params[1][len - 1] = '\0';
			fprintf(file, ",\"intent\":\"ACTION\",\"message\":");
			jsonString(file, &msg->params[1][8]);
		} else {
			fprintf(file, ",\"message\":");
			jsonString(file, msg->params[1]);
		}
	} else {
		fprintf(file, ",\"private\":true");
	}
	fprintf(file, "}");

	// XXX: fmemopen only null-terminates if there is room.
	fclose(file);
	buf[cap - 1] = '\0';
}

static void handlePrivmsg(struct Message *msg) {
	require(msg, true, 2);
	if (!away) return;
	if (!msg->time) return;
	struct tm tm = {0};
	strptime(msg->time, "%FT%T", &tm);
	time_t then = timegm(&tm);
	if (time(NULL) - then > 60) return;

	dbBindText(stmts[Notify], ":nick", msg->nick);
	dbBindText(stmts[Notify], ":channel", msg->params[0]);
	dbBindText(stmts[Notify], ":message", msg->params[1]);
	dbBindText(
		stmts[Notify], ":direct", (!strcmp(msg->params[0], nick) ? "1" : NULL)
	);
	dbVerbose(stmts[Notify]);
	int result;
	bool badged = false;
	while (SQLITE_ROW == (result = sqlite3_step(stmts[Notify]))) {
		int i = 0;
		const char *token = sqlite3_column_text(stmts[Notify], i++);
		const char *endpoint = sqlite3_column_text(stmts[Notify], i++);
		const char *preview = sqlite3_column_text(stmts[Notify], i++);
		const char *network = sqlite3_column_text(stmts[Notify], i++);

		char body[4096];
		if (!badged) {
			badge++;
			badged = true;
		}
		jsonBody(body, sizeof(body), msg, network, !strcmp(preview, "true"));
		pushNotify(endpoint, token, body);
	}
	if (result != SQLITE_DONE) errx(EX_SOFTWARE, "%s", sqlite3_errmsg(db));
	sqlite3_reset(stmts[Notify]);
}

static const struct {
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ "001", handleReplyWelcome },
	{ "302", handleReplyUserHost },
	{ "305", handleReplyUnaway },
	{ "306", handleReplyNowAway },
	{ "CAP", handleCap },
	{ "ERROR", handleError },
	{ "NICK", handleNick },
	{ "NOTICE", handlePrivmsg },
	{ "PALAVER", handlePalaver },
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

static void atExit(void) {
	if (client) tls_close(client);
	curl_easy_cleanup(curl);
	for (size_t i = 0; i < QueriesLen; ++i) {
		sqlite3_finalize(stmts[i]);
	}
	sqlite3_close(db);
}

static void quit(int sig) {
	(void)sig;
	format("QUIT\r\n");
	atExit();
	_exit(EX_OK);
}

int main(int argc, char *argv[]) {
	bool insecure = false;
	char *path = NULL;
	const char *cert = NULL;
	const char *priv = NULL;
	const char *host = NULL;
	const char *port = "6697";
	const char *pass = NULL;
	const char *user = "pounce-palaver";

	for (int opt; 0 < (opt = getopt(argc, argv, "!c:d:k:p:u:vw:"));) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'c': cert = optarg;
			break; case 'd': path = optarg;
			break; case 'k': priv = optarg;
			break; case 'p': port = optarg;
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
			break; case 'w': pass = optarg;
		}
	}
	if (optind == argc) errx(EX_USAGE, "host required");
	host = argv[optind];

	CURLcode code = curl_global_init(CURL_GLOBAL_ALL);
	if (code) errx(EX_OSERR, "curl_global_init: %s", curl_easy_strerror(code));

	curl = curl_easy_init();
	if (!curl) errx(EX_SOFTWARE, "curl_easy_init");

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlError);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, (verbose ? 1L : 0L));
	curl_easy_setopt(curl, CURLOPT_POST, 1L);

	dbFind(path);
	atexit(atExit);

	dbInit();
	sqlite3_create_function(
		db, "keyword", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
		keyword, NULL, NULL
	);
	for (size_t i = 0; i < QueriesLen; ++i) {
		int error = sqlite3_prepare_v3(
			db, Queries[i], -1, SQLITE_PREPARE_PERSISTENT, &stmts[i], NULL
		);
		if (error) errx(EX_SOFTWARE, "%s: %s", sqlite3_errmsg(db), Queries[i]);
		if (sqlite3_bind_parameter_index(stmts[i], ":host")) {
			dbBindText(stmts[i], ":host", host);
			dbBindText(stmts[i], ":port", port);
		}
	}

	client = tls_client();
	if (!client) errx(EX_SOFTWARE, "tls_client");

	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	if (insecure) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
	}

	int error;
	if (cert) {
		error = tls_config_set_keypair_file(config, cert, (priv ? priv : cert));
		if (error) {
			errx(
				EX_SOFTWARE, "tls_config_set_keypair_file: %s",
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
		"CAP REQ :server-time palaverapp.com causal.agency/passive\r\n"
		"CAP END\r\n"
		"NICK *\r\n"
		"USER %s 0 * :pounce-palaver\r\n",
		user
	);

	signal(SIGINT, quit);
	signal(SIGTERM, quit);

	char buf[8191 + 512];
	size_t len = 0;
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
			crlf[0] = '\0';
			struct Message msg = parse(line);
			handle(&msg);
			line = crlf + 2;
		}
		len -= line - buf;
		memmove(buf, line, len);
	}
}
