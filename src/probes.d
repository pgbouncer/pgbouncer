/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * DTrace / USDT static tracepoint provider.
 *
 * This file is processed at build time (only when configured with
 * --enable-dtrace / -Ddtrace=enabled) by the systemtap "dtrace" wrapper
 * or a real DTrace to generate probes.h.  When tracing is disabled,
 * src/gen_probes.py produces a probes.h full of empty macros instead, so
 * the call sites compile away to nothing.
 *
 * Probe names use "__" as a word separator; the generated macros turn each
 * "__" into a single "_" and uppercase the result, e.g. the probe
 * client__server__linked becomes the macro TRACE_PGBOUNCER_CLIENT_SERVER_LINKED.
 *
 * Keep each probe declaration on a single line: gen_probes.py's dummy-header
 * parser expects "probe name(args);" without embedded newlines.
 */

provider pgbouncer {
	/* A client connection has been linked to a server connection (it now owns that backend). */
	probe client__server__linked(const char *client_addr, int client_port, const char *server_addr, int server_port, const char *dbname, const char *username);

	/* A client/server link has been broken (the server returns to the pool or is closed). */
	probe client__server__unlinked(const char *client_addr, int client_port, const char *server_addr, int server_port, const char *dbname, const char *username);

	/* A backend connection has been established. */
	probe server__connect(const char *server_addr, int server_port, const char *dbname, const char *username);

	/* A backend connection is being closed. */
	probe server__disconnect(const char *server_addr, int server_port, const char *dbname, const char *username, const char *reason);

	/* A backend connection is ready to accept queries (authenticated, startup params and any connect_query). */
	probe server__ready(const char *server_addr, int server_port, const char *dbname, const char *username, uint64_t duration);

	/* A client connection has been accepted. */
	probe client__connect(const char *client_addr, int client_port);

	/* A client connection is being closed. */
	probe client__disconnect(const char *client_addr, int client_port, const char *dbname, const char *username, const char *reason);

	/* Authentication is about to be attempted with the chosen authentication method. */
	probe client__login__attempt(const char *client_addr, int client_port, const char *dbname, const char *username, const char *auth_method);

	/* The client authenticated successfully and became active. */
	probe client__login__success(const char *client_addr, int client_port, const char *dbname, const char *username, const char *auth_method);

	/* The client was closed before completing login. */
	probe client__login__failure(const char *client_addr, int client_port, const char *dbname, const char *username, const char *auth_method, const char *reason);

	/* The client entered the wait queue because no server was available. */
	probe client__wait__start(const char *client_addr, int client_port, const char *dbname, const char *username);

	/* The client left the wait queue. */
	probe client__wait__end(const char *client_addr, int client_port, const char *dbname, const char *username, uint64_t duration);

	/* The new query has started for the client. */
	probe client__query__start(const char *client_addr, int client_port, const char *dbname, const char *username);

	/* The query has finished. */
	probe client__query__ready(const char *client_addr, int client_port, const char *dbname, const char *username, uint64_t duration);

	/* PAUSE: pause the pooler, or a single database. */
	probe admin__pause(const char *client_addr, int client_port, const char *username, const char *dbname);

	/* RESUME: resume the pooler, or a single database. */
	probe admin__resume(const char *client_addr, int client_port, const char *username, const char *dbname);

	/* RELOAD: re-read the configuration file. */
	probe admin__reload(const char *client_addr, int client_port, const char *username);

	/* SHUTDOWN: begin shutting down; mode is "immediate", "wait_for_servers", or "wait_for_clients". */
	probe admin__shutdown(const char *client_addr, int client_port, const char *username, const char *mode);

	/* RECONNECT: mark server connections to be reopened, for the pooler or a single database. */
	probe admin__reconnect(const char *client_addr, int client_port, const char *username, const char *dbname);

	/* KILL: immediately drop all connections of the pooler or a single database. */
	probe admin__kill(const char *client_addr, int client_port, const char *username, const char *dbname);
};
