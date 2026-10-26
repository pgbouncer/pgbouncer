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
};
