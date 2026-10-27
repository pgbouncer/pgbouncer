/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * DTrace / USDT tracepoint helpers.
 *
 * This header pulls in the generated probes.h (real macros when built with
 * --enable-dtrace / -Ddtrace=enabled, empty macros otherwise) and wraps the
 * generated TRACE_PGBOUNCER_* macros in convenience macros that take the
 * PgBouncer socket objects directly.
 *
 * Every wrapper is guarded by the probe's _ENABLED() semaphore, so argument
 * formatting (notably address-to-string conversion) only happens when a
 * tracing consumer is actually attached.  With tracing disabled the generated
 * macros and the _ENABLED() guards are all no-ops, so the whole thing folds
 * away to nothing.
 *
 * These wrappers are macros (not functions) so they can be used wherever the
 * PgSocket/PgAddr types and the pga_*() helpers are already in scope, without
 * this header having to depend on bouncer.h.
 */
#ifndef _TRACING_H_
#define _TRACING_H_

#include "probes.h"

/*
 * Fire the client<->server (un)link probes.  "client" and "server" are
 * PgSocket pointers; both must be non-NULL and still carry valid pool/user
 * information at the call site.
 */
#define TRACE_CLIENT_SERVER_LINKED(client, server) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_SERVER_LINKED_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF], _tr_saddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_SERVER_LINKED( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				pga_ntop(&(server)->remote_addr, _tr_saddr, sizeof(_tr_saddr)), \
				pga_port(&(server)->remote_addr), \
				(client)->pool ? (client)->pool->db->name : "", \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : ""); \
		} \
	} while (0)

#define TRACE_CLIENT_SERVER_UNLINKED(client, server) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_SERVER_UNLINKED_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF], _tr_saddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_SERVER_UNLINKED( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				pga_ntop(&(server)->remote_addr, _tr_saddr, sizeof(_tr_saddr)), \
				pga_port(&(server)->remote_addr), \
				(client)->pool ? (client)->pool->db->name : "", \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : ""); \
		} \
	} while (0)

/*
 * Fire the backend connect and disconnect probes.  "server" is a PgSocket
 * pointer for a server-side connection.
 */
#define TRACE_SERVER_CONNECT(server) \
	do { \
		if (TRACE_PGBOUNCER_SERVER_CONNECT_ENABLED()) { \
			char _tr_saddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_SERVER_CONNECT( \
				pga_ntop(&(server)->remote_addr, _tr_saddr, sizeof(_tr_saddr)), \
				pga_port(&(server)->remote_addr), \
				(server)->pool ? (server)->pool->db->name : "", \
				(server)->login_user_credentials ? (server)->login_user_credentials->name : ""); \
		} \
	} while (0)

#define TRACE_SERVER_DISCONNECT(server, reason) \
	do { \
		if (TRACE_PGBOUNCER_SERVER_DISCONNECT_ENABLED()) { \
			char _tr_saddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_SERVER_DISCONNECT( \
				pga_ntop(&(server)->remote_addr, _tr_saddr, sizeof(_tr_saddr)), \
				pga_port(&(server)->remote_addr), \
				(server)->pool ? (server)->pool->db->name : "", \
				(server)->login_user_credentials ? (server)->login_user_credentials->name : "", \
				(reason)); \
		} \
	} while (0)

/*
 * Fire the backend server-ready probe.  duration is derived from
 * server->connect_time (set when the connection was launched), so it covers
 * TCP/TLS connect, PostgreSQL authentication, startup params, and any connect_query.
 */
#define TRACE_SERVER_READY(server) \
	do { \
		if (TRACE_PGBOUNCER_SERVER_READY_ENABLED()) { \
			char _tr_saddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_SERVER_READY( \
				pga_ntop(&(server)->remote_addr, _tr_saddr, sizeof(_tr_saddr)), \
				pga_port(&(server)->remote_addr), \
				(server)->pool ? (server)->pool->db->name : "", \
				(server)->login_user_credentials ? (server)->login_user_credentials->name : "", \
				(uint64_t)((server)->connect_time ? get_cached_time() - (server)->connect_time : 0)); \
		} \
	} while (0)

/*
 * Fire the client connect and disconnect probes.  "client" is a PgSocket
 * pointer for a client-side connection.  At accept time no db or user are
 * known yet, so client__connect carries only the client address.
 */
#define TRACE_CLIENT_CONNECT(client) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_CONNECT_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_CONNECT( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr)); \
		} \
	} while (0)

#define TRACE_CLIENT_DISCONNECT(client, reason) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_DISCONNECT_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_DISCONNECT( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				(client)->pool ? (client)->pool->db->name : "", \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : "", \
				(reason) ? (reason) : ""); \
		} \
	} while (0)

/*
 * Database name for a client during the login phase: client->pool is set once
 * set_pool() runs, but on early failures only client->db may be available.
 */
#define _TR_CLIENT_DB(client) \
	((client)->pool ? (client)->pool->db->name : \
	 ((client)->db ? (client)->db->name : ""))

/*
 * Fire the client authentication probes.  The decided auth method is taken
 * from client->client_auth_type (see auth_type_name()).
 */
#define TRACE_CLIENT_LOGIN_ATTEMPT(client) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_LOGIN_ATTEMPT_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_LOGIN_ATTEMPT( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				_TR_CLIENT_DB(client), \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : "", \
				auth_type_name((client)->client_auth_type)); \
		} \
	} while (0)

#define TRACE_CLIENT_LOGIN_SUCCESS(client) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_LOGIN_SUCCESS_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_LOGIN_SUCCESS( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				_TR_CLIENT_DB(client), \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : "", \
				auth_type_name((client)->client_auth_type)); \
		} \
	} while (0)

#define TRACE_CLIENT_LOGIN_FAILURE(client, reason) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_LOGIN_FAILURE_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_LOGIN_FAILURE( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				_TR_CLIENT_DB(client), \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : "", \
				auth_type_name((client)->client_auth_type), \
				(reason) ? (reason) : ""); \
		} \
	} while (0)

/*
 * Fire the client wait-queue probes.  TRACE_CLIENT_WAIT_END computes the time
 * spent in the queue from client->wait_start (still valid at the call site).
 */
#define TRACE_CLIENT_WAIT_START(client) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_WAIT_START_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_WAIT_START( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				_TR_CLIENT_DB(client), \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : ""); \
		} \
	} while (0)

#define TRACE_CLIENT_WAIT_END(client) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_WAIT_END_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_WAIT_END( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				_TR_CLIENT_DB(client), \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : "", \
				(uint64_t)((client)->wait_start ? get_cached_time() - (client)->wait_start : 0)); \
		} \
	} while (0)

/*
 * Fire the query boundary probes.  TRACE_CLIENT_QUERY_READY takes the measured
 * query duration (microseconds) that the caller already computed.
 */
#define TRACE_CLIENT_QUERY_START(client) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_QUERY_START_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_QUERY_START( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				_TR_CLIENT_DB(client), \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : ""); \
		} \
	} while (0)

#define TRACE_CLIENT_QUERY_READY(client, duration) \
	do { \
		if (TRACE_PGBOUNCER_CLIENT_QUERY_READY_ENABLED()) { \
			char _tr_caddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_CLIENT_QUERY_READY( \
				pga_ntop(&(client)->remote_addr, _tr_caddr, sizeof(_tr_caddr)), \
				pga_port(&(client)->remote_addr), \
				_TR_CLIENT_DB(client), \
				(client)->login_user_credentials ? (client)->login_user_credentials->name : "", \
				(uint64_t)(duration)); \
		} \
	} while (0)

/*
 * Admin console process-control probes.  "admin" is the PgSocket of the admin
 * connection that issued the command; its remote_addr and login user identify
 * the operator.  "dbname" is the target database, or "" when the command
 * applies to all.
 */
#define TRACE_ADMIN_PAUSE(admin, dbname) \
	do { \
		if (TRACE_PGBOUNCER_ADMIN_PAUSE_ENABLED()) { \
			char _tr_aaddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_ADMIN_PAUSE( \
				pga_ntop(&(admin)->remote_addr, _tr_aaddr, sizeof(_tr_aaddr)), \
				pga_port(&(admin)->remote_addr), \
				(admin)->login_user_credentials ? (admin)->login_user_credentials->name : "", \
				(dbname)); \
		} \
	} while (0)

#define TRACE_ADMIN_RESUME(admin, dbname) \
	do { \
		if (TRACE_PGBOUNCER_ADMIN_RESUME_ENABLED()) { \
			char _tr_aaddr[PGADDR_BUF]; \
			TRACE_PGBOUNCER_ADMIN_RESUME( \
				pga_ntop(&(admin)->remote_addr, _tr_aaddr, sizeof(_tr_aaddr)), \
				pga_port(&(admin)->remote_addr), \
				(admin)->login_user_credentials ? (admin)->login_user_credentials->name : "", \
				(dbname)); \
		} \
	} while (0)

#endif
