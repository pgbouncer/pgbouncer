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

#endif
