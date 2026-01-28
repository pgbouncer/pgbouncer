/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Socket pool: tracks connections per host for load balancing.
 * Maintains per-host idle lists and active connection counts.
 */

#ifndef _PGBOUNCER_SOCKETPOOL_H_
#define _PGBOUNCER_SOCKETPOOL_H_

/*
 * Socket pool structure.
 */
struct PgSocketPool {
	uint16_t host_count;
	int *perm;
	int *invperm;
	int *active_count;		/* array of active counts per host */
	struct StatList *idle_lists;	/* array of idle lists per host */
};

/* Create a socket pool for the given number of hosts */
PgSocketPool *socketpool_create(int host_count);

/* Free a socket pool */
void socketpool_free(PgSocketPool *pool);

/* Get the host index with the least active connections */
int socketpool_get_least_loaded(PgSocketPool *pool);

/* Increment active count for a host */
void socketpool_inc_active(PgSocketPool *pool, int host_index);

/* Decrement active count for a host */
void socketpool_dec_active(PgSocketPool *pool, int host_index);

/* Add server to its host's idle list */
void socketpool_add_idle_server(PgSocketPool *pool, PgSocket *server);

/* Remove server from its host's idle list */
void socketpool_remove_idle_server(PgSocketPool *pool, PgSocket *server);

/* Get an idle server from the least-loaded host */
PgSocket *socketpool_get_idle_server(PgSocketPool *pool);

#endif
