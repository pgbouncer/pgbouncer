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
 * Socket pool management for per-host connection tracking and load balancing.
 *
 * Tracks active connection counts per host and maintains per-host idle lists
 * for O(1) server selection from the least-loaded host.
 */

#include "bouncer.h"
#include "common/sortingperm.h"

/*
 * Create a socket pool for the given number of hosts.
 */
PgSocketPool *socketpool_create(int host_count)
{
	PgSocketPool *pool;
	int i;

	if (host_count <= 0)
		return NULL;

	pool = calloc(1, sizeof(PgSocketPool));
	if (!pool)
		return NULL;

	pool->host_count = host_count;

	pool->active_count = calloc(host_count, sizeof(int));
	if (!pool->active_count) {
		socketpool_free(pool);
		return NULL;
	}
	pool->perm = calloc(host_count, sizeof(int));
	if (!pool->perm) {
		socketpool_free(pool);
		return NULL;
	}
	pool->invperm = calloc(host_count, sizeof(int));
	if (!pool->invperm) {
		socketpool_free(pool);
		return NULL;
	}

	pool->idle_lists = calloc(host_count, sizeof(struct StatList));
	if (!pool->idle_lists) {
		socketpool_free(pool);
		return NULL;
	}

	for (i = 0; i < host_count; i++){
		statlist_init(&pool->idle_lists[i], "host_idle_list");
		pool->perm[i] = i;
		pool->invperm[i] = i;
	}
	return pool;
}

/*
 * Free a socket pool.
 */
void socketpool_free(PgSocketPool *pool)
{
	if (!pool)
		return;

	free(pool->active_count);
	free(pool->idle_lists);
	free(pool->perm);
	free(pool->invperm);
	free(pool);
}

/*
 * Get the host index with the least active connections.
 * Returns -1 if pool is NULL or empty.
 */
int socketpool_get_least_loaded(PgSocketPool *pool)
{
	if (!pool || pool->host_count <= 0)
		return -1;

	/* perm[0] is the host with the least active connections */
	return pool->perm[0];
}

/*
 * Increment active count for a host (call when connection becomes active).
 */
void socketpool_inc_active(PgSocketPool *pool, int host_index)
{
	int host_rank;
	Assert (pool && host_index >= 0 && host_index < pool->host_count);
	pool->active_count[host_index]++;
	// find position of host in pool -> perm;
	host_rank = pool -> invperm[host_index];
	// update indices if required
	sortingperm_restore_up(pool->active_count, pool->perm, pool->invperm, host_rank, pool->host_count);
}

/*
 * Decrement active count for a host (call when connection becomes idle/closed).
 */
void socketpool_dec_active(PgSocketPool *pool, int host_index)
{
	int host_rank;
	Assert (pool && host_index >= 0 && host_index < pool->host_count);
	pool->active_count[host_index]--;
	// find position of host in pool -> perm;
	host_rank = pool -> invperm[host_index];
	// update indices if required
	sortingperm_restore_down(pool->active_count, pool->perm, pool->invperm, host_rank, pool->host_count);
}

/*
 * Add server to its host's idle list.
 * Uses host_head to link into per-host list.
 */
void socketpool_add_idle_server(PgSocketPool *pool, PgSocket *server)
{
	int host_idx;
	Assert(pool && server);
	host_idx = server->host_index;
	Assert (host_idx >= 0 && host_idx < pool->host_count);
	statlist_append(&pool->idle_lists[host_idx], &server->host_head);
}

/*
 * Remove server from its host's idle list.
 */
void socketpool_remove_idle_server(PgSocketPool *pool, PgSocket *server)
{
	int host_idx;
	Assert(pool && server);
	host_idx = server->host_index;
	if (host_idx >= 0 && host_idx < pool->host_count)
		statlist_remove(&pool->idle_lists[host_idx], &server->host_head);
}

/*
 * Get an idle server from the least-loaded host.
 * Returns NULL if no suitable server found.
 */
PgSocket *socketpool_get_idle_server(PgSocketPool *pool)
{
	struct List *item;
	PgSocket *server;
	int i;

	Assert(pool && pool->host_count > 0);

	/* Get a suitable server in the loaded host */
	for(i = 0; i < pool->host_count; i++) {
		statlist_for_each(item, &pool->idle_lists[pool -> perm[i]]) {
			server = container_of(item, PgSocket, host_head);
			if (!server->close_needed && server->ready)
				return server;
		}
	}
	return NULL;
}
