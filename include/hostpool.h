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
 * Host pool management - tracks hosts and their connection counts
 * for load balancing purposes.
 */

#pragma once

#include <usual/statlist.h>
#include <usual/list.h>

/* Forward declarations */
struct PgDatabase;
struct PgPool;
struct PgSocket;
struct PgHostPool;

/*
 * Host entry - tracks a single host from configuration.
 * Created via hostpool_create_host() and persists for the lifetime of pgbouncer.
 * Reference counted - multiple databases can reference the same host.
 */
typedef struct PgHost {
	char *name;			/* hostname string */
	char *key;			/* hash key: "hostname:port" */
	int port;			/* port number for this host */
	int refcount;			/* number of databases using this host */
	int active_count;		/* number of active connections to this host */
	int index;			/* position in host_pool->hosts array (original config order) */
	struct List bucket_node;	/* node in active_count bucket list (only for multi-host pools) */
	struct PgHostPool *host_pool;	/* back-pointer to multi-host pool (NULL if only in single-host pools) */
	struct StatList idle_server_list;	/* idle server connections to this host */
	UT_hash_handle hh;		/* makes this structure hashable by key */
} PgHost;

/*
 * Collection of hosts for a database - maintains original order for round-robin
 * and buckets by active_count for least-connections selection.
 *
 * Host pools can be shared between databases when they have exactly the same
 * set of hosts. Reference counting tracks how many databases use this pool.
 *
 * For single-host pools (count == 1):
 *   - buckets is NULL (no bucket tracking needed)
 *   - active_count is tracked directly on the host
 *   - The host can be "upgraded" to a multi-host pool later
 *
 * For multi-host pools (count > 1):
 *   - buckets tracks hosts by active_count for least-connections
 *   - host->host_pool points back to this pool
 */
typedef struct PgHostPool {
	struct List head;	/* entry in global host_pool_list */
	PgHost **hosts;		/* array in original config order (for round-robin) */
	int count;		/* number of hosts */
	int refcount;		/* number of databases using this pool */
	int min_active;		/* minimum active_count among all hosts (multi-host only) */
	struct StatList *buckets;	/* array of lists, indexed by active_count (NULL for single-host) */
	int bucket_count;	/* size of buckets array (grows as needed) */
} PgHostPool;

/*
 * Find or create a host entry by name and port.
 * Hosts persist for the lifetime of pgbouncer and are reused across reloads.
 * Increments refcount on the host.
 */
PgHost *hostpool_get_host(const char *host_name, int port);

/*
 * Increment host refcount.
 */
void hostpool_ref_host(PgHost *host);

/*
 * Increment refcount on array of hosts.
 */
void hostpool_ref_hosts(PgHost **hosts, int count);

/*
 * Decrement host refcount. When refcount reaches 0, host can be freed.
 */
void hostpool_unref_host(PgHost *host);

/*
 * Decrement refcount on array of hosts.
 */
void hostpool_unref_hosts(PgHost **hosts, int count);

/*
 * Free a host entry (internal use).
 */
void hostpool_free_host(PgHost *host);

/*
 * Create a host pool for the given number of hosts.
 * Buckets will grow dynamically as needed.
 */
PgHostPool *hostpool_create_host_pool(int host_count, PgHost **hosts);

/*
 * Free a host pool structure without freeing the hosts.
 * Use this during reload when hosts should persist.
 */
void hostpool_free_pool(PgHostPool *pool);

/*
 * Add a host to a pool at the given index.
 * The host is placed in bucket 0 (zero active connections).
 */
bool hostpool_add_host(PgHostPool *pool, PgHost *host, int index);

/*
 * Parse db->host string (possibly comma-separated) and populate db->host_pool.
 * Also parses db->port_str if present to assign per-host ports.
 *
 * Pool sharing rules:
 *   - Single-host pools: hosts can be "upgraded" to multi-host pools later
 *   - Multi-host pools: hosts can only belong to ONE multi-host pool
 *   - If hosts are already in a multi-host pool, that pool is shared (if exact match)
 *   - If hosts are in different multi-host pools, returns false (error)
 *
 * Returns true on success, false on failure.
 */
bool parse_database_hosts(struct PgDatabase *db);

/*
 * Release reference to a host pool. Decrements refcount and frees
 * the pool structure (but not hosts) when refcount reaches 0.
 */
void hostpool_unref_pool(PgHostPool *pool);

/*
 * Increment reference count on a host pool.
 */
void hostpool_ref(PgHostPool *pool);

/*
 * Track active connection count changes for load balancing.
 * These maintain the bucket structure and min_active.
 */
void hostpool_increment_active(PgHost *host);
void hostpool_decrement_active(PgHost *host);

/*
 * Get the host with minimum active connections from the pool.
 * Returns NULL if pool is empty.
 */
PgHost *hostpool_get_least_active_host(struct PgHostPool *pool);

/*
 * Find an idle server connection from a specific host for the given pool.
 * Returns NULL if no suitable server found.
 */
struct PgSocket *hostpool_get_idle_server(PgHost *host, struct PgPool *pool);

/*
 * Get the sum of refcounts of all hosts in the array.
 */
int hostpool_host_ref_sum(PgHost **hosts, int count);

/*
 * Check if all hosts in the array are distinct (no duplicates).
 * Uses refcount trick: refs all, sums, unrefs all, sums again.
 * If all distinct, the difference equals count.
 */
bool hostpool_all_distinct(PgHost **hosts, int count);
