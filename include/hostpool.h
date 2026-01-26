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
 */
typedef struct PgHost {
	char *name;			/* hostname string */
	char *key;			/* hash key: "hostname:port" */
	int port;			/* port number for this host */
	int active_count;		/* number of active connections to this host */
	int index;			/* position in host_pool->hosts array (original config order) */
	struct List bucket_node;	/* node in active_count bucket list */
	struct PgHostPool *host_pool;	/* back-pointer to containing pool */
	struct StatList idle_server_list;	/* idle server connections to this host */
	UT_hash_handle hh;		/* makes this structure hashable by key */
} PgHost;

/*
 * Collection of hosts for a database - maintains original order for round-robin
 * and buckets by active_count for least-connections selection.
 */
typedef struct PgHostPool {
	PgHost **hosts;		/* array in original config order (for round-robin) */
	int count;		/* number of hosts */
	int min_active;		/* minimum active_count among all hosts */
	struct StatList *buckets;	/* array of lists, indexed by active_count */
	int bucket_count;	/* size of buckets array (grows as needed) */
} PgHostPool;

/*
 * Find or create a host entry by name and port.
 * Hosts persist for the lifetime of pgbouncer and are reused across reloads.
 */
PgHost *hostpool_create_host(const char *host_name, int port);

/*
 * Free a host entry.
 */
void hostpool_free_host(PgHost *host);

/*
 * Create a host pool for the given number of hosts.
 * Buckets will grow dynamically as needed.
 */
PgHostPool *hostpool_create_host_pool(int host_count);

/*
 * Free a host pool structure without freeing the hosts.
 * Use this during reload when hosts should persist.
 */
void hostpool_release_pool(PgHostPool *pool);

/*
 * Free a host pool and all its hosts.
 * Use this for complete cleanup (e.g., shutdown).
 */
void hostpool_free_host_pool(PgHostPool *pool);

/*
 * Add a host to a pool at the given index.
 * The host is placed in bucket 0 (zero active connections).
 */
bool hostpool_add_host(PgHostPool *pool, PgHost *host, int index);

/*
 * Parse db->host string (possibly comma-separated) and populate db->host_pool.
 * Also parses db->port_str if present to assign per-host ports.
 * Returns true on success, false on failure.
 */
bool parse_database_hosts(struct PgDatabase *db);

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
