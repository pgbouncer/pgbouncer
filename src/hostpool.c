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
 * for load balancing purposes using bucket-based organization.
 *
 * Design:
 * - PgHost entries are reference-counted and shared between databases
 * - PgHostPool is always created (even for single host)
 * - Single-host pools: no bucket tracking, active_count on host directly
 * - Multi-host pools: bucket-based tracking for least-connections
 * - A host in a single-host pool can be "grouped" on a multi-host pool
 * - Hosts can only belong to ONE multi-host pool at a time
 */

#include "bouncer.h"

#include <usual/statlist.h>

/* Initial number of buckets (will grow as needed) */
#define INITIAL_BUCKET_COUNT 16

/* Hash table of all hosts, keyed by "hostname:port" */
static PgHost *host_hashtable = NULL;

/* Global list of all host pools for sharing detection */
static STATLIST(host_pool_list);

/*
 * Ensure the bucket array has at least 'needed' buckets.
 * Only used for multi-host pools.
 */
static bool ensure_bucket_capacity(PgHostPool *pool, int needed)
{
	int new_count;
	struct List *new_buckets;

	if (!pool->buckets)
		return true;  /* Single-host pool, no buckets */

	if (needed <= pool->bucket_count)
		return true;

	/* Grow by doubling or to needed size, whichever is larger */
	new_count = pool->bucket_count * 2;
	if (new_count < needed)
		new_count = needed;

	new_buckets = realloc(pool->buckets, new_count * sizeof(struct List));
	if (!new_buckets) {
		log_error("hostpool: out of memory for buckets");
		return false;
	}

	/* Initialize new buckets */
	for (int i = pool->bucket_count; i < new_count; i++) {
		list_init(&new_buckets[i]);
	}

	pool->buckets = new_buckets;
	pool->bucket_count = new_count;
	return true;
}

/*
 * Find or create a host entry by name and port.
 * Increments refcount on the host.
 * Hosts persist for the lifetime of pgbouncer and are reused across reloads.
 * The hash key is "hostname:port" to allow same hostname with different ports.
 */
PgHost *hostpool_get_host(const char *host_name, int port)
{
	PgHost *host;
	char key[512];

	if (!host_name)
		return NULL;

	/* Create hash key as "hostname:port" */
	snprintf(key, sizeof(key), "%s:%d", host_name, port);

	/* Look up existing host by key */
	HASH_FIND_STR(host_hashtable, key, host);
	if (host) {
		host->refcount++;
		return host;
	}

	/* Create new host */
	host = calloc(1, sizeof(PgHost));
	if (!host) {
		log_error("hostpool_get_host: out of memory");
		return NULL;
	}

	host->name = strdup(host_name);
	host->key = strdup(key);
	if (!host->name || !host->key) {
		hostpool_free_host(host);
		log_error("hostpool_get_host: out of memory");
		return NULL;
	}

	host->port = port;
	host->refcount = 1;
	list_init(&host->bucket_node);

	/* Add to hash table */
	HASH_ADD_KEYPTR(hh, host_hashtable, host->key, strlen(host->key), host);

	return host;
}

/*
 * Decrement host refcount. When refcount reaches 0, host is freed.
 */
void hostpool_unref_host(PgHost *host)
{
	if (!host)
		return;

	host->refcount--;
	if (host->refcount <= 0) {
		hostpool_free_host(host);
	}
}

void hostpool_unref_hosts(PgHost **hosts, int count)
{
	if (!hosts || count <= 0)
		return;
	for(int i = 0; i < count; i++) {
		hostpool_unref_host(hosts[i]);
	}
}

void hostpool_ref_host(PgHost *host)
{
	if (host)
		host->refcount++;
}

void hostpool_ref_hosts(PgHost **hosts, int count)
{
	if (!hosts || count <= 0)
		return;
	for (int i = 0; i < count; i++) {
		hostpool_ref_host(hosts[i]);
	}
}
void hostpool_free_host(PgHost *host)
{
	if (!host)
		return;

	/* Only remove from hash table if it was added */
	if (host->hh.tbl)
		HASH_DEL(host_hashtable, host);

	free(host->name);
	free(host->key);
	free(host);
}

/*
 * Free a host pool structure.
 * Does not free hosts (they are reference-counted separately).
 * Caller must clear host->host_pool pointers before freeing hosts.
 */
void hostpool_free_pool(PgHostPool *pool)
{
	if (!pool)
		return;

	/* Remove from global list if it was added */
	if (pool->head.next && pool->head.prev &&
	    pool->head.next != &pool->head) {
		statlist_remove(&host_pool_list, &pool->head);
	}

	free(pool->hosts);
	free(pool->buckets);
	free(pool);
}

/*
 * Increment reference count on a host pool.
 */
void hostpool_ref(PgHostPool *pool)
{
	if (pool) {
		pool->refcount++;
	}
}

/*
 * Release reference to a host pool. Decrements refcount and frees
 * the pool structure when refcount reaches 0.
 * Also decrements refcount on all hosts in the pool.
 */
void hostpool_unref_pool(PgHostPool *pool)
{
	if (!pool)
		return;

	pool->refcount--;
	if (pool->refcount <= 0) {
		/* Remove hosts from buckets and clear host_pool pointers */
		for (int i = 0; i < pool->count; i++) {
			PgHost *host = pool->hosts[i];
			if (host && host->host_pool == pool) {
				/* Remove from bucket list */
				if (pool->buckets)
					list_del(&host->bucket_node);
				host->host_pool = NULL;
			}
		}
		hostpool_unref_hosts(pool->hosts, pool->count);
		hostpool_free_pool(pool);
	}
}

/*
 * Create a new host pool.
 * For single-host pools (host_count == 1): no buckets allocated.
 * For multi-host pools: buckets allocated for least-connections tracking.
 * The pool starts with refcount=1.
 */
PgHostPool *hostpool_create_host_pool(int host_count, PgHost **hosts)
{
	PgHostPool *pool = calloc(1, sizeof(PgHostPool));
	if (!pool) {
		log_error("hostpool_create_host_pool: out of memory");
		return NULL;
	}
	if(hosts == NULL) {
		hosts = calloc(host_count, sizeof(PgHost *));
		if (!hosts) {
			log_error("hostpool_create_host_pool: out of memory");
			hostpool_free_pool(pool);
			return NULL;
		}
	} else {
		/* Ref all provided hosts */
		hostpool_ref_hosts(hosts, host_count);
	}
	pool->hosts = hosts;

	/* Only allocate buckets for multi-host pools */
	if (host_count > 1) {
		pool->buckets = calloc(INITIAL_BUCKET_COUNT, sizeof(struct List));
		if (!pool->buckets) {
			log_error("hostpool_create_host_pool: out of memory");
			free(pool->hosts);
			free(pool);
			return NULL;
		}

		for (int i = 0; i < INITIAL_BUCKET_COUNT; i++) {
			list_init(&pool->buckets[i]);
		}
		pool->bucket_count = INITIAL_BUCKET_COUNT;
	}

	list_init(&pool->head);
	pool->count = host_count;
	pool->min_active = 0;
	pool->refcount = 1;

	/* Link hosts to pool (multi-host only) */
	if (host_count > 1) {
		for (int i = 0; i < host_count; i++) {
			PgHost *host = hosts[i];
			host->index = i;
			host->host_pool = pool;
			list_init(&host->bucket_node);
			list_append(&pool->buckets[0], &host->bucket_node);
		}
	}

	/* Add to global list */
	statlist_append(&host_pool_list, &pool->head);

	return pool;
}

/**
 * Get the sum of the refcounts of all hosts.
 * Complexity: O(n)
 * Space complexity: O(1)
 */
int hostpool_host_ref_sum(PgHost **hosts, int count)
{
	int sum = 0;
	if (!hosts || count <= 0)
		return 0;
	for (int i = 0; i < count; i++) {
		sum += hosts[i]->refcount;
	}
	return sum;
}

/**
 * Check if all hosts are distinct taking advantage of reference counting.
 * Returns true if all hosts are distinct, false otherwise.
 * Complexity: O(n)
 * Space complexity: O(1)
 */
bool hostpool_all_distinct(PgHost **hosts, int count)
{
	int s1, s2;
	hostpool_ref_hosts(hosts, count);
	s1 = hostpool_host_ref_sum(hosts, count);
	hostpool_unref_hosts(hosts, count);
	s2 = hostpool_host_ref_sum(hosts, count);
	return s1 - s2 == count;
}

/** Find or create a host pool for the given hosts.
 *
 * For multi-host (count > 1):
 *   - If hosts are in conflicting multi-host pools: logs error, returns NULL
 *   - If hosts are all in the same multi-host pool: returns that pool (ref'd)
 *   - If hosts partially overlap with existing pool: logs error, returns NULL
 *
 * For any count:
 *   - If an exact matching pool exists: returns that pool (ref'd)
 *   - Otherwise: creates new pool with hosts, returns it (ref'd)
 *
 * On success, caller owns one reference to the returned pool.
 * On failure (NULL), caller still owns refs to hosts array.
 */
static PgHostPool *hostpool_get_pool(PgHost **hosts, int count)
{
	PgHostPool *pool = NULL;

	if (!hostpool_all_distinct(hosts, count)) {
		log_error("hostpool_get_pool: duplicate hosts in configuration");
		return NULL;
	}

	/* For multi-host pools, check if hosts are already in a multi-host pool */
	if (count > 1) {
		for (int i = 0; i < count; i++) {
			PgHost *host = hosts[i];

			if (host->host_pool && host->host_pool->count > 1) {
				if (pool == NULL) {
					pool = host->host_pool;
				} else if (pool != host->host_pool) {
					/* Host appears in distinct multi-host pools - error */
					log_error("hostpool_get_pool: host in conflicting multi-host pools");
					return NULL;
				}
			}
		}

		if (pool) {
			/* Check if existing pool has same hosts */
			if (pool->count != count) {
				log_error("hostpool_get_pool: host count mismatch with existing pool");
				return NULL;
			}
			hostpool_ref(pool);
			return pool;
		}
	}

	/* Create new pool (single-host pools don't share or check existing multi-host pools) */
	return hostpool_create_host_pool(count, hosts);
}

/*
 * Parse db->host and db->port_str, both of which are possibly comma-separated, and populate db->host_pool.
 * Returns true on success, false on failure.
 */
bool parse_database_hosts(PgDatabase *db)
{
	char *host_copy, *port_copy, *p, *host_name, *port_str;
	int host_count = 1;
	int port_count = 1;
	int *ports = NULL;
	int i;
	PgHost **hosts = NULL;
	PgHostPool *pool;

	/* Release old host_pool reference */
	if (db->host_pool) {
		hostpool_unref_pool(db->host_pool);
		db->host_pool = NULL;
	}

	if (!db->host)
		return true;  /* No hosts is valid (unix socket) */

	/* Count hosts */
	for (p = db->host; *p; p++)
		if (*p == ',')
			host_count++;

	/* Count ports */
	if (db->port_str) {
		for (p = db->port_str; *p; p++)
			if (*p == ',')
				port_count++;
	}

	/* Validate port count: must be 1 or match host count */
	if (port_count != 1 && port_count != host_count) {
		log_error("parse_database_hosts: port count (%d) must be 1 or match host count (%d)",
			  port_count, host_count);
		return false;
	}

	/* Parse ports into array */
	ports = calloc(host_count, sizeof(int));
	if (!ports) {
		log_error("parse_database_hosts: out of memory");
		return false;
	}

	if (db->port_str) {
		port_copy = strdup(db->port_str);
		if (!port_copy) {
			free(ports);
			log_error("parse_database_hosts: out of memory");
			return false;
		}

		i = 0;
		for (port_str = strtok(port_copy, ","); port_str && i < host_count; port_str = strtok(NULL, ",")) {
			ports[i] = atoi(port_str);
			if (ports[i] == 0) {
				log_error("parse_database_hosts: invalid port: %s", port_str);
				free(port_copy);
				free(ports);
				return false;
			}
			i++;
		}
		free(port_copy);

		/* If only one port, replicate for all hosts */
		if (port_count == 1) {
			for (i = 1; i < host_count; i++)
				ports[i] = ports[0];
		}
	} else {
		/* No port string, use default */
		for (i = 0; i < host_count; i++)
			ports[i] = db->port;
	}

	/* Get all host entries (increments refcount on each) */
	hosts = calloc(host_count, sizeof(PgHost *));
	if (!hosts) {
		log_error("parse_database_hosts: out of memory");
		free(ports);
		return false;
	}

	host_copy = strdup(db->host);
	if (!host_copy) {
		log_error("parse_database_hosts: out of memory");
		free(hosts);
		free(ports);
		return false;
	}

	i = 0;
	for (host_name = strtok(host_copy, ","); host_name; host_name = strtok(NULL, ",")) {
		PgHost *h = hostpool_get_host(host_name, ports[i]);
		if (!h) {
			/* Release already-acquired hosts */
			hostpool_unref_hosts(hosts, i);
			free(host_copy);
			free(hosts);
			free(ports);
			return false;
		}
		hosts[i] = h;
		i++;
	}
	free(host_copy);
	free(ports);

	/* Find existing pool or create new one */
	pool = hostpool_get_pool(hosts, host_count);
	if (!pool) {
		hostpool_unref_hosts(hosts, host_count);
		free(hosts);
		return false;
	}

	if (pool->hosts != hosts) {
		/* Got existing pool - release our refs and free temp array */
		hostpool_unref_hosts(hosts, host_count);
		free(hosts);
	}
	/* If pool->hosts == hosts, pool took ownership of array and refs */

	db->host_pool = pool;
	return true;
}

/*
 * Increment active connection count for a host.
 * For multi-host pools, moves host between buckets.
 * For single-host pools, just increments the count.
 */
void hostpool_increment_active(PgHost *host)
{
	PgHostPool *pool;
	int old_count, new_count;

	if (!host)
		return;

	pool = host->host_pool;
	old_count = host->active_count;
	new_count = old_count + 1;

	host->active_count = new_count;

	/* Single-host pool or no pool: no bucket tracking */
	if (!pool || !pool->buckets)
		return;

	/* Ensure we have enough buckets */
	if (!ensure_bucket_capacity(pool, new_count + 1))
		return;

	/* Remove from old bucket */
	list_del(&host->bucket_node);

	/* Add to new bucket */
	list_append(&pool->buckets[new_count], &host->bucket_node);

	/* Update min_active if the old bucket is now empty and was the minimum */
	if (old_count == pool->min_active && list_empty(&pool->buckets[old_count])) {
		pool->min_active = new_count;
	}
}

/*
 * Decrement active connection count for a host.
 * For multi-host pools, moves host between buckets.
 * For single-host pools, just decrements the count.
 */
void hostpool_decrement_active(PgHost *host)
{
	PgHostPool *pool;
	int old_count, new_count;

	if (!host)
		return;

	pool = host->host_pool;
	old_count = host->active_count;

	if (old_count <= 0) {
		log_warning("hostpool_decrement_active: active_count already 0");
		return;
	}

	new_count = old_count - 1;
	host->active_count = new_count;

	/* Single-host pool or no pool: no bucket tracking */
	if (!pool || !pool->buckets)
		return;

	/* Remove from old bucket */
	list_del(&host->bucket_node);

	/* Add to new bucket */
	list_append(&pool->buckets[new_count], &host->bucket_node);

	/* Update min_active if the new bucket is lower */
	if (new_count < pool->min_active) {
		pool->min_active = new_count;
	}
}

/*
 * Get first usable idle socket from an idle_server_by_host list (linked via host_head).
 * Skips and disconnects servers that are obsolete, dirty, or in unexpected state.
 */
static inline PgSocket *get_host_idle_server(struct StatList *slist, PgPool *conn_pool)
{
	PgSocket *server;

	while (!statlist_empty(slist)) {
		server = container_of(slist->head.next, PgSocket, host_head);

		// fail in debug
		Assert(server->state == SV_IDLE);
		Assert(server->pool == conn_pool);
		if (server->state != SV_IDLE || server->pool != conn_pool) {
			log_warning("get_host_idle_server: unexpected server state=%d pool=%p (expected pool=%p)",
				    server->state, server->pool, conn_pool);
			/* Remove from this list first to avoid infinite loop in production, then disconnect */
			statlist_remove(slist, &server->host_head);
			disconnect_server(server, true, "server in wrong state or pool");
			continue;
		}

		if (server->close_needed) {
			disconnect_server(server, true, "obsolete connection");
			continue;
		}
		if (!server->ready) {
			disconnect_server(server, true, "idle server got dirty");
			continue;
		}
		return server;
	}
	return NULL;
}

/*
 * Get an idle server from the host pool, preferring hosts with fewer active connections.
 * Uses pool->idle_server_by_host[host->index] for O(1) lookup per host.
 * Iterates through buckets starting from min_active.
 * Returns NULL if no suitable server found.
 */
PgSocket *hostpool_get_idle_server(PgHostPool *host_pool, PgPool *conn_pool)
{
	PgHost *host;
	struct List *el, *tmp;
	PgSocket *server;
	struct StatList *idle_list;
	int n_attempts = 0;

	if (!host_pool || !host_pool->buckets || !conn_pool->idle_server_by_host)
		return NULL;

	for (int i = host_pool->min_active; i < host_pool->bucket_count && n_attempts < host_pool->count; i++) {
		list_for_each_safe(el, &host_pool->buckets[i], tmp) {
			host = container_of(el, PgHost, bucket_node);
			idle_list = &conn_pool->idle_server_by_host[host->index];
			server = get_host_idle_server(idle_list, conn_pool);
			if (server)
				return server;
			n_attempts++;
		}
	}
	return NULL;
}