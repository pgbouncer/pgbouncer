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
 */

#include "bouncer.h"

#include <usual/statlist.h>

/* Initial number of buckets (will grow as needed) */
#define INITIAL_BUCKET_COUNT 16

/* Hash table of all hosts, keyed by "hostname:port" */
static PgHost *host_hashtable = NULL;

/*
 * Ensure the bucket array has at least 'needed' buckets.
 */
static bool ensure_bucket_capacity(PgHostPool *pool, int needed)
{
	int new_count;
	struct StatList *new_buckets;

	if (needed <= pool->bucket_count)
		return true;

	/* Grow by doubling or to needed size, whichever is larger */
	new_count = pool->bucket_count * 2;
	if (new_count < needed)
		new_count = needed;

	new_buckets = realloc(pool->buckets, new_count * sizeof(struct StatList));
	if (!new_buckets) {
		log_error("hostpool: out of memory for buckets");
		return false;
	}

	/* Initialize new buckets */
	for (int i = pool->bucket_count; i < new_count; i++) {
		statlist_init(&new_buckets[i], "host_bucket");
	}

	pool->buckets = new_buckets;
	pool->bucket_count = new_count;
	return true;
}

/*
 * Find or create a host entry by name and port.
 * Hosts persist for the lifetime of pgbouncer and are reused across reloads.
 * The hash key is "hostname:port" to allow same hostname with different ports.
 */
PgHost *hostpool_create_host(const char *host_name, int port)
{
	PgHost *host;
	char key[512];

	if (!host_name)
		return NULL;

	/* Create hash key as "hostname:port" */
	snprintf(key, sizeof(key), "%s:%d", host_name, port);

	/* Look up existing host by key */
	HASH_FIND_STR(host_hashtable, key, host);
	if (host)
		return host;

	/* Create new host */
	host = calloc(1, sizeof(PgHost));
	if (!host) {
		log_error("hostpool_create_host: out of memory");
		return NULL;
	}

	host->name = strdup(host_name);
	host->key = strdup(key);
	if (!host->name || !host->key) {
		hostpool_free_host(host);
		log_error("hostpool_create_host: out of memory");
		return NULL;
	}

	host->port = port;
	list_init(&host->bucket_node);
	statlist_init(&host->idle_server_list, "host_idle_server_list");

	/* Add to hash table */
	HASH_ADD_KEYPTR(hh, host_hashtable, host->key, strlen(host->key), host);

	return host;
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
 * Free a host pool structure without freeing the hosts.
 * Use this during reload when hosts should persist.
 */
void hostpool_release_pool(PgHostPool *pool)
{
	if (pool) {
		free(pool->hosts);
		free(pool->buckets);
		free(pool);
	}
}

/*
 * Free a host pool and all its hosts.
 * Use this for complete cleanup (e.g., shutdown).
 */
void hostpool_free_host_pool(PgHostPool *pool)
{
	if (pool) {
		for (int i = 0; i < pool->count; i++) {
			hostpool_free_host(pool->hosts[i]);
		}
		hostpool_release_pool(pool);
	}
}

/*
 * Create a new host pool with initial bucket capacity.
 * Buckets will grow dynamically as needed.
 */
PgHostPool *hostpool_create_host_pool(int host_count)
{
	PgHostPool *pool = calloc(1, sizeof(PgHostPool));
	if (!pool) {
		log_error("hostpool_create_host_pool: out of memory");
		return NULL;
	}

	pool->hosts = calloc(host_count, sizeof(PgHost *));
	if (!pool->hosts) {
		log_error("hostpool_create_host_pool: out of memory");
		hostpool_release_pool(pool);
		return NULL;
	}

	pool->buckets = calloc(INITIAL_BUCKET_COUNT, sizeof(struct StatList));
	if (!pool->buckets) {
		log_error("hostpool_create_host_pool: out of memory");
		hostpool_release_pool(pool);
		return NULL;
	}

	for (int i = 0; i < INITIAL_BUCKET_COUNT; i++) {
		statlist_init(&pool->buckets[i], "host_bucket");
	}

	pool->bucket_count = INITIAL_BUCKET_COUNT;
	pool->count = 0;
	pool->min_active = 0;
	return pool;
}

/*
 * Add a host to a pool at the given index.
 * The host is placed in bucket 0 (zero active connections).
 */
bool hostpool_add_host(PgHostPool *pool, PgHost *host, int index)
{
	if (!pool || !host)
		return false;

	host->index = index;
	host->host_pool = pool;
	host->active_count = 0;
	pool->hosts[index] = host;

	/* Reinitialize bucket_node (host may be reused from hash table) */
	list_init(&host->bucket_node);

	/* Add to bucket 0 (all hosts start with 0 active connections) */
	statlist_append(&pool->buckets[0], &host->bucket_node);

	if (index >= pool->count)
		pool->count = index + 1;

	return true;
}

/*
 * Parse db->host string (possibly comma-separated) and populate db->host_pool.
 * Returns true on success, false on failure.
 */
bool parse_database_hosts(PgDatabase *db)
{
	char *host_copy, *port_copy, *p, *host_name, *port_str;
	int host_count = 1;
	int port_count = 1;
	int *ports = NULL;
	int i;
	PgHostPool *pool;

	/* Free old host_pool structure (hosts persist in global hash table) */
	if (db->host_pool) {
		hostpool_release_pool(db->host_pool);
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

	/* Create host pool */
	pool = hostpool_create_host_pool(host_count);
	if (!pool) {
		free(ports);
		return false;
	}

	/* Parse and create hosts */
	host_copy = strdup(db->host);
	if (!host_copy) {
		log_error("parse_database_hosts: out of memory");
		hostpool_release_pool(pool);
		free(ports);
		return false;
	}

	i = 0;
	for (host_name = strtok(host_copy, ","); host_name; host_name = strtok(NULL, ",")) {
		PgHost *h = hostpool_create_host(host_name, ports[i]);
		if (!h) {
			free(host_copy);
			hostpool_release_pool(pool);
			free(ports);
			return false;
		}
		hostpool_add_host(pool, h, i);
		i++;
	}

	free(host_copy);
	free(ports);

	db->host_pool = pool;
	return true;
}

/*
 * Increment active connection count for a host.
 * Moves host from bucket N to bucket N+1.
 */
void hostpool_increment_active(PgHost *host)
{
	PgHostPool *pool = host->host_pool;
	int old_count = host->active_count;
	int new_count = old_count + 1;

	host->active_count = new_count;

	if (!pool)
		return;

	/* Ensure we have enough buckets */
	if (!ensure_bucket_capacity(pool, new_count + 1))
		return;

	/* Remove from old bucket */
	statlist_remove(&pool->buckets[old_count], &host->bucket_node);

	/* Add to new bucket */
	statlist_append(&pool->buckets[new_count], &host->bucket_node);

	/* Update min_active if the old bucket is now empty and was the minimum */
	if (old_count == pool->min_active && statlist_empty(&pool->buckets[old_count])) {
		pool->min_active = new_count;
	}
}

/*
 * Decrement active connection count for a host.
 * Moves host from bucket N to bucket N-1.
 */
void hostpool_decrement_active(PgHost *host)
{
	PgHostPool *pool = host->host_pool;
	int old_count = host->active_count;
	int new_count;

	if (old_count <= 0) {
		log_warning("hostpool_decrement_active: active_count already 0");
		return;
	}

	new_count = old_count - 1;
	host->active_count = new_count;

	if (!pool)
		return;

	/* Remove from old bucket */
	statlist_remove(&pool->buckets[old_count], &host->bucket_node);

	/* Add to new bucket */
	statlist_append(&pool->buckets[new_count], &host->bucket_node);

	/* Update min_active if the new bucket is lower */
	if (new_count < pool->min_active) {
		pool->min_active = new_count;
	}
}

/*
 * Get the host with minimum active connections.
 * Returns the first host from the min_active bucket.
 */
PgHost *hostpool_get_least_active_host(PgHostPool *pool)
{
	struct List *el;

	if (!pool || pool->count == 0)
		return NULL;

	/* Find first non-empty bucket starting from min_active */
	while (pool->min_active < pool->bucket_count) {
		if (!statlist_empty(&pool->buckets[pool->min_active])) {
			el = statlist_first(&pool->buckets[pool->min_active]);
			return container_of(el, PgHost, bucket_node);
		}
		pool->min_active++;
	}

	return NULL;
}

/*
 * Find an idle server from the specified host that belongs to the given pool.
 * Returns NULL if no suitable server found.
 */
PgSocket *hostpool_get_idle_server(PgHost *host, PgPool *pool)
{
	struct List *el, *tmp;
	PgSocket *server;

	if (!host)
		return NULL;

	statlist_for_each_safe(el, &host->idle_server_list, tmp) {
		server = container_of(el, PgSocket, host_head);
		if (server->pool != pool)
			continue;
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
