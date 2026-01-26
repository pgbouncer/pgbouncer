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

/*
 * Host entry - tracks a single host from configuration.
 * Created via pg_create_host() and persists for the lifetime of pgbouncer.
 */
typedef struct PgHost {
	char *name;			/* hostname string */
	char *key;			/* hash key: "hostname:port" */
	int port;			/* port number for this host */
	int active_count;		/* number of active connections to this host */
	int index;			/* position in host_list->sorted array */
	struct StatList idle_server_list;	/* idle server connections to this host */
	UT_hash_handle hh;		/* makes this structure hashable by key */
} PgHost;

/*
 * Collection of hosts for a database - maintains both original order
 * (for round-robin) and sorted order (for least-connections).
 */
typedef struct PgHosts {
	PgHost **hosts;		/* array in original config order (for round-robin) */
	PgHost **sorted;	/* same hosts sorted by active_count (for least-connections) */
	int count;		/* number of hosts in arrays */
} PgHosts;

/*
 * Find or create a host entry by name and port.
 * Hosts persist for the lifetime of pgbouncer and are reused across reloads.
 */
PgHost *pg_create_host(const char *host_name, int port);

/*
 * Parse db->host string (possibly comma-separated) and populate db->host_list.
 * Also parses db->port_str if present to assign per-host ports.
 * Returns true on success, false on failure.
 */
bool parse_database_hosts(struct PgDatabase *db);

/*
 * Track active connection count changes for load balancing.
 * These maintain the sorted order of hosts by active_count.
 */
void hostpool_increment_active(struct PgDatabase *db, PgHost *host);
void hostpool_decrement_active(struct PgDatabase *db, PgHost *host);

/*
 * Find an idle server connection from a specific host for the given pool.
 * Returns NULL if no suitable server found.
 */
struct PgSocket *hostpool_get_idle_server(PgHost *host, struct PgPool *pool);
