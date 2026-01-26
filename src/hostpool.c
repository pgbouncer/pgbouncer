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

#include "bouncer.h"

#include <usual/statlist.h>

/* Hash table of all hosts, keyed by "hostname:port" */
static PgHost *host_hashtable = NULL;

/*
 * Find or create a host entry by name and port.
 * Hosts persist for the lifetime of pgbouncer and are reused across reloads.
 * The hash key is "hostname:port" to allow same hostname with different ports.
 */
PgHost *pg_create_host(const char *host_name, int port)
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
		log_error("pg_create_host: out of memory");
		return NULL;
	}

	host->name = strdup(host_name);
	host->key = strdup(key);
	if (!host->name || !host->key) {
		free(host->name);
		free(host->key);
		free(host);
		log_error("pg_create_host: out of memory");
		return NULL;
	}

	host->port = port;
	statlist_init(&host->idle_server_list, "host_idle_server_list");

	/* Add to hash table */
	HASH_ADD_KEYPTR(hh, host_hashtable, host->key, strlen(host->key), host);

	return host;
}

/*
 * Parse db->host string (possibly comma-separated) and populate db->host_list.
 * Returns true on success, false on failure.
 */
bool parse_database_hosts(PgDatabase *db)
{
	char *host_copy, *port_copy, *p, *host_name, *port_str;
	int host_count = 1;
	int port_count = 1;
	int *ports = NULL;
	int i;
	PgHosts *hl;

	/* Free old host_list if any */
	if (db->host_list) {
		/* Note: PgHost objects persist, we just free the arrays */
		free(db->host_list->hosts);
		free(db->host_list->sorted);
		free(db->host_list);
		db->host_list = NULL;
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
	ports = malloc(host_count * sizeof(int));
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

	/* Allocate PgHosts structure */
	hl = malloc(sizeof(PgHosts));
	if (!hl) {
		free(ports);
		log_error("parse_database_hosts: out of memory");
		return false;
	}
	hl->hosts = NULL;
	hl->sorted = NULL;
	hl->count = 0;

	/* Allocate hosts array (original order) */
	hl->hosts = malloc(host_count * sizeof(PgHost *));
	if (!hl->hosts) {
		free(hl);
		free(ports);
		log_error("parse_database_hosts: out of memory");
		return false;
	}

	/* Allocate sorted array (same hosts, will be sorted by active_count) */
	hl->sorted = malloc(host_count * sizeof(PgHost *));
	if (!hl->sorted) {
		free(hl->hosts);
		free(hl);
		free(ports);
		log_error("parse_database_hosts: out of memory");
		return false;
	}

	/* Parse and create hosts */
	host_copy = strdup(db->host);
	if (!host_copy) {
		free(hl->sorted);
		free(hl->hosts);
		free(hl);
		free(ports);
		log_error("parse_database_hosts: out of memory");
		return false;
	}

	i = 0;
	for (host_name = strtok(host_copy, ","); host_name; host_name = strtok(NULL, ",")) {
		PgHost *h = pg_create_host(host_name, ports[i]);
		if (!h) {
			free(host_copy);
			free(hl->sorted);
			free(hl->hosts);
			free(hl);
			free(ports);
			return false;
		}
		h->index = i;
		hl->hosts[i] = h;
		hl->sorted[i] = h;  /* Initially same order as hosts */
		i++;
	}
	hl->count = i;

	free(host_copy);
	free(ports);

	db->host_list = hl;
	return true;
}

/*
 * Swap two hosts in the sorted array and update their indices.
 */
static void swap_hosts(PgHost **hosts, int i, int j)
{
	PgHost *tmp = hosts[i];
	hosts[i] = hosts[j];
	hosts[j] = tmp;
	hosts[i]->index = i;
	hosts[j]->index = j;
}

/*
 * After incrementing active_count, bubble the host right in sorted array.
 */
void hostpool_increment_active(PgDatabase *db, PgHost *host)
{
	int i;
	PgHosts *hl = db->host_list;

	host->active_count++;

	if (!hl)
		return;

	/* Bubble right in sorted array to maintain order by active_count */
	for (i = host->index + 1; i < hl->count; i++) {
		if (hl->sorted[i]->active_count > host->active_count - 1) {
			break;
		}
	}
	if (i != host->index + 1) {
		swap_hosts(hl->sorted, host->index, i - 1);
	}
}

/*
 * After decrementing active_count, bubble the host left in sorted array.
 */
void hostpool_decrement_active(PgDatabase *db, PgHost *host)
{
	int i;
	PgHosts *hl = db->host_list;

	host->active_count--;

	if (!hl)
		return;

	/* Bubble left in sorted array to maintain order by active_count */
	for (i = host->index - 1; i >= 0; i--) {
		if (hl->sorted[i]->active_count < host->active_count + 1) {
			break;
		}
	}
	if (i != host->index - 1) {
		swap_hosts(hl->sorted, host->index, i + 1);
	}
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
