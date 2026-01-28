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
 * Host pool management for multi-host database configurations.
 */

#include "bouncer.h"

/*
 * Create a new PgHost with given hostname, port, and index.
 */
PgHost *hostpool_create_host(const char *hostname, int port, int index)
{
	PgHost *host;

	host = calloc(1, sizeof(PgHost));
	if (!host)
		return NULL;

	host->hostname = strdup(hostname);
	if (!host->hostname) {
		free(host);
		return NULL;
	}

	host->port = port;
	host->index = index;
	return host;
}

/*
 * Free a PgHost.
 */
void hostpool_free_host(PgHost *host)
{
	if (!host)
		return;
	free(host->hostname);
	free(host);
}

/*
 * Create a PgHostPool with given capacity.
 */
PgHostPool *hostpool_create(int count)
{
	PgHostPool *pool;

	pool = calloc(1, sizeof(PgHostPool));
	if (!pool)
		return NULL;

	pool->hosts = calloc(count, sizeof(PgHost *));
	if (!pool->hosts) {
		free(pool);
		return NULL;
	}

	pool->count = count;
	return pool;
}

/*
 * Free a PgHostPool and all its hosts.
 */
void hostpool_free(PgHostPool *pool)
{
	int i;

	if (!pool)
		return;

	for (i = 0; i < pool->count; i++) {
		hostpool_free_host(pool->hosts[i]);
	}
	free(pool->hosts);
	free(pool);
}

/*
 * Parse a comma-separated host string and create a PgHostPool.
 * Returns NULL if host is NULL, empty, or contains only one host (no commas).
 * The default_port is used for all hosts.
 */
PgHostPool *hostpool_parse(const char *host_str, int default_port)
{
	PgHostPool *pool;
	const char *p;
	int count = 0;
	int i = 0;
	char *host_copy, *token, *saveptr;

	if (!host_str || !*host_str)
		return NULL;

	/* Count commas to determine number of hosts */
	for (p = host_str; *p; p++) {
		if (*p == ',')
			count++;
	}

	/* If no commas, single host - no need for host_pool */
	if (count == 0)
		return NULL;

	count++;  /* number of hosts = commas + 1 */

	pool = hostpool_create(count);
	if (!pool)
		return NULL;

	host_copy = strdup(host_str);
	if (!host_copy) {
		hostpool_free(pool);
		return NULL;
	}

	token = strtok_r(host_copy, ",", &saveptr);
	while (token && i < count) {
		/* Skip leading whitespace */
		while (*token == ' ' || *token == '\t')
			token++;

		pool->hosts[i] = hostpool_create_host(token, default_port, i);
		if (!pool->hosts[i]) {
			free(host_copy);
			hostpool_free(pool);
			return NULL;
		}
		i++;
		token = strtok_r(NULL, ",", &saveptr);
	}

	free(host_copy);
	return pool;
}
