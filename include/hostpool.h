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

#pragma once

/*
 * PgHost - represents a single host in a multi-host configuration.
 */
struct PgHost {
	char *hostname;		/* hostname string */
	int port;		/* port number */
	int index;		/* position in host_pool->hosts array */
};

/*
 * PgHostPool - collection of hosts for a database with multiple hosts.
 */
struct PgHostPool {
	struct PgHost **hosts;	/* array of host pointers */
	int count;		/* number of hosts */
};

/* Create a host with given hostname, port, and index */
PgHost *hostpool_create_host(const char *hostname, int port, int index);

/* Free a host */
void hostpool_free_host(PgHost *host);

/* Create a host pool with given capacity */
PgHostPool *hostpool_create(int count);

/* Free a host pool and all its hosts */
void hostpool_free(PgHostPool *pool);

/* Parse comma-separated hosts into a host pool (NULL if single host) */
PgHostPool *hostpool_parse(const char *host_str, int default_port);
