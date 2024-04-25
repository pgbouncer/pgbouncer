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

bool server_proto(SBuf *sbuf, SBufEvent evtype, struct MBuf *pkt)  _MUSTCHECK;
void kill_pool_logins(PgPool *pool, const char *sqlstate, const char *msg);
int pool_pool_mode(PgPool *pool) _MUSTCHECK;
int pool_pool_size(PgPool *pool) _MUSTCHECK;
int pool_min_pool_size(PgPool *pool) _MUSTCHECK;
int pool_server_lifetime(PgPool *pool) _MUSTCHECK;
int database_min_pool_size(PgDatabase *db) _MUSTCHECK;
int database_server_lifetime(PgDatabase *db) _MUSTCHECK;
int pool_res_pool_size(PgPool *pool) _MUSTCHECK;
int database_max_connections(PgDatabase *db) _MUSTCHECK;
int user_max_connections(PgUser *user) _MUSTCHECK;
