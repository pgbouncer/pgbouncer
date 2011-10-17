/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2010  Marko Kreen, Skype Technologies OÜ
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

struct DNSContext;
struct DNSToken;

typedef void (*adns_callback_f)(void *arg, const struct sockaddr *sa, int salen);

struct DNSContext *adns_create_context(void);
void adns_reload(struct DNSContext *ctx);
void adns_free_context(struct DNSContext *ctx);

struct DNSToken *adns_resolve(struct DNSContext *ctx, const char *name, adns_callback_f cb_func, void *arg);

void adns_cancel(struct DNSContext *ctx, struct DNSToken *tk);

const char *adns_get_backend(void);

void adns_zone_cache_maint(struct DNSContext *ctx);

