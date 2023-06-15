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
 * Operations with server config parameters.
 */

#include "bouncer.h"

#include <usual/pgutil.h>
#include <usual/string.h>
#include "uthash.h"

struct var_lookup {
	const char *name;             /* key (string is WITHIN the structure) */
	int idx;
	UT_hash_handle hh;         /* makes this structure hashable */
};

static struct var_lookup* lookup_map;

static struct StrPool *vpool;

static inline struct PStr *get_value(VarCache *cache, const struct var_lookup *lk)
{
	return cache->var_list[lk->idx];
}

static bool sl_add(void *arg, const char *s)
{
	return strlist_append(arg, s);
}

static void init_var_lookup_from_config(const char *cf_track_startup_parameters, int idx)
{

	char *var_name = NULL;
	struct var_lookup *lookup = NULL;
	struct StrList *sl = strlist_new(NULL);

	if (!parse_word_list(cf_track_startup_parameters, sl_add, sl))
		die("failed to parse track_startup_parameters in config %s", cf_track_startup_parameters);

	while (!strlist_empty(sl)) {
		var_name = strlist_pop(sl);

		if (!var_name)
			continue;

		HASH_FIND_STR(lookup_map, var_name, lookup);

		/* If the var name is already on the hash map, do not update its idx */
		if (lookup != NULL)
			continue;

		lookup = (struct var_lookup *)malloc(sizeof *lookup);
		lookup->name = strdup(var_name);

		lookup->idx = idx++;
		HASH_ADD_KEYPTR(hh, lookup_map, lookup->name, strlen(lookup->name), lookup);
	}

	strlist_free(sl);

	if (idx > MAX_NUM_CACHE_VARS)
		die("Recompile PgBouncer increasing MAX_NUM_CACHE_VARS value to %d", idx);
}

void init_var_lookup(const char *cf_track_startup_parameters)
{
	const char *names[] = { "client_encoding", "DateStyle",  "TimeZone", "standard_conforming_strings", "application_name", NULL };
	int idx = 0;

	struct var_lookup *lookup = NULL;

	/* Always add the static list of names for compatibility */
	for (; names[idx]; idx++) {
		lookup = (struct var_lookup *)malloc(sizeof *lookup);
		lookup->name = names[idx];
		lookup->idx = idx;
		HASH_ADD_KEYPTR(hh, lookup_map, lookup->name, strlen(lookup->name), lookup);
	}

	init_var_lookup_from_config(cf_track_startup_parameters, idx);

}

bool varcache_set(VarCache *cache, const char *key, const char *value)
{
	const struct var_lookup *lk = NULL;
	struct PStr *pstr = NULL;

	if (!vpool) {
		vpool = strpool_create(USUAL_ALLOC);
		if (!vpool)
			return false;
	}

	HASH_FIND_STR(lookup_map, key, lk);

	if (lk == NULL)
		return false;

	/* drop old value */
	strpool_decref(cache->var_list[lk->idx]);
	cache->var_list[lk->idx] = NULL;

	/* NULL value? */
	if (!value)
		return false;

	/* set new value */
	pstr = strpool_get(vpool, value, strlen(value));
	if (!pstr)
		return false;
	cache->var_list[lk->idx] = pstr;
	return true;
}

bool varcache_set_quoted(PgSocket *client, const char *key, const char *value)
{
	char qbuf[400];

	if (!pg_quote_literal(qbuf, value, sizeof(qbuf))) {
		slog_warning(client, "could not quote parameter: %s=%s", key, value);
		return false;
	}

	if (varcache_set(&client->vars, key, qbuf)) {
		slog_debug(client, "got var: %s=%s", key, qbuf);
		return true;
	}

	return false;
}

static int apply_var(PktBuf *pkt, const char *key,
		     const struct PStr *cval,
		     const struct PStr *sval)
{
	char buf[128];
	unsigned len;

	/* if unset, skip */
	if (!cval || !sval || !*cval->str)
		return 0;

	/* if equal, skip */
	if (cval == sval)
		return 0;

	/* ignore case difference */
	if (strcasecmp(cval->str, sval->str) == 0)
		return 0;

	/* add SET statement to packet */
	len = snprintf(buf, sizeof(buf), "SET %s=%s;", key, cval->str);
	if (len < sizeof(buf)) {
		pktbuf_put_bytes(pkt, buf, len);
		return 1;
	} else {
		log_warning("got too long value, skipping");
		return 0;
	}
}

bool varcache_apply(PgSocket *server, PgSocket *client, bool *changes_p)
{
	int changes = 0;
	struct PStr *cval, *sval;
	const struct var_lookup *lk, *tmp;
	int sql_ofs;
	struct PktBuf *pkt = pktbuf_temp();

	pktbuf_start_packet(pkt, 'Q');

	/* grab query position inside pkt */
	sql_ofs = pktbuf_written(pkt);

	HASH_ITER(hh, lookup_map, lk, tmp) {

		sval = get_value(&server->vars, lk);
		cval = get_value(&client->vars, lk);
		changes += apply_var(pkt, lk->name, cval, sval);
	}

	*changes_p = changes > 0;
	if (!changes)
		return true;

	pktbuf_put_char(pkt, 0);
	pktbuf_finish_packet(pkt);

	slog_debug(server, "varcache_apply: %s", pkt->buf + sql_ofs);
	return pktbuf_send_immediate(pkt, server);
}

void varcache_fill_unset(VarCache *src, PgSocket *dst)
{
	struct PStr *srcval, *dstval;
	const struct var_lookup *lk, *tmp;

	HASH_ITER(hh, lookup_map, lk, tmp) {
		srcval = src->var_list[lk->idx];
		dstval = dst->vars.var_list[lk->idx];
		if (!dstval) {
			strpool_incref(srcval);
			dst->vars.var_list[lk->idx] = srcval;
		}
	}
}

void varcache_clean(VarCache *cache)
{
	int i;
	for (i = 0; i < NumVars; i++) {
		strpool_decref(cache->var_list[i]);
		cache->var_list[i] = NULL;
	}
}

void varcache_add_params(PktBuf *pkt, VarCache *vars)
{
	struct PStr *val;
	const struct var_lookup *lk, *tmp;

	HASH_ITER(hh, lookup_map, lk, tmp) {
		val = vars->var_list[lk->idx];
		if (val)
			pktbuf_write_ParameterStatus(pkt, lk->name, val->str);
	}
}

void varcache_deinit(void)
{
	strpool_free(vpool);
	vpool = NULL;
}
