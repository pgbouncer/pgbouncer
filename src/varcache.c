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
#include "common/uthash_lowercase.h"

static int num_var_cached = 0;

struct var_lookup {
	const char *name;		/* key (string is WITHIN the structure) */
	int idx;
	UT_hash_handle hh;		/* makes this structure hashable */
};

static struct var_lookup *lookup_map;

static struct StrPool *vpool;

static inline struct PStr *get_value(VarCache *cache, const struct var_lookup *lk)
{
	return cache->var_list[lk->idx];
}

static bool sl_add(void *arg, const char *s)
{
	return strlist_append(arg, s);
}

int get_num_var_cached(void)
{
	return num_var_cached;
}

static void init_var_lookup_from_config(const char *cf_track_extra_parameters, int *num_vars)
{
	char *var_name = NULL;
	struct var_lookup *lookup = NULL;
	struct StrList *sl = strlist_new(NULL);

	if (!parse_word_list(cf_track_extra_parameters, sl_add, sl))
		die("failed to parse track_extra_parameters in config %s", cf_track_extra_parameters);

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

		lookup->idx = (*num_vars)++;
		HASH_ADD_KEYPTR(hh, lookup_map, lookup->name, strlen(lookup->name), lookup);

		free(var_name);
	}

	strlist_free(sl);
}

void init_var_lookup(const char *cf_track_extra_parameters)
{
	const char *names[] = { "DateStyle", "client_encoding", "TimeZone", "standard_conforming_strings", "application_name", "in_hot_standby", "default_transaction_read_only", NULL };
	int idx = 0;

	struct var_lookup *lookup = NULL;

	/* Always add the static list of names for compatibility */
	for (; names[idx]; idx++) {
		lookup = (struct var_lookup *)malloc(sizeof *lookup);
		lookup->name = names[idx];
		lookup->idx = idx;
		HASH_ADD_KEYPTR(hh, lookup_map, lookup->name, strlen(lookup->name), lookup);
	}

	init_var_lookup_from_config(cf_track_extra_parameters, &idx);

	num_var_cached = idx;
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

static bool variable_is_guc_list_quote(const char *key)
{
	if (strcasecmp("search_path", key) == 0)
		return true;

	return false;
}

static int apply_var(PktBuf *pkt, const char *key,
		     const struct PStr *cval,
		     const struct PStr *sval)
{
	char buf[300];
	char qbuf[128];
	unsigned len;
	const char *tmp;

	/* if unset, skip */
	if (!cval || !sval)
		return 0;

	/* if equal, skip */
	if (cval == sval)
		return 0;

	/* ignore case difference */
	if (strcasecmp(cval->str, sval->str) == 0)
		return 0;

	/* parameters that are marked GUC_LIST_QUOTE are returned already fully quoted
	 * re-quoting them using pg_quote_literal will result in malformed values. */
	if (variable_is_guc_list_quote(key)) {
		/* zero length elements of the form "" should be specially handled.*/
		if (strcmp(cval->str, "\"\"") == 0) {
			tmp = "''";
		} else {
			tmp = cval->str;
		}
	} else if (pg_quote_literal(qbuf, cval->str, sizeof(qbuf))) {
		tmp = qbuf;
	} else {
		return 0;
	}

	/* add SET statement to packet */
	len = snprintf(buf, sizeof(buf), "SET %s=%s;", key, tmp);

	if (len < sizeof(buf)) {
		pktbuf_put_bytes(pkt, buf, len);
	} else {
		char *buf2 = malloc(sizeof(char)*len);

		if (!buf2)
			die("failed to allocate memory in apply_var");

		snprintf(buf2, len, "SET %s=%s;", key, tmp);
		pktbuf_put_bytes(pkt, buf2, len);

		free(buf2);
	}

	return 1;
}

bool varcache_apply(PgSocket *server, PgSocket *client, bool *changes_p)
{
	int changes = 0;
	struct PStr *cval, *sval;
	const struct var_lookup *lk, *tmp;
	int sql_ofs;
	struct PktBuf *pkt = pktbuf_temp();

	pktbuf_start_packet(pkt, PqMsg_Query);

	/* grab query position inside pkt */
	sql_ofs = pktbuf_written(pkt);

	HASH_ITER(hh, lookup_map, lk, tmp) {
		sval = get_value(&server->vars, lk);
		cval = get_value(&client->vars, lk);
		if (lk->name && !strcmpeq(lk->name, "in_hot_standby")) {
			changes += apply_var(pkt, lk->name, cval, sval);
		}
	}

	*changes_p = changes > 0;
	if (!changes)
		return true;

	pktbuf_put_char(pkt, 0);
	pktbuf_finish_packet(pkt);

	slog_debug(server, "varcache_apply: %s", pkt->buf + sql_ofs);
	return pktbuf_send_immediate(pkt, server);
}

void varcache_set_canonical(PgSocket *server, PgSocket *client)
{
	struct PStr *server_val, *client_val;
	const struct var_lookup *lk, *tmp;

	HASH_ITER(hh, lookup_map, lk, tmp) {
		server_val = server->vars.var_list[lk->idx];
		client_val = client->vars.var_list[lk->idx];
		if (client_val && server_val && client_val != server_val) {
			slog_debug(client, "varcache_set_canonical: setting %s to its canonical version %s -> %s",
				   lk->name, client_val->str, server_val->str);
			strpool_incref(server_val);
			strpool_decref(client_val);
			client->vars.var_list[lk->idx] = server_val;
		}
	}
}

void varcache_apply_startup(PktBuf *pkt, PgSocket *client)
{
	const struct var_lookup *lk, *tmp;

	HASH_ITER(hh, lookup_map, lk, tmp) {
		struct PStr *val = get_value(&client->vars, lk);
		if (!val)
			continue;
		if (strcmp(lk->name, "in_hot_standby") == 0 || strcmp(lk->name, "default_transaction_read_only") == 0)
			continue;

		slog_debug(client, "varcache_apply_startup: %s=%s", lk->name, val->str);
		pktbuf_put_string(pkt, lk->name);
		pktbuf_put_string(pkt, val->str);
	}
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
	for (int i = 0; i < num_var_cached; i++) {
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
