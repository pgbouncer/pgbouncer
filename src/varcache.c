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

struct var_lookup {
	const char *name;
	enum VarCacheIdx idx;
};

static const struct var_lookup lookup [] = {
 {"client_encoding",             VClientEncoding },
 {"datestyle",                   VDateStyle },
 {"timezone",                    VTimeZone },
 {"standard_conforming_strings", VStdStr },
 {"application_name",            VAppName },
 {NULL},
};

static struct StrPool *vpool;

static inline struct PStr *get_value(VarCache *cache, const struct var_lookup *lk)
{
	return cache->var_list[lk->idx];
}

bool varcache_set(VarCache *cache, const char *key, const char *value)
{
	const struct var_lookup *lk;
	struct PStr *pstr = NULL;

	if (!vpool) {
		vpool = strpool_create();
		if (!vpool)
			return false;
	}

	for (lk = lookup; lk->name; lk++) {
		if (strcasecmp(lk->name, key) == 0)
			goto set_value;
	}
	return false;

set_value:
	/* drop old value */
	strpool_decref(cache->var_list[lk->idx]);
	cache->var_list[lk->idx] = NULL;

	/* ignore empty value */
	if (!value && !value[0])
		return false;

	/* set new value */
	pstr = strpool_get(vpool, value, strlen(value));
	if (!pstr)
		return false;
	cache->var_list[lk->idx] = pstr;
	return true;
}

static int apply_var(PktBuf *pkt, const char *key,
		     const char *cval, const char *sval)
{
	char buf[128];
	char qbuf[128];
	unsigned len;

	if (strcasecmp(cval, sval) == 0)
		return 0;

	/* if unset, ignore */
	if (!*cval)
		return 0;

	/* the string may have been taken from startup pkt */
	if (!pg_quote_literal(qbuf, cval, sizeof(qbuf)))
		return 0;

	/* add SET statement to packet */
	len = snprintf(buf, sizeof(buf), "SET %s=%s;", key, qbuf);
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
	const struct var_lookup *lk;
	int sql_ofs;
	struct PktBuf *pkt = pktbuf_temp();

	pktbuf_start_packet(pkt, 'Q');

	/* grab quory position inside pkt */
	sql_ofs = pktbuf_written(pkt);

	for (lk = lookup; lk->name; lk++) {
		sval = get_value(&server->vars, lk);
		cval = get_value(&client->vars, lk);
		if (cval)
			changes += apply_var(pkt, lk->name, cval->str, sval->str);
	}
	*changes_p = changes > 0;
	if (!changes)
		return true;

	pktbuf_put_char(pkt, 0);
	pktbuf_finish_packet(pkt);

	slog_debug(server, "varcache_apply: %s", pkt->buf + sql_ofs);
	return pktbuf_send_immidiate(pkt, server);
}

void varcache_fill_unset(VarCache *src, PgSocket *dst)
{
	struct PStr *srcval, *dstval;
	const struct var_lookup *lk;
	for (lk = lookup; lk->name; lk++) {
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
	const struct var_lookup *lk;
	for (lk = lookup; lk->name; lk++) {
		val = vars->var_list[lk->idx];
		if (val)
			pktbuf_write_ParameterStatus(pkt, lk->name, val->str);
	}
}

