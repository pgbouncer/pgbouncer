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

struct var_lookup {
	const char *name;
	int offset;
	int len;
};

static const struct var_lookup lookup [] = {
 {"client_encoding",             offsetof(VarCache, client_encoding), VAR_ENCODING_LEN },
 {"datestyle",                   offsetof(VarCache, datestyle),       VAR_DATESTYLE_LEN },
 {"timezone",                    offsetof(VarCache, timezone),        VAR_TIMEZONE_LEN },
 {"standard_conforming_strings", offsetof(VarCache, std_strings),     VAR_STDSTR_LEN },
 {NULL},
};

static inline char *get_value(VarCache *cache, const struct var_lookup *lk)
{
	return (char *)(cache) + lk->offset;
}

bool varcache_set(VarCache *cache, const char *key, const char *value)
{
	int vlen;
	char *pos;
	const struct var_lookup *lk;

	/* convert NULL to empty string */
	if (value == NULL)
		value = "";

	for (lk = lookup; lk->name; lk++) {
		if (strcasecmp(lk->name, key) != 0)
			continue;

		vlen = strlen(value);
		if (vlen >= lk->len) {
			log_warning("varcache_set overflow: %s", key);
			return false;
		}

		pos = get_value(cache, lk);
		memcpy(pos, value, vlen + 1);
		return true;
	}
	return false;
}

static bool is_std_quote(VarCache *vars)
{
	const char *val = vars->std_strings;
	return strcasecmp(val, "on") == 0;
}

static bool quote_literal(char *buf, int buflen, const char *src, bool std_quote)
{
	char *dst = buf;
	char *end = buf + buflen - 2;

	if (buflen < 3)
		return false;

	*dst++ = '\'';
	while (*src && dst < end) {
		if (*src == '\'')
			*dst++ = '\'';
		else if (*src == '\\' && !std_quote)
			*dst++ = '\\';
		*dst++ = *src++;
	}
	if (*src || dst > end)
		return false;

	*dst++ = '\'';
	*dst = 0;

	return true;
}

static int apply_var(PktBuf *pkt, const char *key,
		     const char *cval, const char *sval,
		     bool std_quote)
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
	if (!quote_literal(qbuf, sizeof(qbuf), cval, std_quote))
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
	PktBuf pkt;
	uint8_t buf[STARTUP_BUF];
	int changes = 0;
	const char *cval, *sval;
	const struct var_lookup *lk;
	uint8_t *debug_sql;
	bool std_quote = is_std_quote(&server->vars);

	pktbuf_static(&pkt, buf, sizeof(buf));
	pktbuf_start_packet(&pkt, 'Q');

	/* grab quory position inside pkt */
	debug_sql = pkt.buf + pkt.write_pos;

	for (lk = lookup; lk->name; lk++) {
		sval = get_value(&server->vars, lk);
		cval = get_value(&client->vars, lk);
		changes += apply_var(&pkt, lk->name, cval, sval, std_quote);
	}
	*changes_p = changes > 0;
	if (!changes)
		return true;

	pktbuf_put_char(&pkt, 0);
	pktbuf_finish_packet(&pkt);

	slog_debug(server, "varcache_apply: %s", debug_sql);
	return pktbuf_send_immidiate(&pkt, server);
}

void varcache_fill_unset(VarCache *src, PgSocket *dst)
{
	char *srcval, *dstval;
	const struct var_lookup *lk;
	for (lk = lookup; lk->name; lk++) {
		srcval = get_value(src, lk);
		dstval = get_value(&dst->vars, lk);
		if (!*dstval)
			memcpy(dstval, srcval, lk->len);
	}
}

void varcache_clean(VarCache *cache)
{
	cache->client_encoding[0] = 0;
	cache->datestyle[0] = 0;
	cache->timezone[0] = 0;
	cache->std_strings[0] = 0;
}

void varcache_add_params(PktBuf *pkt, VarCache *vars)
{
	char *val;
	const struct var_lookup *lk;
	for (lk = lookup; lk->name; lk++) {
		val = get_value(vars, lk);
		if (*val)
			pktbuf_write_ParameterStatus(pkt, lk->name, val);
	}
}

