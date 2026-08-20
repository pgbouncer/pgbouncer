/*
 * Config file parser.
 *
 * Copyright (c) 2007-2009 Marko Kreen, Skype Technologies OÜ
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

#include <usual/cfparser.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include <usual/ctype.h>
#include <usual/fileutil.h>
#include <usual/logging.h>
#include <usual/time.h>
#include <usual/string.h>

#define MAX_INCLUDE 10

/*
 * INI file parser.
 */

static int count_lines(const char *s, const char *end)
{
	int lineno = 1;
	for (; s < end; s++) {
		if (*s == '\n')
			lineno++;
	}
	return lineno;
}

static bool parse_ini_file_internal(const char *fn, cf_handler_f user_handler, void *arg, int inclevel)
{
	char *buf;
	char *p, *key, *val;
	int klen, vlen;
	char o1, o2;
	bool ok;

	buf = load_file(fn, NULL);
	if (buf == NULL) {
		log_error("could not load file \"%s\": %s", fn, strerror(errno));
		return false;
	}

	p = buf;
	while (*p) {
		/* space at the start of line - including empty lines */
		while (*p && isspace(*p)) p++;

		if (strncmp(p, "%include", 8) == 0 && p[8] != 0 && isblank(p[8])) {
			if (inclevel >= MAX_INCLUDE) {
				log_error("include nesting level too deep (%s:%d), stopping loading",
					  fn, count_lines(buf, p));
				goto failed;
			}
			p += 8;
			while (*p && isblank(*p)) p++;
			/* now read value */
			val = p;
			while (*p && (*p != '\n'))
				p++;
			vlen = p - val;
			/* eat space at end */
			while (vlen > 0 && isspace(val[vlen - 1]))
				vlen--;

			/*
			 * val now has the name of the file to be included.
			 * Process it recursively.
			 */
			o1 = val[vlen];
			val[vlen] = 0;
			log_debug("processing include: %s", val);
			ok = parse_ini_file_internal(val, user_handler, arg, inclevel + 1);
			val[vlen] = o1;
			if (!ok) {
				log_error("error processing include file in configuration (%s:%d), stopping loading", fn, count_lines(buf, p));
				goto failed;
			}
			log_debug("returned to processing file %s", fn);
			continue;
		}

		/* skip comment lines */
		if (*p == '#' || *p == ';') {
			while (*p && *p != '\n') p++;
			continue;
		}
		/* got new section */
		if (*p == '[') {
			key = ++p;
			while (*p && *p != ']' && *p != '\n') p++;
			if (*p != ']')
				goto syntax_error;
			o1 = *p;
			*p = 0;

			log_debug("parse_ini_file: [%s]", key);
			ok = user_handler(arg, true, key, NULL);
			if (!ok) {
				log_error("invalid section \"%s\" in configuration (%s:%d)",
					  key, fn, count_lines(buf, p));
				goto failed;
			}
			*p++ = o1;
			continue;
		}

		/* done? */
		if (*p == 0)
			break;

		/* read key val */
		if (*p && *p == '\'') {
			key = ++p;
			while (*p && *p != '\'') p++;
			if (*p != '\'') {
				goto syntax_error;
			} else {
				klen = p - key;
				if (klen <= 0)
					goto syntax_error;
				p++;
			}
		} else {
			key = p;
			while (*p && (isalnum(*p) || strchr("_.-*", *p))) p++;
			klen = p - key;
		}

		/* expect '=', skip it */
		while (*p && (*p == ' ' || *p == '\t')) p++;
		if (*p != '=') {
			goto syntax_error;
		} else {
			p++;
		}
		while (*p && (*p == ' ' || *p == '\t')) p++;

		/* now read value */
		val = p;
		while (*p && (*p != '\n'))
			p++;
		vlen = p - val;
		/* eat space at end */
		while (vlen > 0 && isspace(val[vlen - 1]))
			vlen--;

		/* skip junk */
		while (*p && isspace(*p)) p++;

		/* our buf is r/w, so take it easy */
		o1 = key[klen];
		o2 = val[vlen];
		key[klen] = 0;
		val[vlen] = 0;

		log_debug("parse_ini_file: '%s' = '%s'", key, val);

		ok = user_handler(arg, false, key, val);

		log_debug("parse_ini_file: '%s' = '%s' ok:%d", key, val, ok);

		if (!ok) {
			log_error("invalid value \"%s\" for parameter %s in configuration (%s:%d)",
				  val, key, fn, count_lines(buf, p));
		}

		/* restore data, to keep count_lines() working */
		key[klen] = o1;
		val[vlen] = o2;

		if (!ok)
			goto failed;
	}

	free(buf);
	return true;

syntax_error:
	log_error("syntax error in configuration (%s:%d), stopping loading", fn, count_lines(buf, p));
failed:
	free(buf);
	return false;
}

bool parse_ini_file(const char *fn, cf_handler_f user_handler, void *arg)
{
	return parse_ini_file_internal(fn, user_handler, arg, 0);
}

/*
 * Config framework.
 */

static void *get_dest(void *base, const struct CfKey *k)
{
	char *dst;
	if (k->flags & CF_VAL_REL) {
		/* relative address requires base */
		if (!base)
			return NULL;
		dst = (char *)base + k->key_ofs;
	} else {
		dst = (char *)k->key_ofs;
	}
	return dst;
}

static const struct CfSect *find_sect(const struct CfContext *cf, const char *name)
{
	const struct CfSect *s;
	for (s = cf->sect_list; s->sect_name; s++) {
		if (strcmp(s->sect_name, name) == 0)
			return s;
		if (strcmp(s->sect_name, "*") == 0)
			return s;
	}
	return NULL;
}

static const struct CfKey *find_key(const struct CfSect *s, const char *key)
{
	const struct CfKey *k;
	for (k = s->key_list; k->key_name; k++) {
		if (strcmp(k->key_name, key) == 0)
			return k;
	}
	return NULL;
}

const char *cf_get(const struct CfContext *cf, const char *sect, const char *key,
		   char *buf, int buflen)
{
	const struct CfSect *s;
	const struct CfKey *k;
	void *base, *p;
	struct CfValue cv;

	/* find section */
	s = find_sect(cf, sect);
	if (!s)
		return NULL;

	/* find section base */
	base = cf->base;
	if (s->base_lookup)
		base = s->base_lookup(base, sect);

	/* handle dynamic keys */
	if (s->set_key) {
		if (!s->get_key)
			return NULL;
		return s->get_key(base, key, buf, buflen);
	}

	/* get fixed key */
	k = find_key(s, key);
	if (!k || !k->op.getter)
		return NULL;
	p = get_dest(base, k);
	if (!p)
		return NULL;
	cv.key_name = k->key_name;
	cv.extra = k->op.op_extra;
	cv.value_p = p;
	cv.buf = buf;
	cv.buflen = buflen;
	return k->op.getter(&cv);
}

bool cf_set(const struct CfContext *cf, const char *sect, const char *key, const char *val)
{
	const struct CfSect *s;
	const struct CfKey *k;
	void *base, *p;
	struct CfValue cv;

	/* find section */
	s = find_sect(cf, sect);
	if (!s) {
		log_error("unknown section: %s", sect);
		return false;
	}

	/* find section base */
	base = cf->base;
	if (s->base_lookup)
		base = s->base_lookup(base, sect);

	/* handle dynamic keys */
	if (s->set_key)
		return s->set_key(base, key, val);

	/* set fixed key */
	k = find_key(s, key);
	if (!k) {
		log_error("unknown parameter: %s/%s", sect, key);
		return false;
	}
	if (!k->op.setter || (k->flags & CF_READONLY)) {
		/* silently ignore */
		return true;
	}
	if ((k->flags & CF_NO_RELOAD) && cf->loaded) {
		/* silently ignore */
		return true;
	}
	p = get_dest(base, k);
	if (!p) {
		log_error("bug - no base for relative key: %s/%s", sect, key);
		return false;
	}
	cv.key_name = k->key_name;
	cv.extra = k->op.op_extra;
	cv.value_p = p;
	cv.buf = NULL;
	cv.buflen = 0;
	return k->op.setter(&cv, val);
}

/*
 * File loader
 */

struct LoaderCtx {
	const struct CfContext *cf;
	char *cur_sect;
	void *top_base;
	bool got_main_sect;
};

static bool fill_defaults(struct LoaderCtx *ctx)
{
	const struct CfKey *k;
	const struct CfSect *s;

	s = find_sect(ctx->cf, ctx->cur_sect);
	if (!s)
		goto fail;

	if (s == ctx->cf->sect_list)
		ctx->got_main_sect = true;

	if (s->section_start) {
		if (!s->section_start(ctx->top_base, ctx->cur_sect))
			return false;
	}

	if (s->set_key)
		return true;

	for (k = s->key_list; k->key_name; k++) {
		if (!k->def_value || (k->flags & CF_READONLY))
			continue;
		if ((k->flags & CF_NO_RELOAD) && ctx->cf->loaded)
			continue;
		if (!cf_set(ctx->cf, ctx->cur_sect, k->key_name, k->def_value))
			goto fail;
	}
	return true;
fail:
	log_error("fill_defaults fail");
	return false;
}

static bool load_handler(void *arg, bool is_sect, const char *key, const char *val)
{
	struct LoaderCtx *ctx = arg;

	if (is_sect) {
		free(ctx->cur_sect);
		ctx->cur_sect = strdup(key);
		if (!ctx->cur_sect)
			return false;
		return fill_defaults(ctx);
	} else if (!ctx->cur_sect) {
		log_error("load_init_file: value without section: %s", key);
		return false;
	} else {
		return cf_set(ctx->cf, ctx->cur_sect, key, val);
	}
}

bool cf_load_file(const struct CfContext *cf, const char *fn)
{
	struct LoaderCtx ctx;
	bool ok;
	memset(&ctx, 0, sizeof(ctx));
	ctx.cf = cf;

	ok = parse_ini_file(fn, load_handler, &ctx);
	free(ctx.cur_sect);
	if (ok && !ctx.got_main_sect) {
		log_error("load_init_file: main section missing from config file");
		return false;
	}
	return ok;
}

/*
 * Various value parsers.
 */

bool cf_set_int(struct CfValue *cv, const char *value)
{
	int *ptr = cv->value_p;
	char *end;
	long val;

	errno = 0;
	val = strtol(value, &end, 0);
	if (end == value || *end != 0) {
		/* reject partial parse */
		if (!errno)
			errno = EINVAL;
		return false;
	}
	*ptr = val;
	return true;
}

bool cf_set_uint(struct CfValue *cv, const char *value)
{
	unsigned int *ptr = cv->value_p;
	char *end;
	unsigned long val;

	errno = 0;
	val = strtoul(value, &end, 0);
	if (end == value || *end != 0) {
		/* reject partial parse */
		if (!errno)
			errno = EINVAL;
		return false;
	}
	*ptr = val;
	return true;
}

bool cf_set_str(struct CfValue *cv, const char *value)
{
	char **dst_p = cv->value_p;

	char *tmp = strdup(value);
	if (!tmp) {
		log_error("cf_set_str: no mem");
		return false;
	}
	free(*dst_p);
	*dst_p = tmp;
	return true;
}

bool cf_set_filename(struct CfValue *cv, const char *value)
{
	char **dst_p = cv->value_p;
	char *tmp, *home, *p;
	int v_len, usr_len, home_len;
	struct passwd *pw;

	/* do we need to do tilde expansion */
	if (value[0] != '~')
		return cf_set_str(cv, value);

	/* find username end */
	v_len = strlen(value);
	if ((p = memchr(value, '/', v_len)) == NULL)
		usr_len = v_len - 1;
	else
		usr_len = (p - value) - 1;

	if (usr_len) {
		p = malloc(usr_len + 1);
		if (!p)
			return false;
		memcpy(p, value + 1, usr_len);
		p[usr_len] = 0;
		pw = getpwnam(p);
		free(p);
		if (!pw)
			goto fail;
		home = pw->pw_dir;
	} else {
		home = getenv("HOME");
		if (!home) {
			pw = getpwuid(getuid());
			if (!pw)
				goto fail;
			home = pw->pw_dir;
		}
	}
	if (!home)
		goto fail;

	home_len = strlen(home);
	tmp = malloc(v_len - usr_len + home_len);
	if (!tmp)
		return false;
	memcpy(tmp, home, home_len);
	memcpy(tmp + home_len, value + usr_len + 1, v_len - usr_len - 1);
	tmp[v_len - 1 - usr_len + home_len] = 0;

	log_debug("expanded '%s' -> '%s'", value, tmp);

	free(*dst_p);
	*dst_p = tmp;
	return true;
fail:
	log_error("cannot to expand filename: %s", value);
	return false;
}

/* parse float with error checking.  returns -1 if failed */
static double parse_time(const char *value)
{
	double v;
	char *endp = NULL;

	errno = 0;
	v = strtod_dot(value, &endp);
	if (errno)
		return -1;
	if (*endp || endp == value || v < 0) {
		errno = EINVAL;
		return -1;
	}
	return v;
}

bool cf_set_time_usec(struct CfValue *cv, const char *value)
{
	usec_t *ptr = cv->value_p;
	double v = parse_time(value);
	if (v < 0)
		return false;
	*ptr = (usec_t)(USEC * v);
	return true;
}

bool cf_set_time_double(struct CfValue *cv, const char *value)
{
	double *ptr = cv->value_p;
	double v = parse_time(value);
	if (v < 0)
		return false;
	*ptr = v;
	return true;
}

/*
 * Various value formatters.
 */

const char *cf_get_str(struct CfValue *cv)
{
	char **p = cv->value_p;
	return *p;
}

const char *cf_get_int(struct CfValue *cv)
{
	int *p = cv->value_p;
	snprintf(cv->buf, cv->buflen, "%d", *p);
	return cv->buf;
}

const char *cf_get_uint(struct CfValue *cv)
{
	unsigned int *p = cv->value_p;
	snprintf(cv->buf, cv->buflen, "%u", *p);
	return cv->buf;
}

const char *cf_get_time_double(struct CfValue *cv)
{
	double *p = cv->value_p;
	snprintf(cv->buf, cv->buflen, "%g", *p);
	return cv->buf;
}

const char *cf_get_time_usec(struct CfValue *cv)
{
	struct CfValue tmp = *cv;
	usec_t *p = cv->value_p;
	double d = (double)(*p) / USEC;
	tmp.value_p = &d;
	return cf_get_time_double(&tmp);
}

/*
 * str->int mapping
 */

const char *cf_get_lookup(struct CfValue *cv)
{
	int *p = cv->value_p;
	const struct CfLookup *lk = cv->extra;
	for (; lk->name; lk++) {
		if (lk->value == *p)
			return lk->name;
	}
	return "INVALID";
}

bool cf_set_lookup(struct CfValue *cv, const char *value)
{
	int *p = cv->value_p;
	const struct CfLookup *lk = cv->extra;
	for (; lk->name; lk++) {
		if (strcasecmp(lk->name, value) == 0) {
			*p = lk->value;
			return true;
		}
	}
	return false;
}
