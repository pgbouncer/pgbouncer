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

/* configuration parsing */
#define CF_INT		{cf_get_int, cf_set_int}
#define CF_STR		{cf_get_str, cf_set_str}
#define CF_TIME		{cf_get_time, cf_set_time}

#define CF_SECT_VARS	1	/* senction contains pre-defined key-var pairs */
#define CF_SECT_DATA	2	/* key-val pairs are data */

typedef struct ConfElem ConfElem;

/* callback for CF_SECT_DATA loading */
typedef void (*conf_data_callback_fn)(char *key, char *value);

typedef const char * (*conf_var_get_fn)(ConfElem *elem);
typedef bool (*conf_var_set_fn)(ConfElem *elem, const char *value, PgSocket *console) _MUSTCHECK;

typedef struct {
	conf_var_get_fn fn_get;
	conf_var_set_fn fn_set;
} ConfAccess;

struct ConfElem {
	const char *name;
	bool reloadable;
	ConfAccess io;
	void *dst;
	bool allocated;
};

typedef struct ConfSection {
	const char *name;
	ConfElem *elem_list;
	conf_data_callback_fn data_fn;
} ConfSection;

bool iniparser(const char *fn, ConfSection *sect_list, bool reload)  _MUSTCHECK;

const char * cf_get_int(ConfElem *elem);
bool cf_set_int(ConfElem *elem, const char *value, PgSocket *console);

const char * cf_get_time(ConfElem *elem);
bool cf_set_time(ConfElem *elem, const char *value, PgSocket *console);

const char *cf_get_str(ConfElem *elem);
bool cf_set_str(ConfElem *elem, const char *value, PgSocket *console);

const char *conf_to_text(ConfElem *elem);
bool set_config_param(ConfElem *elem_list, const char *key, const char *val, bool reload, PgSocket *console) /* _MUSTCHECK */;

/* connstring parsing */
void parse_database(char *name, char *connstr);

/* user file parsing */
bool load_auth_file(const char *fn)  /* _MUSTCHECK */;
bool loader_users_check(void)  /* _MUSTCHECK */;

