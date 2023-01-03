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
 * Config and auth file reading.
 */

#include "bouncer.h"

#include <usual/fileutil.h>

/*
 * ConnString parsing
 */

/* just skip whitespace */
static char *cstr_skip_ws(char *p)
{
	while (*p && *p == ' ')
		p++;
	return p;
}

/* parse parameter name before '=' */
static char *cstr_get_key(char *p, char **dst_p)
{
	char *end;
	p = cstr_skip_ws(p);
	*dst_p = p;
	while (*p && *p != '=' && *p != ' ')
		p++;
	end = p;
	p = cstr_skip_ws(p);
	/* fail if no '=' or empty name */
	if (*p != '=' || *dst_p == end)
		return NULL;
	*end = 0;
	return p + 1;
}

/* unquote the quoted value after first quote */
static char *cstr_unquote_value(char *p)
{
	char *s = p;
	while (1) {
		if (!*p)
			return NULL;
		if (p[0] == '\'') {
			if (p[1] == '\'')
				p++;
			else
				break;
		}
		*s++ = *p++;
	}
	/* terminate actual value */
	*s = 0;
	/* return position after quote */
	return p + 1;
}

/* parse value, possibly quoted */
static char *cstr_get_value(char *p, char **dst_p)
{
	p = cstr_skip_ws(p);
	if (*p == '\'') {
		*dst_p = ++p;
		p = cstr_unquote_value(p);
		if (!p)
			return NULL;
	} else {
		*dst_p = p;
		while (*p && *p != ' ')
			p++;
	}
	if (*p) {
		/* if not EOL, cut value */
		*p = 0;
		p++;
	}
	/* disallow empty values */
	if (*dst_p[0] == 0)
		return NULL;
	return p;
}

/*
 * Get key=val pair from connstring.  Returns position it stopped
 * or NULL on error.  EOF is signaled by *key = 0.
 */
static char * cstr_get_pair(char *p,
			    char **key_p,
			    char **val_p)
{
	p = cstr_skip_ws(p);
	*key_p = *val_p = p;
	if (*p == 0)
		return p;

	/* read key */
	p = cstr_get_key(p, key_p);
	if (!p)
		return NULL;

	/* read value */
	p = cstr_get_value(p, val_p);
	if (!p)
		return NULL;

	log_noise("cstr_get_pair: \"%s\"=\"%s\"", *key_p, *val_p);

	return cstr_skip_ws(p);
}

/*
 * Same as strcmp, but handles NULLs. If both sides are NULL, returns "true".
 */
static bool strings_equal(const char *str_left, const char *str_right)
{
	if (str_left == NULL && str_right == NULL)
		return true;

	if (str_left == NULL || str_right == NULL)
		return false;

	return strcmp(str_left, str_right) == 0;
}

static bool set_auth_dbname(PgDatabase *db, const char *new_auth_dbname)
{
	if (strings_equal(db->auth_dbname, new_auth_dbname))
		return true;

	if (db->auth_dbname)
		free(db->auth_dbname);

	if (new_auth_dbname) {
		db->auth_dbname = strdup(new_auth_dbname);
		if (!db->auth_dbname) {
			log_error("auth_dbname %s could not be set for database %s, out of memory", new_auth_dbname, db->name);
			return false;
		}
	} else {
		db->auth_dbname = NULL;
	}

	return true;
}

static bool set_autodb(const char *connstr)
{
	char *tmp = strdup(connstr);
	char *old = cf_autodb_connstr;

	if (!tmp) {
		log_error("no mem to change autodb_connstr");
		return false;
	}

	cf_autodb_connstr = tmp;
	if (old) {
		if (strcmp(connstr, old) != 0)
			tag_autodb_dirty();
		free(old);
	}

	return true;
}

/* fill PgDatabase from connstr */
bool parse_database(void *base, const char *name, const char *connstr)
{
	char *p, *key, *val;
	PktBuf *msg;
	PgDatabase *db;
	struct CfValue cv;
	int pool_size = -1;
	int min_pool_size = -1;
	int res_pool_size = -1;
	int max_db_connections = -1;
	int dbname_ofs;
	int pool_mode = POOL_INHERIT;

	char *tmp_connstr;
	const char *dbname = name;
	char *host = NULL;
	int port = 5432;
	char *username = NULL;
	char *password = "";
	char *auth_username = NULL;
	char *auth_dbname = NULL;
	char *client_encoding = NULL;
	char *datestyle = NULL;
	char *timezone = NULL;
	char *connect_query = NULL;
	char *appname = NULL;

	cv.value_p = &pool_mode;
	cv.extra = (const void *)pool_mode_map;

	if (strcmp(name, "pgbouncer") == 0) {
		log_error("database name \"%s\" is reserved", name);
		return false;
	}

	if (strcmp(name, "*") == 0) {
		return set_autodb(connstr);
	}

	tmp_connstr = strdup(connstr);
	if (!tmp_connstr) {
		log_error("out of memory");
		return false;
	}

	p = tmp_connstr;
	while (*p) {
		p = cstr_get_pair(p, &key, &val);
		if (p == NULL) {
			log_error("syntax error in connection string");
			goto fail;
		} else if (!key[0]) {
			break;
		}

		if (strcmp("dbname", key) == 0) {
			dbname = val;
		} else if (strcmp("host", key) == 0) {
			host = strdup(val);
			if (!host) {
				log_error("out of memory");
				goto fail;
			}
		} else if (strcmp("port", key) == 0) {
			port = atoi(val);
			if (port == 0) {
				log_error("invalid port: %s", val);
				goto fail;
			}
		} else if (strcmp("user", key) == 0) {
			username = val;
		} else if (strcmp("password", key) == 0) {
			password = val;
		} else if (strcmp("auth_user", key) == 0) {
			auth_username = val;
		} else if (strcmp("auth_dbname", key) == 0) {
			auth_dbname = val;
		} else if (strcmp("client_encoding", key) == 0) {
			client_encoding = val;
		} else if (strcmp("datestyle", key) == 0) {
			datestyle = val;
		} else if (strcmp("timezone", key) == 0) {
			timezone = val;
		} else if (strcmp("pool_size", key) == 0) {
			pool_size = atoi(val);
		} else if (strcmp("min_pool_size", key) == 0) {
			min_pool_size = atoi(val);
		} else if (strcmp("reserve_pool", key) == 0) {
			res_pool_size = atoi(val);
		} else if (strcmp("max_db_connections", key) == 0) {
			max_db_connections = atoi(val);
		} else if (strcmp("pool_mode", key) == 0) {
			if (!cf_set_lookup(&cv, val)) {
				log_error("invalid pool mode: %s", val);
				goto fail;
			}
		} else if (strcmp("connect_query", key) == 0) {
			connect_query = strdup(val);
			if (!connect_query) {
				log_error("out of memory");
				goto fail;
			}
		} else if (strcmp("application_name", key) == 0) {
			appname = val;
		} else {
			log_error("unrecognized connection parameter: %s", key);
			goto fail;
		}
	}

	db = add_database(name);
	if (!db) {
		log_error("cannot create database, no memory?");
		goto fail;
	}

	/* tag the db as alive */
	db->db_dead = false;
	/* assuming not an autodb */
	db->db_auto = false;
	db->inactive_time = 0;

	/* if updating old db, check if anything changed */
	if (db->dbname) {
		bool changed = false;
		if (strcmp(db->dbname, dbname) != 0) {
			changed = true;
		} else if (!strings_equal(host, db->host)) {
			changed = true;
		} else if (port != db->port) {
			changed = true;
		} else if (username && !db->forced_user) {
			changed = true;
		} else if (username && strcmp(username, db->forced_user->name) != 0) {
			changed = true;
		} else if (!username && db->forced_user) {
			changed = true;
		} else if (!strings_equal(connect_query, db->connect_query)) {
			changed = true;
		} else if (!strings_equal(db->auth_dbname, auth_dbname)) {
			changed = true;
		}
		if (changed)
			tag_database_dirty(db);
	}

	free(db->host);
	db->host = host;
	db->port = port;
	db->pool_size = pool_size;
	db->min_pool_size = min_pool_size;
	db->res_pool_size = res_pool_size;
	db->pool_mode = pool_mode;
	db->max_db_connections = max_db_connections;
	free(db->connect_query);
	db->connect_query = connect_query;

	if (!set_auth_dbname(db, auth_dbname))
		goto fail;

	if (db->startup_params) {
		msg = db->startup_params;
		pktbuf_reset(msg);
	} else {
		msg = pktbuf_dynamic(128);
		if (!msg)
			die("out of memory");
		db->startup_params = msg;
	}

	pktbuf_put_string(msg, "database");
	dbname_ofs = msg->write_pos;
	pktbuf_put_string(msg, dbname);

	if (client_encoding) {
		pktbuf_put_string(msg, "client_encoding");
		pktbuf_put_string(msg, client_encoding);
	}

	if (datestyle) {
		pktbuf_put_string(msg, "datestyle");
		pktbuf_put_string(msg, datestyle);
	}

	if (timezone) {
		pktbuf_put_string(msg, "timezone");
		pktbuf_put_string(msg, timezone);
	}

	if (appname) {
		pktbuf_put_string(msg, "application_name");
		pktbuf_put_string(msg, appname);
	}

	if (auth_username != NULL) {
		db->auth_user = find_user(auth_username);
		if (!db->auth_user) {
			db->auth_user = add_user(auth_username, "");
		}
	} else if (db->auth_user) {
		db->auth_user = NULL;
	}

	/* if user is forced, create fake object for it */
	if (username != NULL) {
		if (!force_user(db, username, password))
			log_warning("db setup failed, trying to continue");
	} else if (db->forced_user) {
		log_warning("losing forced user not supported,"
			    " keeping old setting");
	}

	/* remember dbname */
	db->dbname = (char *)msg->buf + dbname_ofs;

	free(tmp_connstr);
	return true;
fail:
	free(tmp_connstr);
	return false;
}

bool parse_user(void *base, const char *name, const char *connstr)
{
	char *p, *key, *val, *tmp_connstr;
	PgUser *user;
	struct CfValue cv;
	int pool_mode = POOL_INHERIT;
	int max_user_connections = -1;


	cv.value_p = &pool_mode;
	cv.extra = (const void *)pool_mode_map;

	tmp_connstr = strdup(connstr);
	if (!tmp_connstr) {
		log_error("out of memory");
		return false;
	}

	p = tmp_connstr;
	while (*p) {
		p = cstr_get_pair(p, &key, &val);
		if (p == NULL) {
			log_error("syntax error in user settings");
			goto fail;
		} else if (!key[0]) {
			break;
		}

		if (strcmp("pool_mode", key) == 0) {
			if (!cf_set_lookup(&cv, val)) {
				log_error("invalid pool mode: %s", val);
				goto fail;
			}
		} else if (strcmp("max_user_connections", key) == 0) {
			max_user_connections = atoi(val);
		} else {
			log_error("unrecognized user parameter: %s", key);
			goto fail;
		}
	}

	user = find_user(name);
	if (!user) {
		user = add_user(name, "");
		if (!user) {
			log_error("cannot create user, no memory?");
			goto fail;
		}
	}

	user->pool_mode = pool_mode;
	user->max_user_connections = max_user_connections;

	free(tmp_connstr);
	return true;

fail:
	free(tmp_connstr);
	return false;
}

/*
 * User file parsing
 */

/* find next " in string, skipping escaped ones */
static char *find_quote(char *p, bool start)
{
loop:
	while (*p && *p != '"')
		p++;
	if (p[0] == '"' && p[1] == '"' && !start) {
		p += 2;
		goto loop;
	}

	return p;
}

/* string is unquoted while copying */
static void copy_quoted(char *dst, const char *src, int len)
{
	char *end = dst + len - 1;
	while (*src && dst < end) {
		if (*src == '"')
			src++;
		*dst++ = *src++;
	}
	*dst = 0;
}

static void unquote_add_user(const char *username, const char *password)
{
	char real_user[MAX_USERNAME];
	char real_passwd[MAX_PASSWORD];
	PgUser *user;

	copy_quoted(real_user, username, sizeof(real_user));
	copy_quoted(real_passwd, password, sizeof(real_passwd));

	user = add_user(real_user, real_passwd);
	if (!user)
		log_warning("cannot create user, no memory");
}

static bool auth_loaded(const char *fn)
{
	static bool cache_set = false;
	static struct stat cache;
	struct stat cur;

	/* no file specified */
	if (fn == NULL) {
		memset(&cache, 0, sizeof(cache));
		cache_set = true;
		return false;
	}

	if (stat(fn, &cur) < 0)
		memset(&cur, 0, sizeof(cur));

	if (cache_set && cache.st_dev == cur.st_dev
	&& cache.st_ino == cur.st_ino
	&& cache.st_mode == cur.st_mode
	&& cache.st_uid == cur.st_uid
	&& cache.st_gid == cur.st_gid
	&& cache.st_mtime == cur.st_mtime
	&& cache.st_size == cur.st_size)
		return true;
	cache = cur;
	cache_set = true;
	return false;
}

bool loader_users_check(void)
{
	if (auth_loaded(cf_auth_file))
		return true;

	return load_auth_file(cf_auth_file);
}

static void disable_users(void)
{
	PgUser *user;
	struct List *item;

	statlist_for_each(item, &user_list) {
		user = container_of(item, PgUser, head);
		user->passwd[0] = 0;
	}
}

/* load list of users from auth_file */
bool load_auth_file(const char *fn)
{
	char *user, *password, *buf, *p;

	/* No file to load? */
	if (fn == NULL)
		return false;

	buf = load_file(fn, NULL);
	if (buf == NULL) {
		log_error("could not open auth_file %s: %s", fn, strerror(errno));
		return false;
	}

	log_debug("loading auth_file: \"%s\"", fn);
	disable_users();

	p = buf;
	while (*p) {
		/* skip whitespace and empty lines */
		while (*p && isspace(*p)) p++;
		if (!*p)
			break;

		/* skip commented-out lines */
		if (*p == ';') {
			while (*p && *p != '\n') p++;
			continue;
		}

		/* start of line */
		if (*p != '"') {
			log_error("broken auth file");
			break;
		}
		user = ++p;
		p = find_quote(p, false);
		if (*p != '"') {
			log_error("broken auth file");
			break;
		}
		if (p - user >= MAX_USERNAME) {
			log_error("username too long in auth file");
			break;
		}
		*p++ = 0; /* tag username end */

		/* get password */
		p = find_quote(p, true);
		if (*p != '"') {
			log_error("broken auth file");
			break;
		}
		password = ++p;
		p = find_quote(p, false);
		if (*p != '"') {
			log_error("broken auth file");
			break;
		}
		if (p - password >= MAX_PASSWORD) {
			log_error("password too long in auth file");
			break;
		}
		*p++ = 0; /* tag password end */

		/* send them away */
		unquote_add_user(user, password);

		/* skip rest of the line */
		while (*p && *p != '\n') p++;
	}
	free(buf);

	return true;
}
