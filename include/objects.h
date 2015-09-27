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

extern struct StatList user_list;
extern struct AATree user_tree;
extern struct StatList pool_list;
extern struct StatList database_list;
extern struct StatList autodatabase_idle_list;
extern struct StatList login_client_list;
extern struct Slab *client_cache;
extern struct Slab *server_cache;
extern struct Slab *db_cache;
extern struct Slab *pool_cache;
extern struct Slab *user_cache;
extern struct Slab *iobuf_cache;

PgDatabase *find_database(const char *name);
PgUser *find_user(const char *name);
PgPool *get_pool(PgDatabase *, PgUser *);
PgSocket *compare_connections_by_time(PgSocket *lhs, PgSocket *rhs);
bool evict_connection(PgDatabase *db)		_MUSTCHECK;
bool evict_user_connection(PgUser *user)	_MUSTCHECK;
bool find_server(PgSocket *client)		_MUSTCHECK;
bool release_server(PgSocket *server)		/* _MUSTCHECK */;
bool finish_client_login(PgSocket *client)	_MUSTCHECK;
bool check_fast_fail(PgSocket *client)		_MUSTCHECK;

PgSocket *accept_client(int sock, bool is_unix) _MUSTCHECK;
void disconnect_server(PgSocket *server, bool notify, const char *reason, ...) _PRINTF(3, 4);
void disconnect_client(PgSocket *client, bool notify, const char *reason, ...) _PRINTF(3, 4);

PgDatabase * add_database(const char *name) _MUSTCHECK;
PgDatabase *register_auto_database(const char *name);
PgUser * add_user(const char *name, const char *passwd) _MUSTCHECK;
PgUser * add_db_user(PgDatabase *db, const char *name, const char *passwd) _MUSTCHECK;
PgUser * force_user(PgDatabase *db, const char *username, const char *passwd) _MUSTCHECK;

void accept_cancel_request(PgSocket *req);
void forward_cancel_request(PgSocket *server);

void launch_new_connection(PgPool *pool);

bool use_client_socket(int fd, PgAddr *addr, const char *dbname, const char *username, uint64_t ckey, int oldfd, int linkfd,
		       const char *client_end, const char *std_string, const char *datestyle, const char *timezone,
		       const char *password, const char *search_path)
			_MUSTCHECK;
bool use_server_socket(int fd, PgAddr *addr, const char *dbname, const char *username, uint64_t ckey, int oldfd, int linkfd,
		       const char *client_end, const char *std_string, const char *datestyle, const char *timezone,
		       const char *password, const char *search_path)
			_MUSTCHECK;

void activate_client(PgSocket *client);

void change_client_state(PgSocket *client, SocketState newstate);
void change_server_state(PgSocket *server, SocketState newstate);

int get_active_client_count(void);
int get_active_server_count(void);

void tag_database_dirty(PgDatabase *db);
void tag_autodb_dirty(void);
void tag_host_addr_dirty(const char *host, const struct sockaddr *sa);
void for_each_server(PgPool *pool, void (*func)(PgSocket *sk));

void reuse_just_freed_objects(void);

void init_objects(void);

void init_caches(void);

