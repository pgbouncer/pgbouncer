/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007 Marko Kreen, Skype Technologies OÜ
 * 
 * Permission to use, copy, modify, and distribute this software for any
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

extern StatList user_list;
extern StatList pool_list;
extern StatList database_list;
extern StatList login_client_list;
extern StatList free_server_list;
extern StatList free_client_list;
extern StatList login_client_list;

PgDatabase *find_database(const char *name);
PgUser *find_user(const char *name);
PgPool *get_pool(PgDatabase *, PgUser *);
bool find_server(PgSocket *client);
bool release_server(PgSocket *server);
bool finish_client_login(PgSocket *client);

PgSocket * accept_client(int sock, const struct sockaddr_in *addr, bool is_unix);
void disconnect_server(PgSocket *server, bool notify, const char *reason);
void disconnect_client(PgSocket *client, bool notify, const char *reason);

PgDatabase * add_database(const char *name);
PgUser * add_user(const char *name, const char *passwd);
PgUser * force_user(PgDatabase *db, const char *username, const char *passwd);

void accept_cancel_request(PgSocket *req);
void forward_cancel_request(PgSocket *server);

void launch_new_connection(PgPool *pool);

bool use_client_socket(int fd, PgAddr *addr, const char *dbname, const char *username, uint64 ckey, int oldfd, int linkfd);
bool use_server_socket(int fd, PgAddr *addr, const char *dbname, const char *username, uint64 ckey, int oldfd, int linkfd);

void pause_client(PgSocket *client);
void activate_client(PgSocket *client);

void change_client_state(PgSocket *client, SocketState newstate);
void change_server_state(PgSocket *server, SocketState newstate);

int get_active_client_count(void);
int get_active_server_count(void);

void tag_database_dirty(PgDatabase *db);
void for_each_server(PgPool *pool, void (*func)(PgSocket *sk));

void create_auth_cache(void);

void reuse_just_freed_objects(void);

