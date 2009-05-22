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
 * Herding objects between lists happens here.
 */

#include "bouncer.h"

/* those items will be allocated as needed, never freed */
STATLIST(user_list);
STATLIST(database_list);
STATLIST(pool_list);

Tree user_tree;

/*
 * client and server objects will be pre-allocated
 * they are always in either active or free lists
 * in addition to others.
 */
STATLIST(login_client_list);

ObjectCache *server_cache;
ObjectCache *client_cache;
ObjectCache *db_cache;
ObjectCache *pool_cache;
ObjectCache *user_cache;
ObjectCache *iobuf_cache;

/*
 * libevent may still report events when event_del()
 * is called from somewhere else.  So hide just freed
 * PgSockets for one loop.
 */
static STATLIST(justfree_client_list);
static STATLIST(justfree_server_list);

/* init autodb idle list */
STATLIST(autodatabase_idle_list);

/* fast way to get number of active clients */
int get_active_client_count(void)
{
	return objcache_active_count(client_cache);
}

/* fast way to get number of active servers */
int get_active_server_count(void)
{
	return objcache_active_count(server_cache);
}

static void construct_client(void *obj)
{
	PgSocket *client = obj;

	memset(client, 0, sizeof(PgSocket));
	list_init(&client->head);
	sbuf_init(&client->sbuf, client_proto);
	client->state = CL_FREE;
}

static void construct_server(void *obj)
{
	PgSocket *server = obj;

	memset(server, 0, sizeof(PgSocket));
	list_init(&server->head);
	sbuf_init(&server->sbuf, server_proto);
	server->state = SV_FREE;
}

/* compare string with PgUser->name, for usage with btree */
static int user_node_cmp(long userptr, Node *node)
{
	const char *name = (const char *)userptr;
	PgUser *user = container_of(node, PgUser, tree_node);
	return strcmp(name, user->name);
}

/* initialization before config loading */
void init_objects(void)
{
	tree_init(&user_tree, user_node_cmp, NULL);
	user_cache = objcache_create("user_cache", sizeof(PgUser), 0, NULL);
	db_cache = objcache_create("db_cache", sizeof(PgDatabase), 0, NULL);
	pool_cache = objcache_create("pool_cache", sizeof(PgPool), 0, NULL);

	if (!user_cache || !db_cache || !pool_cache)
		fatal("cannot create initial caches");
}

static void do_iobuf_reset(void *arg)
{
	IOBuf *io = arg;
	iobuf_reset(io);
}

/* initialization after config loading */
void init_caches(void)
{
	server_cache = objcache_create("server_cache", sizeof(PgSocket), 0, construct_server);
	client_cache = objcache_create("client_cache", sizeof(PgSocket), 0, construct_client);
	iobuf_cache = objcache_create("iobuf_cache", IOBUF_SIZE, 0, do_iobuf_reset);
}

/* state change means moving between lists */
void change_client_state(PgSocket *client, SocketState newstate)
{
	PgPool *pool = client->pool;

	/* remove from old location */
	switch (client->state) {
	case CL_FREE:
		break;
	case CL_JUSTFREE:
		statlist_remove(&client->head, &justfree_client_list);
		break;
	case CL_LOGIN:
		statlist_remove(&client->head, &login_client_list);
		break;
	case CL_WAITING:
		statlist_remove(&client->head, &pool->waiting_client_list);
		break;
	case CL_ACTIVE:
		statlist_remove(&client->head, &pool->active_client_list);
		break;
	case CL_CANCEL:
		statlist_remove(&client->head, &pool->cancel_req_list);
		break;
	default:
		fatal("bad cur client state: %d", client->state);
	}

	client->state = newstate;

	/* put to new location */
	switch (client->state) {
	case CL_FREE:
		obj_free(client_cache, client);
		break;
	case CL_JUSTFREE:
		statlist_append(&client->head, &justfree_client_list);
		break;
	case CL_LOGIN:
		statlist_append(&client->head, &login_client_list);
		break;
	case CL_WAITING:
		statlist_append(&client->head, &pool->waiting_client_list);
		break;
	case CL_ACTIVE:
		statlist_append(&client->head, &pool->active_client_list);
		break;
	case CL_CANCEL:
		statlist_append(&client->head, &pool->cancel_req_list);
		break;
	default:
		fatal("bad new client state: %d", client->state);
	}
}

/* state change means moving between lists */
void change_server_state(PgSocket *server, SocketState newstate)
{
	PgPool *pool = server->pool;

	/* remove from old location */
	switch (server->state) {
	case SV_FREE:
		break;
	case SV_JUSTFREE:
		statlist_remove(&server->head, &justfree_server_list);
		break;
	case SV_LOGIN:
		statlist_remove(&server->head, &pool->new_server_list);
		break;
	case SV_USED:
		statlist_remove(&server->head, &pool->used_server_list);
		break;
	case SV_TESTED:
		statlist_remove(&server->head, &pool->tested_server_list);
		break;
	case SV_IDLE:
		statlist_remove(&server->head, &pool->idle_server_list);
		break;
	case SV_ACTIVE:
		statlist_remove(&server->head, &pool->active_server_list);
		break;
	default:
		fatal("change_server_state: bad old server state: %d", server->state);
	}

	server->state = newstate;

	/* put to new location */
	switch (server->state) {
	case SV_FREE:
		obj_free(server_cache, server);
		break;
	case SV_JUSTFREE:
		statlist_append(&server->head, &justfree_server_list);
		break;
	case SV_LOGIN:
		statlist_append(&server->head, &pool->new_server_list);
		break;
	case SV_USED:
		/* use LIFO */
		statlist_prepend(&server->head, &pool->used_server_list);
		break;
	case SV_TESTED:
		statlist_append(&server->head, &pool->tested_server_list);
		break;
	case SV_IDLE:
		if (server->close_needed || cf_server_round_robin)
			/* try to avoid immediate usage then */
			statlist_append(&server->head, &pool->idle_server_list);
		else
			/* otherwise use LIFO */
			statlist_prepend(&server->head, &pool->idle_server_list);
		break;
	case SV_ACTIVE:
		statlist_append(&server->head, &pool->active_server_list);
		break;
	default:
		fatal("bad server state");
	}
}

/* compare pool names, for use with put_in_order */
static int cmp_pool(List *i1, List *i2)
{
	PgPool *p1 = container_of(i1, PgPool, head);
	PgPool *p2 = container_of(i2, PgPool, head);
	if (p1->db != p2->db)
		return strcmp(p1->db->name, p2->db->name);
	if (p1->user != p2->user)
		return strcmp(p1->user->name, p2->user->name);
	return 0;
}

/* compare user names, for use with put_in_order */
static int cmp_user(List *i1, List *i2)
{
	PgUser *u1 = container_of(i1, PgUser, head);
	PgUser *u2 = container_of(i2, PgUser, head);
	return strcmp(u1->name, u2->name);
}

/* compare db names, for use with put_in_order */
static int cmp_database(List *i1, List *i2)
{
	PgDatabase *db1 = container_of(i1, PgDatabase, head);
	PgDatabase *db2 = container_of(i2, PgDatabase, head);
	return strcmp(db1->name, db2->name);
}

/* put elem into list in correct pos */
static void put_in_order(List *newitem, StatList *list, int (*cmpfn)(List *, List *))
{
	int res;
	List *item;

	statlist_for_each(item, list) {
		res = cmpfn(item, newitem);
		if (res == 0)
			fatal("put_in_order: found existing elem");
		else if (res > 0) {
			statlist_put_before(newitem, list, item);
			return;
		}
	}
	statlist_append(newitem, list);
}

/* create new object if new, then return it */
PgDatabase *add_database(const char *name)
{
	PgDatabase *db = find_database(name);

	/* create new object if needed */
	if (db == NULL) {
		db = obj_alloc(db_cache);
		if (!db)
			return NULL;

		list_init(&db->head);
		safe_strcpy(db->name, name, sizeof(db->name));
		put_in_order(&db->head, &database_list, cmp_database);
	}

	return db;
}

/* register new auto database */
PgDatabase *register_auto_database(const char *name)
{
	PgDatabase *db;
	int len;
	char *cs;
	
	if (!cf_autodb_connstr)
		return NULL;

	len = strlen(cf_autodb_connstr);
	cs = malloc(len + 1);
	if (!cs)
		return NULL;
	memcpy(cs, cf_autodb_connstr, len + 1);
	parse_database((char*)name, cs);
	free(cs);

	db = find_database(name);
	if (db) {
		db->db_auto = 1;
		/* do not forget to check pool_size like in config_postprocess */
		if (db->pool_size < 0)
			db->pool_size = cf_default_pool_size;
		if (db->res_pool_size < 0)
			db->res_pool_size = cf_res_pool_size;
	}

	return db;
}

/* add or update client users */
PgUser *add_user(const char *name, const char *passwd)
{
	PgUser *user = find_user(name);

	if (user == NULL) {
		user = obj_alloc(user_cache);
		if (!user)
			return NULL;

		list_init(&user->head);
		list_init(&user->pool_list);
		safe_strcpy(user->name, name, sizeof(user->name));
		put_in_order(&user->head, &user_list, cmp_user);

		tree_insert(&user_tree, (long)user->name, &user->tree_node);
	}
	safe_strcpy(user->passwd, passwd, sizeof(user->passwd));
	return user;
}

/* create separate user object for storing server user info */
PgUser *force_user(PgDatabase *db, const char *name, const char *passwd)
{
	PgUser *user = db->forced_user;
	if (!user) {
		user = obj_alloc(user_cache);
		if (!user)
			return NULL;
		list_init(&user->head);
		list_init(&user->pool_list);
	}
	safe_strcpy(user->name, name, sizeof(user->name));
	safe_strcpy(user->passwd, passwd, sizeof(user->passwd));
	db->forced_user = user;
	return user;
}

/* find an existing database */
PgDatabase *find_database(const char *name)
{
	List *item, *tmp;
	PgDatabase *db;
	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);
		if (strcmp(db->name, name) == 0)
			return db;
	}
	/* also trying to find in idle autodatabases list */
	statlist_for_each_safe(item, &autodatabase_idle_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (strcmp(db->name, name) == 0) {
			db->inactive_time = 0;
			statlist_remove(&db->head, &autodatabase_idle_list);
			put_in_order(&db->head, &database_list, cmp_database);
			return db;
		}
	}
	return NULL;
}

/* find existing user */
PgUser *find_user(const char *name)
{
	PgUser *user = NULL;
	Node *node;

	node = tree_search(&user_tree, (long)name);
	user = node ? container_of(node, PgUser, tree_node) : NULL;
	return user;
}

/* create new pool object */
static PgPool *new_pool(PgDatabase *db, PgUser *user)
{
	PgPool *pool;

	pool = obj_alloc(pool_cache);
	if (!pool)
		return NULL;

	list_init(&pool->head);
	list_init(&pool->map_head);

	pool->user = user;
	pool->db = db;

	statlist_init(&pool->active_client_list, "active_client_list");
	statlist_init(&pool->waiting_client_list, "waiting_client_list");
	statlist_init(&pool->active_server_list, "active_server_list");
	statlist_init(&pool->idle_server_list, "idle_server_list");
	statlist_init(&pool->tested_server_list, "tested_server_list");
	statlist_init(&pool->used_server_list, "used_server_list");
	statlist_init(&pool->new_server_list, "new_server_list");
	statlist_init(&pool->cancel_req_list, "cancel_req_list");

	list_append(&pool->map_head, &user->pool_list);

	/* keep pools in db/user order to make stats faster */
	put_in_order(&pool->head, &pool_list, cmp_pool);

	return pool;
}

/* find pool object, create if needed */
PgPool *get_pool(PgDatabase *db, PgUser *user)
{
	List *item;
	PgPool *pool;

	if (!db || !user)
		return NULL;

	list_for_each(item, &user->pool_list) {
		pool = container_of(item, PgPool, map_head);
		if (pool->db == db)
			return pool;
	}

	return new_pool(db, user);
}

/* deactivate socket and put into wait queue */
static void pause_client(PgSocket *client)
{
	Assert(client->state == CL_ACTIVE);

	slog_debug(client, "pause_client");
	change_client_state(client, CL_WAITING);
	if (!sbuf_pause(&client->sbuf))
		disconnect_client(client, true, "pause failed");
}

/* wake client from wait */
void activate_client(PgSocket *client)
{
	Assert(client->state == CL_WAITING);

	slog_debug(client, "activate_client");
	change_client_state(client, CL_ACTIVE);
	sbuf_continue(&client->sbuf);
}

/* link if found, otherwise put into wait queue */
bool find_server(PgSocket *client)
{
	PgPool *pool = client->pool;
	PgSocket *server;
	bool res;
	bool varchange = false;

	Assert(client->state == CL_ACTIVE);

	if (client->link)
		return true;

	/* try to get idle server, if allowed */
	if (cf_pause_mode == P_PAUSE) {
		server = NULL;
	} else {
		while (1) {
			server = first_socket(&pool->idle_server_list);
			if (!server)
				break;
			else if (server->close_needed)
				disconnect_server(server, true, "obsolete connection");
			else if (!server->ready)
				disconnect_server(server, true, "idle server got dirty");
			else
				break;
		}
	}
	Assert(!server || server->state == SV_IDLE);

	/* send var changes */
	if (server) {
		res = varcache_apply(server, client, &varchange);
		if (!res) {
			disconnect_server(server, true, "var change failed");
			server = NULL;
		}
	}

	/* link or send to waiters list */
	if (server) {
		client->link = server;
		server->link = client;
		change_server_state(server, SV_ACTIVE);
		if (varchange) {
			server->setting_vars = 1;
			server->ready = 0;
			res = false; /* don't process client data yet */
			if (!sbuf_pause(&client->sbuf))
				disconnect_client(client, true, "pause failed");
		} else
			res = true;
	} else {
		pause_client(client);
		res = false;
	}
	return res;
}

/* pick waiting client */
static bool reuse_on_release(PgSocket *server)
{
	bool res = true;
	PgPool *pool = server->pool;
	PgSocket *client = first_socket(&pool->waiting_client_list);
	if (client) {
		activate_client(client);

		/*
		 * As the activate_client() does full read loop,
		 * then it may happen that linked client close
		 * couses server close.  Report it.
		 */
		if (server->state == SV_FREE || server->state == SV_JUSTFREE)
			res = false;
	}
	return res;
}

/* send reset query */
static bool reset_on_release(PgSocket *server)
{
	bool res;
	
	Assert(server->state == SV_TESTED);

	slog_debug(server, "Resetting: %s", cf_server_reset_query);
	SEND_generic(res, server, 'Q', "s", cf_server_reset_query);
	if (!res)
		disconnect_server(server, false, "reset query failed");
	return res;
}

static bool life_over(PgSocket *server)
{
	PgPool *pool = server->pool;
	usec_t lifetime_kill_gap = 0;
	usec_t now = get_cached_time();
	usec_t age = now - server->connect_time;
	usec_t last_kill = now - pool->last_lifetime_disconnect;

	if (age < cf_server_lifetime)
		return false;

	if (pool->db->pool_size > 0)
		lifetime_kill_gap = cf_server_lifetime / pool->db->pool_size;

	if (last_kill >= lifetime_kill_gap)
		return true;

	return false;
}

/* connecting/active -> idle, unlink if needed */
bool release_server(PgSocket *server)
{
	PgPool *pool = server->pool;
	SocketState newstate = SV_IDLE;

	Assert(server->ready);

	/* remove from old list */
	switch (server->state) {
	case SV_ACTIVE:
		server->link->link = NULL;
		server->link = NULL;

		if (*cf_server_reset_query)
			/* notify reset is required */
			newstate = SV_TESTED;
		else if (cf_server_check_delay == 0 && *cf_server_check_query)
			/*
			 * deprecated: before reset_query, the check_delay = 0
			 * was used to get same effect.  This if() can be removed
			 * after couple of releases.
			 */
			newstate = SV_USED;
	case SV_USED:
	case SV_TESTED:
		break;
	case SV_LOGIN:
		pool->last_connect_failed = 0;
		break;
	default:
		fatal("bad server state in release_server");
	}

	/* enforce lifetime immidiately on release */
	if (server->state != SV_LOGIN && life_over(server)) {
		disconnect_server(server, true, "server_lifetime");
		return false;
	}

	/* enforce close request */
	if (server->close_needed) {
		disconnect_server(server, true, "close_needed");
		return false;
	}

	Assert(server->link == NULL);
	slog_noise(server, "release_server: new state=%d", newstate);
	change_server_state(server, newstate);

	if (newstate == SV_IDLE)
		/* immediately process waiters, to give fair chance */
		return reuse_on_release(server);
	else if (newstate == SV_TESTED)
		return reset_on_release(server);

	return true;
}

/* drop server connection */
void disconnect_server(PgSocket *server, bool notify, const char *reason)
{
	PgPool *pool = server->pool;
	PgSocket *client = server->link;
	static const uint8_t pkt_term[] = {'X', 0,0,0,4};
	int send_term = 1;
	usec_t now = get_cached_time();

	if (cf_log_disconnections)
		slog_info(server, "closing because: %s (age=%llu)", reason,
			  (now - server->connect_time) / USEC);

	switch (server->state) {
	case SV_ACTIVE:
		client = server->link;
		if (client) {
			client->link = NULL;
			server->link = NULL;
			disconnect_client(client, true, reason);
		}
		break;
	case SV_TESTED:
	case SV_USED:
	case SV_IDLE:
		break;
	case SV_LOGIN:
		/*
		 * usually disconnect means problems in startup phase,
		 * except when sending cancel packet
		 */
		if (!server->ready)
			pool->last_connect_failed = 1;
		else
			send_term = 0;
		break;
	default:
		fatal("disconnect_server: bad server state");
	}

	Assert(server->link == NULL);

	/* notify server and close connection */
	if (send_term && notify) {
		if (!sbuf_answer(&server->sbuf, pkt_term, sizeof(pkt_term)))
			/* ignore result */
			notify = false;
	}

	change_server_state(server, SV_JUSTFREE);
	if (!sbuf_close(&server->sbuf))
		log_noise("sbuf_close failed, retry later");
}

/* drop client connection */
void disconnect_client(PgSocket *client, bool notify, const char *reason)
{
	usec_t now = get_cached_time();

	if (cf_log_disconnections)
		slog_info(client, "closing because: %s (age=%llu)", reason,
			  (now - client->connect_time) / USEC);

	switch (client->state) {
	case CL_ACTIVE:
		if (client->link) {
			PgSocket *server = client->link;
			/* ->ready may be set before all is sent */
			if (server->ready && sbuf_is_empty(&server->sbuf)) {
				/* retval does not matter here */
				release_server(server);
			} else {
				server->link = NULL;
				client->link = NULL;
				disconnect_server(server, true, "unclean server");
			}
		}
	case CL_LOGIN:
	case CL_WAITING:
	case CL_CANCEL:
		break;
	default:
		fatal("bad client state in disconnect_client: %d", client->state);
	}

	/* send reason to client */
	if (notify && reason && client->state != CL_CANCEL) {
		/*
		 * don't send Ready pkt here, or client won't notice
		 * closed connection
		 */
		send_pooler_error(client, false, reason);
	}

	change_client_state(client, CL_JUSTFREE);
	if (!sbuf_close(&client->sbuf))
		log_noise("sbuf_close failed, retry later");
}

/* the pool needs new connection, if possible */
void launch_new_connection(PgPool *pool)
{
	PgSocket *server;
	int total;
	const char *unix_dir = cf_unix_socket_dir;
	bool res;

	/* allow only small number of connection attempts at a time */
	if (!statlist_empty(&pool->new_server_list)) {
		log_debug("launch_new_connection: already progress");
		return;
	}

	/* if server bounces, don't retry too fast */
	if (pool->last_connect_failed) {
		usec_t now = get_cached_time();
		if (now - pool->last_connect_time < cf_server_login_retry) {
			log_debug("launch_new_connection: last failed, wait");
			return;
		}
	}

	/* is it allowed to add servers? */
	total = pool_server_count(pool);
	if (total >= pool->db->pool_size && pool->welcome_msg_ready) {
		/* should we use reserve pool? */
		if (cf_res_pool_timeout && pool->db->res_pool_size) {
			usec_t now = get_cached_time();
			PgSocket *c = first_socket(&pool->waiting_client_list);
			if (c && (now - c->request_time) >= cf_res_pool_timeout) {
				if (total < pool->db->pool_size + pool->db->res_pool_size) {
					log_debug("reserve_pool activated");
					goto allow_new;
				}
			}
		}
		log_debug("launch_new_connection: pool full (%d >= %d)",
				total, pool->db->pool_size);
		return;
	}

allow_new:
	/* get free conn object */
	server = obj_alloc(server_cache);
	if (!server) {
		log_debug("launch_new_connection: no memory");
		return;
	}

	/* initialize it */
	server->pool = pool;
	server->auth_user = server->pool->user;
	server->remote_addr = server->pool->db->addr;
	server->connect_time = get_cached_time();
	pool->last_connect_time = get_cached_time();
	change_server_state(server, SV_LOGIN);

	if (cf_log_connections)
		slog_info(server, "new connection to server");

	/* override socket location if requested */
	if (server->pool->db->unix_socket_dir[0])
		unix_dir = server->pool->db->unix_socket_dir;

	/* start connecting */
	res = sbuf_connect(&server->sbuf, &server->remote_addr, unix_dir,
			   cf_server_connect_timeout / USEC);
	if (!res)
		log_noise("failed to launch new connection");
}

/* new client connection attempt */
PgSocket * accept_client(int sock,
			 const struct sockaddr_in *addr,
			 bool is_unix)
{
	bool res;
	PgSocket *client;

	/* get free PgSocket */
	client = obj_alloc(client_cache);
	if (!client) {
		log_warning("cannot allocate client struct");
		safe_close(sock);
		return NULL;
	}

	client->connect_time = client->request_time = get_cached_time();
	client->query_start = 0;

	fill_remote_addr(client, sock, is_unix);
	fill_local_addr(client, sock, is_unix);

	change_client_state(client, CL_LOGIN);

	res = sbuf_accept(&client->sbuf, sock, is_unix);
	if (!res) {
		if (cf_log_connections)
			slog_debug(client, "failed connection attempt");
		return NULL;
	}

	return client;
}

/* send cached parameters to client to pretend being server */
/* client managed to authenticate, send welcome msg and accept queries */
bool finish_client_login(PgSocket *client)
{
	switch (client->state) {
	case CL_LOGIN:
		change_client_state(client, CL_ACTIVE);
	case CL_ACTIVE:
		break;
	default:
		fatal("bad client state");
	}

	if (!welcome_client(client)) {
		log_debug("finish_client_login: no welcome message, pause");
		client->wait_for_welcome = 1;
		pause_client(client);
		if (cf_pause_mode == P_NONE)
			launch_new_connection(client->pool);
		return false;
	}
	client->wait_for_welcome = 0;

	slog_debug(client, "logged in");

	return true;
}

/* client->cancel_key has requested client key */
void accept_cancel_request(PgSocket *req)
{
	List *pitem, *citem;
	PgPool *pool;
	PgSocket *server = NULL, *client, *main_client = NULL;

	Assert(req->state == CL_LOGIN);

	/* find real client this is for */
	statlist_for_each(pitem, &pool_list) {
		pool = container_of(pitem, PgPool, head);
		statlist_for_each(citem, &pool->active_client_list) {
			client = container_of(citem, PgSocket, head);
			if (memcmp(client->cancel_key, req->cancel_key, 8) == 0) {
				main_client = client;
				goto found;
			}
		}
	}
found:

	/* wrong key */
	if (!main_client) {
		disconnect_client(req, false, "failed cancel request");
		return;
	}

	/* not linked client, just drop it then */
	if (!main_client->link) {
		bool res;

		/* let administrative cancel be handled elsewhere */
		if (main_client->pool->db->admin) {
			disconnect_client(req, false, "cancel request for console client");
			admin_handle_cancel(main_client);
			return;
		}

		disconnect_client(req, false, "cancel request for idle client");

		/* notify readiness */
		SEND_ReadyForQuery(res, main_client);
		if (!res)
			disconnect_client(main_client, true,
					  "ReadyForQuery for main_client failed");
		return;
	}

	/* drop the connection, if fails, retry later in justfree list */
	if (!sbuf_close(&req->sbuf))
		log_noise("sbuf_close failed, retry later");

	/* remember server key */
	server = main_client->link;
	memcpy(req->cancel_key, server->cancel_key, 8);

	/* attach to target pool */
	req->pool = pool;
	change_client_state(req, CL_CANCEL);

	/* need fresh connection */
	launch_new_connection(pool);
}

void forward_cancel_request(PgSocket *server)
{
	bool res;
	PgSocket *req = first_socket(&server->pool->cancel_req_list);

	Assert(req != NULL && req->state == CL_CANCEL);
	Assert(server->state == SV_LOGIN);

	SEND_CancelRequest(res, server, req->cancel_key);

	change_client_state(req, CL_JUSTFREE);
}

bool use_client_socket(int fd, PgAddr *addr,
		       const char *dbname, const char *username,
		       uint64_t ckey, int oldfd, int linkfd,
		       const char *client_enc, const char *std_string,
		       const char *datestyle, const char *timezone)
{
	PgSocket *client;
	PktBuf tmp;

	client = accept_client(fd, NULL, addr->is_unix);
	if (client == NULL)
		return false;
	client->suspended = 1;

	if (!set_pool(client, dbname, username))
		return false;

	change_client_state(client, CL_ACTIVE);

	/* store old cancel key */
	pktbuf_static(&tmp, client->cancel_key, 8);
	pktbuf_put_uint64(&tmp, ckey);

	/* store old fds */
	client->tmp_sk_oldfd = oldfd;
	client->tmp_sk_linkfd = linkfd;

	varcache_set(&client->vars, "client_encoding", client_enc);
	varcache_set(&client->vars, "standard_conforming_strings", std_string);
	varcache_set(&client->vars, "datestyle", datestyle);
	varcache_set(&client->vars, "timezone", timezone);

	return true;
}

bool use_server_socket(int fd, PgAddr *addr,
		       const char *dbname, const char *username,
		       uint64_t ckey, int oldfd, int linkfd,
		       const char *client_enc, const char *std_string,
		       const char *datestyle, const char *timezone)
{
	PgDatabase *db = find_database(dbname);
	PgUser *user;
	PgPool *pool;
	PgSocket *server;
	PktBuf tmp;
	bool res;
	
	/* if the database not found, it's an auto database -> registering... */
	if (!db) {
		db = register_auto_database(dbname);
		if (!db)
			return true;
	}

	if (db->forced_user)
		user = db->forced_user;
	else
		user = find_user(username);

	pool = get_pool(db, user);
	if (!pool)
		return false;

	server = obj_alloc(server_cache);
	if (!server)
		return false;

	res = sbuf_accept(&server->sbuf, fd, addr->is_unix);
	if (!res)
		return false;

	server->suspended = 1;
	server->pool = pool;
	server->auth_user = user;
	server->connect_time = server->request_time = get_cached_time();
	server->query_start = 0;

	fill_remote_addr(server, fd, addr->is_unix);
	fill_local_addr(server, fd, addr->is_unix);

	if (linkfd) {
		server->ready = 0;
		change_server_state(server, SV_ACTIVE);
	} else {
		server->ready = 1;
		change_server_state(server, SV_IDLE);
	}

	/* store old cancel key */
	pktbuf_static(&tmp, server->cancel_key, 8);
	pktbuf_put_uint64(&tmp, ckey);

	/* store old fds */
	server->tmp_sk_oldfd = oldfd;
	server->tmp_sk_linkfd = linkfd;

	varcache_set(&server->vars, "client_encoding", client_enc);
	varcache_set(&server->vars, "standard_conforming_strings", std_string);
	varcache_set(&server->vars, "datestyle", datestyle);
	varcache_set(&server->vars, "timezone", timezone);

	return true;
}

void for_each_server(PgPool *pool, void (*func)(PgSocket *sk))
{
	List *item;

	statlist_for_each(item, &pool->idle_server_list)
		func(container_of(item, PgSocket, head));

	statlist_for_each(item, &pool->used_server_list)
		func(container_of(item, PgSocket, head));

	statlist_for_each(item, &pool->tested_server_list)
		func(container_of(item, PgSocket, head));

	statlist_for_each(item, &pool->active_server_list)
		func(container_of(item, PgSocket, head));

	statlist_for_each(item, &pool->new_server_list)
		func(container_of(item, PgSocket, head));
}

static void tag_dirty(PgSocket *sk)
{
	sk->close_needed = 1;
}

void tag_database_dirty(PgDatabase *db)
{
	List *item;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db == db)
			for_each_server(pool, tag_dirty);
	}
}

/* move objects from justfree_* to free_* lists */
void reuse_just_freed_objects(void)
{
	List *tmp, *item;
	PgSocket *sk;
	bool close_works = true;

	/*
	 * event_del() may fail because of ENOMEM for event handlers
	 * that need only changes sent to kernel on each loop.
	 *
	 * Keep open sbufs in justfree lists until successful.
	 */

	statlist_for_each_safe(item, &justfree_client_list, tmp) {
		sk = container_of(item, PgSocket, head);
		if (sbuf_is_closed(&sk->sbuf))
			change_client_state(sk, CL_FREE);
		else if (close_works)
			close_works = sbuf_close(&sk->sbuf);
	}
	statlist_for_each_safe(item, &justfree_server_list, tmp) {
		sk = container_of(item, PgSocket, head);
		if (sbuf_is_closed(&sk->sbuf))
			change_server_state(sk, SV_FREE);
		else if (close_works)
			close_works = sbuf_close(&sk->sbuf);
	}
}

