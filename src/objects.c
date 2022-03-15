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
#include "scram.h"

#include <usual/safeio.h>
#include <usual/slab.h>

/* those items will be allocated as needed, never freed */
STATLIST(user_list);
STATLIST(database_list);
STATLIST(pool_list);

/* All locally defined users (in auth_file) are kept here. */
struct AATree user_tree;

/*
 * All PAM users are kept here. We need to differentiate two user
 * lists to avoid user clashing for different authentication types,
 * and because pam_user_tree is closer to PgDatabase.user_tree in
 * logic.
 */
struct AATree pam_user_tree;

/*
 * client and server objects will be pre-allocated
 * they are always in either active or free lists
 * in addition to others.
 */
STATLIST(login_client_list);

struct Slab *server_cache;
struct Slab *client_cache;
struct Slab *db_cache;
struct Slab *pool_cache;
struct Slab *user_cache;
struct Slab *iobuf_cache;

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
	return slab_active_count(client_cache);
}

/* fast way to get number of active servers */
int get_active_server_count(void)
{
	return slab_active_count(server_cache);
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
static int user_node_cmp(uintptr_t userptr, struct AANode *node)
{
	const char *name = (const char *)userptr;
	PgUser *user = container_of(node, PgUser, tree_node);
	return strcmp(name, user->name);
}

/* destroy PgUser, for usage with btree */
static void user_node_release(struct AANode *node, void *arg)
{
	PgUser *user = container_of(node, PgUser, tree_node);
	slab_free(user_cache, user);
}

/* initialization before config loading */
void init_objects(void)
{
	aatree_init(&user_tree, user_node_cmp, NULL);
	aatree_init(&pam_user_tree, user_node_cmp, NULL);
	user_cache = slab_create("user_cache", sizeof(PgUser), 0, NULL, USUAL_ALLOC);
	db_cache = slab_create("db_cache", sizeof(PgDatabase), 0, NULL, USUAL_ALLOC);
	pool_cache = slab_create("pool_cache", sizeof(PgPool), 0, NULL, USUAL_ALLOC);

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
	server_cache = slab_create("server_cache", sizeof(PgSocket), 0, construct_server, USUAL_ALLOC);
	client_cache = slab_create("client_cache", sizeof(PgSocket), 0, construct_client, USUAL_ALLOC);
	iobuf_cache = slab_create("iobuf_cache", IOBUF_SIZE, 0, do_iobuf_reset, USUAL_ALLOC);
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
		statlist_remove(&justfree_client_list, &client->head);
		break;
	case CL_LOGIN:
		if (newstate == CL_WAITING)
			newstate = CL_WAITING_LOGIN;
		statlist_remove(&login_client_list, &client->head);
		break;
	case CL_WAITING_LOGIN:
		if (newstate == CL_ACTIVE)
			newstate = CL_LOGIN;
		/* fallthrough */
	case CL_WAITING:
		statlist_remove(&pool->waiting_client_list, &client->head);
		break;
	case CL_ACTIVE:
		statlist_remove(&pool->active_client_list, &client->head);
		break;
	case CL_CANCEL:
		statlist_remove(&pool->cancel_req_list, &client->head);
		break;
	default:
		fatal("bad cur client state: %d", client->state);
	}

	client->state = newstate;

	/* put to new location */
	switch (client->state) {
	case CL_FREE:
		varcache_clean(&client->vars);
		slab_free(client_cache, client);
		break;
	case CL_JUSTFREE:
		statlist_append(&justfree_client_list, &client->head);
		break;
	case CL_LOGIN:
		statlist_append(&login_client_list, &client->head);
		break;
	case CL_WAITING:
	case CL_WAITING_LOGIN:
		client->wait_start = get_cached_time();
		statlist_append(&pool->waiting_client_list, &client->head);
		break;
	case CL_ACTIVE:
		statlist_append(&pool->active_client_list, &client->head);
		break;
	case CL_CANCEL:
		statlist_append(&pool->cancel_req_list, &client->head);
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
		statlist_remove(&justfree_server_list, &server->head);
		break;
	case SV_LOGIN:
		statlist_remove(&pool->new_server_list, &server->head);
		break;
	case SV_USED:
		statlist_remove(&pool->used_server_list, &server->head);
		break;
	case SV_TESTED:
		statlist_remove(&pool->tested_server_list, &server->head);
		break;
	case SV_IDLE:
		statlist_remove(&pool->idle_server_list, &server->head);
		break;
	case SV_ACTIVE:
		statlist_remove(&pool->active_server_list, &server->head);
		break;
	default:
		fatal("bad old server state: %d", server->state);
	}

	server->state = newstate;

	/* put to new location */
	switch (server->state) {
	case SV_FREE:
		varcache_clean(&server->vars);
		slab_free(server_cache, server);
		break;
	case SV_JUSTFREE:
		statlist_append(&justfree_server_list, &server->head);
		break;
	case SV_LOGIN:
		statlist_append(&pool->new_server_list, &server->head);
		break;
	case SV_USED:
		/* use LIFO */
		statlist_prepend(&pool->used_server_list, &server->head);
		break;
	case SV_TESTED:
		statlist_append(&pool->tested_server_list, &server->head);
		break;
	case SV_IDLE:
		if (server->close_needed || cf_server_round_robin) {
			/* try to avoid immediate usage then */
			statlist_append(&pool->idle_server_list, &server->head);
		} else {
			/* otherwise use LIFO */
			statlist_prepend(&pool->idle_server_list, &server->head);
		}
		break;
	case SV_ACTIVE:
		statlist_append(&pool->active_server_list, &server->head);
		break;
	default:
		fatal("bad server state: %d", server->state);
	}
}

/* compare pool names, for use with put_in_order */
static int cmp_pool(struct List *i1, struct List *i2)
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
static int cmp_user(struct List *i1, struct List *i2)
{
	PgUser *u1 = container_of(i1, PgUser, head);
	PgUser *u2 = container_of(i2, PgUser, head);
	return strcmp(u1->name, u2->name);
}

/* compare db names, for use with put_in_order */
static int cmp_database(struct List *i1, struct List *i2)
{
	PgDatabase *db1 = container_of(i1, PgDatabase, head);
	PgDatabase *db2 = container_of(i2, PgDatabase, head);
	return strcmp(db1->name, db2->name);
}

/* put elem into list in correct pos */
static void put_in_order(struct List *newitem, struct StatList *list,
			 int (*cmpfn)(struct List *, struct List *))
{
	int res;
	struct List *item;

	statlist_for_each(item, list) {
		res = cmpfn(item, newitem);
		if (res == 0) {
			fatal("put_in_order: found existing elem");
		} else if (res > 0) {
			statlist_put_before(list, newitem, item);
			return;
		}
	}
	statlist_append(list, newitem);
}

/* create new object if new, then return it */
PgDatabase *add_database(const char *name)
{
	PgDatabase *db = find_database(name);

	/* create new object if needed */
	if (db == NULL) {
		db = slab_alloc(db_cache);
		if (!db)
			return NULL;

		list_init(&db->head);
		if (strlcpy(db->name, name, sizeof(db->name)) >= sizeof(db->name)) {
			log_warning("too long db name: %s", name);
			slab_free(db_cache, db);
			return NULL;
		}
		aatree_init(&db->user_tree, user_node_cmp, user_node_release);
		put_in_order(&db->head, &database_list, cmp_database);
	}

	return db;
}

/* register new auto database */
PgDatabase *register_auto_database(const char *name)
{
	PgDatabase *db;

	if (!cf_autodb_connstr)
		return NULL;

	if (!parse_database(NULL, name, cf_autodb_connstr))
		return NULL;

	db = find_database(name);
	if (db) {
		db->db_auto = true;
	}

	return db;
}

/* add or update client users */
PgUser *add_user(const char *name, const char *passwd)
{
	PgUser *user = find_user(name);

	if (user == NULL) {
		user = slab_alloc(user_cache);
		if (!user)
			return NULL;

		list_init(&user->head);
		list_init(&user->pool_list);
		safe_strcpy(user->name, name, sizeof(user->name));
		put_in_order(&user->head, &user_list, cmp_user);

		aatree_insert(&user_tree, (uintptr_t)user->name, &user->tree_node);
		user->pool_mode = POOL_INHERIT;
	}
	safe_strcpy(user->passwd, passwd, sizeof(user->passwd));
	return user;
}

/* add or update db users */
PgUser *add_db_user(PgDatabase *db, const char *name, const char *passwd)
{
	PgUser *user = NULL;
	struct AANode *node;

	node = aatree_search(&db->user_tree, (uintptr_t)name);
	user = node ? container_of(node, PgUser, tree_node) : NULL;

	if (user == NULL) {
		user = slab_alloc(user_cache);
		if (!user)
			return NULL;

		list_init(&user->head);
		list_init(&user->pool_list);
		safe_strcpy(user->name, name, sizeof(user->name));

		aatree_insert(&db->user_tree, (uintptr_t)user->name, &user->tree_node);
		user->pool_mode = POOL_INHERIT;
	}
	safe_strcpy(user->passwd, passwd, sizeof(user->passwd));
	return user;
}

/* Add PAM user. The logic is same as in add_db_user */
PgUser *add_pam_user(const char *name, const char *passwd)
{
	PgUser *user = NULL;
	struct AANode *node;

	node = aatree_search(&pam_user_tree, (uintptr_t)name);
	user = node ? container_of(node, PgUser, tree_node) : NULL;

	if (user == NULL) {
		user = slab_alloc(user_cache);
		if (!user)
			return NULL;

		list_init(&user->head);
		list_init(&user->pool_list);
		safe_strcpy(user->name, name, sizeof(user->name));

		aatree_insert(&pam_user_tree, (uintptr_t)user->name, &user->tree_node);
		user->pool_mode = POOL_INHERIT;
	}
	if (passwd)
		safe_strcpy(user->passwd, passwd, sizeof(user->passwd));
	return user;
}

/* create separate user object for storing server user info */
PgUser *force_user(PgDatabase *db, const char *name, const char *passwd)
{
	PgUser *user = db->forced_user;
	if (!user) {
		user = slab_alloc(user_cache);
		if (!user)
			return NULL;
		list_init(&user->head);
		list_init(&user->pool_list);
		user->pool_mode = POOL_INHERIT;
	}
	safe_strcpy(user->name, name, sizeof(user->name));
	safe_strcpy(user->passwd, passwd, sizeof(user->passwd));
	db->forced_user = user;
	return user;
}

/* find an existing database */
PgDatabase *find_database(const char *name)
{
	struct List *item, *tmp;
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
			statlist_remove(&autodatabase_idle_list, &db->head);
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
	struct AANode *node;

	node = aatree_search(&user_tree, (uintptr_t)name);
	user = node ? container_of(node, PgUser, tree_node) : NULL;
	return user;
}

/* create new pool object */
static PgPool *new_pool(PgDatabase *db, PgUser *user)
{
	PgPool *pool;

	pool = slab_alloc(pool_cache);
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

	list_append(&user->pool_list, &pool->map_head);

	/* keep pools in db/user order to make stats faster */
	put_in_order(&pool->head, &pool_list, cmp_pool);

	return pool;
}

/* find pool object, create if needed */
PgPool *get_pool(PgDatabase *db, PgUser *user)
{
	struct List *item;
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
	Assert(client->state == CL_ACTIVE || client->state == CL_LOGIN);

	slog_debug(client, "pause_client");
	change_client_state(client, CL_WAITING);
	if (!sbuf_pause(&client->sbuf))
		disconnect_client(client, true, "pause failed");
}

/* wake client from wait */
void activate_client(PgSocket *client)
{
	Assert(client->state == CL_WAITING || client->state == CL_WAITING_LOGIN);

	Assert(client->wait_start > 0);

	/* acount for time client spent waiting for server */
	client->pool->stats.wait_time += (get_cached_time() - client->wait_start);

	slog_debug(client, "activate_client");
	change_client_state(client, CL_ACTIVE);
	sbuf_continue(&client->sbuf);
}

/*
 * Don't let clients queue at all if there is no working server connection.
 *
 * It must still allow following cases:
 * - empty pool on startup
 * - idle pool where all servers are removed
 *
 * Current assumptions:
 * - old server connections will be dropped by query_timeout
 * - new server connections fail due to server_connect_timeout, or other failure
 *
 * So here we drop client if all server connections have been dropped
 * and new ones fail.
 *
 * Return true if the client connection should be allowed, false if it
 * should be rejected.
 */
bool check_fast_fail(PgSocket *client)
{
	int cnt;
	PgPool *pool = client->pool;

	/* Could be mock authentication, proceed normally */
	if (!pool)
		return true;

	/* If last login succeeded, client can go ahead. */
	if (!pool->last_login_failed)
		return true;

	/* If there are servers available, client can go ahead. */
	cnt = pool_server_count(pool) - statlist_count(&pool->new_server_list);
	if (cnt)
		return true;

	/* Else we fail the client. */
	disconnect_client(client, true, "server login has been failing, try again later (server_login_retry)");

	/*
	 * Try to launch a new connection.  (launch_new_connection()
	 * will check for server_login_retry etc.)  The usual relaunch
	 * from janitor.c won't do anything, as there are no waiting
	 * clients, so we need to do it here to get any new servers
	 * eventually.
	 */
	launch_new_connection(pool);

	return false;
}

/* link if found, otherwise put into wait queue */
bool find_server(PgSocket *client)
{
	PgPool *pool = client->pool;
	PgSocket *server;
	bool res;
	bool varchange = false;

	Assert(client->state == CL_ACTIVE || client->state == CL_LOGIN);

	/* no wait by default */
	client->wait_start = 0;

	if (client->link)
		return true;

	/* try to get idle server, if allowed */
	if (cf_pause_mode == P_PAUSE || pool->db->db_paused) {
		server = NULL;
	} else {
		while (1) {
			server = first_socket(&pool->idle_server_list);
			if (!server) {
				break;
			} else if (server->close_needed) {
				disconnect_server(server, true, "obsolete connection");
			} else if (!server->ready) {
				disconnect_server(server, true, "idle server got dirty");
			} else {
				break;
			}
		}

		if (!server && !check_fast_fail(client))
			return false;

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
			server->setting_vars = true;
			server->ready = false;
			res = false; /* don't process client data yet */
			if (!sbuf_pause(&client->sbuf))
				disconnect_client(client, true, "pause failed");
		} else {
			res = true;
		}
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
		 * then it may happen that linked client closing
		 * causes server closing.  Report it.
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

	slog_debug(server, "resetting: %s", cf_server_reset_query);
	SEND_generic(res, server, 'Q', "s", cf_server_reset_query);
	if (!res)
		disconnect_server(server, false, "reset query failed");
	return res;
}

bool life_over(PgSocket *server)
{
	PgPool *pool = server->pool;
	usec_t lifetime_kill_gap = 0;
	usec_t now = get_cached_time();
	usec_t age = now - server->connect_time;
	usec_t last_kill = now - pool->last_lifetime_disconnect;

	if (age < cf_server_lifetime)
		return false;

	/*
	 * Calculate the time that disconnects because of server_lifetime
	 * must be separated.  This avoids the need to re-launch lot
	 * of connections together.
	 */
	if (pool_pool_size(pool) > 0)
		lifetime_kill_gap = cf_server_lifetime / pool_pool_size(pool);

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

		if (*cf_server_reset_query && (cf_server_reset_query_always ||
					       pool_pool_mode(pool) == POOL_SESSION))
		{
			/* notify reset is required */
			newstate = SV_TESTED;
		} else if (cf_server_check_delay == 0 && *cf_server_check_query) {
			/*
			 * deprecated: before reset_query, the check_delay = 0
			 * was used to get same effect.  This if() can be removed
			 * after couple of releases.
			 */
			newstate = SV_USED;
		}
	case SV_USED:
	case SV_TESTED:
		break;
	case SV_LOGIN:
		pool->last_login_failed = false;
		pool->last_connect_failed = false;
		break;
	default:
		fatal("bad server state: %d", server->state);
	}

	/* enforce lifetime immediately on release */
	if (server->state != SV_LOGIN && life_over(server)) {
		disconnect_server(server, true, "server lifetime over");
		pool->last_lifetime_disconnect = get_cached_time();
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

	if (newstate == SV_IDLE) {
		/* immediately process waiters, to give fair chance */
		return reuse_on_release(server);
	} else if (newstate == SV_TESTED) {
		return reset_on_release(server);
	}

	return true;
}

/*
 * close server connection
 *
 * send_term=true means to send a Terminate message to the server
 * before disconnecting, send_term=false means to disconnect without.
 * The latter is for protocol and communication errors where a normal
 * protocol termination is not possible.
 */
void disconnect_server(PgSocket *server, bool send_term, const char *reason, ...)
{
	usec_t now = get_cached_time();
	char buf[128];
	va_list ap;

	va_start(ap, reason);
	vsnprintf(buf, sizeof(buf), reason, ap);
	va_end(ap);
	reason = buf;

	if (cf_log_disconnections)
		slog_info(server, "closing because: %s (age=%" PRIu64 "s)", reason,
			  (now - server->connect_time) / USEC);

	switch (server->state) {
	case SV_ACTIVE:	{
		PgSocket *client = server->link;

		if (client) {
			client->link = NULL;
			server->link = NULL;
			/*
			 * Send reason to client if it is already
			 * logged in, otherwise send generic message.
			 */
			if (client->state == CL_ACTIVE || client->state == CL_WAITING)
				disconnect_client(client, true, "%s", reason);
			else
				disconnect_client(client, true, "bouncer config error");
		}
		break;
	}
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
		{
			server->pool->last_login_failed = true;
			server->pool->last_connect_failed = true;
		}
		else
		{
			/*
			 * We did manage to connect and used the connection for query
			 * cancellation, so to the best of our knowledge we can connect to
			 * the server, reset last_connect_failed accordingly.
			 */
			server->pool->last_connect_failed = false;
			send_term = false;
		}
		break;
	default:
		fatal("bad server state: %d", server->state);
	}

	Assert(server->link == NULL);

	/* notify server and close connection */
	if (send_term) {
		static const uint8_t pkt_term[] = {'X', 0,0,0,4};
		bool _ignore = sbuf_answer(&server->sbuf, pkt_term, sizeof(pkt_term));
		(void) _ignore;
	}

	if (server->dns_token) {
		adns_cancel(adns, server->dns_token);
		server->dns_token = NULL;
	}

	free_scram_state(&server->scram_state);

	server->pool->db->connection_count--;
	server->pool->user->connection_count--;

	change_server_state(server, SV_JUSTFREE);
	if (!sbuf_close(&server->sbuf))
		log_noise("sbuf_close failed, retry later");
}

/*
 * close client connection
 *
 * notify=true means to send the reason message as an error to the
 * client, notify=false means no message is sent.  The latter is for
 * protocol and communication errors where sending a regular error
 * message is not possible.
 */
void disconnect_client(PgSocket *client, bool notify, const char *reason, ...)
{
	usec_t now = get_cached_time();

	if (reason) {
		char buf[128];
		va_list ap;

		va_start(ap, reason);
		vsnprintf(buf, sizeof(buf), reason, ap);
		va_end(ap);
		reason = buf;
	}

	if (cf_log_disconnections && reason)
		slog_info(client, "closing because: %s (age=%" PRIu64 "s)", reason,
			  (now - client->connect_time) / USEC);

	switch (client->state) {
	case CL_ACTIVE:
	case CL_LOGIN:
		if (client->link) {
			PgSocket *server = client->link;
			if (!server->ready) {
				server->link = NULL;
				client->link = NULL;
				/*
				 * This can happen if the client
				 * connection is normally closed while
				 * the server has a transaction block
				 * open.  Then there is no way for us
				 * to reset the server other than by
				 * closing it.  Perhaps it would be
				 * worth tracking this separately to
				 * make the error message more
				 * precise and less scary.
				 */
				disconnect_server(server, true, "client disconnect while server was not ready");
			} else if (!sbuf_is_empty(&server->sbuf)) {
				/* ->ready may be set before all is sent */
				server->link = NULL;
				client->link = NULL;
				disconnect_server(server, true, "client disconnect before everything was sent to the server");
			} else {
				/* retval does not matter here */
				release_server(server);
			}
		}
	case CL_WAITING:
	case CL_WAITING_LOGIN:
	case CL_CANCEL:
		break;
	default:
		fatal("bad client state: %d", client->state);
	}

	/* send reason to client */
	if (notify && reason && client->state != CL_CANCEL) {
		/*
		 * don't send Ready pkt here, or client won't notice
		 * closed connection
		 */
		send_pooler_error(client, false, true, reason);
	}

	free_scram_state(&client->scram_state);
	if (client->login_user && client->login_user->mock_auth) {
		free(client->login_user);
		client->login_user = NULL;
	}
	if (client->db && client->db->fake) {
		free(client->db);
		client->db = NULL;
	}

	change_client_state(client, CL_JUSTFREE);
	if (!sbuf_close(&client->sbuf))
		log_noise("sbuf_close failed, retry later");
}

/*
 * Connection creation utilities
 */

static void connect_server(struct PgSocket *server, const struct sockaddr *sa, int salen)
{
	bool res;

	/* fill remote_addr */
	memset(&server->remote_addr, 0, sizeof(server->remote_addr));
	if (sa->sa_family == AF_UNIX) {
		pga_set(&server->remote_addr, AF_UNIX, server->pool->db->port);
	} else {
		pga_copy(&server->remote_addr, sa);
	}

	slog_debug(server, "launching new connection to server");

	/* start connecting */
	res = sbuf_connect(&server->sbuf, sa, salen,
			   cf_server_connect_timeout / USEC);
	if (!res)
		log_noise("failed to launch new connection");
}

static void dns_callback(void *arg, const struct sockaddr *sa, int salen)
{
	struct PgSocket *server = arg;
	struct PgDatabase *db = server->pool->db;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_in6;

	server->dns_token = NULL;

	if (!sa) {
		disconnect_server(server, true, "server DNS lookup failed");
		return;
	} else if (sa->sa_family == AF_INET) {
		char buf[64];
		memcpy(&sa_in, sa, sizeof(sa_in));
		sa_in.sin_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in;
		salen = sizeof(sa_in);
		slog_debug(server, "dns_callback: inet4: %s",
			   sa2str(sa, buf, sizeof(buf)));
	} else if (sa->sa_family == AF_INET6) {
		char buf[64];
		memcpy(&sa_in6, sa, sizeof(sa_in6));
		sa_in6.sin6_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in6;
		salen = sizeof(sa_in6);
		slog_debug(server, "dns_callback: inet6: %s",
			   sa2str(sa, buf, sizeof(buf)));
	} else {
		disconnect_server(server, true, "unknown address family: %d", sa->sa_family);
		return;
	}

	connect_server(server, sa, salen);
}

static void dns_connect(struct PgSocket *server)
{
	struct sockaddr_un sa_un;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_in6;
	struct sockaddr *sa;
	struct PgDatabase *db = server->pool->db;
	const char *host = db->host;
	int sa_len;
	int res;

	if (!host || host[0] == '/' || host[0] == '@') {
		const char *unix_dir;

		memset(&sa_un, 0, sizeof(sa_un));
		sa_un.sun_family = AF_UNIX;
		unix_dir = host ? host : cf_unix_socket_dir;
		if (!unix_dir || !*unix_dir) {
			log_error("unix socket dir not configured: %s", db->name);
			disconnect_server(server, false, "cannot connect");
			return;
		}
		snprintf(sa_un.sun_path, sizeof(sa_un.sun_path),
			 "%s/.s.PGSQL.%d", unix_dir, db->port);
		slog_noise(server, "unix socket: %s", sa_un.sun_path);
		if (unix_dir[0] == '@') {
			/*
			 * By convention, for abstract Unix sockets,
			 * only the length of the string is the
			 * sockaddr length.
			 */
			sa_len = offsetof(struct sockaddr_un, sun_path) + strlen(sa_un.sun_path);
			sa_un.sun_path[0] = '\0';
		}
		else {
			sa_len = sizeof(sa_un);
		}
		sa = (struct sockaddr *)&sa_un;
		res = 1;
	} else if (strchr(host, ':')) {  /* assume IPv6 address on any : in addr */
		slog_noise(server, "inet6 socket: %s", host);
		memset(&sa_in6, 0, sizeof(sa_in6));
		sa_in6.sin6_family = AF_INET6;
		res = inet_pton(AF_INET6, host, &sa_in6.sin6_addr);
		sa_in6.sin6_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in6;
		sa_len = sizeof(sa_in6);
	} else { /* else try IPv4 */
		slog_noise(server, "inet socket: %s", host);
		memset(&sa_in, 0, sizeof(sa_in));
		sa_in.sin_family = AF_INET;
		res = inet_pton(AF_INET, host, &sa_in.sin_addr);
		sa_in.sin_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in;
		sa_len = sizeof(sa_in);
	}

	/* if simple parse failed, use DNS */
	if (res != 1) {
		struct DNSToken *tk;
		slog_noise(server, "dns socket: %s", host);
		/* launch dns lookup */
		tk = adns_resolve(adns, host, dns_callback, server);
		if (tk)
			server->dns_token = tk;
		return;
	}

	connect_server(server, sa, sa_len);
}

PgSocket *compare_connections_by_time(PgSocket *lhs, PgSocket *rhs)
{
	if (!lhs)
		return rhs;
	if (!rhs)
		return lhs;
	return lhs->request_time < rhs->request_time ? lhs : rhs;
}

/* evict the single most idle connection from among all pools to make room in the db */
bool evict_connection(PgDatabase *db)
{
	struct List *item;
	PgPool *pool;
	PgSocket *oldest_connection = NULL;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db != db)
			continue;
		oldest_connection = compare_connections_by_time(oldest_connection, last_socket(&pool->idle_server_list));
		/* only evict testing connections if nobody's waiting */
		if (statlist_empty(&pool->waiting_client_list)) {
			oldest_connection = compare_connections_by_time(oldest_connection, last_socket(&pool->used_server_list));
			oldest_connection = compare_connections_by_time(oldest_connection, last_socket(&pool->tested_server_list));
		}
	}

	if (oldest_connection) {
		disconnect_server(oldest_connection, true, "evicted");
		return true;
	}
	return false;
}

/* evict the single most idle connection from among all pools to make room in the user */
bool evict_user_connection(PgUser *user)
{
	struct List *item;
	PgPool *pool;
	PgSocket *oldest_connection = NULL;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->user != user)
			continue;
		oldest_connection = compare_connections_by_time(oldest_connection, last_socket(&pool->idle_server_list));
		/* only evict testing connections if nobody's waiting */
		if (statlist_empty(&pool->waiting_client_list)) {
			oldest_connection = compare_connections_by_time(oldest_connection, last_socket(&pool->used_server_list));
			oldest_connection = compare_connections_by_time(oldest_connection, last_socket(&pool->tested_server_list));
		}
	}

	if (oldest_connection) {
		disconnect_server(oldest_connection, true, "evicted");
		return true;
	}
	return false;
}

/* the pool needs new connection, if possible */
void launch_new_connection(PgPool *pool)
{
	PgSocket *server;
	int max;

	/* allow only small number of connection attempts at a time */
	if (!statlist_empty(&pool->new_server_list)) {
		log_debug("launch_new_connection: already progress");
		return;
	}

	/* if server bounces, don't retry too fast */
	if (pool->last_connect_failed) {
		usec_t now = get_cached_time();
		if (now - pool->last_connect_time < cf_server_login_retry) {
			log_debug("launch_new_connection: last failed, not launching new connection yet, still waiting %" PRIu64 " s",
				  (cf_server_login_retry - (now - pool->last_connect_time)) / USEC);
			return;
		}
	}

	max = pool_server_count(pool);

	/* when a cancel request is queued allow connections up to twice the pool size */
	if (!statlist_empty(&pool->cancel_req_list) && max < (2 * pool_pool_size(pool))) {
		log_debug("launch_new_connection: bypass pool limitations for cancel request");
		goto force_new;
	}

	/* is it allowed to add servers? */
	if (max >= pool_pool_size(pool) && pool->welcome_msg_ready) {
		/* should we use reserve pool? */
		if (cf_res_pool_timeout && pool_res_pool_size(pool)) {
			usec_t now = get_cached_time();
			PgSocket *c = first_socket(&pool->waiting_client_list);
			if (c && (now - c->request_time) >= cf_res_pool_timeout) {
				if (max < pool_pool_size(pool) + pool_res_pool_size(pool)) {
					slog_warning(c, "taking connection from reserve_pool");
					goto allow_new;
				}
			}
		}
		log_debug("launch_new_connection: pool full (%d >= %d)",
				max, pool_pool_size(pool));
		return;
	}

allow_new:
	max = database_max_connections(pool->db);
	if (max > 0) {
		/* try to evict unused connections first */
		while (pool->db->connection_count >= max) {
			if (!evict_connection(pool->db)) {
				break;
			}
		}
		if (pool->db->connection_count >= max) {
			log_debug("launch_new_connection: database '%s' full (%d >= %d)",
				  pool->db->name, pool->db->connection_count, max);
			return;
		}
	}

	max = user_max_connections(pool->user);
	if (max > 0) {
		/* try to evict unused connection first */
		while (pool->user->connection_count >= max) {
			if (!evict_user_connection(pool->user)) {
				break;
			}
		}
		if (pool->user->connection_count >= max) {
			log_debug("launch_new_connection: user '%s' full (%d >= %d)",
				  pool->user->name, pool->user->connection_count, max);
			return;
		}
	}

force_new:
	/* get free conn object */
	server = slab_alloc(server_cache);
	if (!server) {
		log_debug("launch_new_connection: no memory");
		return;
	}

	/* initialize it */
	server->pool = pool;
	server->login_user = server->pool->user;
	server->connect_time = get_cached_time();
	pool->last_connect_time = get_cached_time();
	change_server_state(server, SV_LOGIN);
	pool->db->connection_count++;
	pool->user->connection_count++;

	dns_connect(server);
}

/* new client connection attempt */
PgSocket *accept_client(int sock, bool is_unix)
{
	bool res;
	PgSocket *client;

	/* get free PgSocket */
	client = slab_alloc(client_cache);
	if (!client) {
		log_warning("cannot allocate client struct");
		safe_close(sock);
		return NULL;
	}

	client->connect_time = client->request_time = get_cached_time();
	client->query_start = 0;

	/* FIXME: take local and remote address from pool_accept() */
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
	if (client->db->fake) {
		if (cf_log_connections)
			slog_info(client, "login failed: db=%s user=%s", client->db->name, client->login_user->name);
		disconnect_client(client, true, "no such database: %s", client->db->name);
		return false;
	}

	if (client->db->db_disabled) {
		disconnect_client(client, true, "database \"%s\" is disabled", client->db->name);
		return false;
	}

	switch (client->state) {
	case CL_LOGIN:
		change_client_state(client, CL_ACTIVE);
	case CL_ACTIVE:
		break;
	default:
		fatal("bad client state: %d", client->state);
	}

	client->wait_for_auth = false;

	/* check if we know server signature */
	if (!client->pool->welcome_msg_ready) {
		log_debug("finish_client_login: no welcome message, pause");
		client->wait_for_welcome = true;
		pause_client(client);
		if (cf_pause_mode == P_NONE)
			launch_new_connection(client->pool);
		return false;
	}
	client->wait_for_welcome = false;

	/* send the message */
	if (!welcome_client(client))
		return false;

	slog_debug(client, "logged in");

	return true;
}

/* client->cancel_key has requested client key */
void accept_cancel_request(PgSocket *req)
{
	struct List *pitem, *citem;
	PgPool *pool = NULL;
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
		statlist_for_each(citem, &pool->waiting_client_list) {
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
		/* let administrative cancel be handled elsewhere */
		if (main_client->pool->db->admin) {
			disconnect_client(req, false, "cancel request for console client");
			admin_handle_cancel(main_client);
			return;
		}

		disconnect_client(req, false, "cancel request for idle client");

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
	if (!res)
		log_warning("sending cancel request failed: %s", strerror(errno));

	change_client_state(req, CL_JUSTFREE);
}

bool use_client_socket(int fd, PgAddr *addr,
		       const char *dbname, const char *username,
		       uint64_t ckey, int oldfd, int linkfd,
		       const char *client_enc, const char *std_string,
		       const char *datestyle, const char *timezone,
		       const char *password,
		       const char *scram_client_key, int scram_client_key_len,
		       const char *scram_server_key, int scram_server_key_len)
{
	PgDatabase *db = find_database(dbname);
	PgSocket *client;
	PktBuf tmp;

	/* if the database not found, it's an auto database -> registering... */
	if (!db) {
		db = register_auto_database(dbname);
		if (!db)
			return true;
	}

	if (scram_client_key || scram_server_key) {
		PgUser *user;

		if (!scram_client_key || !scram_server_key) {
			log_error("incomplete SCRAM key data");
			return false;
		}
		if (sizeof(user->scram_ClientKey) != scram_client_key_len
		    || sizeof(user->scram_ServerKey) != scram_server_key_len) {
			log_error("incompatible SCRAM key data");
			return false;
		}
		if (db->forced_user) {
			log_error("SCRAM key data received for forced user");
			return false;
		}
		if (cf_auth_type == AUTH_PAM) {
			log_error("SCRAM key data received for PAM user");
			return false;
		}
		user = find_user(username);
		if (!user && db->auth_user)
			user = add_db_user(db, username, password);

		if (!user)
			return false;

		memcpy(user->scram_ClientKey, scram_client_key, sizeof(user->scram_ClientKey));
		memcpy(user->scram_ServerKey, scram_server_key, sizeof(user->scram_ServerKey));
		user->has_scram_keys = true;
	}

	client = accept_client(fd, pga_is_unix(addr));
	if (client == NULL)
		return false;
	client->suspended = true;

	if (!set_pool(client, dbname, username, password, true))
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
		       const char *datestyle, const char *timezone,
		       const char *password,
		       const char *scram_client_key, int scram_client_key_len,
		       const char *scram_server_key, int scram_server_key_len)
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

	if (db->forced_user) {
		user = db->forced_user;
	} else if (cf_auth_type == AUTH_PAM) {
		user = add_pam_user(username, password);
	} else {
		user = find_user(username);
	}
	if (!user && db->auth_user)
		user = add_db_user(db, username, password);

	pool = get_pool(db, user);
	if (!pool)
		return false;

	server = slab_alloc(server_cache);
	if (!server)
		return false;

	res = sbuf_accept(&server->sbuf, fd, pga_is_unix(addr));
	if (!res)
		return false;

	db->connection_count++;

	server->suspended = true;
	server->pool = pool;
	server->login_user = user;
	server->connect_time = server->request_time = get_cached_time();
	server->query_start = 0;

	fill_remote_addr(server, fd, pga_is_unix(addr));
	fill_local_addr(server, fd, pga_is_unix(addr));

	if (linkfd) {
		server->ready = false;
		change_server_state(server, SV_ACTIVE);
	} else {
		server->ready = true;
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
	struct List *item;

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

static void for_each_server_filtered(PgPool *pool, void (*func)(PgSocket *sk), bool (*filter)(PgSocket *sk, void *arg), void *filter_arg)
{
	struct List *item;
	PgSocket *sk;

	statlist_for_each(item, &pool->idle_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}

	statlist_for_each(item, &pool->used_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}

	statlist_for_each(item, &pool->tested_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}

	statlist_for_each(item, &pool->active_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}

	statlist_for_each(item, &pool->new_server_list) {
		sk = container_of(item, PgSocket, head);
		if (filter(sk, filter_arg))
			func(sk);
	}
}


static void tag_dirty(PgSocket *sk)
{
	sk->close_needed = true;
}

void tag_pool_dirty(PgPool *pool)
{
	struct List *item, *tmp;
	struct PgSocket *server;

	/*
	 * Don't tag the admin pool as dirty, since this is not an actual postgres
	 * server. Marking it as dirty breaks connecting to the pgbouncer admin
	 * database on future connections.
	 */
	if (pool->db->admin)
		return;

	/* reset welcome msg */
	if (pool->welcome_msg) {
		pktbuf_free(pool->welcome_msg);
		pool->welcome_msg = NULL;
	}
	pool->welcome_msg_ready = false;

	/* drop all existing servers ASAP */
	for_each_server(pool, tag_dirty);

	/* drop servers login phase immediately */
	statlist_for_each_safe(item, &pool->new_server_list, tmp) {
		server = container_of(item, PgSocket, head);
		disconnect_server(server, true, "connect string changed");
	}
}

void tag_database_dirty(PgDatabase *db)
{
	struct List *item;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db == db)
			tag_pool_dirty(pool);
	}
}

void tag_autodb_dirty(void)
{
	struct List *item, *tmp;
	PgDatabase *db;
	PgPool *pool;

	/*
	 * reload databases.
	 */
	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);
		if (db->db_auto)
			register_auto_database(db->name);
	}
	statlist_for_each_safe(item, &autodatabase_idle_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (db->db_auto)
			register_auto_database(db->name);
	}
	/*
	 * reload pools
	 */
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->db_auto)
			tag_pool_dirty(pool);
	}
}

static bool server_remote_addr_filter(PgSocket *sk, void *arg) {
	PgAddr *addr = arg;

	return (pga_cmp_addr(&sk->remote_addr, addr) == 0);
}

void tag_host_addr_dirty(const char *host, const struct sockaddr *sa)
{
	struct List *item;
	PgPool *pool;
	PgAddr addr;

	memset(&addr, 0, sizeof(addr));
	pga_copy(&addr, sa);

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->host && strcmp(host, pool->db->host) == 0) {
			for_each_server_filtered(pool, tag_dirty, server_remote_addr_filter, &addr);
		}
	}
}


/* move objects from justfree_* to free_* lists */
void reuse_just_freed_objects(void)
{
	struct List *tmp, *item;
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
		if (sbuf_is_closed(&sk->sbuf)) {
			change_client_state(sk, CL_FREE);
		} else if (close_works) {
			close_works = sbuf_close(&sk->sbuf);
		}
	}
	statlist_for_each_safe(item, &justfree_server_list, tmp) {
		sk = container_of(item, PgSocket, head);
		if (sbuf_is_closed(&sk->sbuf)) {
			change_server_state(sk, SV_FREE);
		} else if (close_works) {
			close_works = sbuf_close(&sk->sbuf);
		}
	}
}

void objects_cleanup(void)
{
	struct List *item, *tmp;
	PgDatabase *db;

	/* close can be postpones, just in case call twice */
	reuse_just_freed_objects();
	reuse_just_freed_objects();

	statlist_for_each_safe(item, &autodatabase_idle_list, tmp) {
		db = container_of(item, PgDatabase, head);
		kill_database(db);
	}
	statlist_for_each_safe(item, &database_list, tmp) {
		db = container_of(item, PgDatabase, head);
		kill_database(db);
	}

	memset(&login_client_list, 0, sizeof login_client_list);
	memset(&user_list, 0, sizeof user_list);
	memset(&database_list, 0, sizeof database_list);
	memset(&pool_list, 0, sizeof pool_list);
	memset(&user_tree, 0, sizeof user_tree);
	memset(&autodatabase_idle_list, 0, sizeof autodatabase_idle_list);

	slab_destroy(server_cache);
	server_cache = NULL;
	slab_destroy(client_cache);
	client_cache = NULL;
	slab_destroy(db_cache);
	db_cache = NULL;
	slab_destroy(pool_cache);
	pool_cache = NULL;
	slab_destroy(user_cache);
	user_cache = NULL;
	slab_destroy(iobuf_cache);
	iobuf_cache = NULL;
}
