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

#include <usual/err.h>
#include <usual/safeio.h>
#include <usual/slab.h>

/* those items will be allocated as needed, never freed */
STATLIST(user_list);
STATLIST(database_list);
STATLIST(pool_list);
STATLIST(peer_list);
STATLIST(peer_pool_list);

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
 * The global prepared statement cache, which deduplicates prepared statements
 * sent by the clients statements by storing every unique prepared statement
 * only once.
 */
PgPreparedStatement *prepared_statements = NULL;

/*
 * client and server objects will be pre-allocated
 * they are always in either active or free lists
 * in addition to others.
 */
STATLIST(login_client_list);

struct Slab *server_cache;
struct Slab *client_cache;
struct Slab *db_cache;
struct Slab *peer_cache;
struct Slab *peer_pool_cache;
struct Slab *pool_cache;
struct Slab *user_cache;
struct Slab *credentials_cache;
struct Slab *iobuf_cache;
struct Slab *outstanding_request_cache;
struct Slab *var_list_cache;
struct Slab *server_prepared_statement_cache;
unsigned long long int last_pgsocket_id;

/*
 * libevent may still report events when event_del()
 * is called from somewhere else.  So hide just freed
 * PgSockets for one loop.
 */
static STATLIST(justfree_client_list);
static STATLIST(justfree_server_list);

/* init autodb idle list */
STATLIST(autodatabase_idle_list);

const char *replication_type_parameters[] = {
	[REPLICATION_NONE] = "no",
	[REPLICATION_LOGICAL] = "database",
	[REPLICATION_PHYSICAL] = "yes",
};

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
	client->vars.var_list = slab_alloc(var_list_cache);
	client->state = CL_FREE;
	client->client_prepared_statements = NULL;

	client->id = ++last_pgsocket_id;
}

static void construct_server(void *obj)
{
	PgSocket *server = obj;

	memset(server, 0, sizeof(PgSocket));
	list_init(&server->head);
	sbuf_init(&server->sbuf, server_proto);
	server->vars.var_list = slab_alloc(var_list_cache);
	server->state = SV_FREE;
	server->server_prepared_statements = NULL;
	statlist_init(&server->outstanding_requests, "outstanding_requests");

	server->id = ++last_pgsocket_id;
}

/* compare string with PgGlobalUser->credentials.name, for usage with btree */
static int global_user_node_cmp(uintptr_t userptr, struct AANode *node)
{
	const char *name = (const char *)userptr;
	PgGlobalUser *global_user = container_of(node, PgGlobalUser, credentials.tree_node);
	return strcmp(name, global_user->credentials.name);
}

/* compare string with PgCredentials->name, for usage with btree */
static int credentials_node_cmp(uintptr_t userptr, struct AANode *node)
{
	const char *name = (const char *)userptr;
	PgCredentials *credentials = container_of(node, PgCredentials, tree_node);
	return strcmp(name, credentials->name);
}

/* destroy PgCredentials, for usage with btree */
static void credentials_node_release(struct AANode *node, void *arg)
{
	PgCredentials *user = container_of(node, PgCredentials, tree_node);
	slab_free(credentials_cache, user);
}

/* initialization before config loading */
void init_objects(void)
{
	aatree_init(&user_tree, global_user_node_cmp, NULL);
	aatree_init(&pam_user_tree, credentials_node_cmp, NULL);
	user_cache = slab_create("user_cache", sizeof(PgGlobalUser), 0, NULL, USUAL_ALLOC);
	credentials_cache = slab_create("credentials_cache", sizeof(PgCredentials), 0, NULL, USUAL_ALLOC);
	db_cache = slab_create("db_cache", sizeof(PgDatabase), 0, NULL, USUAL_ALLOC);
	peer_cache = slab_create("peer_cache", sizeof(PgDatabase), 0, NULL, USUAL_ALLOC);
	peer_pool_cache = slab_create("peer_pool_cache", sizeof(PgPool), 0, NULL, USUAL_ALLOC);
	pool_cache = slab_create("pool_cache", sizeof(PgPool), 0, NULL, USUAL_ALLOC);
	outstanding_request_cache = slab_create("outstanding_request_cache", sizeof(OutstandingRequest), 0, NULL, USUAL_ALLOC);

	if (!user_cache || !db_cache || !peer_cache || !peer_pool_cache || !pool_cache)
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
	var_list_cache = slab_create("var_list_cache", sizeof(struct PStr *) * get_num_var_cached(), 0, NULL, USUAL_ALLOC);
	server_prepared_statement_cache = slab_create("server_prepared_statement_cache", sizeof(PgServerPreparedStatement), 0, NULL, USUAL_ALLOC);
}

/* free all memory related to the given client */
static void client_free(PgSocket *client)
{
	free_client_prepared_statements(client);
	varcache_clean(&client->vars);
	slab_free(var_list_cache, client->vars.var_list);
	slab_free(client_cache, client);
}

/* free all memory related to the given server */
static void server_free(PgSocket *server)
{
	struct List *el, *tmp_l;
	OutstandingRequest *request;

	statlist_for_each_safe(el, &server->outstanding_requests, tmp_l) {
		request = container_of(el, OutstandingRequest, node);
		statlist_remove(&server->canceling_clients, el);
		if (request->server_ps)
			free_server_prepared_statement(request->server_ps);
		slab_free(outstanding_request_cache, request);
	}

	free_server_prepared_statements(server);
	varcache_clean(&server->vars);
	slab_free(var_list_cache, server->vars.var_list);
	slab_free(server_cache, server);
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
	case CL_ACTIVE_CANCEL:
		statlist_remove(&pool->active_cancel_req_list, &client->head);
		break;
	case CL_WAITING_CANCEL:
		statlist_remove(&pool->waiting_cancel_req_list, &client->head);
		break;
	default:
		fatal("bad cur client state: %d", client->state);
	}

	client->state = newstate;

	/* put to new location */
	switch (client->state) {
	case CL_FREE:
		client_free(client);
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
	case CL_ACTIVE_CANCEL:
		statlist_append(&pool->active_cancel_req_list, &client->head);
		break;
	case CL_WAITING_CANCEL:
		statlist_append(&pool->waiting_cancel_req_list, &client->head);
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
	case SV_BEING_CANCELED:
		statlist_remove(&pool->being_canceled_server_list, &server->head);
		break;
	case SV_IDLE:
		statlist_remove(&pool->idle_server_list, &server->head);
		break;
	case SV_ACTIVE:
		statlist_remove(&pool->active_server_list, &server->head);
		break;
	case SV_ACTIVE_CANCEL:
		statlist_remove(&pool->active_cancel_server_list, &server->head);
		break;
	default:
		fatal("bad old server state: %d", server->state);
	}

	server->state = newstate;

	/* put to new location */
	switch (server->state) {
	case SV_FREE:
		server_free(server);
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
	case SV_BEING_CANCELED:
		statlist_append(&pool->being_canceled_server_list, &server->head);
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
	case SV_ACTIVE_CANCEL:
		statlist_append(&pool->active_cancel_server_list, &server->head);
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
	if (p1->user_credentials != p2->user_credentials) {
		if (p1->user_credentials == NULL) {
			return 1;
		}
		if (p2->user_credentials == NULL) {
			return -1;
		}
		return strcmp(p1->user_credentials->name, p2->user_credentials->name);
	}
	return 0;
}

/* compare pool names, for use with put_in_order */
static int cmp_peer_pool(struct List *i1, struct List *i2)
{
	PgPool *p1 = container_of(i1, PgPool, head);
	PgPool *p2 = container_of(i2, PgPool, head);
	if (p1->db != p2->db)
		return p1->db->peer_id - p2->db->peer_id;
	return 0;
}

/* compare user names, for use with put_in_order */
static int cmp_user(struct List *i1, struct List *i2)
{
	PgGlobalUser *u1 = container_of(i1, PgGlobalUser, head);
	PgGlobalUser *u2 = container_of(i2, PgGlobalUser, head);
	return strcmp(u1->credentials.name, u2->credentials.name);
}

/* compare db names, for use with put_in_order */
static int cmp_peer(struct List *i1, struct List *i2)
{
	PgDatabase *db1 = container_of(i1, PgDatabase, head);
	PgDatabase *db2 = container_of(i2, PgDatabase, head);
	return db1->peer_id - db2->peer_id;
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
PgDatabase *add_peer(const char *name, int peer_id)
{
	PgDatabase *peer = find_peer(peer_id);

	/* create new object if needed */
	if (peer == NULL) {
		peer = slab_alloc(peer_cache);
		if (!peer)
			return NULL;

		list_init(&peer->head);
		peer->peer_id = peer_id;
		put_in_order(&peer->head, &peer_list, cmp_peer);
	}

	return peer;
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
		aatree_init(&db->user_tree, credentials_node_cmp, credentials_node_release);
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

PgGlobalUser *update_global_user_passwd(PgGlobalUser *user, const char *passwd)
{
	Assert(user);
	passwd = passwd ? passwd : "";
	safe_strcpy(user->credentials.passwd, passwd, sizeof(user->credentials.passwd));
	user->credentials.dynamic_passwd = strlen(passwd) == 0;
	return user;
}

static PgGlobalUser *add_new_global_user(const char *name, const char *passwd)
{
	PgGlobalUser *user = slab_alloc(user_cache);

	if (!user)
		return NULL;

	user->credentials.global_user = user;

	list_init(&user->head);
	list_init(&user->pool_list);
	safe_strcpy(user->credentials.name, name, sizeof(user->credentials.name));
	put_in_order(&user->head, &user_list, cmp_user);

	aatree_insert(&user_tree, (uintptr_t)user->credentials.name, &user->credentials.tree_node);
	user->pool_mode = POOL_INHERIT;
	user->pool_size = -1;

	return update_global_user_passwd(user, passwd);
}

/*
 * Add dynamic credentials to this database. This should be used for dynamic
 * credentials, that were retrieved using the auth_query.
 */
PgCredentials *add_dynamic_credentials(PgDatabase *db, const char *name, const char *passwd)
{
	PgCredentials *credentials = NULL;
	struct AANode *node;

	/*
	 * Dynamic credentials are stored in an aatree that's specific to the
	 * database. So we cannot use find_global_user() here.
	 */
	node = aatree_search(&db->user_tree, (uintptr_t)name);
	credentials = node ? container_of(node, PgCredentials, tree_node) : NULL;

	if (credentials == NULL) {
		credentials = slab_alloc(credentials_cache);
		if (!credentials)
			return NULL;

		safe_strcpy(credentials->name, name, sizeof(credentials->name));

		credentials->global_user = find_or_add_new_global_user(name, NULL);
		if (!credentials->global_user) {
			slab_free(credentials_cache, credentials);
			return NULL;
		}

		aatree_insert(&db->user_tree, (uintptr_t)credentials->name, &credentials->tree_node);
	}

	safe_strcpy(credentials->passwd, passwd, sizeof(credentials->passwd));
	credentials->dynamic_passwd = true;

	return credentials;
}

/* Add PAM user. The logic is same as in add_dynamic_credentials */
PgCredentials *add_pam_credentials(const char *name, const char *passwd)
{
	PgCredentials *credentials = NULL;
	struct AANode *node;

	node = aatree_search(&pam_user_tree, (uintptr_t)name);
	credentials = node ? container_of(node, PgCredentials, tree_node) : NULL;

	if (credentials == NULL) {
		credentials = slab_alloc(credentials_cache);
		if (!credentials)
			return NULL;

		safe_strcpy(credentials->name, name, sizeof(credentials->name));

		credentials->global_user = find_or_add_new_global_user(name, NULL);
		if (!credentials->global_user) {
			slab_free(credentials_cache, credentials);
			return NULL;
		}

		aatree_insert(&pam_user_tree, (uintptr_t)credentials->name, &credentials->tree_node);
	}
	if (passwd)
		safe_strcpy(credentials->passwd, passwd, sizeof(credentials->passwd));
	return credentials;
}

/* create separate PgCredentials object for this database */
PgCredentials *force_user_credentials(PgDatabase *db, const char *name, const char *passwd)
{
	PgCredentials *credentials = db->forced_user_credentials;
	if (!credentials) {
		credentials = slab_alloc(credentials_cache);
		if (!credentials)
			return NULL;

		credentials->global_user = find_or_add_new_global_user(name, NULL);
		if (!credentials->global_user) {
			slab_free(credentials_cache, credentials);
			return NULL;
		}
	}
	safe_strcpy(credentials->name, name, sizeof(credentials->name));
	safe_strcpy(credentials->passwd, passwd, sizeof(credentials->passwd));
	db->forced_user_credentials = credentials;
	return credentials;
}

/* find an existing database */
PgDatabase *find_peer(int peer_id)
{
	struct List *item;
	PgDatabase *peer;
	statlist_for_each(item, &peer_list) {
		peer = container_of(item, PgDatabase, head);
		if (peer->peer_id == peer_id)
			return peer;
	}
	return NULL;
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

/*
 * Similar to find_database. In case database is not found, it will try to register
 * it if auto-database ('*') is configured.
 */
PgDatabase *find_or_register_database(PgSocket *connection, const char *name)
{
	PgDatabase *db = find_database(name);
	if (db == NULL) {
		db = register_auto_database(name);
		if (db != NULL) {
			slog_info(connection,
				  "registered new auto-database: %s", name);
		}
	}
	return db;
}

/* find existing user */
PgGlobalUser *find_global_user(const char *name)
{
	PgGlobalUser *user = NULL;
	struct AANode *node;

	node = aatree_search(&user_tree, (uintptr_t)name);
	/* we use the tree_node in the embedded PgCredentials struct */
	user = node ? (PgGlobalUser *) container_of(node, PgCredentials, tree_node) : NULL;
	return user;
}

PgCredentials *find_global_credentials(const char *name)
{
	PgGlobalUser *user = find_global_user(name);
	if (!user)
		return NULL;
	return &user->credentials;
}


/* create new pool object */
static PgPool *new_pool(PgDatabase *db, PgCredentials *user_credentials)
{
	PgPool *pool;

	pool = slab_alloc(pool_cache);
	if (!pool)
		return NULL;

	list_init(&pool->head);
	list_init(&pool->map_head);
	pool->orig_vars.var_list = slab_alloc(var_list_cache);

	pool->user_credentials = user_credentials;
	pool->db = db;

	statlist_init(&pool->active_client_list, "active_client_list");
	statlist_init(&pool->waiting_client_list, "waiting_client_list");
	statlist_init(&pool->active_server_list, "active_server_list");
	statlist_init(&pool->idle_server_list, "idle_server_list");
	statlist_init(&pool->tested_server_list, "tested_server_list");
	statlist_init(&pool->used_server_list, "used_server_list");
	statlist_init(&pool->new_server_list, "new_server_list");
	statlist_init(&pool->waiting_cancel_req_list, "waiting_cancel_req_list");
	statlist_init(&pool->active_cancel_req_list, "active_cancel_req_list");
	statlist_init(&pool->active_cancel_server_list, "active_cancel_server_list");
	statlist_init(&pool->being_canceled_server_list, "being_canceled_server_list");

	list_append(&user_credentials->global_user->pool_list, &pool->map_head);

	/* keep pools in db/user order to make stats faster */
	put_in_order(&pool->head, &pool_list, cmp_pool);

	return pool;
}


/*
 * create new peer pool object
 *
 * This pool should only be used to forward cancellations to other pgbouncers
 * behind the same load balancer. The user field of this pool is NULL, because
 * cancellations don't need a user.
 */
static PgPool *new_peer_pool(PgDatabase *db)
{
	PgPool *pool;

	pool = slab_alloc(peer_pool_cache);
	if (!pool)
		return NULL;

	list_init(&pool->head);
	list_init(&pool->map_head);
	pool->orig_vars.var_list = slab_alloc(var_list_cache);

	pool->db = db;

	statlist_init(&pool->new_server_list, "new_server_list");
	statlist_init(&pool->waiting_cancel_req_list, "waiting_cancel_req_list");
	statlist_init(&pool->active_cancel_req_list, "active_cancel_req_list");
	statlist_init(&pool->active_cancel_server_list, "active_cancel_server_list");

	/* keep pools in peer_id order to make stats faster */
	put_in_order(&pool->head, &peer_pool_list, cmp_peer_pool);

	return pool;
}
/* find pool object, create if needed */
PgPool *get_pool(PgDatabase *db, PgCredentials *user_credentials)
{
	struct List *item;
	PgPool *pool;

	if (!db || !user_credentials)
		return NULL;

	list_for_each(item, &user_credentials->global_user->pool_list) {
		pool = container_of(item, PgPool, map_head);
		if (pool->db == db)
			return pool;
	}

	return new_pool(db, user_credentials);
}

/* find pool object for the peer */
PgPool *get_peer_pool(PgDatabase *db)
{
	if (!db)
		return NULL;
	if (!db->pool) {
		db->pool = new_peer_pool(db);
	}
	return db->pool;
}

/* deactivate socket and put into wait queue */
static void pause_client(PgSocket *client)
{
	Assert(client->state == CL_ACTIVE || client->state == CL_LOGIN);
	slog_debug(client, "pause_client");

	if (cf_shutdown == SHUTDOWN_WAIT_FOR_SERVERS) {
		disconnect_client(client, true, "server shutting down");
		return;
	}
	change_client_state(client, CL_WAITING);
	if (!sbuf_pause(&client->sbuf))
		disconnect_client(client, true, "pause failed");
}

/*
 * Deactivate the client socket and put it into the cancel request wait queue.
 * We're not expecting any data from the client anymore at this point at all.
 * But some clients might send some anyway (specifically the Go client). Since
 * we don't care about any of that extra data we just stop reading from the
 * socket.
 */
static void pause_cancel_request(PgSocket *client)
{
	Assert(client->state == CL_LOGIN);

	slog_debug(client, "pause_cancel_request");
	change_client_state(client, CL_WAITING_CANCEL);
	if (!sbuf_pause(&client->sbuf))
		disconnect_client(client, true, "pause cancel request failed");
}


/* wake client from wait */
void activate_client(PgSocket *client)
{
	Assert(client->state == CL_WAITING || client->state == CL_WAITING_LOGIN);

	Assert(client->wait_start > 0);

	/* account for time client spent waiting for server */
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
	disconnect_client(client, true, "server login has been failing, cached error: %s (server_login_retry)", pool->last_connect_failed_message);

	/*
	 * Try to launch a new connection.  (launch_new_connection()
	 * will check for server_login_retry etc.)  The usual relaunch
	 * from janitor.c won't do anything, as there are no waiting
	 * clients, so we need to do it here to get any new servers
	 * eventually.
	 */
	launch_new_connection(pool, /* evict_if_needed= */ true);

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

	slog_noise(client, "find_server: client had no linked server yet");
	/* try to get idle server, if allowed */
	if (cf_pause_mode == P_PAUSE || pool->db->db_paused) {
		server = NULL;
	} else if (client->replication && !sending_auth_query(client)) {
		/*
		 * For replication clients we open dedicated server connections. These
		 * connections are linked to a client as soon as the server is ready,
		 * instead of lazily being assigned to a client only when the client
		 * sends a query. So if we reach this point we know that that has not
		 * happened yet, and we need to create a new replication connection for
		 * this client.
		 */
		launch_new_connection(pool, /*evict_if_needed= */ true);
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
		PktBuf *msg;
		const WelcomeVarLookup *lk, *tmp;

		slog_noise(client, "linking client to S-%p", server);
		client->link = server;
		server->link = client;
		server->pool->stats.server_assignment_count++;

		if (client->state == CL_ACTIVE && !client->wait_for_welcome) {
			msg = pktbuf_temp();
			HASH_ITER(hh, server->pool->welcome_vars, lk, tmp) {
				if (lk->value != NULL)
					pktbuf_write_ParameterStatus(msg, lk->name, lk->value);
			}

			res = pktbuf_send_immediate(msg, client);
			if (!res) {
				disconnect_client(client, true, "failed to send welcome vars to client");
			}
		}

		change_server_state(server, SV_ACTIVE);
		if (varchange) {
			server->setting_vars = true;
			server->ready = false;
			res = false;	/* don't process client data yet */
			slog_noise(client, "pausing client while applying vars");
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
	PgSocket *client;
	Assert(!server->replication);
	slog_debug(server, "reuse_on_release: replication %d", server->replication);
	client = first_socket(&pool->waiting_client_list);
	if (client && (!client->replication || sending_auth_query(client))) {
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

bool queue_fake_response(PgSocket *client, char request_type)
{
	bool res = true;
	PgSocket *server = client->link;
	Assert(server);

	if (request_type == PqMsg_Parse) {
		slog_debug(client, "Queuing fake ParseComplete packet");
		QUEUE_ParseComplete(res, server, client);
	} else if (request_type == PqMsg_Close) {
		slog_debug(client, "Queuing fake CloseComplete packet");
		QUEUE_CloseComplete(res, server, client);
	} else {
		fatal("Unknown fake request type %c", request_type);
	}
	return res;
}

/* Find an existing global user or add a new global user */
PgGlobalUser *find_or_add_new_global_user(const char *name, const char *passwd)
{
	PgGlobalUser *user = find_global_user(name);

	if (!user)
		user = add_new_global_user(name, passwd);

	return user;
}

/* Find an existing global credentials or add a new global credentials */
PgCredentials *find_or_add_new_global_credentials(const char *name, const char *passwd)
{
	PgGlobalUser *user = find_or_add_new_global_user(name, passwd);

	if (!user)
		return NULL;

	return &user->credentials;
}

/*
 * Adds a request to the outstanding requests queue, and schedule the given
 * action (see comments on ResponseAction for details).
 *
 * returns false if the required allocations failed
 */
bool add_outstanding_request(PgSocket *client, char type, ResponseAction action)
{
	OutstandingRequest *request = NULL;

	PgSocket *server = client->link;
	Assert(server);

	if (action == RA_FAKE && statlist_empty(&server->outstanding_requests)) {
		/*
		 * If there's no outstanding requests, we can send the response
		 * right away. And we're actually required to do that to make
		 * sure the client receives it, because we normally only send
		 * responses to fake requests right after we handle a response
		 * to a real request. So if none are outstanding, we won't send
		 * such a response.
		 */
		slog_noise(client, "add_outstanding_request: queueing fake response right away %c",
			   type);
		return queue_fake_response(client, type);
	}

	request = slab_alloc(outstanding_request_cache);
	if (request == NULL)
		return false;
	request->type = type;
	request->action = action;
	statlist_append(&server->outstanding_requests, &request->node);
	slog_noise(client, "add_outstanding_request: added %c, still outstanding %d",
		   type, statlist_count(&client->link->outstanding_requests));
	return true;
}

/*
 * If the next outstanding request is of one of the given types, pop it off the
 * queue. If it is of a different type, don't do anything.
 *
 * returns true if one of the given types was popped of off the queue.
 */
bool pop_outstanding_request(PgSocket *server, const char types[], bool *skip)
{
	OutstandingRequest *request;
	struct List *item = statlist_first(&server->outstanding_requests);
	if (!item)
		return false;

	request = container_of(item, OutstandingRequest, node);
	if (request->action == RA_FAKE) {
		/*
		 * This is weird, normally we should have already processed all fake
		 * requests at the end of the previous packet.
		 */
		slog_warning(server, "pop_outstanding_request: unexpected fake request of type %c", request->type);
		return false;
	}

	if (strchr(types, request->type) == NULL)
		return false;

	statlist_pop(&server->outstanding_requests);
	if (skip)
		*skip = request->action == RA_SKIP;
	slog_noise(server, "pop_outstanding_request: popped %c, still outstanding %d, skip %d",
		   request->type, statlist_count(&server->outstanding_requests), request->action == RA_SKIP);
	if (request->server_ps != NULL) {
		free_server_prepared_statement(request->server_ps);
	}
	slab_free(outstanding_request_cache, request);
	return true;
}

/*
 * Clear all outstanding requests until we reach response of any of the message
 * types in "types". Any Parse or Close statement requests that were still
 * outstanding will be unregistered or re-registered from the server its cache.
 */
bool clear_outstanding_requests_until(PgSocket *server, const char types[])
{
	struct List *item, *tmp;
	statlist_for_each_safe(item, &server->outstanding_requests, tmp) {
		OutstandingRequest *request = container_of(item, OutstandingRequest, node);
		char type = request->type;
		if (type == PqMsg_Parse && request->server_ps_query_id > 0) {
			unregister_prepared_statement(server, request->server_ps_query_id);
			slog_noise(server,
				   "failed prepared statement '" PREPARED_STMT_NAME_FORMAT "' removed from server cache, %d cached items",
				   request->server_ps_query_id,
				   HASH_COUNT(server->server_prepared_statements));
		} else if (type == PqMsg_Close && request->server_ps != NULL) {
			if (!add_prepared_statement(server, request->server_ps)) {
				if (server->link)
					disconnect_client(server->link, true, "out of memory");
				disconnect_server(server, true, "out of memory");
				return false;
			}
			slog_noise(server,
				   "prepared statement '%s' added back to server cache, %d cached items",
				   request->server_ps->ps->stmt_name,
				   HASH_COUNT(server->server_prepared_statements));
		}
		statlist_remove(&server->outstanding_requests, item);
		slab_free(outstanding_request_cache, request);

		if (strchr(types, type))
			break;
	}
	slog_noise(server, "clear_outstanding_requests_until_sync: still outstanding %d", statlist_count(&server->outstanding_requests));
	return true;
}

/* send reset query */
static bool reset_on_release(PgSocket *server)
{
	bool res;

	Assert(server->state == SV_TESTED);

	slog_debug(server, "resetting: %s", cf_server_reset_query);
	SEND_generic(res, server, PqMsg_Query, "s", cf_server_reset_query);
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
	usec_t server_lifetime = pool_server_lifetime(pool);

	if (age < server_lifetime)
		return false;

	/*
	 * Calculate the time that disconnects because of server_lifetime
	 * must be separated.  This avoids the need to re-launch lot
	 * of connections together.
	 */
	if (pool_pool_size(pool) > 0)
		lifetime_kill_gap = server_lifetime / pool_pool_size(pool);

	if (last_kill >= lifetime_kill_gap)
		return true;

	return false;
}

/* connecting/active -> idle, unlink if needed */
bool release_server(PgSocket *server)
{
	PgPool *pool = server->pool;
	SocketState newstate = SV_IDLE;
	struct List *cancel_item, *tmp;

	Assert(server->ready);

	/* remove from old list */
	switch (server->state) {
	case SV_BEING_CANCELED:
	case SV_ACTIVE:
		if (server->link) {
			server->link->link = NULL;
			server->link = NULL;
		}

		if (*cf_server_reset_query && (cf_server_reset_query_always ||
					       connection_pool_mode(server) == POOL_SESSION)) {
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

	statlist_for_each_safe(cancel_item, &server->canceling_clients, tmp) {
		PgSocket *cancel_client = container_of(cancel_item, PgSocket, cancel_head);
		/*
		 * If the cancel request is not in flight yet we can simply unlink
		 * the cancel_client. When a cancel request doesn't have a
		 * canceled_server linked to it forward_cancel_request will simply drop
		 * the cancel request without forwarding it anywhere.
		 */
		if (cancel_client->state == CL_WAITING_CANCEL) {
			cancel_client->canceled_server = NULL;
			statlist_remove(&server->canceling_clients, cancel_item);
		}
	}

	/* enforce lifetime immediately on release */
	if (server->state != SV_LOGIN && life_over(server)) {
		disconnect_server(server, true, "server lifetime over");
		pool->last_lifetime_disconnect = get_cached_time();
		return false;
	}

	if (statlist_count(&server->outstanding_requests) > 0) {
		/*
		 * We can't release the server if there are outstanding requests
		 * that haven't been responded to yet, otherwise the server
		 * might get linked to another client and it will get those
		 * responses when it does not expect them. To be on the safe
		 * side we simply close this connection.
		 */
		disconnect_server(server, true, "client disconnected with queries in progress");
		return true;
	}

	/* enforce close request */
	if (server->close_needed) {
		disconnect_server(server, true, "close_needed");
		return false;
	}

	if (statlist_count(&server->canceling_clients) > 0) {
		change_server_state(server, SV_BEING_CANCELED);
		return true;
	}

	if (server->replication) {
		if (server->link) {
			slog_debug(server, "release_server: new replication connection ready");
			change_server_state(server, SV_ACTIVE);
			activate_client(server->link);
			return true;
		} else {
			disconnect_server(server, true, "replication client was closed");
			return false;
		}
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

static void unlink_server(PgSocket *server, const char *reason)
{
	PgSocket *client;
	if (!server->link)
		return;

	client = server->link;

	client->link = NULL;
	server->link = NULL;
	/*
	 * Send reason to client if it is already
	 * logged in, otherwise send generic message.
	 */
	if (client->state == CL_ACTIVE || client->state == CL_WAITING)
		disconnect_client(client, true, "%s", reason);
	else if (client->state == CL_ACTIVE_CANCEL)
		disconnect_client(client, false, "successfully sent cancel request");
	else
		disconnect_client(client, true, "bouncer config error");
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
	struct List *cancel_item, *tmp;

	if (server == NULL) {
		return;
	}

	va_start(ap, reason);
	vsnprintf(buf, sizeof(buf), reason, ap);
	va_end(ap);
	reason = buf;

	if (cf_log_disconnections) {
		slog_info(server, "closing because: %s (age=%" PRIu64 "s)", reason,
			  (now - server->connect_time) / USEC);
	}

	switch (server->state) {
	case SV_ACTIVE_CANCEL:
	case SV_ACTIVE:
		unlink_server(server, reason);
		break;
	case SV_TESTED:
	case SV_USED:
	case SV_IDLE:
	case SV_BEING_CANCELED:
		break;
	case SV_LOGIN:
		/*
		 * usually disconnect means problems in startup phase,
		 * except when sending cancel packet
		 */
		if (!server->ready) {
			server->pool->last_login_failed = true;
			server->pool->last_connect_failed = true;
			safe_strcpy(server->pool->last_connect_failed_message, reason, sizeof(server->pool->last_connect_failed_message));
		} else
		{
			/*
			 * We did manage to connect and used the connection for query
			 * cancellation, so to the best of our knowledge we can connect to
			 * the server, reset last_connect_failed accordingly.
			 */
			server->pool->last_connect_failed = false;
			send_term = false;
		}
		if (server->replication)
			unlink_server(server, reason);
		break;
	default:
		fatal("bad server state: %d", server->state);
	}

	Assert(server->link == NULL);

	statlist_for_each_safe(cancel_item, &server->canceling_clients, tmp) {
		PgSocket *cancel_client = container_of(cancel_item, PgSocket, cancel_head);
		cancel_client->canceled_server = NULL;
		statlist_remove(&server->canceling_clients, cancel_item);
	}

	/* notify server and close connection */
	if (send_term) {
		static const uint8_t pkt_term[] = {PqMsg_Terminate, 0, 0, 0, 4};
		bool _ignore = sbuf_answer(&server->sbuf, pkt_term, sizeof(pkt_term));
		(void) _ignore;
	}

	if (server->dns_token) {
		adns_cancel(adns, server->dns_token);
		server->dns_token = NULL;
	}

	free_scram_state(&server->scram_state);

	server->pool->db->connection_count--;
	if (server->pool->user_credentials)
		server->pool->user_credentials->global_user->connection_count--;

	change_server_state(server, SV_JUSTFREE);
	if (!sbuf_close(&server->sbuf))
		log_noise("sbuf_close failed, retry later");
}

/*
 * A wrapper around disconnect_client_sqlstate()
 *
 * The function disconnect_client_sqlstate() inherits the disconnect_client()
 * content and add a new option that provides a specific SQLSTATE that is
 * forwarded to client.  PgBouncer used to report SQLSTATE 08P01
 * (protocol_violation) for all cases but it diverges from what Postgres
 * reports in some cases.
 */
void disconnect_client(PgSocket *client, bool notify, const char *reason, ...)
{
	if (client->db && client->contributes_db_client_count)
		client->db->client_connection_count--;

	if (client->login_user_credentials) {
		if (client->login_user_credentials->global_user && client->user_connection_counted) {
			client->login_user_credentials->global_user->client_connection_count--;
		}
	}
	if (reason) {
		char buf[128];
		va_list ap;

		va_start(ap, reason);
		vsnprintf(buf, sizeof(buf), reason, ap);
		va_end(ap);

		disconnect_client_sqlstate(client, notify, NULL, buf);
	} else {
		disconnect_client_sqlstate(client, notify, NULL, reason);
	}
}

/*
 * close client connection
 *
 * notify=true means to send the reason message as an error to the
 * client, notify=false means no message is sent.  The latter is for
 * protocol and communication errors where sending a regular error
 * message is not possible.
 */
void disconnect_client_sqlstate(PgSocket *client, bool notify, const char *sqlstate, const char *reason)
{
	usec_t now = get_cached_time();

	if (cf_log_disconnections && reason) {
		slog_info(client, "closing because: %s (age=%" PRIu64 "s)", reason,
			  (now - client->connect_time) / USEC);
	}

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
			} else if (statlist_count(&server->outstanding_requests) > 0) {
				server->link = NULL;
				client->link = NULL;
				/*
				 * If there are outstanding requests we can't
				 * release the server, because the responses
				 * might be received by a different client. So
				 * we need to close the client connection
				 * immediately.
				 */
				disconnect_server(server, true, "client disconnected with query in progress");
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
		break;
	case CL_ACTIVE_CANCEL:
	case CL_WAITING_CANCEL:
		/*
		 * During normal operation, cancel clients get closed because their
		 * linked server finished sending the cancel request. But this is not
		 * always the case. It's possible for the client to disconnect
		 * itself. To avoid a reference to freed client object from the linked
		 * server in such cases, we now unlink any still linked server.
		 */
		if (client->link) {
			PgSocket *server = client->link;
			server->link = NULL;
			client->link = NULL;
			disconnect_server(server, false, "client gave up on cancel request, so we also give up forwarding to server");
		}
		/*
		 * If the cancel request is still linked to the server that it
		 * cancelled (or wanted to cancel) a query from, this is the time to
		 * unlink them. The cancel request has finished at this point and we're
		 * going to free its memory soon, so we don't want references to it
		 * left behind.
		 */
		if (client->canceled_server) {
			PgSocket *canceled_server = client->canceled_server;
			statlist_remove(&canceled_server->canceling_clients, &client->cancel_head);
			client->canceled_server = NULL;

			/*
			 * If the linked server was waiting until all cancel requests
			 * targeting it were finished, and we were the last cancel request,
			 * then we can now safely move the server to the idle state. We
			 * trigger this by calling release_server again.
			 */
			if (canceled_server->state == SV_BEING_CANCELED
			    && statlist_count(&canceled_server->canceling_clients) == 0) {
				release_server(canceled_server);
			}
		}
		break;
	case CL_WAITING:
	case CL_WAITING_LOGIN:
		/*
		 * replication connections might already be linked to a server
		 * while they are still in a waiting state.
		 */
		if (client->replication && client->link) {
			PgSocket *server = client->link;
			server->link = NULL;
			client->link = NULL;
			disconnect_server(server, false, "replication client disconnected");
		}
		break;
	default:
		fatal("bad client state: %d", client->state);
	}

	/* send reason to client */
	if (notify && reason && client->state != CL_WAITING_CANCEL) {
		/*
		 * don't send Ready pkt here, or client won't notice
		 * closed connection
		 */
		send_pooler_error(client, false, sqlstate, true, reason);
	}

	free_header(&client->packet_cb_state.pkt);
	free_scram_state(&client->scram_state);
	if (client->login_user_credentials && client->login_user_credentials->mock_auth) {
		free(client->login_user_credentials);
		client->login_user_credentials = NULL;
	}
	if (client->db && client->db->fake) {
		free(client->db);
		client->db = NULL;
	}

	free(client->startup_options);
	client->startup_options = NULL;

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
	const char *host;
	int sa_len;
	int res;
	char *host_copy = NULL;

	/* host list? */
	if (db->host && strchr(db->host, ',')) {
		int count = 1;
		int n;

		if (server->pool->db->load_balance_hosts == LOAD_BALANCE_HOSTS_DISABLE && server->pool->last_connect_failed)
			server->pool->rrcounter++;

		for (const char *p = db->host; *p; p++)
			if (*p == ',')
				count++;

		host_copy = xstrdup(db->host);
		for (host = strtok(host_copy, ","), n = 0; host; host = strtok(NULL, ","), n++)
			if (server->pool->rrcounter % count == n)
				break;
		Assert(host);

		if (server->pool->db->load_balance_hosts == LOAD_BALANCE_HOSTS_ROUND_ROBIN)
			server->pool->rrcounter++;
	} else {
		host = db->host;
	}

	if (!host || host[0] == '/' || host[0] == '@') {
		const char *unix_dir;

		memset(&sa_un, 0, sizeof(sa_un));
		sa_un.sun_family = AF_UNIX;
		unix_dir = host ? host : cf_unix_socket_dir;
		if (!unix_dir || !*unix_dir) {
			log_error("unix socket dir not configured: %s", db->name);
			disconnect_server(server, false, "cannot connect");
			goto cleanup;
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
		} else {
			sa_len = sizeof(sa_un);
		}
		sa = (struct sockaddr *)&sa_un;
		res = 1;
	} else if (strchr(host, ':')) {	/* assume IPv6 address on any : in addr */
		slog_noise(server, "inet6 socket: %s", host);
		memset(&sa_in6, 0, sizeof(sa_in6));
		sa_in6.sin6_family = AF_INET6;
		res = inet_pton(AF_INET6, host, &sa_in6.sin6_addr);
		sa_in6.sin6_port = htons(db->port);
		sa = (struct sockaddr *)&sa_in6;
		sa_len = sizeof(sa_in6);
	} else {/* else try IPv4 */
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
		goto cleanup;
	}

	connect_server(server, sa, sa_len);
cleanup:
	free(host_copy);
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

/* evict the oldest idle connection from the pool */
bool evict_pool_connection(PgPool *pool)
{
	PgSocket *oldest_connection = NULL;

	oldest_connection = compare_connections_by_time(oldest_connection, last_socket(&pool->idle_server_list));

	if (oldest_connection) {
		disconnect_server(oldest_connection, true, "evicted");
		return true;
	}
	return false;
}


/* evict the single most idle connection from among all pools to make room in the user */
bool evict_user_connection(PgCredentials *user_credentials)
{
	struct List *item;
	PgPool *pool;
	PgSocket *oldest_connection = NULL;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->user_credentials != user_credentials)
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

/*
 * Launches a new connection if possible.
 *
 * Called when the pool needs new connection.
 *
 * If `evict_if_needed` is true and the db or user has reached their
 * connection limits, this method will attempt to evict existing connections
 * from other users/dbs to make room for the new connection.
 */
void launch_new_connection(PgPool *pool, bool evict_if_needed)
{
	PgSocket *server;
	int max;

	log_debug("launch_new_connection: start");
	/*
	 * Allow only a single connection attempt at a time.
	 *
	 * NOTE: If this is ever changed to allow more than a single connection
	 * attempt at once (which would probably be a good thing), some code needs
	 * to change that depends on the fact that there's only ever one connection
	 * attempt at once. At least a little bit below in this function, where
	 * connections are opened for cancel requests.
	 */
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

	/*
	 * Peer pools only have a single pool_size.
	 */
	if (pool->db->peer_id) {
		if (max < pool_pool_size(pool))
			goto force_new;

		log_debug("launch_new_connection: peer pool full (%d >= %d)",
			  max, pool_pool_size(pool));
		return;
	}

	/*
	 * When a cancel request is queued allow connections up to twice the pool
	 * size.
	 *
	 * NOTE: This logic might seem a bit confusing, because it seems like we'll
	 * open many connections even if there's only a single cancel request. But
	 * this works just fine, because we only ever open a single connection at
	 * once (see top of this function).
	 */
	if (!statlist_empty(&pool->waiting_cancel_req_list) && max < (2 * pool_pool_size(pool))) {
		log_debug("launch_new_connection: bypass pool limitations for cancel request");
		goto force_new;
	}

	/* is it allowed to add servers? */
	if (max >= pool_pool_size(pool) && pool->welcome_msg_ready) {
		/* should we use reserve pool? */
		PgSocket *c = first_socket(&pool->waiting_client_list);
		if (cf_res_pool_timeout && pool_res_pool_size(pool)) {
			usec_t now = get_cached_time();
			if (c && (now - c->request_time) >= cf_res_pool_timeout) {
				if (max < pool_pool_size(pool) + pool_res_pool_size(pool)) {
					slog_warning(c, "taking connection from reserve_pool");
					goto allow_new;
				}
			}
		}

		if (c && c->replication && !sending_auth_query(c)) {
			while (evict_if_needed && pool_pool_size(pool) >= max) {
				if (!evict_pool_connection(pool))
					break;
			}
			if (pool_pool_size(pool) < max)
				goto allow_new;
		}
		log_debug("launch_new_connection: pool full (%d >= %d)",
			  max, pool_pool_size(pool));
		return;
	}

allow_new:
	max = database_max_connections(pool->db);
	if (max > 0) {
		/* try to evict unused connections first */
		while (evict_if_needed && pool->db->connection_count >= max) {
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

	max = user_max_connections(pool->user_credentials->global_user);
	if (max > 0) {
		/* try to evict unused connection first */
		while (evict_if_needed && pool->user_credentials->global_user->connection_count >= max) {
			if (!evict_user_connection(pool->user_credentials)) {
				break;
			}
		}
		if (pool->user_credentials->global_user->connection_count >= max) {
			log_debug("launch_new_connection: user '%s' full (%d >= %d)",
				  pool->user_credentials->name, pool->user_credentials->global_user->connection_count, max);
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
	server->login_user_credentials = server->pool->user_credentials;
	server->connect_time = get_cached_time();
	statlist_init(&server->canceling_clients, "canceling_clients");
	pool->last_connect_time = get_cached_time();
	change_server_state(server, SV_LOGIN);
	pool->db->connection_count++;
	if (pool->user_credentials)
		pool->user_credentials->global_user->connection_count++;

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
			slog_info(client, "login failed: db=%s user=%s", client->db->name, client->login_user_credentials->name);
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
			launch_new_connection(client->pool, /* evict_if_needed= */ true);
		return false;
	}
	client->wait_for_welcome = false;

	/* send the message */
	if (!welcome_client(client))
		return false;

	slog_debug(client, "logged in");

	return true;
}

static void accept_cancel_request_for_peer(int peer_id, PgSocket *req)
{
	PgDatabase *peer = NULL;
	PgPool *pool = NULL;
	int ttl = req->cancel_key[7] & CANCELLATION_TTL_MASK;

	if (ttl == 0) {
		disconnect_client(req, false, "failed to forward cancel request because its TTL was exhausted");
		return;
	}

	/*
	 * Before forwarding the cancel key, we need to decrement the TTL. Now is
	 * as a good a time as any to do so. We simply subtract 1 from the last
	 * byte, since the TTL is stored in the least significant bits.
	 */
	req->cancel_key[7]--;

	peer = find_peer(peer_id);
	if (!peer) {
		disconnect_client(req, false, "could not find peer to forward request to");
		return;
	}
	log_debug("forwarding cancellation request to peer %d", peer_id);

	/*
	 * When using peering (multiple pgbouncers behind the same load
	 * balancer), we may receive cancellation messages that were intended
	 * for another peer via the load balancer. We propagate the
	 * cancellation via the peer's pool, instead of the server pool.
	 */
	pool = get_peer_pool(peer);
	if (!pool) {
		disconnect_client(req, false, "out of memory");
		return;
	}

	/*
	 * Attach to the target pool and change state to waiting_cancel. This way
	 * once a new connection is opened, it's used to forward the cancel
	 * request.
	 */
	req->pool = pool;
	pause_cancel_request(req);

	/*
	 * Open a new connection over which the cancel request is forwarded to the
	 * server.
	 */
	launch_new_connection(pool, /* evict_if_needed= */ true);
}

/*
 * Accepts a cancellation request, which will eventual cancel the query running
 * on the client that matches req->client_key
 */
void accept_cancel_request(PgSocket *req)
{
	struct List *pitem, *citem;
	PgPool *pool = NULL;
	PgSocket *server = NULL, *client, *main_client = NULL;
	bool peering_enabled = false;

	Assert(req->state == CL_LOGIN);

	/*
	 * PgBouncer peering
	 */
	peering_enabled = cf_peer_id > 0;
	if (peering_enabled) {
		/*
		 * Extract the peer id from the cancel key. The peer id is
		 * stored in the 2nd and 3rd byte.
		 */
		int peer_id = req->cancel_key[1] + (req->cancel_key[2] << 8);
		bool needs_forwarding_to_peer = cf_peer_id != peer_id;
		if (needs_forwarding_to_peer) {
			accept_cancel_request_for_peer(peer_id, req);
			return;
		}

		/*
		 * Set the last two bits of the cancel key to 1. This is necessary to
		 * compare the key from the request to our stored cancel keys, because
		 * the stored cancel keys always have these TTL bits set to 1.
		 */
		req->cancel_key[7] |= CANCELLATION_TTL_MASK;
	}


	/* find the client that has the same cancel_key as this request */
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

	/*
	 * cancel requests for administrative databases should be handled
	 * differently from cancel request for normal servers. We should handle
	 * these directly instead of forwarding them.
	 */
	if (main_client->pool->db->admin) {
		disconnect_client(req, false, "cancel request for console client");
		admin_handle_cancel(main_client);
		return;
	}

	/*
	 * The client is not linked to a server, which means that no query is
	 * running that can be cancelled. This likely means the query finished by
	 * itself before the cancel request arived to pgbouncer.
	 */
	if (!main_client->link) {
		disconnect_client(req, false, "cancel request for idle client");

		return;
	}

	/*
	 * Link the cancel request and the server on which the query is being
	 * cancelled in a many-to-one way.
	 */
	server = main_client->link;
	req->canceled_server = server;
	statlist_append(&server->canceling_clients, &req->cancel_head);

	/*
	 * Attach to the target pool and change state to waiting_cancel. This way
	 * once a new connection is opened, it's used to forward the cancel
	 * request.
	 */
	req->pool = pool;
	pause_cancel_request(req);

	/*
	 * Open a new connection over which the cancel request is forwarded to the
	 * server.
	 */
	launch_new_connection(pool, /* evict_if_needed= */ true);
}

bool forward_cancel_request(PgSocket *server)
{
	bool res;
	PgSocket *req = first_socket(&server->pool->waiting_cancel_req_list);
	bool forwarding_to_peer = server->pool->db->peer_id != 0;

	Assert(req != NULL && req->state == CL_WAITING_CANCEL);
	Assert(server->state == SV_LOGIN);

	if (!forwarding_to_peer) {
		/*
		 * In between accepting the cancel request and receiving an open connection
		 * the query that was supposed to be cancelled has now completed. This
		 * becomes a problem when the server is then reused for some other client.
		 * Because this will mean that the cancel that is forwarded will cancel a
		 * query from a completely different client than the client it was intended
		 * for.
		 */
		if (!req->canceled_server) {
			disconnect_client(req, false, "not sending cancel request for client that is now idle");
			return false;
		}
	}

	server->link = req;
	req->link = server;

	if (forwarding_to_peer) {
		SEND_CancelRequest(res, server, req->cancel_key);
	} else {
		SEND_CancelRequest(res, server, req->canceled_server->cancel_key);
	}
	if (!res) {
		slog_warning(req, "sending cancel request failed: %s", strerror(errno));
		disconnect_client(req, false, "failed to send cancel request");
		return false;
	}
	slog_debug(req, "started sending cancel request");
	change_client_state(req, CL_ACTIVE_CANCEL);
	return true;
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
		PgCredentials *credentials;

		if (!scram_client_key || !scram_server_key) {
			log_error("incomplete SCRAM key data");
			return false;
		}
		if (sizeof(credentials->scram_ClientKey) != scram_client_key_len
		    || sizeof(credentials->scram_ServerKey) != scram_server_key_len) {
			log_error("incompatible SCRAM key data");
			return false;
		}
		if (db->forced_user_credentials) {
			log_error("SCRAM key data received for forced user");
			return false;
		}
		if (cf_auth_type == AUTH_TYPE_PAM) {
			log_error("SCRAM key data received for PAM user");
			return false;
		}
		credentials = find_global_credentials(username);
		if (!credentials && db->auth_user_credentials)
			credentials = add_dynamic_credentials(db, username, password);

		if (!credentials)
			return false;

		memcpy(credentials->scram_ClientKey, scram_client_key, sizeof(credentials->scram_ClientKey));
		memcpy(credentials->scram_ServerKey, scram_server_key, sizeof(credentials->scram_ServerKey));
		credentials->has_scram_keys = true;
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
	PgCredentials *credentials;
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

	if (db->forced_user_credentials) {
		credentials = db->forced_user_credentials;
	} else if (cf_auth_type == AUTH_TYPE_PAM) {
		credentials = add_pam_credentials(username, password);
	} else {
		credentials = find_global_credentials(username);
	}
	if (!credentials && db->auth_user_credentials)
		credentials = add_dynamic_credentials(db, username, password);

	pool = get_pool(db, credentials);
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
	server->login_user_credentials = credentials;
	server->connect_time = server->request_time = get_cached_time();
	server->query_start = 0;
	statlist_init(&server->canceling_clients, "canceling_clients");

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

	statlist_for_each(item, &pool->idle_server_list) {
		func(container_of(item, PgSocket, head));
	}

	statlist_for_each(item, &pool->used_server_list) {
		func(container_of(item, PgSocket, head));
	}

	statlist_for_each(item, &pool->tested_server_list) {
		func(container_of(item, PgSocket, head));
	}

	statlist_for_each(item, &pool->active_server_list) {
		func(container_of(item, PgSocket, head));
	}

	statlist_for_each(item, &pool->new_server_list) {
		func(container_of(item, PgSocket, head));
	}
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

static bool server_remote_addr_filter(PgSocket *sk, void *arg)
{
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
	statlist_for_each_safe(item, &peer_list, tmp) {
		PgDatabase *peer = container_of(item, PgDatabase, head);
		kill_peer(peer);
	}

	statlist_for_each_safe(item, &justfree_server_list, tmp) {
		PgSocket *server = container_of(item, PgSocket, head);
		server_free(server);
	}

	statlist_for_each_safe(item, &justfree_client_list, tmp) {
		PgSocket *client = container_of(item, PgSocket, head);
		client_free(client);
	}

	memset(&login_client_list, 0, sizeof login_client_list);
	memset(&user_list, 0, sizeof user_list);
	memset(&database_list, 0, sizeof database_list);
	memset(&pool_list, 0, sizeof pool_list);
	memset(&pam_user_tree, 0, sizeof pam_user_tree);
	memset(&user_tree, 0, sizeof user_tree);
	memset(&autodatabase_idle_list, 0, sizeof autodatabase_idle_list);

	slab_destroy(server_cache);
	server_cache = NULL;
	slab_destroy(client_cache);
	client_cache = NULL;
	slab_destroy(db_cache);
	db_cache = NULL;
	slab_destroy(peer_cache);
	peer_cache = NULL;
	slab_destroy(peer_pool_cache);
	peer_pool_cache = NULL;
	slab_destroy(pool_cache);
	pool_cache = NULL;
	slab_destroy(user_cache);
	user_cache = NULL;
	slab_destroy(credentials_cache);
	credentials_cache = NULL;
	slab_destroy(iobuf_cache);
	iobuf_cache = NULL;
	slab_destroy(outstanding_request_cache);
	outstanding_request_cache = NULL;
	slab_destroy(var_list_cache);
	var_list_cache = NULL;
	slab_destroy(server_prepared_statement_cache);
	server_prepared_statement_cache = NULL;
}
