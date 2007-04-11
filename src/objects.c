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

/*
 * Herding objects between lists happens here.
 */

#include "bouncer.h"

/* those items will be allocated as needed, never freed */
STATLIST(user_list);
STATLIST(database_list);
STATLIST(pool_list);

/*
 * client and server objects will be pre-allocated
 * they are always in either active or free lists
 * in addition to others.
 */
STATLIST(free_client_list);
STATLIST(free_server_list);
STATLIST(login_client_list);

/*
 * libevent may still report events when event_del()
 * is called from somewhere else.  So hide just freed
 * PgSockets for one loop.
 */
static STATLIST(justfree_client_list);
static STATLIST(justfree_server_list);

/* how many client sockets are allocated */
static int absolute_client_count = 0;
/* how many server sockets are allocated */
static int absolute_server_count = 0;

/* list of users ordered by name */
static PgUser **user_lookup = NULL;

/* drop lookup list because it will be out of sync */
static void reset_auth_cache(void)
{
	if (user_lookup != NULL) {
		free(user_lookup);
		user_lookup = NULL;
	}
}

/* fast way to get number of active clients */
int get_active_client_count(void)
{
	return absolute_client_count - statlist_count(&free_client_list);
}

/* fast way to get number of active servers */
int get_active_server_count(void)
{
	return absolute_server_count - statlist_count(&free_server_list);
}

/* this should be called on free socket that is put into use */
static void clean_socket(PgSocket *sk)
{
	sk->link = NULL;
	sk->pool = NULL;

	sk->wait_for_welcome = 0;
	sk->ready = 0;
	sk->flush_req = 0;
	sk->admin_user = 0;
	sk->own_user = 0;
	sk->suspended = 0;
	sk->wait_for_response = 0;

	sk->connect_time = 0;
	sk->request_time = 0;
	sk->query_start = 0;

	sk->auth_user = NULL;
}

/* allocate & fll client socket */
static PgSocket *new_client(void)
{
	PgSocket *client;

	/* get free PgSocket */
	client = first_socket(&free_client_list);
	if (client) {
		clean_socket(client);
		return client;
	}

	client = zmalloc(sizeof(*client) + cf_sbuf_len);
	if (!client)
		return NULL;

	list_init(&client->head);
	sbuf_init(&client->sbuf, client_proto, client);
	statlist_prepend(&client->head, &free_client_list);
	client->state = CL_FREE;

	absolute_client_count++;

	return client;
}

/* allocate & fill server socket */
static PgSocket *new_server(void)
{
	PgSocket *server;

	/* get free PgSocket */
	server = first_socket(&free_server_list);
	if (server) {
		clean_socket(server);
		return server;
	}

	server = zmalloc(sizeof(*server) + cf_sbuf_len);
	if (!server)
		return NULL;

	list_init(&server->head);
	sbuf_init(&server->sbuf, server_proto, server);
	statlist_prepend(&server->head, &free_server_list);
	server->state = SV_FREE;

	absolute_server_count++;

	return server;
}

/* state change means moving between lists */
void change_client_state(PgSocket *client, SocketState newstate)
{
	PgPool *pool = client->pool;

	/* remove from old location */
	switch (client->state) {
	case CL_FREE:
		statlist_remove(&client->head, &free_client_list);
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
		statlist_prepend(&client->head, &free_client_list);
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
		statlist_remove(&server->head, &free_server_list);
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
		statlist_prepend(&server->head, &free_server_list);
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
		if (server->close_needed)
			/* try to avoid immidiate usage then */
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
		db = zmalloc(sizeof(*db));
		if (!db)
			return NULL;

		list_init(&db->head);
		strlcpy(db->name, name, sizeof(db->name));
		put_in_order(&db->head, &database_list, cmp_database);
	}

	return db;
}

/* add or update client users */
PgUser *add_user(const char *name, const char *passwd)
{
	PgUser *user = find_user(name);

	reset_auth_cache();

	if (user == NULL) {
		user = zmalloc(sizeof(*user));
		if (!user)
			return NULL;

		list_init(&user->head);
		list_init(&user->pool_list);
		strlcpy(user->name, name, sizeof(user->name));
		put_in_order(&user->head, &user_list, cmp_user);
	}
	strlcpy(user->passwd, passwd, sizeof(user->passwd));
	return user;
}

/* create separate user object for storing server user info */
PgUser *force_user(PgDatabase *db, const char *name, const char *passwd)
{
	PgUser *user = db->forced_user;
	if (!user) {
		user = zmalloc(sizeof(*user));
		if (!user)
			return NULL;
		list_init(&user->head);
		list_init(&user->pool_list);
	}
	strlcpy(user->name, name, sizeof(user->name));
	strlcpy(user->passwd, passwd, sizeof(user->passwd));
	db->forced_user = user;
	return user;
}

/* find a existing database */
PgDatabase *find_database(const char *name)
{
	List *item;
	PgDatabase *db;
	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);
		if (strcmp(db->name, name) == 0)
			return db;
	}
	return NULL;
}

/* compare string with PgUser->name, for usage with bsearch() */
static int user_name_cmp(const void *namestr, const void *userptr)
{
	const PgUser * const *user_p = userptr;
	const PgUser *user = *user_p;
	return strcmp(namestr, user->name);
}

/* find existing user */
PgUser *find_user(const char *name)
{
	List *item;
	PgUser *user;

	/* if lookup table is available, use faster method */
	if (user_lookup) {
		PgUser **res;
		res = bsearch(name, user_lookup,
			      statlist_count(&user_list),
			      sizeof(PgUser *),
			      user_name_cmp);
		return res ? *res : NULL;
	}

	/* slow lookup */
	statlist_for_each(item, &user_list) {
		user = container_of(item, PgUser, head);
		if (strcmp(user->name, name) == 0)
			return user;
	}
	return NULL;
}

/* create lookup list */
void create_auth_cache(void)
{
	int i = 0;
	List *item;
	PgUser *user;

	reset_auth_cache();

	user_lookup = malloc(sizeof(PgUser *) * statlist_count(&user_list));
	if (!user_lookup)
		return;

	statlist_for_each(item, &user_list) {
		user = container_of(item, PgUser, head);
		user_lookup[i++] = user;
	}
}

/* create new pool object */
static PgPool *new_pool(PgDatabase *db, PgUser *user)
{
	PgPool *pool;

	pool = zmalloc(sizeof(*pool));
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
void pause_client(PgSocket *client)
{
	Assert(client->state == CL_ACTIVE);

	slog_debug(client, "pause_client");
	change_client_state(client, CL_WAITING);
	sbuf_pause(&client->sbuf);
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

	Assert(client->state == CL_ACTIVE);

	if (client->link)
		return true;

	/* try to get idle server, if allowed */
	if (cf_pause_mode == P_PAUSE)
		server = NULL;
	else {
		while (1) {
			server = first_socket(&pool->idle_server_list);
			if (!server || server->ready)
				break;
			disconnect_server(server, true, "idle server got dirty");
		}
	}

	/* link or send to waiters list */
	if (server) {
		Assert(server->state == SV_IDLE);
		client->link = server;
		server->link = client;
		change_server_state(server, SV_ACTIVE);
		res = true;
	} else {
		pause_client(client);
		Assert(client->state == CL_WAITING);
		res = false;
	}
	return res;
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

		if (cf_server_check_delay == 0 && *cf_server_check_query)
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

	Assert(server->link == NULL);

	log_debug("release_server: new state=%d", newstate);

	change_server_state(server, newstate);

	/* immidiately process waiters, to give fair chance */
	if (newstate == SV_IDLE) {
		PgSocket *client = first_socket(&pool->waiting_client_list);
		if (client) {
			activate_client(client);

			/*
			 * As the activate_client() does full read loop,
			 * then it may happen that linked client close
			 * couses server close.  Report it.
			 */
			switch (server->state) {
			case SV_FREE:
			case SV_JUSTFREE:
				return false;
			default:
				break;
			}
		}
	}
	return true;
}

/* drop server connection */
void disconnect_server(PgSocket *server, bool notify, const char *reason)
{
	PgPool *pool = server->pool;
	PgSocket *client = server->link;
	static const uint8 pkt_term[] = {'X', 0,0,0,4};
	int send_term = 1;

	if (cf_log_disconnections)
		slog_info(server, "closing because: %s", reason);

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
	if (send_term && notify)
		sbuf_answer(&server->sbuf, pkt_term, sizeof(pkt_term));
	sbuf_close(&server->sbuf);

	change_server_state(server, SV_JUSTFREE);
}

/* drop client connection */
void disconnect_client(PgSocket *client, bool notify, const char *reason)
{
	if (cf_log_disconnections)
		slog_debug(client, "closing because: %s", reason);

	switch (client->state) {
	case CL_ACTIVE:
		if (client->link) {
			PgSocket *server = client->link;
			/* ->ready may be set before all is sent */
			if (server->ready && sbuf_is_empty(&server->sbuf)) {
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
	if (notify && reason) {
		/*
		 * dont send Ready pkt here, or client wont notice
		 * closed connection
		 */
		send_pooler_error(client, false, reason);
	}

	sbuf_close(&client->sbuf);

	change_client_state(client, CL_JUSTFREE);
}

/* the pool needs new connection, if possible */
void launch_new_connection(PgPool *pool)
{
	PgSocket *server;
	int total;

	/* allow only small number of connection attempts at a time */
	if (!statlist_empty(&pool->new_server_list)) {
		log_debug("launch_new_connection: already progress");
		return;
	}

	/* if server bounces, dont retry too fast */
	if (pool->last_connect_failed) {
		usec_t now = get_cached_time();
		if (now - pool->last_connect_time < cf_server_login_retry) {
			log_debug("launch_new_connection: last failed, wait");
			return;
		}
	}

	/* is it allowed to add servers? */
	total = pool_server_count(pool);
	if (total >= pool->db->pool_size && pool->db->welcome_msg_ready) {
		log_debug("launch_new_connection: pool full (%d >= %d)",
				total, pool->db->pool_size);
		return;
	}

	/* get free conn object */
	server = new_server();
	if (!server) {
		log_debug("launch_new_connection: no mem");
		return;
	}

	/* initialize it */
	server->pool = pool;
	server->auth_user = server->pool->user;
	server->addr = server->pool->db->addr;
	server->connect_time = get_cached_time();
	pool->last_connect_time = get_cached_time();
	change_server_state(server, SV_LOGIN);

	if (cf_log_connections)
		slog_info(server, "new connection to server");

	/* start connecting */
	sbuf_connect(&server->sbuf, &server->addr, cf_server_connect_timeout / USEC);
}

/* new client connection attempt */
PgSocket * accept_client(int sock,
			 const struct sockaddr_in *addr,
			 bool is_unix)
{
	PgSocket *client;

	/* get free PgSocket */
	client = new_client();
	if (!client)
		return NULL;

	client->connect_time = client->request_time = get_cached_time();
	client->query_start = 0;

	if (addr) {
		client->addr.ip_addr = addr->sin_addr;
		client->addr.port = ntohs(addr->sin_port);
	} else {
		memset(&client->addr, 0, sizeof(client->addr));
	}
	client->addr.is_unix = is_unix;
	change_client_state(client, CL_LOGIN);

	if (cf_log_connections)
		slog_debug(client, "got connection attempt");
	sbuf_accept(&client->sbuf, sock, is_unix);

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
		log_debug("finish_client_login: no welcome msg, pause");
		client->wait_for_welcome = 1;
		pause_client(client);
		if (cf_pause_mode == P_NONE)
			launch_new_connection(client->pool);
		return false;
	}
	client->wait_for_welcome = 0;

	slog_debug(client, "logged in");

	/* in suspend, dont let send query */
	if (cf_pause_mode == P_SUSPEND)
		suspend_socket(client);

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
				break;
			}
		}
	}

	/* wrong key */
	if (!main_client) {
		disconnect_client(req, false, "failed cancel req");
		return;
	}

	/* not linked client, just drop it then */
	if (!main_client->link) {
		disconnect_client(main_client, true, "canceling idle client");
		disconnect_client(req, false, "cancel req for idle client");
		return;
	}

	/* drop the connection silently */
	sbuf_close(&req->sbuf);

	/* remember server key */
	server = main_client->link;
	memcpy(req->cancel_key, server->cancel_key, 8);
	statlist_remove(&req->head, &login_client_list);
	statlist_append(&req->head, &pool->cancel_req_list);
	req->state =  CL_CANCEL;

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
		       uint64 ckey, int oldfd, int linkfd)
{
	PgDatabase *db = find_database(dbname);
	PgUser *user = find_user(username);
	PgPool *pool = get_pool(db, user);
	PgSocket *client;
	PktBuf tmp;

	if (!pool)
		return false;

	client = accept_client(fd, NULL, addr->is_unix);
	client->addr = *addr;
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

	return true;
}

bool use_server_socket(int fd, PgAddr *addr,
		       const char *dbname, const char *username,
		       uint64 ckey, int oldfd, int linkfd)
{
	PgDatabase *db = find_database(dbname);
	PgUser *user;
	PgPool *pool;
	PgSocket *server;
	PktBuf tmp;

	if (db->forced_user)
		user = db->forced_user;
	else
		user = find_user(username);

	pool = get_pool(db, user);
	if (!pool)
		return false;

	server = new_server();
	if (!server)
		return false;

	sbuf_accept(&server->sbuf, fd, addr->is_unix);
	server->suspended = 1;
	server->pool = pool;
	server->auth_user = user;
	server->addr = *addr;
	server->connect_time = server->request_time = get_cached_time();
	server->query_start = 0;

	if (linkfd)
		change_server_state(server, SV_ACTIVE);
	else
		change_server_state(server, SV_IDLE);

	/* store old cancel key */
	pktbuf_static(&tmp, server->cancel_key, 8);
	pktbuf_put_uint64(&tmp, ckey);

	/* store old fds */
	server->tmp_sk_oldfd = oldfd;
	server->tmp_sk_linkfd = linkfd;

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

	/*
	 * Obviously, if state would be set to *_FREE,
	 * they could be moved in one go.
	 */
	statlist_for_each_safe(item, &justfree_client_list, tmp) {
		sk = container_of(item, PgSocket, head);
		change_client_state(sk, CL_FREE);
	}
	statlist_for_each_safe(item, &justfree_server_list, tmp) {
		sk = container_of(item, PgSocket, head);
		change_server_state(sk, SV_FREE);
	}
}


