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
 * Periodic maintenance.
 */

#include "bouncer.h"

static struct timeval full_maint_period = {0, USEC / 3};
static struct event full_maint_ev;

/* close all sockets in server list */
static void close_server_list(StatList *sk_list, const char *reason)
{
	List *item, *tmp;
	PgSocket *server;

	statlist_for_each_safe(item, sk_list, tmp) {
		server = container_of(item, PgSocket, head);
		disconnect_server(server, true, reason);
	}
}

bool suspend_socket(PgSocket *sk)
{
	if (!sk->suspended) {
		if (sbuf_is_empty(&sk->sbuf)) {
			sbuf_pause(&sk->sbuf);
			sk->suspended = 1;
		} else
			return false;
	}
	return true;
}

/* suspend all sockets in socket list */
static int suspend_socket_list(StatList *list)
{
	List *item;
	PgSocket *sk;
	int active = 0;

	statlist_for_each(item, list) {
		sk = container_of(item, PgSocket, head);
		if (!suspend_socket(sk))
			active++;
	}
	return active;
}

/* resume all suspended sockets in socket list */
static void resume_socket_list(StatList *list)
{
	List *item, *tmp;
	PgSocket *sk;

	statlist_for_each_safe(item, list, tmp) {
		sk = container_of(item, PgSocket, head);
		if (sk->suspended) {
			sk->suspended = 0;
			sbuf_continue(&sk->sbuf);
		}
	}
}

/* resume all suspended sockets in all pools */
static void resume_sockets(void)
{
	List *item;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->admin)
			continue;
		resume_socket_list(&pool->active_client_list);
		resume_socket_list(&pool->active_server_list);
		resume_socket_list(&pool->idle_server_list);
		resume_socket_list(&pool->used_server_list);
	}
}

/* resume pools and listen sockets */
void resume_all(void)
{
	resume_sockets();
	resume_pooler();
}

/*
 * send test/reset query to server if needed
 */
static void launch_recheck(PgPool *pool)
{
	const char *q = cf_server_check_query;
	bool need_check = true;
	PgSocket *server;
	bool res = true;

	/* find clean server */
	while (1) {
		server = first_socket(&pool->used_server_list);
		if (!server)
			return;
		if (server->ready)
			break;
		disconnect_server(server, true, "idle server got dirty");
	}

	/* is the check needed? */
	if (q == NULL || q[0] == 0)
		need_check = false;
	else if (cf_server_check_delay > 0) {
		usec_t now = get_cached_time();
		if (now - server->request_time < cf_server_check_delay)
			need_check = false;
	}

	if (need_check) {
		/* send test query, wait for result */
		change_server_state(server, SV_TESTED);
		SEND_generic(res, server, 'Q', "s", q);
		if (!res)
			disconnect_server(server, false, "test query failed");
	} else
		/* make immidiately available */
		release_server(server);
}

/*
 * make servers available
 */
static void per_loop_activate(PgPool *pool)
{
	List *item, *tmp;
	PgSocket *client;

	/* see if any server have been freed */
	statlist_for_each_safe(item, &pool->waiting_client_list, tmp) {
		client = container_of(item, PgSocket, head);
		if (!statlist_empty(&pool->idle_server_list)) {

			/* db not fully initialized after reboot */
			if (client->wait_for_welcome && !pool->db->welcome_msg_ready) {
				launch_new_connection(pool);
				continue;
			}

			/* there is a ready server already */
			activate_client(client);
		} else if (!statlist_empty(&pool->tested_server_list)) {
			/* some connections are in testing process */
			break;
		} else if (!statlist_empty(&pool->used_server_list)) {
			/* ask for more connections to be tested */
			launch_recheck(pool);
			break;
		} else {
			/* not enough connections */
			launch_new_connection(pool);
			break;
		}
	}
}

/*
 * pause active clients
 */
static int per_loop_pause(PgPool *pool)
{
	int active = 0;

	if (pool->admin)
		return 0;

	close_server_list(&pool->idle_server_list, "pause mode");
	close_server_list(&pool->used_server_list, "pause mode");
	close_server_list(&pool->new_server_list, "pause mode");

	active += statlist_count(&pool->active_server_list);
	active += statlist_count(&pool->tested_server_list);

	return active;
}

/*
 * suspend active clients and servers
 */
static int per_loop_suspend(PgPool *pool)
{
	int active = 0;

	if (pool->admin)
		return 0;

	active += suspend_socket_list(&pool->active_client_list);

	if (!statlist_empty(&pool->waiting_client_list)) {
		active += statlist_count(&pool->waiting_client_list);
		per_loop_activate(pool);
	}

	if (!active) {
		active += suspend_socket_list(&pool->active_server_list);
		active += suspend_socket_list(&pool->idle_server_list);

		/* as all clients are done, no need for them */
		close_server_list(&pool->tested_server_list, "close unsafe fds on suspend");
		close_server_list(&pool->used_server_list, "close unsafe fds on suspend");
	}

	return active;
}

/*
 * this function is called for each event loop.
 */
void per_loop_maint(void)
{
	List *item;
	PgPool *pool;
	int active = 0;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->admin)
			continue;
		switch (cf_pause_mode) {
		case P_NONE:
			per_loop_activate(pool);
			break;
		case P_PAUSE:
			active += per_loop_pause(pool);
			break;
		case P_SUSPEND:
			active += per_loop_suspend(pool);
			break;
		}
	}

	switch (cf_pause_mode) {
	case P_SUSPEND:
		active += statlist_count(&login_client_list);
	case P_PAUSE:
		if (!active)
			admin_pause_done();
	default:
		break;
	}
}

/* maintaing clients in pool */
static void pool_client_maint(PgPool *pool)
{
	List *item, *tmp;
	usec_t now = get_cached_time();
	PgSocket *client;
	usec_t age;

	/* force client_idle_timeout */
	if (cf_client_idle_timeout > 0) {
		statlist_for_each_safe(item, &pool->active_client_list, tmp) {
			client = container_of(item, PgSocket, head);
			Assert(client->state == CL_ACTIVE);
			if (client->link)
				continue;
			if (now - client->request_time > cf_client_idle_timeout)
				disconnect_client(client, true, "idle_timeout");
		}
	}

	/* force client_query_timeout */
	if (cf_query_timeout > 0) {
		statlist_for_each_safe(item, &pool->waiting_client_list, tmp) {
			client = container_of(item, PgSocket, head);
			Assert(client->state == CL_WAITING);
			if (client->query_start == 0) {
				age = now - client->request_time;
				//log_warning("query_start==0");
			} else
				age = now - client->query_start;
			if (age > cf_query_timeout)
				disconnect_client(client, true, "query_timeout");
		}
	}
}

static void check_unused_servers(StatList *slist, usec_t now, bool idle_test)
{
	List *item, *tmp;
	usec_t idle, age;
	PgSocket *server;

	/* disconnect idle servers if needed */
	statlist_for_each_safe(item, slist, tmp) {
		server = container_of(item, PgSocket, head);

		age = now - server->connect_time;
		idle = now - server->request_time;

		if (server->close_needed)
			disconnect_server(server, true, "db conf changed");
		else if (server->state == SV_IDLE && !server->ready)
			disconnect_server(server, true, "SV_IDLE server got dirty");
		else if (server->state == SV_USED && !server->ready)
			disconnect_server(server, true, "SV_USED server got dirty");
		else if (cf_server_idle_timeout > 0 && idle > cf_server_idle_timeout)
			disconnect_server(server, true, "server idle timeout");
		else if (cf_server_lifetime > 0 && age > cf_server_lifetime)
			disconnect_server(server, true, "server lifetime over");
		else if (cf_pause_mode == P_PAUSE)
			disconnect_server(server, true, "pause mode");
		else if (idle_test && *cf_server_check_query) {
			if (idle > cf_server_check_delay)
				change_server_state(server, SV_USED);
		}
	}
}

/*
 * Check pool size, close conns if too many.  Makes pooler
 * react faster to the case when admin decreased pool size.
 */
static void check_pool_size(PgPool *pool)
{
	PgSocket *server;
	int cur = statlist_count(&pool->active_server_list)
		+ statlist_count(&pool->idle_server_list)
		+ statlist_count(&pool->used_server_list)
		+ statlist_count(&pool->tested_server_list);
		
		/* cancel pkt may create new srv conn without
		 * taking pool_size into account
		 *
		 * statlist_count(&pool->new_server_list)
		 */

	int many = cur - pool->db->pool_size;

	Assert(pool->db->pool_size >= 0);

	while (many > 0) {
		server = first_socket(&pool->used_server_list);
		if (!server)
			server = first_socket(&pool->idle_server_list);
		if (!server)
			break;
		disconnect_server(server, true, "too many servers in pool");
		many--;
	}
}

/* maintain servers in a pool */
static void pool_server_maint(PgPool *pool)
{
	List *item, *tmp;
	usec_t age, now = get_cached_time();
	PgSocket *server;

	/* find and disconnect idle servers */
	check_unused_servers(&pool->used_server_list, now, 0);
	check_unused_servers(&pool->tested_server_list, now, 0);
	check_unused_servers(&pool->idle_server_list, now, 1);

	/* where query got did not get answer in query_timeout */
	if (cf_query_timeout > 0) {
		statlist_for_each_safe(item, &pool->active_server_list, tmp) {
			server = container_of(item, PgSocket, head);
			Assert(server->state == SV_ACTIVE);
			if (server->ready)
				continue;
			age = now - server->link->request_time;
			if (age > cf_query_timeout)
				disconnect_server(server, true, "statement timeout");
		}
	}

	/* find connections that got connect, but could not log in */
	if (cf_server_connect_timeout > 0) {
		statlist_for_each_safe(item, &pool->new_server_list, tmp) {
			server = container_of(item, PgSocket, head);
			Assert(server->state == SV_LOGIN);

			age = now - server->connect_time;
			if (age > cf_server_connect_timeout)
				disconnect_server(server, true, "connect timeout");
		}
	}

	check_pool_size(pool);
}

static void cleanup_client_logins(void)
{
	List *item, *tmp;
	PgSocket *client;
	usec_t age;
	usec_t now = get_cached_time();

	if (cf_client_login_timeout <= 0)
		return;

	statlist_for_each_safe(item, &login_client_list, tmp) {
		client = container_of(item, PgSocket, head);
		age = now - client->connect_time;
		if (age > cf_client_login_timeout)
			disconnect_client(client, true, "client_login_timeout");
	}
}

/* full-scale maintenenace, done only occasionally */
static void do_full_maint(int sock, short flags, void *arg)
{
	List *item;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->admin)
			continue;
		pool_server_maint(pool);
		pool_client_maint(pool);
	}

	cleanup_client_logins();

	if (cf_shutdown && get_active_server_count() == 0) {
		log_info("server connections dropped, exiting");
		exit(0);
	}

	loader_users_check();

	evtimer_add(&full_maint_ev, &full_maint_period);
}

/* first-time initializtion */
void janitor_setup(void)
{
	/* launch maintenance */
	evtimer_set(&full_maint_ev, do_full_maint, NULL);
	evtimer_add(&full_maint_ev, &full_maint_period);
}

/* as [pgbouncer] section can be loaded after databases,
   theres need for review */
void config_postprocess(void)
{
	List *item;
	PgDatabase *db;

	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);
		if (db->pool_size < 0)
			db->pool_size = cf_default_pool_size;
	}
}

