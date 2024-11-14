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
 * Periodic maintenance.
 */

#include "bouncer.h"

#include <usual/slab.h>

bool fast_switchover = false;

/* do full maintenance 3x per second */
static struct timeval full_maint_period = {0, USEC / 3};
static struct event full_maint_ev;

/* close all sockets in server list */
static void close_server_list(struct StatList *sk_list, const char *reason)
{
	struct List *item, *tmp;
	PgSocket *server;

	statlist_for_each_safe(item, sk_list, tmp) {
		server = container_of(item, PgSocket, head);
		disconnect_server(server, true, "%s", reason);
	}
}

static void close_client_list(struct StatList *sk_list, const char *reason)
{
	struct List *item, *tmp;
	PgSocket *client;

	statlist_for_each_safe(item, sk_list, tmp) {
		client = container_of(item, PgSocket, head);
		disconnect_client(client, true, "%s", reason);
	}
}

bool suspend_socket(PgSocket *sk, bool force_suspend)
{
	if (sk->suspended)
		return true;

	if (sbuf_is_empty(&sk->sbuf)) {
		if (sbuf_pause(&sk->sbuf))
			sk->suspended = true;
	}

	if (sk->suspended || !force_suspend)
		return sk->suspended;

	if (is_server_socket(sk))
		disconnect_server(sk, true, "suspend_timeout");
	else
		disconnect_client(sk, true, "suspend_timeout");
	return true;
}

/* suspend all sockets in socket list */
static int suspend_socket_list(struct StatList *list, bool force_suspend)
{
	struct List *item, *tmp;
	PgSocket *sk;
	int active = 0;

	statlist_for_each_safe(item, list, tmp) {
		sk = container_of(item, PgSocket, head);
		if (!suspend_socket(sk, force_suspend))
			active++;
	}
	return active;
}

/* resume all suspended sockets in socket list */
static void resume_socket_list(struct StatList *list)
{
	struct List *item, *tmp;
	PgSocket *sk;

	statlist_for_each_safe(item, list, tmp) {
		sk = container_of(item, PgSocket, head);
		if (sk->suspended) {
			sk->suspended = false;
			sbuf_continue(&sk->sbuf);
		}
	}
}

/* resume all suspended sockets in all pools */
static void resume_sockets(void)
{
	struct List *item;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->admin)
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

static bool update_client_pool(PgSocket *client, PgPool *new_pool)
{
	char *username = NULL;
	char *passwd = NULL;

	if (client->pool == new_pool)
		return true;

	username = client->login_user->name;
	passwd = client->login_user->passwd;
	if (!set_pool(client, new_pool->db->name, username, passwd, true)) {
		log_error("could not set pool to: %s", new_pool->db->name);
		return false;
	}

	return true;
}

static void reset_recently_checked(void)
{
	struct List *item;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->admin)
			continue;

		if (!pool->db->topology_query)
			continue;

		log_debug("resetting pool: %s", pool->db->name);
		pool->recently_checked = false;
	}
}

/*
 * send test/reset query to server if needed. If using fast switchovers,
 * this is the entry point for finding the new writer.
 */
static void launch_recheck(PgPool *pool, PgSocket *client)
{
	char *q = cf_server_check_query;
	char *recovery_query = NULL;
	bool need_check = true;
	PgSocket *server;
	bool res = true;
	struct List *item;
	PgPool *next_pool;
	usec_t polling_freq_in_ms = cf_polling_frequency / 1000;
	usec_t last_poll_time;
	usec_t difference_in_ms;
	usec_t now;
	PgPool *global_writer = get_global_writer(pool);

	log_debug("launch_recheck: for db: %s, global_writer? %s", pool->db->name, global_writer ? global_writer->db->name : "no global_writer");

	if (!pool->db->topology_query) {
		log_debug("launch_recheck: no topology_query for this pool, so proceeding without cache");
	} else if (global_writer) {
		log_debug("launch_recheck: global writer is set: using cached pool: %s", global_writer->db->name);
		update_client_pool(client, global_writer);
	} else if (pool->last_connect_failed) {
		bool found = false;
		bool need_to_reconnect = true;
		reset_time_cache();
		now = get_cached_time();
		log_debug("launch_recheck: need to iterate pool list");

		statlist_for_each(item, &pool_list) {
			next_pool = container_of(item, PgPool, head);

			if (!next_pool->parent_pool || next_pool->parent_pool != pool) {
				log_debug("launch_recheck: no parent pool, skipping: %s", next_pool->db->name);
				continue;
			}

			if (next_pool->last_connect_failed) {
				log_debug("launch_recheck: last_connect_failed, skipping: %s", next_pool->db->name);
				continue;
			}

			need_to_reconnect = false;

			if (next_pool->checking_for_new_writer) {
				log_debug("launch_recheck: checking_for_new_writer is true for node '%s', can't run another recovery check until done.", next_pool->db->name);
				return;
			}

			if (next_pool->recently_checked) {
				log_debug("launch_recheck: pool was recently checked, skipping: %s", next_pool->db->name);
				continue;
			}

			last_poll_time = next_pool->last_poll_time;
			difference_in_ms = (now - last_poll_time) / 1000;
			log_debug("launch_recheck: last time checked for pool %s: now: %llu last: %llu, diff: %llu, polling_freq_max: %llu", next_pool->db->name, now, last_poll_time, difference_in_ms, cf_polling_frequency/1000);

			if (difference_in_ms < polling_freq_in_ms) {
				log_debug("launch_recheck: skipping because it's too soon for pool %s (%llu ms)", next_pool->db->name, difference_in_ms);
				continue;
			}

			log_debug("launch_recheck: found pool during iteration, setting to: %s", next_pool->db->name);

			found = update_client_pool(client, next_pool);
			if (!found)
				return;

			break;
		}

		if (need_to_reconnect && cf_recreate_disconnected_pools) {
			log_debug("launch_recheck: all pools failed, so need to try to reconnect to parents");
			statlist_for_each(item, &pool_list) {
				next_pool = container_of(item, PgPool, head);

				if (!next_pool->parent_pool || next_pool->parent_pool != pool) {
					continue;
				}

				log_debug("launch_recheck: establishing new connection to pool: %s", next_pool->db->name);
				launch_new_connection(next_pool, /* evict_if_needed= */ true);
			}

			return;
		} else if (!found) {
			log_debug("could not find alternate server, need to reset all pools");
			reset_recently_checked();
			/* drastically reduces switchover/failover time since we don't need to wait to get called again from per_loop_activate() */
			launch_recheck(pool, client);

			return;
		} else {
			next_pool->last_poll_time = now;
			next_pool->recently_checked = true;
		}
	}

	/* find clean server */
	while (1) {
		server = first_socket(&client->pool->used_server_list);
		if (!server) {
			log_debug("launch_recheck: could not find used_server for pool: %s", client->pool->db->name);

			/* if a new connection pool was created because all three nodes in the cluster are down, servers are in the idle list instead of used list */
			server = first_socket(&client->pool->idle_server_list);
			if (!server) {
				client->pool->last_connect_failed = true;
				return;
			}
		}
		if (server->ready)
			break;
		disconnect_server(server, true, "idle server got dirty");
	}

	/* is the check needed? */
	if (q == NULL || q[0] == 0) {
		need_check = false;
	} else if (cf_server_check_delay > 0) {
		usec_t now = get_cached_time();
		if (now - server->request_time < cf_server_check_delay)
			need_check = false;
	}

	if (fast_switchover && pool->db->topology_query) {
		if (!global_writer) {
			client->pool->checking_for_new_writer = true;
			recovery_query = strdup("select pg_is_in_recovery()");
			if (recovery_query == NULL) {
				log_error("strdup: no mem for pg_is_in_recovery()");
				return;
			}
			slog_debug(server, "P: checking: %s (not done polling)", recovery_query);
			SEND_generic(res, server, 'Q', "s", recovery_query);
			if (!res)
				disconnect_server(server, false, "pg_is_in_recovery() query failed");
			free(recovery_query);
			return;
		} else {
			reset_recently_checked();
			change_server_state(server, SV_TESTED);

			/* reactivate paused clients that never finished logging in */
			if (client->state == CL_WAITING_LOGIN || client->state == CL_WAITING) {
				activate_client(client);
			}
		}
	}

	if (need_check) {
		/* send test query, wait for result */
		slog_debug(server, "P: checking: %s", q);
		change_server_state(server, SV_TESTED);
		SEND_generic(res, server, 'Q', "s", q);
		if (!res)
			disconnect_server(server, false, "test query failed");
	} else {
		/* make immediately available */
		release_server(server);
	}
}

/*
 * make servers available
 */
static void per_loop_activate(PgPool *pool)
{
	struct List *item, *tmp;
	PgSocket *client;
	int sv_tested, sv_used;

	/* if there is a cancel request waiting, open a new connection */
	if (!statlist_empty(&pool->waiting_cancel_req_list)) {
		launch_new_connection(pool, /* evict_if_needed= */ true);
		return;
	}

	/* see if any server have been freed */
	sv_tested = statlist_count(&pool->tested_server_list);
	sv_used = statlist_count(&pool->used_server_list);
	statlist_for_each_safe(item, &pool->waiting_client_list, tmp) {
		client = container_of(item, PgSocket, head);
		if (!statlist_empty(&pool->idle_server_list)) {

			/* db not fully initialized after reboot */
			if (client->wait_for_welcome && !pool->welcome_msg_ready) {
				launch_new_connection(pool, /* evict_if_needed= */ true);
				continue;
			}

			/* there is a ready server already */
			activate_client(client);
		} else if (sv_tested > 0) {
			/* some connections are in testing process */
			--sv_tested;
		} else if (sv_used > 0) {
			/* ask for more connections to be tested */
			launch_recheck(pool, client);
			--sv_used;
		} else {
			/* not enough connections */
			log_debug("launch_new_connection because not enough connections. number pools: %d, for: %s", statlist_count(&pool_list), pool->db->name);

			if (fast_switchover && pool->db->topology_query &&
			 	(!get_global_writer(pool) || pool->last_connect_failed)) {
				log_debug("launch_new_connection loop: going to try to use pool cache since this pool was a writer: last_connect_failed (%d)",
						pool->last_connect_failed);
				launch_recheck(pool, client);
			} else {
				log_debug("launch_new_connection loop: need to launch new connection because pool is not already a writer");
				launch_new_connection(pool, /* evict_if_needed= */ true);
			}

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

	if (pool->db->admin)
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
static int per_loop_suspend(PgPool *pool, bool force_suspend)
{
	int active = 0;

	if (pool->db->admin)
		return 0;

	active += suspend_socket_list(&pool->active_client_list, force_suspend);

	/* this list is not suspendable, but still need force_suspend and counting */
	active += suspend_socket_list(&pool->waiting_client_list, force_suspend);
	if (active)
		per_loop_activate(pool);

	if (!active) {
		active += suspend_socket_list(&pool->active_server_list, force_suspend);
		active += suspend_socket_list(&pool->idle_server_list, force_suspend);

		/* as all clients are done, no need for them */
		close_server_list(&pool->tested_server_list, "close unsafe file descriptors on suspend");
		close_server_list(&pool->used_server_list, "close unsafe file descriptors on suspend");
	}

	return active;
}

/*
 * Count the servers in server_list that have close_needed set.
 */
static int count_close_needed(struct StatList *server_list)
{
	struct List *item;
	PgSocket *server;
	int count = 0;

	statlist_for_each(item, server_list) {
		server = container_of(item, PgSocket, head);
		if (server->close_needed)
			count++;
	}

	return count;
}

/*
 * Per-loop tasks for WAIT_CLOSE
 */
static int per_loop_wait_close(PgPool *pool)
{
	int count = 0;

	if (pool->db->admin)
		return 0;

	count += count_close_needed(&pool->active_server_list);
	count += count_close_needed(&pool->idle_server_list);
	count += count_close_needed(&pool->new_server_list);
	count += count_close_needed(&pool->tested_server_list);
	count += count_close_needed(&pool->used_server_list);

	return count;
}

static void loop_maint(bool initialize)
{
	struct List *item;
	PgPool *pool;
	int active_count = 0;
	int waiting_count = 0;
	bool partial_pause = false;
	bool partial_wait = false;
	bool force_suspend = false;
	usec_t now = get_cached_time();

	if (cf_pause_mode == P_SUSPEND && cf_suspend_timeout > 0) {
		usec_t stime = get_cached_time() - g_suspend_start;
		if (stime >= cf_suspend_timeout)
			force_suspend = true;
	}

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->admin)
			continue;

		if (initialize) {
			if (!pool->db->topology_query)
				continue;

			pool->initial_writer_endpoint = true;
			log_debug("create initial pool during startup for: %s", pool->db->name);
		} else {
			if (fast_switchover && pool->last_connect_failed && get_global_writer(pool)) {
				if (now - pool->last_failed_time > cf_server_failed_delay) {
					log_debug("last connect failed: %s, so launching new connection in per_loop_maint", pool->db->name);
					launch_new_connection(pool, true);
				}
			}
		}

		switch (cf_pause_mode) {
		case P_NONE:
			if (pool->db->db_paused) {
				partial_pause = true;
				active_count += per_loop_pause(pool);
			} else {
				if (initialize)
					launch_new_connection(pool, false);
				else
					per_loop_activate(pool);
			}
			break;
		case P_PAUSE:
			active_count += per_loop_pause(pool);
			break;
		case P_SUSPEND:
			active_count += per_loop_suspend(pool, force_suspend);
			break;
		}

		if (pool->db->db_wait_close) {
			partial_wait = true;
			waiting_count += per_loop_wait_close(pool);
		}
	}

	switch (cf_pause_mode) {
	case P_SUSPEND:
		if (force_suspend) {
			close_client_list(&login_client_list, "suspend_timeout");
		} else {
			active_count += statlist_count(&login_client_list);
		}
		/* fallthrough */
	case P_PAUSE:
		if (!active_count)
			admin_pause_done();
		break;
	case P_NONE:
		if (partial_pause && !active_count)
			admin_pause_done();
		break;
	}

	if (partial_wait && !waiting_count)
		admin_wait_close_done();
}

/*
 * Used to pre-create connection pools at pgbouncer init time.
 */
void run_once_to_init(void)
{
	if (!fast_switchover) {
		log_debug("database does not have fast_switchovers enabled, so will not precreate pools to nodes");
		return;
	}

	loop_maint(true);
}

/*
 * this function is called for each event loop.
 */
void per_loop_maint(void)
{
	loop_maint(false);
}

/* maintaining clients in pool */
static void pool_client_maint(PgPool *pool)
{
	struct List *item, *tmp;
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
				disconnect_client(client, true, "client_idle_timeout");
		}
	}

	/* force timeouts for waiting queries */
	if (cf_query_timeout > 0 || cf_query_wait_timeout > 0) {
		statlist_for_each_safe(item, &pool->waiting_client_list, tmp) {
			client = container_of(item, PgSocket, head);
			Assert(client->state == CL_WAITING || client->state == CL_WAITING_LOGIN);
			if (client->query_start == 0) {
				age = now - client->request_time;
				/* log_warning("query_start==0"); */
			} else {
				age = now - client->query_start;
			}

			if (cf_query_timeout > 0 && age > cf_query_timeout) {
				disconnect_client(client, true, "query_timeout");
			} else if (cf_query_wait_timeout > 0 && age > cf_query_wait_timeout) {
				disconnect_client(client, true, "query_wait_timeout");
			}
		}
	}

	/* apply cancel_wait_timeout for cancel connections */
	if (cf_cancel_wait_timeout > 0) {
		statlist_for_each_safe(item, &pool->waiting_cancel_req_list, tmp) {
			client = container_of(item, PgSocket, head);
			Assert(client->state == CL_WAITING_CANCEL);
			age = now - client->request_time;

			if (age > cf_cancel_wait_timeout)
				disconnect_client(client, false, "cancel_wait_timeout");
		}
	}

	/* apply client_login_timeout to clients waiting for welcome pkt */
	if (cf_client_login_timeout > 0 && !pool->welcome_msg_ready) {
		statlist_for_each_safe(item, &pool->waiting_client_list, tmp) {
			client = container_of(item, PgSocket, head);
			if (!client->wait_for_welcome)
				continue;
			age = now - client->connect_time;
			if (age > cf_client_login_timeout)
				disconnect_client(client, true, "client_login_timeout (server down)");
		}
	}
}

/* maintaining clients in peer pool */
static void peer_pool_client_maint(PgPool *pool)
{
	struct List *item, *tmp;
	usec_t now = get_cached_time();
	PgSocket *client;
	usec_t age;

	if (cf_cancel_wait_timeout > 0) {
		statlist_for_each_safe(item, &pool->waiting_cancel_req_list, tmp) {
			client = container_of(item, PgSocket, head);
			Assert(client->state == CL_WAITING_CANCEL);
			age = now - client->request_time;

			if (age > cf_cancel_wait_timeout)
				disconnect_client(client, false, "cancel_wait_timeout");
		}
	}
}

static void check_unused_servers(PgPool *pool, struct StatList *slist, bool idle_test)
{
	usec_t now = get_cached_time();
	struct List *item, *tmp;
	usec_t idle, age;
	PgSocket *server;

	/* disconnect idle servers if needed */
	statlist_for_each_safe(item, slist, tmp) {
		server = container_of(item, PgSocket, head);

		age = now - server->connect_time;
		idle = now - server->request_time;

		if (server->close_needed) {
			disconnect_server(server, true, "database configuration changed");
		} else if (server->state == SV_IDLE && !server->ready) {
			disconnect_server(server, true, "SV_IDLE server got dirty");
		} else if (server->state == SV_USED && !server->ready) {
			disconnect_server(server, true, "SV_USED server got dirty");
		} else if (cf_server_idle_timeout > 0 && idle > cf_server_idle_timeout
			   && (pool->db && !pool->db->topology_query)
			   && (pool_min_pool_size(pool) == 0 || pool_connected_server_count(pool) > pool_min_pool_size(pool))) {
			disconnect_server(server, true, "server idle timeout");
		} else if (age >= cf_server_lifetime) {
			if (life_over(server)) {
				disconnect_server(server, true, "server lifetime over");
				pool->last_lifetime_disconnect = now;
			}
		} else if (cf_pause_mode == P_PAUSE) {
			disconnect_server(server, true, "pause mode");
		} else if (idle_test && *cf_server_check_query) {
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
	int cur = pool_connected_server_count(pool);
	int many = cur - (pool_pool_size(pool) + pool_res_pool_size(pool));

	Assert(pool_pool_size(pool) >= 0);

	while (many > 0) {
		server = first_socket(&pool->used_server_list);
		if (!server)
			server = first_socket(&pool->idle_server_list);
		if (!server)
			break;
		disconnect_server(server, true, "too many servers in the pool");
		many--;
		cur--;
	}

	/* launch extra connections to satisfy min_pool_size */
	if (cur < pool_min_pool_size(pool) &&
	    cur < pool_pool_size(pool) &&
	    cf_pause_mode == P_NONE &&
	    cf_reboot == 0 &&
	    pool_client_count(pool) > 0)
	{
		log_debug("launching new connection to satisfy min_pool_size");
		launch_new_connection(pool, /* evict_if_needed= */ false);
	}
}

/* maintain servers in a pool */
static void pool_server_maint(PgPool *pool)
{
	struct List *item, *tmp;
	usec_t now = get_cached_time();
	PgSocket *server;

	/* find and disconnect idle servers */
	check_unused_servers(pool, &pool->used_server_list, 0);
	check_unused_servers(pool, &pool->tested_server_list, 0);
	check_unused_servers(pool, &pool->idle_server_list, 1);

	/* disconnect close_needed active servers if server_fast_close is set */
	if (cf_server_fast_close) {
		statlist_for_each_safe(item, &pool->active_server_list, tmp) {
			server = container_of(item, PgSocket, head);
			Assert(server->state == SV_ACTIVE);
			if (server->ready && server->close_needed)
				disconnect_server(server, true, "database configuration changed");
		}
	}

	/* handle query_timeout and idle_transaction_timeout */
	if (cf_query_timeout > 0 || cf_idle_transaction_timeout > 0) {
		statlist_for_each_safe(item, &pool->active_server_list, tmp) {
			usec_t age_client, age_server;

			server = container_of(item, PgSocket, head);
			Assert(server->state == SV_ACTIVE);
			if (server->ready)
				continue;

			/*
			 * Note the different age calculations:
			 * query_timeout counts from the last request
			 * of the client (the client started the
			 * query), idle_transaction_timeout counts
			 * from the last request of the server (the
			 * server sent the idle information).
			 */
			age_client = now - server->link->request_time;
			age_server = now - server->request_time;

			if (cf_query_timeout > 0 && age_client > cf_query_timeout) {
				disconnect_server(server, true, "query timeout");
			} else if (cf_idle_transaction_timeout > 0 &&
				   server->idle_tx &&
				   age_server > cf_idle_transaction_timeout)
			{
				disconnect_server(server, true, "idle transaction timeout");
			}
		}
	}

	/* find connections that got connect, but could not log in */
	if (cf_server_connect_timeout > 0) {
		statlist_for_each_safe(item, &pool->new_server_list, tmp) {
			usec_t age;

			server = container_of(item, PgSocket, head);
			Assert(server->state == SV_LOGIN);

			age = now - server->connect_time;
			if (age > cf_server_connect_timeout)
				disconnect_server(server, true, "connect timeout");
		}
	}

	check_pool_size(pool);
}

/* maintain servers in a peer pool */
static void peer_pool_server_maint(PgPool *pool)
{
	struct List *item, *tmp;
	usec_t now = get_cached_time();
	PgSocket *server;

	/*
	 * find connections that got connected, but could not log in. For normal
	 * pools we only compare against server_connect_timeout for these servers,
	 * but since peer pools are only for sending cancellations we also compare
	 * against cancel_wait_timeout here.
	 */
	if (cf_server_connect_timeout > 0 || cf_cancel_wait_timeout > 0) {
		statlist_for_each_safe(item, &pool->new_server_list, tmp) {
			usec_t age;

			server = container_of(item, PgSocket, head);
			Assert(server->state == SV_LOGIN);

			age = now - server->connect_time;
			if (cf_server_connect_timeout > 0 && age > cf_server_connect_timeout) {
				disconnect_server(server, true, "connect timeout");
			}
			else if (cf_cancel_wait_timeout > 0 && age > cf_cancel_wait_timeout) {
				disconnect_server(server, true, "cancel_wait_timeout");
			}
		}
	}
}


static void cleanup_client_logins(void)
{
	struct List *item, *tmp;
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

static void cleanup_inactive_autodatabases(void)
{
	struct List *item, *tmp;
	PgDatabase *db;
	usec_t age;
	usec_t now = get_cached_time();

	if (cf_autodb_idle_timeout <= 0)
		return;

	/* now kill the old ones */
	statlist_for_each_safe(item, &autodatabase_idle_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (db->db_paused)
			continue;
		age = now - db->inactive_time;
		if (age > cf_autodb_idle_timeout) {
			kill_database(db);
		} else {
			break;
		}
	}
}

/* full-scale maintenance, done only occasionally */
static void do_full_maint(evutil_socket_t sock, short flags, void *arg)
{
	struct List *item, *tmp;
	PgPool *pool;
	PgDatabase *db;

	static unsigned int seq;
	seq++;

	/*
	 * Avoid doing anything that may surprise other pgbouncer.
	 */
	if (cf_pause_mode == P_SUSPEND)
		return;

	statlist_for_each_safe(item, &pool_list, tmp) {
		pool = container_of(item, PgPool, head);
		if (pool->db->admin)
			continue;
		pool_server_maint(pool);
		pool_client_maint(pool);

		/* is autodb active? */
		if (pool->db->db_auto && pool->db->inactive_time == 0) {
			if (pool_client_count(pool) > 0 || pool_server_count(pool) > 0)
				pool->db->active_stamp = seq;
		}
	}

	statlist_for_each_safe(item, &peer_pool_list, tmp) {
		pool = container_of(item, PgPool, head);
		peer_pool_server_maint(pool);
		peer_pool_client_maint(pool);
	}

	/* find inactive autodbs */
	statlist_for_each_safe(item, &database_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (db->db_auto && db->inactive_time == 0) {
			if (db->active_stamp == seq)
				continue;
			db->inactive_time = get_cached_time();
			statlist_remove(&database_list, &db->head);
			statlist_append(&autodatabase_idle_list, &db->head);
		}
	}

	cleanup_inactive_autodatabases();

	cleanup_client_logins();

	if (cf_shutdown == 1 && get_active_server_count() == 0) {
		log_info("server connections dropped, exiting");
		cf_shutdown = 2;
		event_base_loopbreak(pgb_event_base);
		return;
	}

	adns_zone_cache_maint(adns);
}

/* first-time initialization */
void janitor_setup(void)
{
	/* launch maintenance */
	event_assign(&full_maint_ev, pgb_event_base, -1, EV_PERSIST, do_full_maint, NULL);
	event_add(&full_maint_ev, &full_maint_period);
}

void kill_pool(PgPool *pool)
{
	const char *reason = "database removed";

	close_client_list(&pool->active_client_list, reason);
	close_client_list(&pool->waiting_client_list, reason);

	close_client_list(&pool->active_cancel_req_list, reason);
	close_client_list(&pool->waiting_cancel_req_list, reason);

	close_server_list(&pool->active_server_list, reason);
	close_server_list(&pool->active_cancel_server_list, reason);
	close_server_list(&pool->being_canceled_server_list, reason);
	close_server_list(&pool->idle_server_list, reason);
	close_server_list(&pool->used_server_list, reason);
	close_server_list(&pool->tested_server_list, reason);
	close_server_list(&pool->new_server_list, reason);

	pktbuf_free(pool->welcome_msg);

	list_del(&pool->map_head);
	statlist_remove(&pool_list, &pool->head);
	varcache_clean(&pool->orig_vars);
	slab_free(pool_cache, pool);
}

void kill_peer_pool(PgPool *pool)
{
	const char *reason = "peer removed";

	close_client_list(&pool->active_cancel_req_list, reason);
	close_client_list(&pool->waiting_cancel_req_list, reason);
	close_server_list(&pool->active_cancel_server_list, reason);
	close_server_list(&pool->new_server_list, reason);

	pktbuf_free(pool->welcome_msg);

	list_del(&pool->map_head);
	statlist_remove(&peer_pool_list, &pool->head);
	varcache_clean(&pool->orig_vars);
	slab_free(peer_pool_cache, pool);
}


void kill_database(PgDatabase *db)
{
	PgPool *pool;
	struct List *item, *tmp;

	log_warning("dropping database '%s' as it does not exist anymore or inactive auto-database", db->name);

	statlist_for_each_safe(item, &pool_list, tmp) {
		pool = container_of(item, PgPool, head);
		if (pool->db == db)
			kill_pool(pool);
	}

	pktbuf_free(db->startup_params);
	free(db->host);

	if (db->forced_user)
		slab_free(user_cache, db->forced_user);
	free(db->connect_query);
	free(db->topology_query);
	if (db->inactive_time) {
		statlist_remove(&autodatabase_idle_list, &db->head);
	} else {
		statlist_remove(&database_list, &db->head);
	}

	if (db->auth_dbname)
		free((void *)db->auth_dbname);

	aatree_destroy(&db->user_tree);
	slab_free(db_cache, db);
}

void kill_peer(PgDatabase *db)
{
	PgPool *pool;
	struct List *item, *tmp;

	log_warning("dropping peer %s as it does not exist anymore", db->name);

	statlist_for_each_safe(item, &peer_pool_list, tmp) {
		pool = container_of(item, PgPool, head);
		if (pool->db == db)
			kill_peer_pool(pool);
	}

	free(db->host);

	statlist_remove(&peer_list, &db->head);
	slab_free(peer_cache, db);
}

/* as [pgbouncer] section can be loaded after databases,
   there's need for review */
void config_postprocess(void)
{
	struct List *item, *tmp;
	PgDatabase *db;

	statlist_for_each_safe(item, &database_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (db->db_dead) {
			kill_database(db);
			continue;
		}
	}

	statlist_for_each_safe(item, &peer_list, tmp) {
		db = container_of(item, PgDatabase, head);
		if (db->db_dead) {
			kill_peer(db);
			continue;
		}
	}
}
