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
 * Admin console commands.
 */

#include "bouncer.h"
#include "multithread.h"

#include <usual/regex.h>
#include <usual/netdb.h>
#include <usual/endian.h>
#include <usual/safeio.h>
#include <usual/slab.h>
#include <usual/strpool.h>

/* regex elements */
#define WS0     "[ \t\n\r]*"
#define WS1     "[ \t\n\r]+"
#define WORD    "(\"([^\"]+|\"\")*\"|[0-9a-z_]+)"
#define STRING  "('([^']|'')*')"

/* possible max + 1 */
#define MAX_GROUPS 10

/* group numbers */
#define CMD_NAME 1
#define CMD_ARG 4
#define SET_KEY 1
#define SET_VAL 4

typedef bool (*cmd_func_t)(PgSocket *admin, const char *arg);
struct cmd_lookup {
	const char *word;
	cmd_func_t func;
};

/* CMD [arg]; */
static const char cmd_normal_rx[] =
	"^" WS0 WORD "(" WS1 WORD ")?" WS0 "(;" WS0 ")?$";

/* SET with simple value */
static const char cmd_set_word_rx[] =
	"^" WS0 "set" WS1 WORD WS0 "(=|to)" WS0 WORD WS0 "(;" WS0 ")?$";

/* SET with quoted value */
static const char cmd_set_str_rx[] =
	"^" WS0 "set" WS1 WORD WS0 "(=|to)" WS0 STRING WS0 "(;" WS0 ")?$";

/* compiled regexes */
static regex_t rc_cmd;
static regex_t rc_set_word;
static regex_t rc_set_str;

// admin_pool multithread support implemented
static PgPool *admin_pool;	// Only used in single-thread mode

/* only valid during processing */
static const char *current_query;

void admin_cleanup(void)
{
	regfree(&rc_cmd);
	regfree(&rc_set_str);
	regfree(&rc_set_word);
	admin_pool = NULL;
}

static bool syntax_error(PgSocket *admin)
{
	return admin_error(admin, "invalid command '%s', use SHOW HELP;",
			   current_query ? current_query : "<no query>");
}

static bool exec_cmd(struct cmd_lookup *lookup, PgSocket *admin,
		     const char *cmd, const char *arg)
{
	for (; lookup->word; lookup++) {
		if (strcasecmp(lookup->word, cmd) == 0)
			return lookup->func(admin, arg);
	}
	return syntax_error(admin);
}

bool admin_error(PgSocket *admin, const char *fmt, ...)
{
	char str[1024];
	va_list ap;
	bool res = true;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str), fmt, ap);
	va_end(ap);

	log_error("%s", str);
	if (admin)
		res = send_pooler_error(admin, true, NULL, false, str);
	return res;
}


static int count_paused_databases(void)
{
	struct List *item;
	PgDatabase *db;
	int cnt = 0;
	THREAD_SAFE_STATLIST_EACH(&database_list, item, {
		db = container_of(item, PgDatabase, head);
		cnt += db->db_paused;
	});

	return cnt;
}



static int count_db_active(PgDatabase *db)
{
	struct List *item;
	PgPool *pool;
	int cnt = 0;
	THREAD_ITERATE(thread_id, {
		struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
		THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
			pool = container_of(item, PgPool, head);
			if (pool->db->name == db->name)
				cnt += pool_server_count(pool);
		});
	});
	return cnt;
}

bool admin_flush(PgSocket *admin, PktBuf *buf, const char *desc)
{
	pktbuf_write_CommandComplete(buf, desc);
	pktbuf_write_ReadyForQuery(buf);
	return pktbuf_send_queued(buf, admin);
}

bool admin_ready(PgSocket *admin, const char *desc)
{
	PktBuf buf;
	uint8_t tmp[512];
	pktbuf_static(&buf, tmp, sizeof(tmp));
	pktbuf_write_CommandComplete(&buf, desc);
	pktbuf_write_ReadyForQuery(&buf);
	return pktbuf_send_immediate(&buf, admin);
}

/*
 * some silly clients start actively messing with server parameters
 * without checking if that's necessary.  Fake some env for them.
 */
struct FakeParam {
	const char *name;
	const char *value;
};

static const struct FakeParam fake_param_list[] = {
	{ "client_encoding", "UTF-8" },
	{ "default_transaction_isolation", "read committed" },
	{ "standard_conforming_strings", "on" },
	{ "datestyle", "ISO" },
	{ "timezone", "GMT" },
	{ NULL },
};

/* fake result send, returns if handled */
static bool fake_show(PgSocket *admin, const char *name)
{
	PktBuf *buf;
	const struct FakeParam *p;
	bool got = false;

	for (p = fake_param_list; p->name; p++) {
		if (strcasecmp(name, p->name) == 0) {
			got = true;
			break;
		}
	}

	if (got) {
		buf = pktbuf_dynamic(256);
		if (buf) {
			pktbuf_write_RowDescription(buf, "s", p->name);
			pktbuf_write_DataRow(buf, "s", p->value);
			admin_flush(admin, buf, "SHOW");
		} else {
			admin_error(admin, "no mem");
		}
	}
	return got;
}

static bool fake_set(PgSocket *admin, const char *key, const char *val)
{
	PktBuf *buf;
	const struct FakeParam *p;
	bool got = false;

	for (p = fake_param_list; p->name; p++) {
		if (strcasecmp(key, p->name) == 0) {
			got = true;
			break;
		}
	}

	if (got) {
		buf = pktbuf_dynamic(256);
		if (buf) {
			pktbuf_write_Notice(buf, "SET ignored");
			admin_flush(admin, buf, "SET");
		} else {
			admin_error(admin, "no mem");
		}
	}
	return got;
}

/* Command: SET key = val; */
static bool admin_set(PgSocket *admin, const char *key, const char *val)
{
	char tmp[512];
	bool ok;

	if (fake_set(admin, key, val))
		return true;

	if (admin->admin_user) {
		ok = set_config_param(key, val);
		if (ok) {
			PktBuf *buf = pktbuf_dynamic(256);
			if (!buf) {
				return admin_error(admin, "no mem");
			}
			if (strstr(key, "_tls_") != NULL || strstr(key, "_tls13_") != NULL) {
				if (!sbuf_tls_setup())
					pktbuf_write_Notice(buf, "TLS settings could not be applied, still using old configuration");
			}
			snprintf(tmp, sizeof(tmp), "SET %s=%s", key, val);
			return admin_flush(admin, buf, tmp);
		} else {
			return admin_error(admin, "SET failed");
		}
	} else {
		return admin_error(admin, "admin access needed");
	}
}

/* send a row with sendmsg, optionally attaching a fd */
static bool send_one_fd(PgSocket *admin, int thread_id,
			int fd, const char *task,
			const char *user, const char *db,
			const char *addr, int port,
			uint64_t ckey, int link,
			const char *client_enc,
			const char *std_strings,
			const char *datestyle,
			const char *timezone,
			const char *password,
			const uint8_t *scram_client_key,
			int scram_client_key_len,
			const uint8_t *scram_server_key,
			int scram_server_key_len)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iovec;
	ssize_t res;
	uint8_t cntbuf[CMSG_SPACE(sizeof(int))];

	struct PktBuf *pkt = global_pktbuf_temp();

	pktbuf_write_DataRow(pkt, "issssiqisssssbbi",
			     fd, task, user, db, addr, port,
			     ckey, link, client_enc, std_strings,
			     datestyle, timezone, password,
			     scram_client_key_len, scram_client_key,
			     scram_server_key_len, scram_server_key,
			     multithread_mode ? thread_id : 0);
	if (pkt->failed)
		return false;
	iovec.iov_base = pkt->buf;
	iovec.iov_len = pktbuf_written(pkt);

	/* sending fds */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iovec;
	msg.msg_iovlen = 1;

	/* attach a fd */
	if (pga_is_unix(&admin->remote_addr) && admin->own_user && !admin->sbuf.tls) {
		msg.msg_control = cntbuf;
		msg.msg_controllen = sizeof(cntbuf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));

		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
		msg.msg_controllen = cmsg->cmsg_len;
	}

	slog_debug(admin, "sending socket list: fd=%d, len=%d",
		   fd, (int)msg.msg_controllen);
	if (msg.msg_controllen) {
		res = safe_sendmsg(sbuf_socket(&admin->sbuf), &msg, 0);
	} else {
		res = sbuf_op_send(&admin->sbuf, pkt->buf, pktbuf_written(pkt));
	}
	if (res < 0) {
		log_error("send_one_fd: sendmsg error: %s", strerror(errno));
		return false;
	} else if ((size_t)res != iovec.iov_len) {
		log_error("send_one_fd: partial sendmsg");
		return false;
	}
	return true;
}

/* send a row with sendmsg, optionally attaching a fd */
static bool show_one_fd(PgSocket *admin, PgSocket *sk, int thread_id)
{
	PgAddr *addr = &sk->remote_addr;
	struct MBuf tmp;
	VarCache *v = &sk->vars;
	uint64_t ckey;
	const struct PStr *client_encoding = v->var_list[VClientEncoding];
	const struct PStr *std_strings = v->var_list[VStdStr];
	const struct PStr *datestyle = v->var_list[VDateStyle];
	const struct PStr *timezone = v->var_list[VTimeZone];
	char addrbuf[PGADDR_BUF];
	const char *password = NULL;
	bool send_scram_keys = false;

	/* Skip TLS sockets */
	if (sk->sbuf.tls || (sk->link && sk->link->sbuf.tls))
		return true;

	mbuf_init_fixed_reader(&tmp, sk->cancel_key, 8);
	if (!mbuf_get_uint64be(&tmp, &ckey))
		return false;

	if (sk->pool && sk->pool->db->auth_user_credentials && sk->login_user_credentials) {
		if (!find_global_user(sk->login_user_credentials->name))
			password = sk->login_user_credentials->passwd;
	}

	/* PAM requires passwords as well since they are not stored externally */
	if (cf_auth_type == AUTH_TYPE_PAM) {
		if (!find_global_user(sk->login_user_credentials->name))
			password = sk->login_user_credentials->passwd;
	}

	if (sk->pool && sk->pool->user_credentials && sk->pool->user_credentials->use_scram_keys)
		send_scram_keys = true;

	return send_one_fd(admin, thread_id,
			   sbuf_socket(&sk->sbuf),
			   is_server_socket(sk) ? "server" : "client",
			   sk->login_user_credentials ? sk->login_user_credentials->name : NULL,
			   sk->pool ? sk->pool->db->name : NULL,
			   pga_ntop(addr, addrbuf, sizeof(addrbuf)),
			   pga_port(addr),
			   ckey,
			   sk->link ? sbuf_socket(&sk->link->sbuf) : 0,
			   client_encoding ? client_encoding->str : NULL,
			   std_strings ? std_strings->str : NULL,
			   datestyle ? datestyle->str : NULL,
			   timezone ? timezone->str : NULL,
			   password,
			   send_scram_keys ? sk->pool->user_credentials->scram_ClientKey : NULL,
			   send_scram_keys ? (int) sizeof(sk->pool->user_credentials->scram_ClientKey) : -1,
			   send_scram_keys ? sk->pool->user_credentials->scram_ServerKey : NULL,
			   send_scram_keys ? (int) sizeof(sk->pool->user_credentials->scram_ServerKey) : -1);
}

static bool show_pooler_cb(void *arg, int fd, const PgAddr *a)
{
	char buf[PGADDR_BUF];

	return send_one_fd(arg, -1, fd, "pooler", NULL, NULL,
			   pga_ntop(a, buf, sizeof(buf)), pga_port(a), 0, 0,
			   NULL, NULL, NULL, NULL, NULL, NULL, -1, NULL, -1);
}

/* send a row with sendmsg, optionally attaching a fd */
static bool show_pooler_fds(PgSocket *admin)
{
	return for_each_pooler_fd(show_pooler_cb, admin);
}

static bool show_fds_from_list(PgSocket *admin, struct StatList *list, int thread_id)
{
	struct List *item;
	PgSocket *sk;
	bool res = true;

	statlist_for_each(item, list) {
		sk = container_of(item, PgSocket, head);
		res = show_one_fd(admin, sk, thread_id);
		if (!res)
			break;
	}
	return res;
}

static void show_fds_from_lists(PgSocket *admin, PgPool *pool, int thread_id, bool *res)
{
	*(res) = *(res) && show_fds_from_list(admin, &pool->active_client_list, thread_id);
	*(res) = *(res) && show_fds_from_list(admin, &pool->waiting_client_list, thread_id);
	*(res) = *(res) && show_fds_from_list(admin, &pool->active_server_list, thread_id);
	*(res) = *(res) && show_fds_from_list(admin, &pool->idle_server_list, thread_id);
	*(res) = *(res) && show_fds_from_list(admin, &pool->used_server_list, thread_id);
	*(res) = *(res) && show_fds_from_list(admin, &pool->tested_server_list, thread_id);
	*(res) = *(res) && show_fds_from_list(admin, &pool->new_server_list, thread_id);
}


/*
 * Command: SHOW FDS
 *
 * If privileged connection, send also actual fds
 */
static bool admin_show_fds(PgSocket *admin, const char *arg)
{
	struct List *item;
	PgPool *pool;
	bool res;

	/*
	 * Dangerous to show to everybody:
	 * - can lock pooler as code flips async option
	 * - show cancel keys for all users
	 * - shows passwords (md5) for dynamic users
	 */
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	/*
	 * It's very hard to send it reliably over in async manner,
	 * so turn async off for this resultset.
	 */
	socket_set_nonblocking(sbuf_socket(&admin->sbuf), 0);

	/*
	 * send resultset
	 */
	SEND_RowDescription(res, admin, "issssiqisssssbbi",
			    "fd", "task",
			    "user", "database",
			    "addr", "port",
			    "cancel", "link",
			    "client_encoding", "std_strings",
			    "datestyle", "timezone", "password",
			    "scram_client_key", "scram_server_key",
			    "thread_id");
	if (res)
		res = show_pooler_fds(admin);

	if (res) {
		if (multithread_mode) {
			FOR_EACH_THREAD(thread_id){
				// TODO correct me
				res &= show_fds_from_list(admin, &(threads[thread_id].login_client_list), thread_id);
			}
		} else {
			res &= show_fds_from_list(admin, &login_client_list, 0);
		}
	}

	THREAD_ITERATE(thread_id, {
		THREAD_SAFE_STATLIST_EACH_BY_NAME(pool_list, thread_id, item, {
			pool = container_of(item, PgPool, head);
			if (pool->db->admin)
				continue;
			show_fds_from_lists(admin, pool, thread_id, &res);
			if (!res)
				break;
		});
		if (!res)
			break;
	});
	if (res)
		res = admin_ready(admin, "SHOW");

	/* turn async back on */
	socket_set_nonblocking(sbuf_socket(&admin->sbuf), 1);

	return res;
}

static void show_one_database(PgDatabase *db, PktBuf *buf, struct CfValue *cv, struct CfValue *load_balance_hosts_lookup)
{
	usec_t server_lifetime_secs;
	const char *f_user;
	const char *pool_mode_str;
	const char *load_balance_hosts_str;

	server_lifetime_secs = (db->server_lifetime > 0 ? db->server_lifetime : cf_server_lifetime) / USEC;
	f_user = db->forced_user_credentials ? db->forced_user_credentials->name : NULL;
	pool_mode_str = NULL;
	load_balance_hosts_str = NULL;
	cv->value_p = &db->pool_mode;
	load_balance_hosts_lookup->value_p = &db->load_balance_hosts;
	if (db->pool_mode != POOL_INHERIT)
		pool_mode_str = cf_get_lookup(cv);

	if (db->host && strchr(db->host, ','))
		load_balance_hosts_str = cf_get_lookup(load_balance_hosts_lookup);

	pktbuf_write_DataRow(buf, "ssissiiiissiiiiii",
			     db->name, db->host, db->port,
			     db->dbname, f_user,
			     db->pool_size >= 0 ? db->pool_size : cf_default_pool_size,
			     db->min_pool_size >= 0 ? db->min_pool_size : cf_min_pool_size,
			     db->res_pool_size >= 0 ? db->res_pool_size : cf_res_pool_size,
			     server_lifetime_secs,
			     pool_mode_str,
			     load_balance_hosts_str,
			     database_max_connections(db),
			     db->connection_count,
			     database_max_client_connections(db),
			     db->client_connection_count,
			     db->db_paused,
			     db->db_disabled);
}


/* Command: SHOW DATABASES */
static bool admin_show_databases(PgSocket *admin, const char *arg)
{
	struct List *item;
	PktBuf *buf;
	struct CfValue cv;
	struct CfValue load_balance_hosts_lookup;

	cv.extra = pool_mode_map;
	load_balance_hosts_lookup.extra = load_balance_hosts_map;
	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "ssissiiiissiiiiii",
				    "name", "host", "port",
				    "database", "force_user", "pool_size", "min_pool_size", "reserve_pool_size",
				    "server_lifetime", "pool_mode", "load_balance_hosts", "max_connections",
				    "current_connections", "max_client_connections", "current_client_connections",
				    "paused", "disabled");


	THREAD_SAFE_STATLIST_EACH(&database_list, item, {
		PgDatabase *db = container_of(item, PgDatabase, head);
		show_one_database(db, buf, &cv, &load_balance_hosts_lookup);
	});

	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW PEERS */
static bool admin_show_peers(PgSocket *admin, const char *arg)
{
	PgDatabase *peer;
	struct List *item;
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "isiii",
				    "peer_id", "host", "port", "pool_size", "thread_id");
	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id){
			THREAD_SAFE_STATLIST_EACH(&(threads[thread_id].peer_list), item, {
				peer = container_of(item, PgDatabase, head);

				pktbuf_write_DataRow(buf, "isiii",
						     peer->peer_id, peer->host, peer->port,
						     peer->pool_size >= 0 ? peer->pool_size : cf_default_pool_size,
						     thread_id);
			});
		}
	} else {
		THREAD_SAFE_STATLIST_EACH(&peer_list, item, {
			peer = container_of(item, PgDatabase, head);

			pktbuf_write_DataRow(buf, "isiii",
					     peer->peer_id, peer->host, peer->port,
					     peer->pool_size >= 0 ? peer->pool_size : cf_default_pool_size, 0);
		});
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}


/* Command: SHOW LISTS */
static bool admin_show_lists(PgSocket *admin, const char *arg)
{
	int total_pool_list, total_peer_pool_list, total_peer_list;
	int total_free_clients, total_used_clients, total_login_clients;
	int total_free_servers, total_used_servers;

	PktBuf *buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "si", "list", "items");
#define SENDLIST(name, size) pktbuf_write_DataRow(buf, "si", (name), (size))

	total_pool_list = 0;
	total_peer_list = 0;
	total_peer_pool_list = 0;
	total_free_clients = 0;
	total_used_clients = 0;
	total_login_clients = 0;
	total_free_servers = 0;
	total_used_servers = 0;

	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id){
			total_pool_list += thread_safe_statlist_count(&(threads[thread_id].pool_list));
			total_peer_list += thread_safe_statlist_count(&(threads[thread_id].peer_list));
			total_peer_pool_list += thread_safe_statlist_count(&(threads[thread_id].peer_pool_list));
			total_free_clients += slab_free_count(threads[thread_id].client_cache);
			total_used_clients += slab_active_count(threads[thread_id].client_cache);
			total_login_clients += statlist_count(&(threads[thread_id].login_client_list));
			total_free_servers += slab_free_count(threads[thread_id].server_cache);
			total_used_servers += slab_active_count(threads[thread_id].server_cache);
		}
	} else {
		total_pool_list = thread_safe_statlist_count(&pool_list);
		total_peer_list = thread_safe_statlist_count(&peer_list);
		total_peer_pool_list = thread_safe_statlist_count(&peer_pool_list);
		total_free_clients = slab_free_count(client_cache);
		total_used_clients = slab_active_count(client_cache);
		total_login_clients = statlist_count(&login_client_list);
		total_free_servers = slab_free_count(server_cache);
		total_used_servers = slab_active_count(server_cache);
	}

	SENDLIST("databases", thread_safe_statlist_count(&database_list));
	SENDLIST("users", thread_safe_statlist_count(&thread_safe_user_list));
	SENDLIST("peers", total_peer_list);
	SENDLIST("pools", total_pool_list);
	SENDLIST("peer_pools", total_peer_pool_list);
	SENDLIST("free_clients", total_free_clients);
	SENDLIST("used_clients", total_used_clients);
	SENDLIST("login_clients", total_login_clients);
	SENDLIST("free_servers", total_free_servers);
	SENDLIST("used_servers", total_used_servers);
	{
		int names, zones, qry, pend;
		MULTITHREAD_VISIT(&adns_lock, adns_info(adns, &names, &zones, &qry, &pend));
		SENDLIST("dns_names", names);
		SENDLIST("dns_zones", zones);
		SENDLIST("dns_queries", qry);
		SENDLIST("dns_pending", pend);
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW USERS */
static bool admin_show_users(PgSocket *admin, const char *arg)
{
	struct List *item;
	PktBuf *buf = pktbuf_dynamic(256);
	struct CfValue cv;
	char pool_size_str[12] = "";
	char res_pool_size_str[12] = "";
	const char *pool_mode_str;

	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	cv.extra = pool_mode_map;

	pktbuf_write_RowDescription(
		buf, "ssssiiii", "name", "pool_size", "reserve_pool_size", "pool_mode", "max_user_connections", "current_connections",
		"max_user_client_connections", "current_client_connections");
	THREAD_SAFE_STATLIST_EACH(&thread_safe_user_list, item, {
		PgGlobalUser *user = container_of(item, PgGlobalUser, head);
		if (user->pool_size >= 0)
			snprintf(pool_size_str, sizeof(pool_size_str), "%9d", user->pool_size);
		if (user->res_pool_size >= 0)
			snprintf(res_pool_size_str, sizeof(res_pool_size_str), "%9d", user->res_pool_size);
		pool_mode_str = NULL;

		cv.value_p = &user->pool_mode;
		if (user->pool_mode != POOL_INHERIT)
			pool_mode_str = cf_get_lookup(&cv);

		pktbuf_write_DataRow(buf, "ssssiiii", user->credentials.name,
				     pool_size_str,
				     res_pool_size_str,
				     pool_mode_str,
				     user_max_connections(user),
				     user->connection_count,
				     user_client_max_connections(user),
				     user->client_connection_count
				     );
	});
	admin_flush(admin, buf, "SHOW");
	return true;
}

#define SKF_STD "ssssssisiTTiiississiii"
#define SKF_DBG "ssssssisiTTiiississiiiiiiiiii"

static void socket_header(PktBuf *buf, bool debug)
{
	pktbuf_write_RowDescription(buf, debug ? SKF_DBG : SKF_STD,
				    "type", "user", "database",
				    "replication", "state", "addr", "port",
				    "local_addr", "local_port",
				    "connect_time", "request_time",
				    "wait", "wait_us", "close_needed",
				    "ptr", "link", "remote_pid", "tls",
				    "application_name",
				    "prepared_statements", "id",
				    "thread_id",
					/* debug follows */
				    "recv_pos", "pkt_pos", "pkt_remain",
				    "send_pos", "send_remain",
				    "pkt_avail", "send_avail");
}

static void adr2txt(const PgAddr *adr, char *dst, unsigned dstlen)
{
	pga_ntop(adr, dst, dstlen);
}

static void socket_row(PktBuf *buf, PgSocket *sk, int thread_id, const char *state, bool debug)
{
	int pkt_avail = 0, send_avail = 0;
	int remote_pid;
	int prepared_statement_count = 0;
	char ptrbuf[128], linkbuf[128];
	char l_addr[PGADDR_BUF], r_addr[PGADDR_BUF];
	IOBuf *io = sk->sbuf.io;
	char infobuf[96] = "";
	VarCache *v = &sk->vars;
	const struct PStr *application_name = v->var_list[VAppName];
	usec_t now = get_multithread_time_with_id(thread_id);
	usec_t wait_time = sk->query_start ? now - sk->query_start : 0;
	char *replication;

	if (io) {
		pkt_avail = iobuf_amount_parse(sk->sbuf.io);
		send_avail = iobuf_amount_pending(sk->sbuf.io);
	}

	adr2txt(&sk->remote_addr, r_addr, sizeof(r_addr));
	adr2txt(&sk->local_addr, l_addr, sizeof(l_addr));

	snprintf(ptrbuf, sizeof(ptrbuf), "%p", sk);
	if (sk->link)
		snprintf(linkbuf, sizeof(linkbuf), "%p", sk->link);
	else
		linkbuf[0] = 0;

	/* get pid over unix socket */
	if (pga_is_unix(&sk->remote_addr))
		remote_pid = sk->remote_addr.scred.pid;
	else
		remote_pid = 0;
	/* if that failed, get it from cancel key */
	if (is_server_socket(sk) && remote_pid == 0)
		remote_pid = be32dec(sk->cancel_key);

	if (sk->sbuf.tls)
		tls_get_connection_info(sk->sbuf.tls, infobuf, sizeof infobuf);

	if (is_server_socket(sk))
		prepared_statement_count = HASH_COUNT(sk->server_prepared_statements);
	else
		prepared_statement_count = HASH_COUNT(sk->client_prepared_statements);

	if (sk->replication == REPLICATION_NONE)
		replication = "none";
	else if (sk->replication == REPLICATION_LOGICAL)
		replication = "logical";
	else
		replication = "physical";

	pktbuf_write_DataRow(buf, debug ? SKF_DBG : SKF_STD,
			     is_server_socket(sk) ? "S" : "C",
			     sk->login_user_credentials ? sk->login_user_credentials->name : "(nouser)",
			     sk->pool && !sk->pool->db->peer_id ? sk->pool->db->name : "(nodb)",
			     replication,
			     (!sk->link && strcmp(state, "active") == 0) ? "idle" : state,
			     r_addr, pga_port(&sk->remote_addr),
			     l_addr, pga_port(&sk->local_addr),
			     sk->connect_time,
			     sk->request_time,
			     (int)(wait_time / USEC),
			     (int)(wait_time % USEC),
			     sk->close_needed,
			     ptrbuf, linkbuf, remote_pid, infobuf,
			     application_name ? application_name->str : "",
			     prepared_statement_count, sk->id,
			     multithread_mode ? thread_id : 0,
				/* debug */
			     io ? io->recv_pos : 0,
			     io ? io->parse_pos : 0,
			     sk->sbuf.pkt_remain,
			     io ? io->done_pos : 0,
			     0,
			     pkt_avail, send_avail);
}

/* Helper for SHOW CLIENTS/SERVERS/SOCKETS */
static void show_socket_list(PktBuf *buf, struct StatList *list, int thread_id, const char *state, bool debug)
{
	struct List *item;
	PgSocket *sk;

	statlist_for_each(item, list) {
		sk = container_of(item, PgSocket, head);
		socket_row(buf, sk, thread_id, state, debug);
	}
}

static void show_client(PktBuf *buf, struct ThreadSafeStatList *pool_list_ptr, struct ThreadSafeStatList *peer_pool_list_ptr)
{
	struct List *item;
	PgPool *pool;

	THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
		pool = container_of(item, PgPool, head);
		show_socket_list(buf, &pool->active_client_list, pool->thread_id, "active", false);
		show_socket_list(buf, &pool->waiting_client_list, pool->thread_id, "waiting", false);
		show_socket_list(buf, &pool->active_cancel_req_list, pool->thread_id, "active_cancel_req", false);
		show_socket_list(buf, &pool->waiting_cancel_req_list, pool->thread_id, "waiting_cancel_req", false);
	});

	THREAD_SAFE_STATLIST_EACH(peer_pool_list_ptr, item, {
		pool = container_of(item, PgPool, head);
		show_socket_list(buf, &pool->active_cancel_req_list, pool->thread_id, "active_cancel_req", false);
		show_socket_list(buf, &pool->waiting_cancel_req_list, pool->thread_id, "waiting_cancel_req", false);
	});
}


/* Command: SHOW CLIENTS */
static bool admin_show_clients(PgSocket *admin, const char *arg)
{
	PktBuf *buf = pktbuf_dynamic(256);

	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	socket_header(buf, false);
	THREAD_ITERATE(thread_id, {
		struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
		struct ThreadSafeStatList *peer_pool_list_ptr = GET_MULTITHREAD_PTR(peer_pool_list, thread_id);
		show_client(buf, pool_list_ptr, peer_pool_list_ptr);
	});

	admin_flush(admin, buf, "SHOW");
	return true;
}

static void show_server_list(PktBuf *buf, PgPool *pool, int thread_id, bool debug)
{
	show_socket_list(buf, &pool->active_server_list, thread_id, "active", debug);
	show_socket_list(buf, &pool->idle_server_list, thread_id, "idle", debug);
	show_socket_list(buf, &pool->used_server_list, thread_id, "used", debug);
	show_socket_list(buf, &pool->tested_server_list, thread_id, "tested", debug);
	show_socket_list(buf, &pool->new_server_list, thread_id, "new", debug);
	show_socket_list(buf, &pool->active_cancel_server_list, thread_id, "active_cancel", debug);
	show_socket_list(buf, &pool->being_canceled_server_list, thread_id, "being_canceled", debug);
}


/* Command: SHOW SERVERS */
static bool admin_show_servers(PgSocket *admin, const char *arg)
{
	struct List *item;
	PgPool *pool;
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	socket_header(buf, false);
	THREAD_ITERATE(thread_id, {
		struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
		struct ThreadSafeStatList *peer_pool_list_ptr = GET_MULTITHREAD_PTR(peer_pool_list, thread_id);
		lock_thread(thread_id);
		THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
			pool = container_of(item, PgPool, head);
			show_server_list(buf, pool, thread_id, false);
		});
		THREAD_SAFE_STATLIST_EACH(peer_pool_list_ptr, item, {
			pool = container_of(item, PgPool, head);
			show_socket_list(buf, &pool->new_server_list, thread_id, "new", false);
			show_socket_list(buf, &pool->active_cancel_server_list, thread_id, "active_cancel", false);
		});
		unlock_thread(thread_id);
	});

	admin_flush(admin, buf, "SHOW");
	return true;
}

static void show_socket_list_internal(PktBuf *buf, PgPool *pool, int thread_id, bool debug)
{
	show_socket_list(buf, &pool->active_client_list, thread_id, "cl_active", debug);
	show_socket_list(buf, &pool->waiting_client_list, thread_id, "cl_waiting", debug);
	show_socket_list(buf, &pool->active_server_list, thread_id, "sv_active", debug);
	show_socket_list(buf, &pool->idle_server_list, thread_id, "sv_idle", debug);
	show_socket_list(buf, &pool->used_server_list, thread_id, "sv_used", debug);
	show_socket_list(buf, &pool->tested_server_list, thread_id, "sv_tested", debug);
	show_socket_list(buf, &pool->new_server_list, thread_id, "sv_login", debug);
}


/* Command: SHOW SOCKETS */
static bool admin_show_sockets(PgSocket *admin, const char *arg)
{
	struct List *item;
	PgPool *pool;
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	socket_header(buf, true);
	THREAD_ITERATE(thread_id, {
		struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
		struct StatList *login_client_list_ptr = GET_MULTITHREAD_PTR(login_client_list, thread_id);
		THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
			pool = container_of(item, PgPool, head);
			show_socket_list_internal(buf, pool, thread_id, true);
		});
		show_socket_list(buf, login_client_list_ptr, thread_id, "cl_login", true);
	});

	admin_flush(admin, buf, "SHOW");
	return true;
}

static void show_active_socket_list(PktBuf *buf, struct StatList *list, int thread_id, const char *state)
{
	struct List *item;
	statlist_for_each(item, list) {
		PgSocket *sk = container_of(item, PgSocket, head);
		if (!sbuf_is_empty(&sk->sbuf))
			socket_row(buf, sk, thread_id, state, true);
	}
}

static void show_active_socket_list_internal(PktBuf *buf, PgPool *pool, int thread_id)
{
	show_active_socket_list(buf, &pool->active_client_list, thread_id, "cl_active");
	show_active_socket_list(buf, &pool->waiting_client_list, thread_id, "cl_waiting");

	show_active_socket_list(buf, &pool->active_server_list, thread_id, "sv_active");
	show_active_socket_list(buf, &pool->idle_server_list, thread_id, "sv_idle");
	show_active_socket_list(buf, &pool->used_server_list, thread_id, "sv_used");
	show_active_socket_list(buf, &pool->tested_server_list, thread_id, "sv_tested");
	show_active_socket_list(buf, &pool->new_server_list, thread_id, "sv_login");
}


/* Command: SHOW ACTIVE_SOCKETS */
static bool admin_show_active_sockets(PgSocket *admin, const char *arg)
{
	struct List *item;
	PgPool *pool;
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	socket_header(buf, true);
	THREAD_ITERATE(thread_id, {
		struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
		struct StatList *login_client_list_ptr = GET_MULTITHREAD_PTR(login_client_list, thread_id);
		lock_thread(thread_id);
		THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
			pool = container_of(item, PgPool, head);
			show_active_socket_list_internal(buf, pool, thread_id);
		});
		show_active_socket_list(buf, login_client_list_ptr, thread_id, "cl_login");
		unlock_thread(thread_id);
	});
	admin_flush(admin, buf, "SHOW");
	return true;
}

static void show_pools_internal(PgPool *pool, PktBuf *buf, int thread_id, usec_t now, struct CfValue *cv)
{
	PgSocket *waiter;
	usec_t max_wait;
	struct CfValue load_balance_hosts_lookup;
	const char *load_balance_hosts_str;
	load_balance_hosts_lookup.extra = load_balance_hosts_map;

	waiter = first_socket(&pool->waiting_client_list);
	max_wait = (waiter && waiter->query_start) ? now - waiter->query_start : 0;
	*(int *)(cv->value_p) = probably_wrong_pool_pool_mode(pool);

	load_balance_hosts_str = NULL;
	load_balance_hosts_lookup.value_p = &pool->db->load_balance_hosts;
	if (pool->db->host && strchr(pool->db->host, ','))
		load_balance_hosts_str = cf_get_lookup(&load_balance_hosts_lookup);

	pktbuf_write_DataRow(buf, "ssiiiiiiiiiiiiissi",
			     pool->db->name, pool->user_credentials->name,
			     statlist_count(&pool->active_client_list),
			     statlist_count(&pool->waiting_client_list),
			     statlist_count(&pool->active_cancel_req_list),
			     statlist_count(&pool->waiting_cancel_req_list),
			     statlist_count(&pool->active_server_list),
			     statlist_count(&pool->active_cancel_server_list),
			     statlist_count(&pool->being_canceled_server_list),
			     statlist_count(&pool->idle_server_list),
			     statlist_count(&pool->used_server_list),
			     statlist_count(&pool->tested_server_list),
			     statlist_count(&pool->new_server_list),
				/* how long is the oldest client waited */
			     (int)(max_wait / USEC),
			     (int)(max_wait % USEC),
			     cf_get_lookup(cv),
			     load_balance_hosts_str,
			     multithread_mode ? thread_id : 0);
}


/* Command: SHOW POOLS */
static bool admin_show_pools(PgSocket *admin, const char *arg)
{
	struct List *item;
	PktBuf *buf;
	usec_t now = get_cached_time();
	struct CfValue cv;
	int pool_mode;

	cv.extra = pool_mode_map;
	cv.value_p = &pool_mode;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "ssiiiiiiiiiiiiissi",
				    "database", "user",
				    "cl_active", "cl_waiting",
				    "cl_active_cancel_req",
				    "cl_waiting_cancel_req",
				    "sv_active",
				    "sv_active_cancel",
				    "sv_being_canceled",
				    "sv_idle",
				    "sv_used", "sv_tested",
				    "sv_login", "maxwait",
				    "maxwait_us", "pool_mode",
				    "load_balance_hosts",
				    "thread_id");

	THREAD_ITERATE(thread_id, {
		struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
		THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
			PgPool *pool = container_of(item, PgPool, head);
			show_pools_internal(pool, buf, thread_id, now, &cv);
		});
	});
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW PEER_POOLS */
static bool admin_show_peer_pools(PgSocket *admin, const char *arg)
{
	struct List *item;
	PgPool *pool;
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "iiiiii",
				    "peer_id",
				    "cl_active_cancel_req",
				    "cl_waiting_cancel_req",
				    "sv_active_cancel",
				    "sv_login",
				    "thread_id");
	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id){
			THREAD_SAFE_STATLIST_EACH((&threads[thread_id].peer_pool_list), item, {
				pool = container_of(item, PgPool, head);
				pktbuf_write_DataRow(buf, "iiiiii",
						     thread_id, pool->db->peer_id,
						     statlist_count(&pool->active_cancel_req_list),
						     statlist_count(&pool->waiting_cancel_req_list),
						     statlist_count(&pool->active_cancel_server_list),
						     statlist_count(&pool->new_server_list));
			});
		}
	} else {
		THREAD_SAFE_STATLIST_EACH(&peer_pool_list, item, {
			pool = container_of(item, PgPool, head);
			pktbuf_write_DataRow(buf, "iiiiii",
					     0, pool->db->peer_id,
					     statlist_count(&pool->active_cancel_req_list),
					     statlist_count(&pool->waiting_cancel_req_list),
					     statlist_count(&pool->active_cancel_server_list),
					     statlist_count(&pool->new_server_list));
		});
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}


static void slab_stat_cb(void *arg, const char *slab_name,
			 unsigned size, unsigned free,
			 unsigned total)
{
	PktBuf *buf = arg;
	unsigned alloc = total * size;
	pktbuf_write_DataRow(buf, "siiii", slab_name,
			     size, total - free, free, alloc);
}

/* Command: SHOW MEM */
static bool admin_show_mem(PgSocket *admin, const char *arg)
{
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "siiii", "name",
				    "size", "used", "free", "memtotal");
	slab_stats(slab_stat_cb, buf);
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW STATE */
static bool admin_show_state(PgSocket *admin, const char *arg)
{
	PktBuf *buf;

	buf = pktbuf_dynamic(64);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "ss", "key", "value");

	pktbuf_write_DataRow(buf, "ss", "active", (cf_pause_mode == P_NONE) ? "yes" : "no");
	pktbuf_write_DataRow(buf, "ss", "paused", (cf_pause_mode == P_PAUSE) ? "yes" : "no");
	pktbuf_write_DataRow(buf, "ss", "suspended", (cf_pause_mode == P_SUSPEND) ? "yes" : "no");

	admin_flush(admin, buf, "SHOW");

	return true;
}

/* Command: SHOW DNS_HOSTS */

static void dns_name_cb(void *arg, const char *name, const struct addrinfo *ai, usec_t ttl)
{
	PktBuf *buf = arg;
	char *s, *end;
	char adrs[1024];
	usec_t now = get_cached_time();

	end = adrs + sizeof(adrs) - 2;
	for (s = adrs; ai && s < end; ai = ai->ai_next) {
		if (s != adrs)
			*s++ = ',';
		sa2str(ai->ai_addr, s, end - s);
		s += strlen(s);
	}
	*s = 0;

	/*
	 * Ttl can be smaller than now if we are waiting for dns reply for long.
	 *
	 * It's better to show 0 in that case as otherwise it confuses users into
	 * thinking that there is large ttl for the name.
	 */
	pktbuf_write_DataRow(buf, "sqs", name, ttl < now ? 0 : (ttl - now) / USEC, adrs);
}

static bool admin_show_dns_hosts(PgSocket *admin, const char *arg)
{
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "sqs", "hostname", "ttl", "addrs");
	MULTITHREAD_VISIT(&adns_lock, adns_walk_names(adns, dns_name_cb, buf));
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW DNS_ZONES */

static void dns_zone_cb(void *arg, const char *name, uint32_t serial, int nhosts)
{
	PktBuf *buf = arg;
	pktbuf_write_DataRow(buf, "sqi", name, (uint64_t)serial, nhosts);
}

static bool admin_show_dns_zones(PgSocket *admin, const char *arg)
{
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "sqi", "zonename", "serial", "count");
	MULTITHREAD_VISIT(&adns_lock, adns_walk_zones(adns, dns_zone_cb, buf));
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW CONFIG */

static void show_one_param(void *arg, const char *name, const char *val, const char *defval, bool reloadable)
{
	PktBuf *buf = arg;
	pktbuf_write_DataRow(buf, "ssss", name, val, defval,
			     reloadable ? "yes" : "no");
}

static bool admin_show_config(PgSocket *admin, const char *arg)
{
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "ssss", "key", "value", "default", "changeable");

	config_for_each(show_one_param, buf);

	admin_flush(admin, buf, "SHOW");

	return true;
}

/* Command: RELOAD */
static bool admin_cmd_reload(PgSocket *admin, const char *arg)
{
	bool ok = true;
	if (arg && *arg)
		return syntax_error(admin);

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	log_info("RELOAD command issued");

	if (!load_config()) {
		ok = false;
		log_error("RELOAD Failed, see logs for more details");
	}

	if (!sbuf_tls_setup()) {
		ok = false;
		log_error("TLS configuration could not be reloaded, keeping old configuration");
	}

	if (ok)
		return admin_ready(admin, "RELOAD");
	else
		return send_pooler_error(admin, true, "F0000", false, "RELOAD failed, see logs for additional details");
}

/* Command: SHUTDOWN */
static bool admin_cmd_shutdown(PgSocket *admin, const char *arg)
{
	enum ShutDownMode mode = SHUTDOWN_IMMEDIATE;
	if (arg && *arg) {
		if (strcasecmp(arg, "WAIT_FOR_CLIENTS") == 0)
			mode = SHUTDOWN_WAIT_FOR_CLIENTS;
		else if (strcasecmp(arg, "WAIT_FOR_SERVERS") == 0)
			mode = SHUTDOWN_WAIT_FOR_SERVERS;
		else
			return syntax_error(admin);
	}

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	/*
	 * note: new pooler expects unix socket file gone when it gets
	 * event from fd.  Currently atexit() cleanup should be called
	 * before closing open sockets.
	 */
	cf_shutdown = mode;
	if (mode == SHUTDOWN_IMMEDIATE) {
		log_info("SHUTDOWN command issued");
		event_base_loopbreak(pgb_event_base);
		MULTITHREAD_ONLY_ITERATE(thread_id, {
			lock_thread(thread_id);
			threads[thread_id].cf_shutdown = SHUTDOWN_IMMEDIATE;
			event_base_loopbreak(threads[thread_id].base);
			unlock_thread(thread_id);
		});
		/*
		 * By not running admin_ready the connection is kept open
		 * until the process is actually shut down.
		 */
		return true;
	} else {
		if (mode == SHUTDOWN_WAIT_FOR_SERVERS) {
			cf_pause_mode = P_PAUSE;
			MULTITHREAD_ONLY_ITERATE(thread_id, {
				threads[thread_id].cf_pause_mode = P_PAUSE;
			});
			log_info("SHUTDOWN WAIT_FOR_SERVERS command issued");
		} else {
			log_info("SHUTDOWN WAIT_FOR_CLIENTS command issued");
		}
		cleanup_tcp_sockets();
		return admin_ready(admin, "SHUTDOWN");
	}
}

static void full_resume(void)
{
	int tmp_mode = cf_pause_mode;

	/* Reset pause mode on all threads */
	MULTITHREAD_ONLY_ITERATE(thread_id, {
		lock_thread(thread_id);
		threads[thread_id].cf_pause_mode = P_NONE;
		threads[thread_id].pause_ready = false;
		threads[thread_id].wait_close_ready = false;
		threads[thread_id].partial_pause = false;
		threads[thread_id].active_count = 0;
		unlock_thread(thread_id);
	});
	MULTITHREAD_VISIT(&total_active_count_lock, {
		total_active_count = 0;
	});

	cf_pause_mode = P_NONE;
	if (tmp_mode == P_SUSPEND)
		resume_all();
}

/* Command: RESUME */
static bool admin_cmd_resume(PgSocket *admin, const char *arg)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (!arg[0]) {
		log_info("RESUME command issued");
		if (cf_shutdown) {
			return admin_error(admin, "pooler is shutting down");
		} else if (cf_pause_mode != P_NONE) {
			full_resume();
		} else {
			return admin_error(admin, "pooler is not paused/suspended");
		}
	} else {
		PgDatabase *db = NULL;
		log_info("RESUME '%s' command issued", arg);
		db = find_database(arg);
		if (db == NULL)
			return admin_error(admin, "no such database: %s", arg);
		if (!db->db_paused)
			return admin_error(admin, "database %s is not paused", arg);
		db->db_paused = false;
	}
	return admin_ready(admin, "RESUME");
}

/* Command: SUSPEND */
static bool admin_cmd_suspend(PgSocket *admin, const char *arg)
{
	if (arg && *arg)
		return syntax_error(admin);

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (cf_pause_mode)
		return admin_error(admin, "already suspended/paused");

	/* suspend needs to be able to flush buffers */
	if (count_paused_databases() > 0)
		return admin_error(admin, "cannot suspend with paused databases");

	log_info("SUSPEND command issued");
	if (multithread_mode) {
		/* Set pause mode on all threads */
		FOR_EACH_THREAD(thread_id) {
			lock_thread(thread_id);
			threads[thread_id].cf_pause_mode = P_SUSPEND;
			unlock_thread(thread_id);
		}
	}
	cf_pause_mode = P_SUSPEND;
	admin->wait_for_response = true;
	suspend_pooler();

	g_suspend_start = get_cached_time();

	return true;
}

/* Command: PAUSE */
static bool admin_cmd_pause(PgSocket *admin, const char *arg)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (cf_pause_mode)
		return admin_error(admin, "already suspended/paused");

	if (!arg[0]) {
		log_info("PAUSE command issued");
		if (multithread_mode) {
			/* Set pause mode on all threads */
			FOR_EACH_THREAD(thread_id) {
				lock_thread(thread_id);
				threads[thread_id].cf_pause_mode = P_PAUSE;
				unlock_thread(thread_id);
			}
		}
		cf_pause_mode = P_PAUSE;
		admin->wait_for_response = true;
	} else {
		PgDatabase *db;
		log_info("PAUSE '%s' command issued", arg);
		db = find_or_register_database(admin, arg);
		if (db == NULL)
			return admin_error(admin, "no such database: %s", arg);
		if (db == admin->pool->db)
			return admin_error(admin, "cannot pause admin db: %s", arg);
		db->db_paused = true;
		if (count_db_active(db) > 0)
			admin->wait_for_response = true;
		else
			return admin_ready(admin, "PAUSE");
	}

	return true;
}

/* Command: RECONNECT */
static bool admin_cmd_reconnect(PgSocket *admin, const char *arg)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (!arg[0]) {
		struct List *item;
		PgPool *pool;

		log_info("RECONNECT command issued");
		THREAD_ITERATE(thread_id, {
			struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
			lock_thread(thread_id);
			THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
				pool = container_of(item, PgPool, head);
				if (pool->db->admin)
					continue;
				tag_database_dirty(pool->db);
			});
			unlock_thread(thread_id);
		});
	} else {
		PgDatabase *db;

		log_info("RECONNECT '%s' command issued", arg);
		if (multithread_mode) {
			bool found = false;
			FOR_EACH_THREAD(thread_id){
				lock_thread(thread_id);
				admin->sbuf.thread_id = thread_id;
				db = find_or_register_database(admin, arg);
				if (!db) {
					unlock_thread(thread_id);
					continue;
				}
				if (db == admin->pool->db) {
					unlock_thread(thread_id);
					return admin_error(admin, "cannot reconnect admin db: %s", arg);
				}
				found = true;
				tag_database_dirty(db);
				unlock_thread(thread_id);
			}
			if (!found)
				return admin_error(admin, "no such database: %s", arg);
		} else {
			db = find_or_register_database(admin, arg);
			if (db == NULL)
				return admin_error(admin, "no such database: %s", arg);
			if (db == admin->pool->db)
				return admin_error(admin, "cannot reconnect admin db: %s", arg);
			tag_database_dirty(db);
		}
	}

	return admin_ready(admin, "RECONNECT");
}

static bool admin_cmd_disable_internal(PgSocket *admin, const char *arg, bool disable)
{
	PgDatabase *db;

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (!arg[0])
		return admin_error(admin, "a database is required");

	if (disable)
		log_info("DISABLE '%s' command issued", arg);
	else
		log_info("ENABLE '%s' command issued", arg);

	if (multithread_mode) {
		bool found = false;
		FOR_EACH_THREAD(thread_id){
			lock_thread(thread_id);
			admin->sbuf.thread_id = thread_id;
			db = find_or_register_database(admin, arg);
			unlock_thread(thread_id);

			if (db->admin) {
				if (disable)
					return admin_error(admin, "cannot disable admin db: %s", arg);
				else
					return admin_error(admin, "cannot enable admin db: %s", arg);
			}

			if (db)
				found = true;

			db->db_disabled = disable;
		}
		if (!found)
			return admin_error(admin, "no such database: %s", arg);
	} else {
		db = find_or_register_database(admin, arg);
		if (db == NULL)
			return admin_error(admin, "no such database: %s", arg);
		if (db->admin) {
			if (disable) {
				return admin_error(admin, "cannot disable admin db: %s", arg);
			}
			return admin_error(admin, "cannot enable admin db: %s", arg);
		}

		db->db_disabled = disable;
	}
	if (disable)
		return admin_ready(admin, "DISABLE");
	else
		return admin_ready(admin, "ENABLE");
}

/* Command: DISABLE */
static bool admin_cmd_disable(PgSocket *admin, const char *arg)
{
	return admin_cmd_disable_internal(admin, arg, true);
}

/* Command: ENABLE */
static bool admin_cmd_enable(PgSocket *admin, const char *arg)
{
	return admin_cmd_disable_internal(admin, arg, false);
}


static PgSocket *find_socket_in_list(unsigned long long int target_id, struct StatList *sockets)
{
	struct List *item;
	PgSocket *socket;

	statlist_for_each(item, sockets) {
		socket = container_of(item, PgSocket, head);
		if (target_id == socket->id) {
			return socket;
		}
	}
	return NULL;
}

static PgSocket *find_client_global_pool(PgPool *pool, int target_id)
{
	PgSocket *kill_client = NULL;
	kill_client = find_socket_in_list(target_id, &pool->active_client_list);
	if (kill_client != NULL)
		return kill_client;
	kill_client = find_socket_in_list(target_id, &pool->waiting_client_list);
	if (kill_client != NULL)
		return kill_client;
	kill_client = find_socket_in_list(target_id, &pool->active_cancel_req_list);
	if (kill_client != NULL)
		return kill_client;
	kill_client = find_socket_in_list(target_id, &pool->waiting_cancel_req_list);
	if (kill_client != NULL)
		return kill_client;
	return NULL;
}

static PgSocket *find_client_global_peer_pool(PgPool *pool, int target_id)
{
	PgSocket *kill_client = NULL;
	kill_client = find_socket_in_list(target_id, &pool->active_cancel_req_list);
	if (kill_client != NULL) {
		return kill_client;
	}
	kill_client = find_socket_in_list(target_id, &pool->waiting_cancel_req_list);
	if (kill_client != NULL) {
		return kill_client;
	}
	return NULL;
}


static PgSocket * find_client_global(unsigned long long int target_id)
{
	PgSocket *kill_client;
	struct List *item;
	PgPool *pool;

	THREAD_ITERATE(thread_id, {
		struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
		struct ThreadSafeStatList *peer_pool_list_ptr = GET_MULTITHREAD_PTR(peer_pool_list, thread_id);
		lock_thread(thread_id);
		THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
			pool = container_of(item, PgPool, head);
			kill_client = find_client_global_pool(pool, target_id);
			if (kill_client != NULL) {
				unlock_thread(thread_id);
				return kill_client;
				break;
			}
		});
		THREAD_SAFE_STATLIST_EACH(peer_pool_list_ptr, item, {
			pool = container_of(item, PgPool, head);
			kill_client = find_client_global_peer_pool(pool, target_id);
			if (kill_client != NULL) {
				unlock_thread(thread_id);
				return kill_client;
			}
		});
		unlock_thread(thread_id);
	});

	return kill_client;
}

/* Command: KILL_CLIENT */
static bool admin_cmd_kill_client(PgSocket *admin, const char *arg)
{
	PgSocket *kill_client;
	unsigned long long int target_id = 0;

	if (sscanf(arg, "%llu", &target_id) != 1) {
		return admin_error(admin, "invalid client pointer supplied");
	}

	kill_client = find_client_global((unsigned long long int) target_id);
	if (kill_client == NULL) {
		return admin_error(admin, "client not found");
	}


	if (!multithread_mode) {
		disconnect_client(kill_client, true, "admin forced disconnect");
		return admin_ready(admin, "KILL_CLIENT");
	}


	lock_thread(kill_client->sbuf.thread_id);

	disconnect_client(kill_client, true, "admin forced disconnect");

	unlock_thread(kill_client->sbuf.thread_id);
	return admin_ready(admin, "KILL_CLIENT");
}


/* Helper function to kill pools for a specific database in a thread */
static bool kill_database_pools_in_thread(int thread_id, const char *db_name, PgSocket *admin)
{
	PgDatabase *db;
	struct List *item;
	bool found = false;

	lock_thread(thread_id);
	admin->sbuf.thread_id = thread_id;
	db = find_or_register_database(admin, db_name);
	if (!db) {
		unlock_thread(thread_id);
		return false;
	}

	if (db == admin->pool->db) {
		unlock_thread(thread_id);
		return false;
	}

	found = true;
	THREAD_SAFE_STATLIST_EACH(&(threads[thread_id].pool_list), item, {
		PgPool *pool = container_of(item, PgPool, head);
		if (pool->db->name == db->name) {
			pool->db->db_paused = true;
			kill_pool(pool);
		}
	});
	unlock_thread(thread_id);
	return found;
}


/* Helper function to kill pools for a specific database (single-thread mode) */
static bool kill_database_pools_single_thread(const char *db_name, PgSocket *admin)
{
	struct List *item;
	PgPool *pool;
	PgDatabase *db;

	db = find_or_register_database(admin, db_name);
	if (db == NULL)
		return false;

	if (db == admin->pool->db)
		return false;	/* Will be handled by caller */

	db->db_paused = true;
	THREAD_SAFE_STATLIST_EACH(&pool_list, item, {
		pool = container_of(item, PgPool, head);
		if (pool->db->name == db->name)
			kill_pool(pool);
	});
	return true;
}

/* Command: KILL */
static bool admin_cmd_kill(PgSocket *admin, const char *arg)
{
	struct List *item;
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (cf_pause_mode)
		return admin_error(admin, "already suspended/paused");

	/* Kill all databases */
	if (!arg[0]) {
		log_info("KILL command issued");

		THREAD_ITERATE(thread_id, {
			struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
			lock_thread(thread_id);
			THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
				PgPool *pool = container_of(item, PgPool, head);
				if (pool->db->admin)
					continue;
				pool->db->db_paused = true;
				kill_pool(pool);
			});
			unlock_thread(thread_id);
		});
		return admin_ready(admin, "KILL");
	}

	/* Kill specific database */
	log_info("KILL '%s' command issued", arg);

	if (multithread_mode) {
		bool found = false;
		FOR_EACH_THREAD(thread_id) {
			if (kill_database_pools_in_thread(thread_id, arg, admin)) {
				found = true;
			}
		}

		if (!found) {
			/*
			 * Check if it's the admin database.
			 * Only search in the current thread, since the admin database should exist in all threads.
			 */
			PgDatabase *db = find_or_register_database(admin, arg);
			if (db && db == admin->pool->db) {
				return admin_error(admin, "cannot kill admin db: %s", arg);
			}
			return admin_error(admin, "no such database: %s", arg);
		}
	} else {
		if (!kill_database_pools_single_thread(arg, admin)) {
			/* Check if it's the admin database */
			PgDatabase *db = find_or_register_database(admin, arg);
			if (db && db == admin->pool->db) {
				return admin_error(admin, "cannot kill admin db: %s", arg);
			}
			return admin_error(admin, "no such database: %s", arg);
		}
	}

	return admin_ready(admin, "KILL");
}


/* Command: WAIT_CLOSE */
static bool admin_cmd_wait_close(PgSocket *admin, const char *arg)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (!arg[0]) {
		struct List *item;
		PgPool *pool;
		int active = 0;

		log_info("WAIT_CLOSE command issued");
		THREAD_ITERATE(thread_id, {
			struct ThreadSafeStatList *pool_list_ptr = GET_MULTITHREAD_PTR(pool_list, thread_id);
			THREAD_SAFE_STATLIST_EACH(pool_list_ptr, item, {
				PgDatabase *db;

				pool = container_of(item, PgPool, head);
				db = pool->db;
				db->db_wait_close = true;
				active += count_db_active(db);
			});
		});
		if (active > 0)
			admin->wait_for_response = true;
		else
			return admin_ready(admin, "WAIT_CLOSE");
	} else {
		PgDatabase *db;

		log_info("WAIT_CLOSE '%s' command issued", arg);
		if (multithread_mode) {
			bool found = false;
			bool wait = false;
			FOR_EACH_THREAD(thread_id){
				lock_thread(thread_id);
				admin->sbuf.thread_id = thread_id;
				db = find_or_register_database(admin, arg);
				unlock_thread(thread_id);
				if (!db) {
					continue;
				}
				found = true;
				if (db == admin->pool->db)
					return admin_error(admin, "cannot wait in admin db: %s", arg);
				if (count_db_active(db) > 0) {
					admin->wait_for_response = true;
					wait = true;
				}
			}
			if (!found)
				return admin_error(admin, "no such database: %s", arg);
			if (!wait)
				return admin_ready(admin, "WAIT_CLOSE");
		} else {
			db = find_or_register_database(admin, arg);
			if (db == NULL)
				return admin_error(admin, "no such database: %s", arg);
			if (db == admin->pool->db)
				return admin_error(admin, "cannot wait in admin db: %s", arg);
			db->db_wait_close = true;
			if (count_db_active(db) > 0)
				admin->wait_for_response = true;
			else
				return admin_ready(admin, "WAIT_CLOSE");
		}
	}

	return true;
}

/* extract substring from regex group */
static bool copy_arg(const char *src, regmatch_t *glist,
		     int gnum, char *dst, unsigned dstmax,
		     char qchar)
{
	regmatch_t *g = &glist[gnum];
	unsigned len;
	const char *s;
	char *d = dst;
	unsigned i;

	/* no match, if regex allows, it must be fine */
	if (g->rm_so < 0 || g->rm_eo < 0) {
		dst[0] = 0;
		return true;
	}

	len = g->rm_eo - g->rm_so;
	s = src + g->rm_so;

	/* too big value */
	if (len >= dstmax) {
		dst[0] = 0;
		return false;
	}

	/* copy and unquote */
	if (*s == qchar) {
		for (i = 1; i < len - 1; i++) {
			if (s[i] == qchar && s[i + 1] == qchar)
				i++;
			*d++ = s[i];
		}
		len = d - dst;
	} else {
		memcpy(dst, s, len);
	}
	dst[len] = 0;
	return true;
}

static bool admin_show_help(PgSocket *admin, const char *arg)
{
	bool res;
	SEND_generic(res, admin, PqMsg_NoticeResponse,
		     "sssss",
		     "SNOTICE", "C00000", "MConsole usage",
		     "D\n\tSHOW HELP|CONFIG|DATABASES"
		     "|POOLS|CLIENTS|SERVERS|USERS|VERSION\n"
		     "\tSHOW PEERS|PEER_POOLS\n"
		     "\tSHOW FDS|SOCKETS|ACTIVE_SOCKETS|LISTS|MEM|STATE\n"
		     "\tSHOW DNS_HOSTS|DNS_ZONES\n"
		     "\tSHOW STATS|STATS_TOTALS|STATS_AVERAGES|TOTALS\n"
		     "\tSET key = arg\n"
		     "\tRELOAD\n"
		     "\tPAUSE [<db>]\n"
		     "\tRESUME [<db>]\n"
		     "\tDISABLE <db>\n"
		     "\tENABLE <db>\n"
		     "\tRECONNECT [<db>]\n"
		     "\tKILL [<db>]\n"
		     "\tKILL_CLIENT <client_id>\n"
		     "\tSUSPEND\n"
		     "\tSHUTDOWN\n"
		     "\tSHUTDOWN WAIT_FOR_SERVERS|WAIT_FOR_CLIENTS\n"
		     "\tWAIT_CLOSE [<db>]", "");
	if (res)
		res = admin_ready(admin, "SHOW");
	return res;
}

static bool admin_show_version(PgSocket *admin, const char *arg)
{
	PktBuf *buf;

	buf = pktbuf_dynamic(128);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "s", "version");
	pktbuf_write_DataRow(buf, "s", PACKAGE_STRING);

	admin_flush(admin, buf, "SHOW");

	return true;
}

static bool admin_show_stats(PgSocket *admin, const char *arg)
{
	return admin_database_stats(admin);
}

static bool admin_show_stats_totals(PgSocket *admin, const char *arg)
{
	return admin_database_stats_totals(admin);
}

static bool admin_show_stats_averages(PgSocket *admin, const char *arg)
{
	return admin_database_stats_averages(admin);
}

static bool admin_show_totals(PgSocket *admin, const char *arg)
{
	return show_stat_totals(admin);
}


static struct cmd_lookup show_map [] = {
	{"clients", admin_show_clients},
	{"config", admin_show_config},
	{"databases", admin_show_databases},
	{"fds", admin_show_fds},
	{"help", admin_show_help},
	{"lists", admin_show_lists},	// TODO(beihao): check if we show total from all threads (esp. databases)
	{"peers", admin_show_peers},
	{"peer_pools", admin_show_peer_pools},
	{"pools", admin_show_pools},
	{"servers", admin_show_servers},
	{"sockets", admin_show_sockets},
	{"active_sockets", admin_show_active_sockets},
	{"stats", admin_show_stats},	// TODO: check
	{"stats_totals", admin_show_stats_totals},	// TODO: check
	{"stats_averages", admin_show_stats_averages},	// TODO: check
	{"users", admin_show_users},
	{"version", admin_show_version},
	{"totals", admin_show_totals},	// TODO: check
	{"mem", admin_show_mem},
	{"dns_hosts", admin_show_dns_hosts},
	{"dns_zones", admin_show_dns_zones},
	{"state", admin_show_state},
	{NULL, NULL}
};

static bool admin_cmd_show(PgSocket *admin, const char *arg)
{
	if (fake_show(admin, arg))
		return true;
	return exec_cmd(show_map, admin, arg, NULL);
}

static struct cmd_lookup cmd_list [] = {
	{"disable", admin_cmd_disable},
	{"enable", admin_cmd_enable},
	{"kill", admin_cmd_kill},
	{"kill_client", admin_cmd_kill_client},
	{"pause", admin_cmd_pause},
	{"reconnect", admin_cmd_reconnect},
	{"reload", admin_cmd_reload},
	{"resume", admin_cmd_resume},
	{"select", admin_cmd_show},
	{"show", admin_cmd_show},
	{"shutdown", admin_cmd_shutdown},
	{"suspend", admin_cmd_suspend},
	{"wait_close", admin_cmd_wait_close},
	{NULL, NULL}
};

/* handle user query */
static bool admin_parse_query(PgSocket *admin, const char *q)
{
	regmatch_t grp[MAX_GROUPS];
	char cmd[16];
	char arg[64];
	char val[256];
	bool res;
	bool ok;

	current_query = q;

	if (regexec(&rc_cmd, q, MAX_GROUPS, grp, 0) == 0) {
		ok = copy_arg(q, grp, CMD_NAME, cmd, sizeof(cmd), '"');
		if (!ok)
			goto failed;
		ok = copy_arg(q, grp, CMD_ARG, arg, sizeof(arg), '"');
		if (!ok)
			goto failed;
		res = exec_cmd(cmd_list, admin, cmd, arg);
	} else if (regexec(&rc_set_str, q, MAX_GROUPS, grp, 0) == 0) {
		ok = copy_arg(q, grp, SET_KEY, arg, sizeof(arg), '"');
		if (!ok || !arg[0])
			goto failed;
		ok = copy_arg(q, grp, SET_VAL, val, sizeof(val), '\'');
		if (!ok)
			goto failed;
		res = admin_set(admin, arg, val);
	} else if (regexec(&rc_set_word, q, MAX_GROUPS, grp, 0) == 0) {
		ok = copy_arg(q, grp, SET_KEY, arg, sizeof(arg), '"');
		if (!ok || !arg[0])
			goto failed;
		ok = copy_arg(q, grp, SET_VAL, val, sizeof(val), '"');
		if (!ok)
			goto failed;
		res = admin_set(admin, arg, val);
	} else {
		res = syntax_error(admin);
	}
done:
	current_query = NULL;
	if (!res)
		disconnect_client(admin, true, "failure");
	return res;
failed:
	res = admin_error(admin, "bad arguments");
	goto done;
}

/* handle packets */
bool admin_handle_client(PgSocket *admin, PktHdr *pkt)
{
	const char *q;
	bool res;

	/* don't tolerate partial packets */
	if (incomplete_pkt(pkt)) {
		disconnect_client(admin, true, "incomplete pkt");
		return false;
	}

	switch (pkt->type) {
	case PqMsg_Query:
		if (!mbuf_get_string(&pkt->data, &q)) {
			disconnect_client(admin, true, "incomplete query");
			return false;
		}
		log_debug("got admin query: %s", q);
		res = admin_parse_query(admin, q);
		if (res)
			sbuf_prepare_skip(&admin->sbuf, pkt->len);
		return res;
	case PqMsg_Terminate:
		disconnect_client(admin, false, "close req");
		break;
	case PqMsg_Parse:
	case PqMsg_Bind:
	case PqMsg_Execute:
		/*
		 * Effectively the same as the default case, but give
		 * a more helpful error message in these cases.
		 */
		admin_error(admin, "extended query protocol not supported by admin console");
		disconnect_client(admin, true, "bad packet");
		break;
	default:
		admin_error(admin, "unsupported packet type for admin console: %d", pkt_desc(pkt));
		disconnect_client(admin, true, "bad packet");
		break;
	}
	return false;
}

/**
 * Client is unauthenticated, look if it wants to connect
 * to special "pgbouncer" user.
 */
bool admin_pre_login(PgSocket *client, const char *username)
{
	PgPool *admin_pool_local;
	client->admin_user = false;
	client->own_user = false;

	/* Get the admin pool for this client's thread */
	admin_pool_local = NULL;
	if (multithread_mode) {
		int thread_id = client->sbuf.thread_id;
		admin_pool_local = threads[thread_id].admin_pool;
	} else {
		admin_pool_local = admin_pool;
	}

	if (!admin_pool_local) {
		log_error("no admin pool found for client");
		return false;
	}

	/* tag same uid as special */
	if (pga_is_unix(&client->remote_addr)) {
		uid_t peer_uid;
		gid_t peer_gid;
		int res;

		res = getpeereid(sbuf_socket(&client->sbuf), &peer_uid, &peer_gid);
		if (res >= 0 && peer_uid == getuid()
		    && strcmp("pgbouncer", username) == 0) {
			client->login_user_credentials = admin_pool_local->db->forced_user_credentials;
			client->own_user = true;
			client->admin_user = true;
			if (!check_db_connection_count(client))
				return false;
			if (cf_log_connections)
				slog_info(client, "pgbouncer access from unix socket");
			return true;
		}
	}

	/*
	 * auth_type=any does not keep original username around,
	 * so username based check has to take place here
	 */
	if (cf_auth_type == AUTH_TYPE_ANY) {
		if (strlist_contains(cf_admin_users, username)) {
			client->login_user_credentials = admin_pool_local->db->forced_user_credentials;
			client->admin_user = true;
			if (!check_db_connection_count(client))
				return false;
			return true;
		} else if (strlist_contains(cf_stats_users, username)) {
			client->login_user_credentials = admin_pool_local->db->forced_user_credentials;
			if (!check_db_connection_count(client))
				return false;

			if (!check_user_connection_count(client))
				return false;

			return true;
		}
	}
	return false;
}

bool admin_post_login(PgSocket *client)
{
	const char *username = client->login_user_credentials->name;

	if (cf_auth_type == AUTH_TYPE_ANY)
		return true;

	if (client->admin_user || strlist_contains(cf_admin_users, username)) {
		client->admin_user = true;
		return true;
	} else if (strlist_contains(cf_stats_users, username)) {
		return true;
	}

	disconnect_client(client, true, "not allowed");
	return false;
}

/* init special database and query parsing */
void admin_setup(void)
{
	PgDatabase *db;
	PgPool *pool;
	PgGlobalUser *user;
	PktBuf *msg;

	/* fake database */
	db = add_database("pgbouncer");

	if (!db)
		die("no memory for admin database");
	db->port = cf_listen_port;
	db->pool_size = 2;
	db->admin = true;
	db->pool_mode = POOL_STMT;
	if (!force_user_credentials(db, "pgbouncer", ""))
		die("no mem on startup - cannot alloc pgbouncer user");

	/* fake pool */
	THREAD_ITERATE(thread_id, {
		pool = get_pool(db, db->forced_user_credentials, thread_id);
		if (!pool)
			die("cannot create admin pool?");

		if (!multithread_mode) {
			admin_pool = pool;
		} else {
			threads[thread_id].admin_pool = pool;
		}
	});


	/* find an existing user or create a new fake user with disabled password */
	user = find_or_add_new_global_user("pgbouncer", "");
	if (!user) {
		die("cannot create admin user?");
	}

	/* prepare welcome */
	msg = pktbuf_dynamic(128);
	if (!msg)
		die("out of memory");
	pktbuf_write_AuthenticationOk(msg);
	pktbuf_write_ParameterStatus(msg, "server_version", PACKAGE_VERSION "/bouncer");
	pktbuf_write_ParameterStatus(msg, "client_encoding", "UTF8");
	pktbuf_write_ParameterStatus(msg, "server_encoding", "UTF8");
	pktbuf_write_ParameterStatus(msg, "DateStyle", "ISO");
	pktbuf_write_ParameterStatus(msg, "TimeZone", "GMT");
	pktbuf_write_ParameterStatus(msg, "standard_conforming_strings", "on");
	pktbuf_write_ParameterStatus(msg, "is_superuser", "on");

	if (msg->failed)
		die("admin welcome failed");

	THREAD_ITERATE(thread_id, {
		GET_MULTITHREAD_TYPE_PTR(admin_pool, thread_id)->welcome_msg = msg;
		GET_MULTITHREAD_TYPE_PTR(admin_pool, thread_id)->welcome_msg_ready = true;
	});


	msg = pktbuf_dynamic(128);
	if (!msg)
		die("cannot create admin startup pkt");
	db->startup_params = msg;
	pktbuf_put_string(msg, "database");
	db->dbname = "pgbouncer";
	pktbuf_put_string(msg, db->dbname);
}

// only init once to avoid memory leak
void admin_regex_init(void)
{
	int res;

	/* initialize regexes */
	res = regcomp(&rc_cmd, cmd_normal_rx, REG_EXTENDED | REG_ICASE);
	if (res != 0)
		fatal("cmd regex compilation error");
	res = regcomp(&rc_set_word, cmd_set_word_rx, REG_EXTENDED | REG_ICASE);
	if (res != 0)
		fatal("set/word regex compilation error");
	res = regcomp(&rc_set_str, cmd_set_str_rx, REG_EXTENDED | REG_ICASE);
	if (res != 0)
		fatal("set/str regex compilation error");
}

void admin_pause_done(void)
{
	struct List *item, *tmp;
	PgSocket *admin;
	bool res;

	/* This function is now only called from the main thread when all threads are ready */

	/* In multithread mode, check admin clients from all threads */
	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id) {
			spin_lock_acquire(&threads[thread_id].pool_list.lock);
			/* Process admin clients from this thread's admin pool */
			statlist_for_each_safe(item, &threads[thread_id].admin_pool->active_client_list, tmp) {
				admin = container_of(item, PgSocket, head);
				if (!admin->wait_for_response)
					continue;

				switch (cf_pause_mode) {
				case P_PAUSE:
					res = admin_ready(admin, "PAUSE");
					break;
				case P_SUSPEND:
					res = admin_ready(admin, "SUSPEND");
					break;
				default:
					if (count_paused_databases() > 0) {
						res = admin_ready(admin, "PAUSE");
					} else {
						fatal("admin_pause_done: bad state");
						res = false;
					}
				}

				if (!res)
					disconnect_client(admin, false, "dead admin");
				else
					admin->wait_for_response = false;
			}
			spin_lock_release(&threads[thread_id].pool_list.lock);
		}
	} else {
		/* Single-thread mode: use the global admin_pool */
		statlist_for_each_safe(item, &admin_pool->active_client_list, tmp) {
			admin = container_of(item, PgSocket, head);
			if (!admin->wait_for_response)
				continue;

			switch (cf_pause_mode) {
			case P_PAUSE:
				res = admin_ready(admin, "PAUSE");
				break;
			case P_SUSPEND:
				res = admin_ready(admin, "SUSPEND");
				break;
			default:
				if (count_paused_databases() > 0) {
					res = admin_ready(admin, "PAUSE");
				} else {
					/* FIXME */
					fatal("admin_pause_done: bad state");
					res = false;
				}
			}

			if (!res)
				disconnect_client(admin, false, "dead admin");
			else
				admin->wait_for_response = false;
		}
	}

	/* Check if all admin clients are gone (for SUSPEND mode) */
	if (multithread_mode) {
		bool all_admin_clients_gone = true;
		FOR_EACH_THREAD(thread_id) {
			spin_lock_acquire(&threads[thread_id].pool_list.lock);
			if (!statlist_empty(&threads[thread_id].admin_pool->active_client_list)) {
				all_admin_clients_gone = false;
				break;
			}
			spin_lock_release(&threads[thread_id].pool_list.lock);
		}
		if (all_admin_clients_gone && cf_pause_mode == P_SUSPEND) {
			log_info("admin disappeared when suspended, doing RESUME");
			cf_pause_mode = P_NONE;
			resume_all();
		}
	} else {
		if (statlist_empty(&admin_pool->active_client_list)
		    && cf_pause_mode == P_SUSPEND) {
			log_info("admin disappeared when suspended, doing RESUME");
			cf_pause_mode = P_NONE;
			resume_all();
		}
	}
}

void admin_wait_close_done(void)
{
	struct List *item, *tmp;
	PgSocket *admin;
	bool res;

	/* In multithread mode, check admin clients from all threads */
	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id) {
			spin_lock_acquire(&threads[thread_id].pool_list.lock);
			/* Process admin clients from this thread's admin pool */
			statlist_for_each_safe(item, &threads[thread_id].admin_pool->active_client_list, tmp) {
				admin = container_of(item, PgSocket, head);
				if (!admin->wait_for_response)
					continue;

				res = admin_ready(admin, "WAIT_CLOSE");

				if (!res)
					disconnect_client(admin, false, "dead admin");
				else
					admin->wait_for_response = false;
			}
			spin_lock_release(&threads[thread_id].pool_list.lock);
		}
	} else {
		/* Single-thread mode: use the global admin_pool */
		statlist_for_each_safe(item, &admin_pool->active_client_list, tmp) {
			admin = container_of(item, PgSocket, head);
			if (!admin->wait_for_response)
				continue;

			res = admin_ready(admin, "WAIT_CLOSE");

			if (!res)
				disconnect_client(admin, false, "dead admin");
			else
				admin->wait_for_response = false;
		}
	}
}

/* admin on console has pressed ^C */
void admin_handle_cancel(PgSocket *admin)
{
	/* weird, but no reason to fail */
	if (!admin->wait_for_response)
		slog_warning(admin, "admin cancel request for non-waiting client?");

	if (cf_shutdown)
		return;

	if (cf_pause_mode != P_NONE)
		full_resume();
}
