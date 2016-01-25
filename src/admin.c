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

#include <usual/regex.h>
#include <usual/netdb.h>
#include <usual/endian.h>

/* regex elements */
#define WS0	"[ \t\n\r]*"
#define WS1	"[ \t\n\r]+"
#define WORD	"(\"([^\"]+|\"\")*\"|[0-9a-z_]+)"
#define STRING	"('([^']|'')*')"

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

static PgPool *admin_pool;

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
		res = send_pooler_error(admin, true, str);
	return res;
}

static int count_paused_databases(void)
{
	struct List *item;
	PgDatabase *db;
	int cnt = 0;

	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);
		cnt += db->db_paused;
	}
	return cnt;
}

static int count_db_active(PgDatabase *db)
{
	struct List *item;
	PgPool *pool;
	int cnt = 0;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db != db)
			continue;
		cnt += pool_server_count(pool);
	}
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
 * without checking if thats necessary.  Fake some env for them.
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
		} else
			admin_error(admin, "no mem");
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
		} else
			admin_error(admin, "no mem");
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
			snprintf(tmp, sizeof(tmp), "SET %s=%s", key, val);
			return admin_ready(admin, tmp);
		} else {
			return admin_error(admin, "SET failed");
		}
	} else
		return admin_error(admin, "admin access needed");
}

/* send a row with sendmsg, optionally attaching a fd */
static bool send_one_fd(PgSocket *admin,
			int fd, const char *task,
			const char *user, const char *db,
			const char *addr, int port,
			uint64_t ckey, int link,
			const char *client_enc,
			const char *std_strings,
			const char *datestyle,
			const char *timezone,
			const char *password)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iovec;
	int res;
	uint8_t cntbuf[CMSG_SPACE(sizeof(int))];

	struct PktBuf *pkt = pktbuf_temp();

	pktbuf_write_DataRow(pkt, "issssiqisssss",
		      fd, task, user, db, addr, port, ckey, link,
		      client_enc, std_strings, datestyle, timezone,
		      password);
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
static bool show_one_fd(PgSocket *admin, PgSocket *sk)
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

	/* Skip TLS sockets */
	if (sk->sbuf.tls || (sk->link && sk->link->sbuf.tls))
		return true;

	mbuf_init_fixed_reader(&tmp, sk->cancel_key, 8);
	if (!mbuf_get_uint64be(&tmp, &ckey))
		return false;

	if (sk->pool->db->auth_user && sk->auth_user && !find_user(sk->auth_user->name))
		password = sk->auth_user->passwd;

	return send_one_fd(admin, sbuf_socket(&sk->sbuf),
			   is_server_socket(sk) ? "server" : "client",
			   sk->auth_user ? sk->auth_user->name : NULL,
			   sk->pool ? sk->pool->db->name : NULL,
			   pga_ntop(addr, addrbuf, sizeof(addrbuf)),
			   pga_port(addr),
			   ckey,
			   sk->link ? sbuf_socket(&sk->link->sbuf) : 0,
			   client_encoding ? client_encoding->str : NULL,
			   std_strings ? std_strings->str : NULL,
			   datestyle ? datestyle->str : NULL,
			   timezone ? timezone->str : NULL,
			   password);
}

static bool show_pooler_cb(void *arg, int fd, const PgAddr *a)
{
	char buf[PGADDR_BUF];

	return send_one_fd(arg, fd, "pooler", NULL, NULL,
			   pga_ntop(a, buf, sizeof(buf)), pga_port(a), 0, 0,
			   NULL, NULL, NULL, NULL, NULL);
}

/* send a row with sendmsg, optionally attaching a fd */
static bool show_pooler_fds(PgSocket *admin)
{
	return for_each_pooler_fd(show_pooler_cb, admin);
}

static bool show_fds_from_list(PgSocket *admin, struct StatList *list)
{
	struct List *item;
	PgSocket *sk;
	bool res = true;

	statlist_for_each(item, list) {
		sk = container_of(item, PgSocket, head);
		res = show_one_fd(admin, sk);
		if (!res)
			break;
	}
	return res;
}

static PgDatabase *find_or_register_database(PgSocket *admin, const char *name)
{
	PgDatabase *db = find_database(name);
	if (db == NULL) {
		db = register_auto_database(name);
		if (db != NULL) {
			slog_info(admin,
			          "registered new auto-database: %s", name);
		}
	}
	return db;
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
	SEND_RowDescription(res, admin, "issssiqisssss",
				 "fd", "task",
				 "user", "database",
				 "addr", "port",
				 "cancel", "link",
				 "client_encoding", "std_strings",
				 "datestyle", "timezone", "password");
	if (res)
		res = show_pooler_fds(admin);

	if (res)
		res = show_fds_from_list(admin, &login_client_list);

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->admin)
			continue;
		res = res && show_fds_from_list(admin, &pool->active_client_list);
		res = res && show_fds_from_list(admin, &pool->waiting_client_list);
		res = res && show_fds_from_list(admin, &pool->active_server_list);
		res = res && show_fds_from_list(admin, &pool->idle_server_list);
		res = res && show_fds_from_list(admin, &pool->used_server_list);
		res = res && show_fds_from_list(admin, &pool->tested_server_list);
		res = res && show_fds_from_list(admin, &pool->new_server_list);
		if (!res)
			break;
	}
	if (res)
		res = admin_ready(admin, "SHOW");

	/* turn async back on */
	socket_set_nonblocking(sbuf_socket(&admin->sbuf), 1);

	return res;
}

/* Command: SHOW DATABASES */
static bool admin_show_databases(PgSocket *admin, const char *arg)
{
	PgDatabase *db;
	struct List *item;
	const char *f_user;
	PktBuf *buf;
	struct CfValue cv;
	const char *pool_mode_str;

	cv.extra = pool_mode_map;
	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "ssissiisii",
				    "name", "host", "port",
				    "database", "force_user", "pool_size", "reserve_pool",
				    "pool_mode", "max_connections", "current_connections");
	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);

		f_user = db->forced_user ? db->forced_user->name : NULL;
		pool_mode_str = NULL;
		cv.value_p = &db->pool_mode;
		if (db->pool_mode != POOL_INHERIT)
			pool_mode_str = cf_get_lookup(&cv);
		pktbuf_write_DataRow(buf, "ssissiisii",
				     db->name, db->host, db->port,
				     db->dbname, f_user,
				     db->pool_size,
				     db->res_pool_size,
				     pool_mode_str,
				     database_max_connections(db),
				     db->connection_count);
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}


/* Command: SHOW LISTS */
static bool admin_show_lists(PgSocket *admin, const char *arg)
{
	PktBuf *buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "si", "list", "items");
#define SENDLIST(name, size) pktbuf_write_DataRow(buf, "si", (name), (size))
	SENDLIST("databases", statlist_count(&database_list));
	SENDLIST("users", statlist_count(&user_list));
	SENDLIST("pools", statlist_count(&pool_list));
	SENDLIST("free_clients", slab_free_count(client_cache));
	SENDLIST("used_clients", slab_active_count(client_cache));
	SENDLIST("login_clients", statlist_count(&login_client_list));
	SENDLIST("free_servers", slab_free_count(server_cache));
	SENDLIST("used_servers", slab_active_count(server_cache));
	{
		int names, zones, qry, pend;
		adns_info(adns, &names, &zones, &qry, &pend);
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
	PgUser *user;
	struct List *item;
	PktBuf *buf = pktbuf_dynamic(256);
	struct CfValue cv;
	const char *pool_mode_str;

	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	cv.extra = pool_mode_map;

	pktbuf_write_RowDescription(buf, "ss", "name", "pool_mode");
	statlist_for_each(item, &user_list) {
		user = container_of(item, PgUser, head);
		pool_mode_str = NULL;
		cv.value_p = &user->pool_mode;
		if (user->pool_mode != POOL_INHERIT)
			pool_mode_str = cf_get_lookup(&cv);

		pktbuf_write_DataRow(buf, "ss", user->name, pool_mode_str);
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}

#define SKF_STD "sssssisiTTssis"
#define SKF_DBG "sssssisiTTssisiiiiiii"

static void socket_header(PktBuf *buf, bool debug)
{
	pktbuf_write_RowDescription(buf, debug ? SKF_DBG : SKF_STD,
				    "type", "user", "database", "state",
				    "addr", "port", "local_addr", "local_port",
				    "connect_time", "request_time",
				    "ptr", "link", "remote_pid", "tls",
				    /* debug follows */
				    "recv_pos", "pkt_pos", "pkt_remain",
				    "send_pos", "send_remain",
				    "pkt_avail", "send_avail");
}

static void adr2txt(const PgAddr *adr, char *dst, unsigned dstlen)
{
	pga_ntop(adr, dst, dstlen);
}

static void socket_row(PktBuf *buf, PgSocket *sk, const char *state, bool debug)
{
	int pkt_avail = 0, send_avail = 0;
	int remote_pid;
	char ptrbuf[128], linkbuf[128];
	char l_addr[PGADDR_BUF], r_addr[PGADDR_BUF];
	IOBuf *io = sk->sbuf.io;
	char infobuf[96] = "";

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

	pktbuf_write_DataRow(buf, debug ? SKF_DBG : SKF_STD,
			     is_server_socket(sk) ? "S" :"C",
			     sk->auth_user ? sk->auth_user->name : "(nouser)",
			     sk->pool ? sk->pool->db->name : "(nodb)",
			     state, r_addr, pga_port(&sk->remote_addr),
			     l_addr, pga_port(&sk->local_addr),
			     sk->connect_time,
			     sk->request_time,
			     ptrbuf, linkbuf, remote_pid, infobuf,
			     /* debug */
			     io ? io->recv_pos : 0,
			     io ? io->parse_pos : 0,
			     sk->sbuf.pkt_remain,
			     io ? io->done_pos : 0,
			     0,
			     pkt_avail, send_avail);
}

/* Helper for SHOW CLIENTS */
static void show_socket_list(PktBuf *buf, struct StatList *list, const char *state, bool debug)
{
	struct List *item;
	PgSocket *sk;

	statlist_for_each(item, list) {
		sk = container_of(item, PgSocket, head);
		socket_row(buf, sk, state, debug);
	}
}

/* Command: SHOW CLIENTS */
static bool admin_show_clients(PgSocket *admin, const char *arg)
{
	struct List *item;
	PgPool *pool;
	PktBuf *buf = pktbuf_dynamic(256);

	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	socket_header(buf, false);
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);

		show_socket_list(buf, &pool->active_client_list, "active", false);
		show_socket_list(buf, &pool->waiting_client_list, "waiting", false);
	}

	admin_flush(admin, buf, "SHOW");
	return true;
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
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		show_socket_list(buf, &pool->active_server_list, "active", false);
		show_socket_list(buf, &pool->idle_server_list, "idle", false);
		show_socket_list(buf, &pool->used_server_list, "used", false);
		show_socket_list(buf, &pool->tested_server_list, "tested", false);
		show_socket_list(buf, &pool->new_server_list, "new", false);
	}
	admin_flush(admin, buf, "SHOW");
	return true;
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
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		show_socket_list(buf, &pool->active_client_list, "cl_active", true);
		show_socket_list(buf, &pool->waiting_client_list, "cl_waiting", true);

		show_socket_list(buf, &pool->active_server_list, "sv_active", true);
		show_socket_list(buf, &pool->idle_server_list, "sv_idle", true);
		show_socket_list(buf, &pool->used_server_list, "sv_used", true);
		show_socket_list(buf, &pool->tested_server_list, "sv_tested", true);
		show_socket_list(buf, &pool->new_server_list, "sv_login", true);
	}
	show_socket_list(buf, &login_client_list, "cl_login", true);
	admin_flush(admin, buf, "SHOW");
	return true;
}

static void show_active_socket_list(PktBuf *buf, struct StatList *list, const char *state)
{
	struct List *item;
	statlist_for_each(item, list) {
		PgSocket *sk = container_of(item, PgSocket, head);
		if (!sbuf_is_empty(&sk->sbuf))
			socket_row(buf, sk, state, true);
	}
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
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		show_active_socket_list(buf, &pool->active_client_list, "cl_active");
		show_active_socket_list(buf, &pool->waiting_client_list, "cl_waiting");

		show_active_socket_list(buf, &pool->active_server_list, "sv_active");
		show_active_socket_list(buf, &pool->idle_server_list, "sv_idle");
		show_active_socket_list(buf, &pool->used_server_list, "sv_used");
		show_active_socket_list(buf, &pool->tested_server_list, "sv_tested");
		show_active_socket_list(buf, &pool->new_server_list, "sv_login");
	}
	show_active_socket_list(buf, &login_client_list, "cl_login");
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW POOLS */
static bool admin_show_pools(PgSocket *admin, const char *arg)
{
	struct List *item;
	PgPool *pool;
	PktBuf *buf;
	PgSocket *waiter;
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
	pktbuf_write_RowDescription(buf, "ssiiiiiiiis",
				    "database", "user",
				    "cl_active", "cl_waiting",
				    "sv_active", "sv_idle",
				    "sv_used", "sv_tested",
				    "sv_login", "maxwait",
				    "pool_mode");
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		waiter = first_socket(&pool->waiting_client_list);
		pool_mode = pool_pool_mode(pool);
		pktbuf_write_DataRow(buf, "ssiiiiiiiis",
				     pool->db->name, pool->user->name,
				     statlist_count(&pool->active_client_list),
				     statlist_count(&pool->waiting_client_list),
				     statlist_count(&pool->active_server_list),
				     statlist_count(&pool->idle_server_list),
				     statlist_count(&pool->used_server_list),
				     statlist_count(&pool->tested_server_list),
				     statlist_count(&pool->new_server_list),
				     /* how long is the oldest client waited */
				     (waiter && waiter->query_start)
				     ?  (int)((now - waiter->query_start) / USEC) : 0,
				     cf_get_lookup(&cv));
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

	pktbuf_write_DataRow(buf, "sqs", name, (ttl - now) / USEC, adrs);
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
	adns_walk_names(adns, dns_name_cb, buf);
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
	adns_walk_zones(adns, dns_zone_cb, buf);
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW CONFIG */

static void show_one_param(void *arg, const char *name, const char *val, bool reloadable)
{
	PktBuf *buf = arg;
	pktbuf_write_DataRow(buf, "sss", name, val,
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

	pktbuf_write_RowDescription(buf, "sss", "key", "value", "changeable");

	config_for_each(show_one_param, buf);

	admin_flush(admin, buf, "SHOW");

	return true;
}

/* Command: RELOAD */
static bool admin_cmd_reload(PgSocket *admin, const char *arg)
{
	if (arg && *arg)
		return syntax_error(admin);

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	log_info("RELOAD command issued");
	load_config();
	return admin_ready(admin, "RELOAD");
}

/* Command: SHUTDOWN */
static bool admin_cmd_shutdown(PgSocket *admin, const char *arg)
{
	if (arg && *arg)
		return syntax_error(admin);

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	/*
	 * note: new pooler expects unix socket file gone when it gets
	 * event from fd.  Currently atexit() cleanup should be called
	 * before closing open sockets.
	 */
	log_info("SHUTDOWN command issued");
	cf_shutdown = 2;
	event_loopbreak();

	return true;
}

static void full_resume(void)
{
	int tmp_mode = cf_pause_mode;
	cf_pause_mode = P_NONE;
	if (tmp_mode == P_SUSPEND)
		resume_all();

	/* avoid surprise later if cf_shutdown stays set */
	if (cf_shutdown) {
		log_info("canceling shutdown");
		cf_shutdown = 0;
	}
}

/* Command: RESUME */
static bool admin_cmd_resume(PgSocket *admin, const char *arg)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (!arg[0]) {
		log_info("RESUME command issued");
		if (cf_pause_mode != P_NONE)
			full_resume();
		else
			return admin_error(admin, "Pooler is not paused/suspended");
	} else {
		PgDatabase *db = find_database(arg);
		log_info("RESUME '%s' command issued", arg);
		if (db == NULL)
			return admin_error(admin, "no such database: %s", arg);
		if (!db->db_paused)
			return admin_error(admin, "database %s is not paused", arg);
		db->db_paused = 0;
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
	cf_pause_mode = P_SUSPEND;
	admin->wait_for_response = 1;
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
		cf_pause_mode = P_PAUSE;
		admin->wait_for_response = 1;
	} else {
		PgDatabase *db;
		log_info("PAUSE '%s' command issued", arg);
		db = find_or_register_database(admin, arg);
		if (db == NULL)
			return admin_error(admin, "no such database: %s", arg);
		if (db == admin->pool->db)
			return admin_error(admin, "cannot pause admin db: %s", arg);
		db->db_paused = 1;
		if (count_db_active(db) > 0)
			admin->wait_for_response = 1;
		else
			return admin_ready(admin, "PAUSE");
	}

	return true;
}

/* Command: DISABLE */
static bool admin_cmd_disable(PgSocket *admin, const char *arg)
{
	PgDatabase *db;

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (!arg[0])
		return admin_error(admin, "a database is required");

	log_info("DISABLE '%s' command issued", arg);
	db = find_or_register_database(admin, arg);
	if (db == NULL)
		return admin_error(admin, "no such database: %s", arg);
	if (db->admin)
		return admin_error(admin, "cannot disable admin db: %s", arg);

	db->db_disabled = 1;
	return admin_ready(admin, "DISABLE");
}

/* Command: ENABLE */
static bool admin_cmd_enable(PgSocket *admin, const char *arg)
{
	PgDatabase *db;

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (!arg[0])
		return admin_error(admin, "a database is required");

	log_info("ENABLE '%s' command issued", arg);
	db = find_database(arg);
	if (db == NULL)
		return admin_error(admin, "no such database: %s", arg);
	if (db->admin)
		return admin_error(admin, "cannot disable admin db: %s", arg);

	db->db_disabled = 0;
	return admin_ready(admin, "ENABLE");
}

/* Command: KILL */
static bool admin_cmd_kill(PgSocket *admin, const char *arg)
{
	struct List *item, *tmp;
	PgDatabase *db;
	PgPool *pool;

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (cf_pause_mode)
		return admin_error(admin, "already suspended/paused");

	if (!arg[0])
		return admin_error(admin, "a database is required");

	log_info("KILL '%s' command issued", arg);
	db = find_or_register_database(admin, arg);
	if (db == NULL)
		return admin_error(admin, "no such database: %s", arg);
	if (db == admin->pool->db)
		return admin_error(admin, "cannot kill admin db: %s", arg);

	db->db_paused = 1;
	statlist_for_each_safe(item, &pool_list, tmp) {
		pool = container_of(item, PgPool, head);
		if (pool->db == db)
			kill_pool(pool);
	}

	return admin_ready(admin, "KILL");
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
			if (s[i] == qchar && s[i+1] == qchar)
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
	SEND_generic(res, admin, 'N',
		"sssss",
		"SNOTICE", "C00000", "MConsole usage",
		"D\n\tSHOW HELP|CONFIG|DATABASES"
		"|POOLS|CLIENTS|SERVERS|VERSION\n"
		"\tSHOW STATS|FDS|SOCKETS|ACTIVE_SOCKETS|LISTS|MEM\n"
		"\tSHOW DNS_HOSTS|DNS_ZONES\n"
		"\tSET key = arg\n"
		"\tRELOAD\n"
		"\tPAUSE [<db>]\n"
		"\tRESUME [<db>]\n"
		"\tDISABLE <db>\n"
		"\tENABLE <db>\n"
		"\tKILL <db>\n"
		"\tSUSPEND\n"
		"\tSHUTDOWN", "");
	if (res)
		res = admin_ready(admin, "SHOW");
	return res;
}

static bool admin_show_version(PgSocket *admin, const char *arg)
{
	bool res;
	SEND_generic(res, admin, 'N',
		"ssss", "SNOTICE", "C00000",
		"M" FULLVER, "");
	if (res)
		res = admin_ready(admin, "SHOW");
	return res;
}

static bool admin_show_stats(PgSocket *admin, const char *arg)
{
	return admin_database_stats(admin, &pool_list);
}

static bool admin_show_totals(PgSocket *admin, const char *arg)
{
	return show_stat_totals(admin, &pool_list);
}


static struct cmd_lookup show_map [] = {
	{"clients", admin_show_clients},
	{"config", admin_show_config},
	{"databases", admin_show_databases},
	{"fds", admin_show_fds},
	{"help", admin_show_help},
	{"lists", admin_show_lists},
	{"pools", admin_show_pools},
	{"servers", admin_show_servers},
	{"sockets", admin_show_sockets},
	{"active_sockets", admin_show_active_sockets},
	{"stats", admin_show_stats},
	{"users", admin_show_users},
	{"version", admin_show_version},
	{"totals", admin_show_totals},
	{"mem", admin_show_mem},
	{"dns_hosts", admin_show_dns_hosts},
	{"dns_zones", admin_show_dns_zones},
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
	{"pause", admin_cmd_pause},
	{"reload", admin_cmd_reload},
	{"resume", admin_cmd_resume},
	{"select", admin_cmd_show},
	{"show", admin_cmd_show},
	{"shutdown", admin_cmd_shutdown},
	{"suspend", admin_cmd_suspend},
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
	} else
		res = syntax_error(admin);
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
	case 'Q':
		if (!mbuf_get_string(&pkt->data, &q)) {
			disconnect_client(admin, true, "incomplete query");
			return false;
		}
		log_debug("got admin query: %s", q);
		res = admin_parse_query(admin, q);
		if (res)
			sbuf_prepare_skip(&admin->sbuf, pkt->len);
		return res;
	case 'X':
		disconnect_client(admin, false, "close req");
		break;
	default:
		admin_error(admin, "unsupported pkt type: %d", pkt_desc(pkt));
		disconnect_client(admin, true, "bad pkt");
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
	uid_t peer_uid = -1;
	gid_t peer_gid = -1;
	int res;

	client->admin_user = 0;
	client->own_user = 0;

	/* tag same uid as special */
	if (pga_is_unix(&client->remote_addr)) {
		res = getpeereid(sbuf_socket(&client->sbuf), &peer_uid, &peer_gid);
		if (res >= 0 && peer_uid == getuid()
			&& strcmp("pgbouncer", username) == 0)
		{
			client->auth_user = admin_pool->db->forced_user;
			client->own_user = 1;
			client->admin_user = 1;
			slog_info(client, "pgbouncer access from unix socket");
			return true;
		}
	}

	/*
	 * auth_mode=any does not keep original username around,
	 * so username based check has to take place here
	 */
	if (cf_auth_type == AUTH_ANY) {
		if (strlist_contains(cf_admin_users, username)) {
			client->auth_user = admin_pool->db->forced_user;
			client->admin_user = 1;
			return true;
		} else if (strlist_contains(cf_stats_users, username)) {
			client->auth_user = admin_pool->db->forced_user;
			return true;
		}
	}
	return false;
}

bool admin_post_login(PgSocket *client)
{
	const char *username = client->auth_user->name;

	if (cf_auth_type == AUTH_ANY)
		return true;

	if (client->admin_user || strlist_contains(cf_admin_users, username)) {
		client->admin_user = 1;
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
	PgUser *user;
	PktBuf *msg;
	int res;

	/* fake database */
	db = add_database("pgbouncer");
	if (!db)
		fatal("no memory for admin database");

	db->port = cf_listen_port;
	db->pool_size = 2;
	db->admin = 1;
	db->pool_mode = POOL_STMT;
	if (!force_user(db, "pgbouncer", ""))
		fatal("no mem on startup - cannot alloc pgbouncer user");

	/* fake pool */
	pool = get_pool(db, db->forced_user);
	if (!pool)
		fatal("cannot create admin pool?");
	admin_pool = pool;

	/* user */
	user = find_user("pgbouncer");
	if (!user) {
		/* fake user with disabled psw */
		user = add_user("pgbouncer", "");
		if (!user)
			fatal("cannot create admin user?");
	}

	/* prepare welcome */
	msg = pktbuf_dynamic(128);
	if (!msg)
		fatal("cannot create admin welcome");
	pktbuf_write_AuthenticationOk(msg);
	pktbuf_write_ParameterStatus(msg, "server_version", PACKAGE_VERSION "/bouncer");
	pktbuf_write_ParameterStatus(msg, "client_encoding", "UNICODE");
	pktbuf_write_ParameterStatus(msg, "server_encoding", "SQL_ASCII");
	pktbuf_write_ParameterStatus(msg, "DateStyle", "ISO");
	pktbuf_write_ParameterStatus(msg, "TimeZone", "GMT");
	pktbuf_write_ParameterStatus(msg, "standard_conforming_strings", "on");
	pktbuf_write_ParameterStatus(msg, "is_superuser", "on");

	if (msg->failed)
		fatal("admin welcome failed");

	pool->welcome_msg = msg;
	pool->welcome_msg_ready = 1;

	msg = pktbuf_dynamic(128);
	if (!msg)
		fatal("cannot create admin startup pkt");
	db->startup_params = msg;
	pktbuf_put_string(msg, "database");
	db->dbname = "pgbouncer";
	pktbuf_put_string(msg, db->dbname);

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

	statlist_for_each_safe(item, &admin_pool->active_client_list, tmp) {
		admin = container_of(item, PgSocket, head);
		if (!admin->wait_for_response)
			continue;

		res = false;
		switch (cf_pause_mode) {
		case P_PAUSE:
			res = admin_ready(admin, "PAUSE");
			break;
		case P_SUSPEND:
			res = admin_ready(admin, "SUSPEND");
			break;
		default:
			if (count_paused_databases() > 0)
				res = admin_ready(admin, "PAUSE");
			else
				/* FIXME */
				fatal("admin_pause_done: bad state");
		}

		if (!res)
			disconnect_client(admin, false, "dead admin");
		else
			admin->wait_for_response = 0;
	}

	if (statlist_empty(&admin_pool->active_client_list)
	    && cf_pause_mode == P_SUSPEND)
	{
		log_info("Admin disappeared when suspended, doing RESUME");
		cf_pause_mode = P_NONE;
		resume_all();
	}
}

/* admin on console has pressed ^C */
void admin_handle_cancel(PgSocket *admin)
{
	bool res;

	/* weird, but no reason to fail */
	if (!admin->wait_for_response)
		slog_warning(admin, "admin cancel request for non-waiting client?");

	if (cf_pause_mode != P_NONE)
		full_resume();

	/* notify readiness */
	SEND_ReadyForQuery(res, admin);
	if (!res)
		disconnect_client(admin, false, "readiness send failed");
}

