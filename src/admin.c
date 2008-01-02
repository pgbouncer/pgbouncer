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

#include "bouncer.h"

#include <regex.h>

/* regex elements */
#define WS0	"[ \t\n\r]*"
#define WS1	"[ \t\n\r]+"
#define WORD	"([0-9a-z_]+)"
#define STRING	"'(([^']*|'')*)'"

/* possible max + 1 */
#define MAX_GROUPS 10

/* group numbers */
#define CMD_NAME 1
#define CMD_ARG 3
#define SET_KEY 1
#define SET_VAL 3

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

static bool exec_cmd(struct cmd_lookup *lookup, PgSocket *admin,
		     const char *cmd, const char *arg)
{
	for (; lookup->word; lookup++) {
		if (strcasecmp(lookup->word, cmd) == 0)
			return lookup->func(admin, arg);
	}
	return admin_error(admin, "syntax error, use SHOW HELP");
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
	List *item;
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
	List *item;
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
	return pktbuf_send_immidiate(&buf, admin);
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

	if (fake_set(admin, key, val))
		return true;

	if (admin->admin_user) {
		if (set_config_param(bouncer_params, key, val, true, admin)) {
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
			const char *timezone)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int res;
	struct iovec iovec;
	uint8_t pktbuf[1024];
	uint8_t cntbuf[CMSG_SPACE(sizeof(int))];

	iovec.iov_base = pktbuf;
	BUILD_DataRow(res, pktbuf, sizeof(pktbuf), "issssiqissss",
		      fd, task, user, db, addr, port, ckey, link,
		      client_enc, std_strings, datestyle, timezone);
	if (res < 0)
		return false;
	iovec.iov_len = res;

	/* sending fds */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iovec;
	msg.msg_iovlen = 1;

	/* attach a fd */
	if (admin->remote_addr.is_unix && admin->own_user) {
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
		   fd, msg.msg_controllen);
	res = safe_sendmsg(sbuf_socket(&admin->sbuf), &msg, 0);
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
	MBuf tmp;
	VarCache *v = &sk->vars;

	mbuf_init(&tmp, sk->cancel_key, 8);

	return send_one_fd(admin, sbuf_socket(&sk->sbuf),
			   is_server_socket(sk) ? "server" : "client",
			   sk->auth_user ? sk->auth_user->name : NULL,
			   sk->pool ? sk->pool->db->name : NULL,
			   addr->is_unix ? "unix" : inet_ntoa(addr->ip_addr),
			   addr->port,
			   mbuf_get_uint64(&tmp),
			   sk->link ? sbuf_socket(&sk->link->sbuf) : 0,
			   v->client_encoding[0] ? v->client_encoding : NULL,
			   v->std_strings[0] ? v->std_strings : NULL,
			   v->datestyle[0] ? v->datestyle : NULL,
			   v->timezone[0] ? v->timezone : NULL);
}

/* send a row with sendmsg, optionally attaching a fd */
static bool show_pooler_fds(PgSocket *admin)
{
	int fd_net, fd_unix;
	bool res = true;

	get_pooler_fds(&fd_net, &fd_unix);

	if (fd_net)
		res = send_one_fd(admin, fd_net, "pooler", NULL, NULL,
				  cf_listen_addr, cf_listen_port, 0, 0,
				  NULL, NULL, NULL, NULL);
	if (fd_unix && res)
		res = send_one_fd(admin, fd_unix, "pooler", NULL, NULL,
				  "unix", cf_listen_port, 0, 0,
				  NULL, NULL, NULL, NULL);
	return res;
}

static bool show_fds_from_list(PgSocket *admin, StatList *list)
{
	List *item;
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

/*
 * Command: SHOW FDS
 *
 * If privileged connection, send also actual fds
 */
static bool admin_show_fds(PgSocket *admin, const char *arg)
{
	List *item;
	PgPool *pool;
	bool res;

	/*
	 * Dangerous to show to everybody:
	 * - can lock pooler as code flips async option
	 * - show cancel keys for all users
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
	SEND_RowDescription(res, admin, "issssiqissss",
				 "fd", "task",
				 "user", "database",
				 "addr", "port",
				 "cancel", "link",
				 "client_encoding", "std_strings",
				 "datestyle", "timezone");
	if (res)
		res = show_pooler_fds(admin);

	if (res)
		res = show_fds_from_list(admin, &login_client_list);

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->admin)
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
	List *item;
	char *host;
	const char *f_user;
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "ssissi",
				    "name", "host", "port",
				    "database", "force_user", "pool_size");
	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);

		if (!db->addr.is_unix) {
			host = inet_ntoa(db->addr.ip_addr);
		} else
			host = NULL;

		f_user = db->forced_user ? db->forced_user->name : NULL;
		pktbuf_write_DataRow(buf, "ssissi",
				     db->name, host, db->addr.port,
				     db->dbname, f_user,
				     db->pool_size);
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
	SENDLIST("free_clients", objcache_free_count(client_cache));
	SENDLIST("used_clients", objcache_active_count(client_cache));
	SENDLIST("login_clients", statlist_count(&login_client_list));
	SENDLIST("free_servers", objcache_free_count(server_cache));
	SENDLIST("used_servers", objcache_active_count(server_cache));
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW USERS */
static bool admin_show_users(PgSocket *admin, const char *arg)
{
	PgUser *user;
	List *item;
	PktBuf *buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "s", "name");
	statlist_for_each(item, &user_list) {
		user = container_of(item, PgUser, head);
		pktbuf_write_DataRow(buf, "s", user->name);
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}

#define SKF_STD "sssssisiTTss"
#define SKF_DBG "sssssisiTTssiiiiiii"

static void socket_header(PktBuf *buf, bool debug)
{
	pktbuf_write_RowDescription(buf, debug ? SKF_DBG : SKF_STD,
				    "type", "user", "database", "state",
				    "addr", "port", "local_addr", "local_port",
				    "connect_time", "request_time",
				    "ptr", "link",
				    "recv_pos", "pkt_pos", "pkt_remain",
				    "send_pos", "send_remain",
				    "pkt_avail", "send_avail");
}

static void adr2txt(const PgAddr *adr, char *dst, int dstlen)
{
	if (adr->is_unix) {
		strlcpy(dst, "unix", dstlen);
	} else {
		char *tmp = inet_ntoa(adr->ip_addr);
		strlcpy(dst, tmp, dstlen);
	}
}

static void socket_row(PktBuf *buf, PgSocket *sk, const char *state, bool debug)
{
	int pkt_avail = sk->sbuf.recv_pos - sk->sbuf.pkt_pos;
	int send_avail = sk->sbuf.recv_pos - sk->sbuf.send_pos;
	char ptrbuf[128], linkbuf[128];
	char l_addr[32], r_addr[32];

	adr2txt(&sk->remote_addr, r_addr, sizeof(r_addr));
	adr2txt(&sk->local_addr, l_addr, sizeof(l_addr));

	snprintf(ptrbuf, sizeof(ptrbuf), "%p", sk);
	if (sk->link)
		snprintf(linkbuf, sizeof(linkbuf), "%p", sk->link);
	else
		linkbuf[0] = 0;

	pktbuf_write_DataRow(buf, debug ? SKF_DBG : SKF_STD,
			     is_server_socket(sk) ? "S" :"C",
			     sk->auth_user ? sk->auth_user->name : "(nouser)",
			     sk->pool ? sk->pool->db->name : "(nodb)",
			     state, r_addr, sk->remote_addr.port,
			     l_addr, sk->local_addr.port,
			     sk->connect_time,
			     sk->request_time,
			     ptrbuf, linkbuf,
			     sk->sbuf.recv_pos,
			     sk->sbuf.pkt_pos,
			     sk->sbuf.pkt_remain,
			     sk->sbuf.send_pos,
			     sk->sbuf.send_remain,
			     pkt_avail, send_avail);
}

/* Helper for SHOW CLIENTS */
static void show_socket_list(PktBuf *buf, StatList *list, const char *state, bool debug)
{
	List *item;
	PgSocket *sk;

	statlist_for_each(item, list) {
		sk = container_of(item, PgSocket, head);
		socket_row(buf, sk, state, debug);
	}
}

/* Command: SHOW CLIENTS */
static bool admin_show_clients(PgSocket *admin, const char *arg)
{
	List *item;
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
	List *item;
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
	List *item;
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

/* Command: SHOW POOLS */
static bool admin_show_pools(PgSocket *admin, const char *arg)
{
	List *item;
	PgPool *pool;
	PktBuf *buf;
	PgSocket *waiter;
	usec_t now = get_cached_time();

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "ssiiiiiiii",
				    "database", "user",
				    "cl_active", "cl_waiting",
				    "sv_active", "sv_idle",
				    "sv_used", "sv_tested",
				    "sv_login", "maxwait");
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		waiter = first_socket(&pool->waiting_client_list);
		pktbuf_write_DataRow(buf, "ssiiiiiiii",
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
				     ?  (int)((now - waiter->query_start) / USEC) : 0);
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW CONFIG */
static bool admin_show_config(PgSocket *admin, const char *arg)
{
	ConfElem *cf;
	int i = 0;
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "sss", "key", "value", "changeable");
	while (1) {
		cf = &bouncer_params[i++];
		if (!cf->name)
			break;

		pktbuf_write_DataRow(buf, "sss",
				     cf->name, conf_to_text(cf),
				     cf->reloadable ? "yes" : "no");
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: RELOAD */
static bool admin_cmd_reload(PgSocket *admin, const char *arg)
{
	if (arg && *arg)
		return admin_error(admin, "syntax error");

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	log_info("RELOAD command issued");
	load_config(true);
	return admin_ready(admin, "RELOAD");
}

/* Command: SHUTDOWN */
static bool admin_cmd_shutdown(PgSocket *admin, const char *arg)
{
	if (arg && *arg)
		return admin_error(admin, "syntax error");

	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	log_info("SHUTDOWN command issued");
	exit(0);
	return true;
}

static void full_resume(void)
{
	int tmp_mode = cf_pause_mode;
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
		if (cf_pause_mode != P_NONE)
			full_resume();
		else
			return admin_error(admin, "Pooler is not paused/suspended");
	} else {
		PgDatabase *db = find_database(arg);
		log_info("PAUSE '%s' command issued", arg);
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
		return admin_error(admin, "syntax error");

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
		db = find_database(arg);
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

/* extract substring from regex group */
static void copy_arg(const char *src, regmatch_t *glist,
		     int gnum, char *dst, unsigned dstmax)
{
	regmatch_t *g = &glist[gnum];
	unsigned len = g->rm_eo - g->rm_so;
	if (len < dstmax)
		memcpy(dst, src + g->rm_so, len);
	else
		len = 0;
	dst[len] = 0;
}

/* extract quoted substring from regex group */
static void copy_arg_unquote(const char *str, regmatch_t *glist,
			     int gnum, char *dst, int dstmax)
{
	regmatch_t *g = &glist[gnum];
	int len = g->rm_eo - g->rm_so;
	const char *src = str + g->rm_so;
	const char *end = src + len;

	if (len < dstmax) {
		len = 0;
		while (src < end) {
			if (src[0] == '\'' && src[1] == '\'') {
				*dst++ = '\'';
				src += 2;
			} else
				*dst++ = *src++;
		}
	}
	*dst = 0;
}

static bool admin_show_help(PgSocket *admin, const char *arg)
{
	bool res;
	SEND_generic(res, admin, 'N',
		"sssss",
		"SNOTICE", "C00000", "MConsole usage",
		"D\n\tSHOW [HELP|CONFIG|DATABASES|FDS"
		"|POOLS|CLIENTS|SERVERS|SOCKETS|LISTS|VERSION]\n"
		"\tSET key = arg\n"
		"\tRELOAD\n"
		"\tPAUSE\n"
		"\tSUSPEND\n"
		"\tRESUME\n"
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
	{"stats", admin_show_stats},
	{"users", admin_show_users},
	{"version", admin_show_version},
	{NULL, NULL}
};

static bool admin_cmd_show(PgSocket *admin, const char *arg)
{
	if (fake_show(admin, arg))
		return true;
	return exec_cmd(show_map, admin, arg, NULL);
}

static struct cmd_lookup cmd_list [] = {
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

	if (regexec(&rc_cmd, q, MAX_GROUPS, grp, 0) == 0) {
		copy_arg(q, grp, CMD_NAME, cmd, sizeof(cmd));
		copy_arg(q, grp, CMD_ARG, arg, sizeof(arg));
		res = exec_cmd(cmd_list, admin, cmd, arg);
	} else if (regexec(&rc_set_str, q, MAX_GROUPS, grp, 0) == 0) {
		copy_arg(q, grp, SET_KEY, arg, sizeof(arg));
		copy_arg_unquote(q, grp, SET_VAL, val, sizeof(val));
		if (!arg[0] || !val[0]) {
			res = admin_error(admin, "bad arguments");
		} else
			res = admin_set(admin, arg, val);
	} else if (regexec(&rc_set_word, q, MAX_GROUPS, grp, 0) == 0) {
		copy_arg(q, grp, SET_KEY, arg, sizeof(arg));
		copy_arg(q, grp, SET_VAL, val, sizeof(val));
		if (!arg[0] || !val[0]) {
			res = admin_error(admin, "bad arguments");
		} else
			res = admin_set(admin, arg, val);
	} else
		res = admin_error(admin, "unknown cmd: %s", q);

	if (!res)
		disconnect_client(admin, true, "failure");
	return res;
}

/* handle packets */
bool admin_handle_client(PgSocket *admin, PktHdr *pkt)
{
	const char *q;
	bool res;

	/* dont tolerate partial packets */
	if (incomplete_pkt(pkt)) {
		disconnect_client(admin, true, "incomplete pkt");
		return false;
	}

	switch (pkt->type) {
	case 'Q':
		q = mbuf_get_string(&pkt->data);
		if (!q) {
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
bool admin_pre_login(PgSocket *client)
{
	uid_t peer_uid = -1;
	gid_t peer_gid = -1;
	int res;
	const char *username = client->auth_user->name;

	client->admin_user = 0;
	client->own_user = 0;

	/* tag same uid as special */
	if (client->remote_addr.is_unix) {
		res = getpeereid(sbuf_socket(&client->sbuf), &peer_uid, &peer_gid);
		if (res >= 0 && peer_uid == getuid()
			&& strcmp("pgbouncer", username) == 0)
		{
			client->own_user = 1;
			client->admin_user = 1;
			slog_info(client, "pgbouncer access from unix socket");
			return true;
		}
	}

	if (strlist_contains(cf_admin_users, username)) {
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
	PktBuf msg;
	int res;

	/* fake database */
	db = add_database("pgbouncer");
	if (!db)
		fatal("no memory for admin database");

	db->addr.port = cf_listen_port;
	db->addr.is_unix = 1;
	db->pool_size = 2;
	if (!force_user(db, "pgbouncer", ""))
		fatal("no mem on startup - cannot alloc pgbouncer user");

	/* fake pool, tag the it as special */
	pool = get_pool(db, db->forced_user);
	if (!pool)
		fatal("cannot create admin pool?");
	pool->admin = 1;
	admin_pool = pool;

	/* fake user, with disabled psw */
	user = add_user("pgbouncer", "");
	if (!user)
		fatal("cannot create admin user?");

	/* prepare welcome */
	pktbuf_static(&msg, pool->welcome_msg, sizeof(pool->welcome_msg));
	pktbuf_write_AuthenticationOk(&msg);
	pktbuf_write_ParameterStatus(&msg, "server_version", "8.0/bouncer");
	pktbuf_write_ParameterStatus(&msg, "client_encoding", "UNICODE");
	pktbuf_write_ParameterStatus(&msg, "server_encoding", "SQL_ASCII");
	pktbuf_write_ParameterStatus(&msg, "is_superuser", "on");

	pool->welcome_msg_len = pktbuf_written(&msg);
	pool->welcome_msg_ready = 1;

	pktbuf_static(&msg, db->startup_params, sizeof(db->startup_params));
	pktbuf_put_string(&msg, "database");
	db->dbname = (char *)db->startup_params + pktbuf_written(&msg);
	pktbuf_put_string(&msg, "pgbouncer");
	db->startup_params_len = pktbuf_written(&msg);

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
	List *item, *tmp;
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
				/* fixme */
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

