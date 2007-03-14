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
#define SHOW_ARG 1
#define SET_KEY 1
#define SET_VAL 2
#define SINGLECMD 1

/* SHOW */
static const char cmd_show_rx[] =
"^" WS0 "show" WS1 WORD "?" WS0 ";" WS0 "$";

/* SET with simple value */
static const char cmd_set_word_rx[] =
"^" WS0 "set" WS1 WORD WS0 "=" WS0 WORD WS0 ";" WS0 "$";

/* SET with quoted value */
static const char cmd_set_str_rx[] =
"^" WS0 "set" WS1 WORD WS0 "=" WS0 STRING WS0 ";" WS0 "$";

/* single word cmd */
static const char cmd_single_rx[] =
"^" WS0 WORD ";" WS0 "$";

/* compiled regexes */
static regex_t rc_show;
static regex_t rc_set_word;
static regex_t rc_set_str;
static regex_t rc_single;

static PgPool *admin_pool;

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

void admin_flush(PgSocket *admin, PktBuf *buf, const char *desc)
{
	pktbuf_write_CommandComplete(buf, desc);
	pktbuf_write_ReadyForQuery(buf);
	pktbuf_send_queued(buf, admin);
}

bool admin_ready(PgSocket *admin, const char *desc)
{
	PktBuf buf;
	uint8 tmp[512];
	pktbuf_static(&buf, tmp, sizeof(tmp));
	pktbuf_write_CommandComplete(&buf, desc);
	pktbuf_write_ReadyForQuery(&buf);
	return pktbuf_send_immidiate(&buf, admin);
}

/* Command: SET key = val; */
static bool admin_set(PgSocket *admin, const char *key, const char *val)
{
	char tmp[512];

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
			uint64 ckey, int link)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int res;
	struct iovec iovec;
	uint8 pktbuf[1024];
	uint8 cntbuf[CMSG_SPACE(sizeof(int))];

	iovec.iov_base = pktbuf;
	BUILD_DataRow(res, pktbuf, sizeof(pktbuf), "issssiqi",
		      fd, task, user, db, addr, port, ckey, link);
	if (res < 0)
		return false;
	iovec.iov_len = res;

	/* sending fds */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iovec;
	msg.msg_iovlen = 1;

	/* attach a fd */
	if (admin->addr.is_unix && admin->own_user) {
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
	} else if (res != iovec.iov_len) {
		log_error("send_one_fd: partial sendmsg");
		return false;
	}
	return true;
}

/* send a row with sendmsg, optionally attaching a fd */
static bool show_one_fd(PgSocket *admin, PgSocket *sk)
{
	PgAddr *addr = &sk->addr;
	MBuf tmp;

	mbuf_init(&tmp, sk->cancel_key, 8);

	return send_one_fd(admin, sbuf_socket(&sk->sbuf),
			   is_server_socket(sk) ? "server" : "client",
			   sk->auth_user ? sk->auth_user->name : NULL,
			   sk->pool ? sk->pool->db->name : NULL,
			   addr->is_unix ? "unix" : inet_ntoa(addr->ip_addr),
			   addr->port,
			   mbuf_get_uint64(&tmp),
			   sk->link ? sbuf_socket(&sk->link->sbuf) : 0);
}

/* send a row with sendmsg, optionally attaching a fd */
static bool show_pooler_fds(PgSocket *admin)
{
	int fd_net, fd_unix;
	bool res = true;

	get_pooler_fds(&fd_net, &fd_unix);

	if (fd_net)
		res = send_one_fd(admin, fd_net, "pooler", NULL, NULL,
				  cf_listen_addr, cf_listen_port, 0, 0);
	if (fd_unix && res)
		res = send_one_fd(admin, fd_unix, "pooler", NULL, NULL,
				  "unix", cf_listen_port, 0, 0);
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
static bool admin_show_fds(PgSocket *admin)
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
	 * Its very hard to send it reliably over in async manner,
	 * so turn async off for this resultset.
	 */
	socket_set_nonblocking(sbuf_socket(&admin->sbuf), 0);

	/*
	 * send resultset
	 */
	SEND_RowDescription(res, admin, "issssiqi",
				 "fd", "task",
				 "user", "database",
				 "addr", "port",
				 "cancel", "link");
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
static bool admin_show_databases(PgSocket *admin)
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
static bool admin_show_lists(PgSocket *admin)
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
	SENDLIST("free_clients", statlist_count(&free_client_list));
	SENDLIST("used_clients", get_active_client_count());
	SENDLIST("login_clients", statlist_count(&login_client_list));
	SENDLIST("free_servers", statlist_count(&free_server_list));
	SENDLIST("used_servers", get_active_server_count());
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW USERS */
static bool admin_show_users(PgSocket *admin)
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

#define SKF_STD "sssssiTT"
#define SKF_DBG "sssssiTTiiiiiiiss"

static void socket_header(PktBuf *buf, bool debug)
{
	pktbuf_write_RowDescription(buf, debug ? SKF_DBG : SKF_STD,
				    "type", "user", "database", "state",
				    "addr", "port",
				    "connect_time", "request_time",
				    "recv_pos", "pkt_pos", "pkt_remain",
				    "send_pos", "send_remain",
				    "pkt_avail", "send_avail",
				    "ptr", "link");
}

static void socket_row(PktBuf *buf, PgSocket *sk, const char *state, bool debug)
{
	const char *addr = sk->addr.is_unix ? "unix"
			: inet_ntoa(sk->addr.ip_addr);
	int pkt_avail = sk->sbuf.recv_pos - sk->sbuf.pkt_pos;
	int send_avail = sk->sbuf.recv_pos - sk->sbuf.send_pos;
	char ptrbuf[128], linkbuf[128];

	snprintf(ptrbuf, sizeof(ptrbuf), "%p", sk);
	if (sk->link)
		snprintf(linkbuf, sizeof(linkbuf), "%p", sk->link);
	else
		linkbuf[0] = 0;

	pktbuf_write_DataRow(buf, debug ? SKF_DBG : SKF_STD,
			     is_server_socket(sk) ? "S" :"C",
			     sk->auth_user->name,
			     sk->pool->db->name,
			     state, addr, sk->addr.port,
			     sk->connect_time,
			     sk->request_time,
			     sk->sbuf.recv_pos,
			     sk->sbuf.pkt_pos,
			     sk->sbuf.pkt_remain,
			     sk->sbuf.send_pos,
			     sk->sbuf.send_remain,
			     pkt_avail, send_avail,
			     ptrbuf, linkbuf);
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
static bool admin_show_clients(PgSocket *admin)
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
static bool admin_show_servers(PgSocket *admin)
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
static bool admin_show_sockets(PgSocket *admin)
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
		show_socket_list(buf, &pool->active_client_list, "active", true);
		show_socket_list(buf, &pool->waiting_client_list, "waiting", true);

		show_socket_list(buf, &pool->active_server_list, "active", true);
		show_socket_list(buf, &pool->idle_server_list, "idle", true);
		show_socket_list(buf, &pool->used_server_list, "used", true);
		show_socket_list(buf, &pool->tested_server_list, "tested", true);
		show_socket_list(buf, &pool->new_server_list, "login", true);
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW POOLS */
static bool admin_show_pools(PgSocket *admin)
{
	List *item;
	PgPool *pool;
	PktBuf *buf;

	buf = pktbuf_dynamic(256);
	if (!buf) {
		admin_error(admin, "no mem");
		return true;
	}
	pktbuf_write_RowDescription(buf, "ssiiiiiii",
				    "database", "user",
				    "cl_active", "cl_waiting",
				    "sv_active", "sv_idle",
				    "sv_used", "sv_tested",
				    "sv_login");
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		pktbuf_write_DataRow(buf, "ssiiiiiii",
				     pool->db->name, pool->user->name,
				     statlist_count(&pool->active_client_list),
				     statlist_count(&pool->waiting_client_list),
				     statlist_count(&pool->active_server_list),
				     statlist_count(&pool->idle_server_list),
				     statlist_count(&pool->used_server_list),
				     statlist_count(&pool->tested_server_list),
				     statlist_count(&pool->new_server_list));
	}
	admin_flush(admin, buf, "SHOW");
	return true;
}

/* Command: SHOW CONFIG */
static bool admin_show_config(PgSocket *admin)
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
static bool admin_cmd_reload(PgSocket *admin)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	log_info("RELOAD command issued");
	load_config(true);
	return admin_ready(admin, "RELOAD");
}

/* Command: SHUTDOWN */
static bool admin_cmd_shutdown(PgSocket *admin)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	log_info("SHUTDOWN command issued");
	exit(0);
	return true;
}

/* Command: RESUME */
static bool admin_cmd_resume(PgSocket *admin)
{
	int tmp_mode = cf_pause_mode;
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	log_info("RESUME command issued");
	cf_pause_mode = 0;
	switch (tmp_mode) {
	case 2:
		resume_all();
	case 1:
		return admin_ready(admin, "RESUME");
	default:
		return admin_error(admin, "Pooler is not paused/suspended");
	}
}

/* Command: SUSPEND */
static bool admin_cmd_suspend(PgSocket *admin)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (cf_pause_mode)
		return admin_error(admin, "already suspended/paused");

	log_info("SUSPEND command issued");
	cf_pause_mode = 2;
	admin->wait_for_response = 1;
	suspend_pooler();

	return true;
}

/* Command: PAUSE */
static bool admin_cmd_pause(PgSocket *admin)
{
	if (!admin->admin_user)
		return admin_error(admin, "admin access needed");

	if (cf_pause_mode)
		return admin_error(admin, "already suspended/paused");

	log_info("PAUSE command issued");
	cf_pause_mode = 1;
	admin->wait_for_response = 1;

	return true;
}

/* extract substring from regex group */
static void copy_arg(const char *src, regmatch_t *glist,
		     int gnum, char *dst, int dstmax)
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

static bool admin_show_help(PgSocket *admin)
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

static bool admin_show_version(PgSocket *admin)
{
	bool res;
	SEND_generic(res, admin, 'N',
		"ssss", "SNOTICE", "C00000",
		"MPgBouncer version " PACKAGE_VERSION, "");
	if (res)
		res = admin_ready(admin, "SHOW");
	return res;
}

/* handle user query */
static bool admin_parse_query(PgSocket *admin, const char *q)
{
	regmatch_t grp[MAX_GROUPS];
	char key[64];
	char val[256];
	bool res = true;

	if (regexec(&rc_show, q, MAX_GROUPS, grp, 0) == 0) {
		copy_arg(q, grp, SHOW_ARG, key, sizeof(key));
		if (strcasecmp(key, "help") == 0) {
			res = admin_show_help(admin);
		} else if (strcasecmp(key, "stats") == 0) {
			res = admin_database_stats(admin, &pool_list);
		} else if (strcasecmp(key, "config") == 0) {
			res = admin_show_config(admin);
		} else if (strcasecmp(key, "databases") == 0) {
			res = admin_show_databases(admin);
		} else if (strcasecmp(key, "users") == 0) {
			res = admin_show_users(admin);
		} else if (strcasecmp(key, "pools") == 0) {
			res = admin_show_pools(admin);
		} else if (strcasecmp(key, "clients") == 0) {
			res = admin_show_clients(admin);
		} else if (strcasecmp(key, "servers") == 0) {
			res = admin_show_servers(admin);
		} else if (strcasecmp(key, "lists") == 0) {
			res = admin_show_lists(admin);
		} else if (strcasecmp(key, "sockets") == 0) {
			res = admin_show_sockets(admin);
		} else if (strcasecmp(key, "fds") == 0) {
			res = admin_show_fds(admin);
		} else if (strcasecmp(key, "version") == 0) {
			res = admin_show_version(admin);
		} else
			res = admin_error(admin, "bad SHOW arg, use SHOW HELP");
	} else if (regexec(&rc_set_str, q, MAX_GROUPS, grp, 0) == 0) {
		copy_arg(q, grp, SET_KEY, key, sizeof(key));
		copy_arg_unquote(q, grp, SET_VAL, val, sizeof(val));
		if (!key[0] || !val[0]) {
			res = admin_error(admin, "bad arguments");
		} else
			res = admin_set(admin, key, val);
	} else if (regexec(&rc_set_word, q, MAX_GROUPS, grp, 0) == 0) {
		copy_arg(q, grp, SET_KEY, key, sizeof(key));
		copy_arg(q, grp, SET_VAL, val, sizeof(val));
		if (!key[0] || !val[0]) {
			res = admin_error(admin, "bad arguments");
		} else
			res = admin_set(admin, key, val);
	} else if (regexec(&rc_single, q, MAX_GROUPS, grp, 0) == 0) {
		copy_arg(q, grp, SINGLECMD, key, sizeof(key));
		if (strcasecmp(key, "SHUTDOWN") == 0)
			res = admin_cmd_shutdown(admin);
		else if (strcasecmp(key, "SUSPEND") == 0)
			res = admin_cmd_suspend(admin);
		else if (strcasecmp(key, "PAUSE") == 0)
			res = admin_cmd_pause(admin);
		else if (strcasecmp(key, "RESUME") == 0)
			res = admin_cmd_resume(admin);
		else if (strcasecmp(key, "RELOAD") == 0)
			res = admin_cmd_reload(admin);
		else
			res = admin_error(admin, "unknown command: %s", q);
	} else
		res = admin_error(admin, "unknown cmd: %s", q);

	if (!res)
		disconnect_client(admin, true, "failure");
	return res;
}

/* handle packets */
bool admin_handle_client(PgSocket *admin, MBuf *pkt, int pkt_type, int pkt_len)
{
	const char *q;
	bool res;

	/* dont tolerate partial packets */
	if (mbuf_avail(pkt) < pkt_len - 5) {
		disconnect_client(admin, true, "incomplete pkt");
		return false;
	}

	switch (pkt_type) {
	case 'Q':
		q = mbuf_get_string(pkt);
		if (!q) {
			disconnect_client(admin, true, "incomplete query");
			return false;
		}
		log_debug("got admin query: %s", q);
		res = admin_parse_query(admin, q);
		if (res)
			sbuf_prepare_skip(&admin->sbuf, pkt_len);
		return res;
	case 'X':
		disconnect_client(admin, false, "close req");
		break;
	default:
		admin_error(admin, "unsupported pkt type: %d", pkt_type);
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
	uid_t peer_uid = 0;
	bool res;
	const char *username = client->auth_user->name;

	client->admin_user = 0;
	client->own_user = 0;

	/* tag same uid as special */
	if (client->addr.is_unix) {
		res = get_unix_peer_uid(sbuf_socket(&client->sbuf), &peer_uid);
		if (res && peer_uid == getuid()
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
		fatal("no mem for admin database");

	db->addr.port = cf_listen_port;
	db->addr.is_unix = 1;
	db->pool_size = 2;
	force_user(db, "pgbouncer", "");

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
	create_auth_cache();

	/* prepare welcome */
	pktbuf_static(&msg, db->welcome_msg, sizeof(db->welcome_msg));
	pktbuf_write_AuthenticationOk(&msg);
	pktbuf_write_ParameterStatus(&msg, "server_version", "8.0/bouncer");
	pktbuf_write_ParameterStatus(&msg, "client_encoding", "UNICODE");
	pktbuf_write_ParameterStatus(&msg, "server_encoding", "UNICODE");
	pktbuf_write_ParameterStatus(&msg, "is_superuser", "on");

	db->welcome_msg_len = pktbuf_written(&msg);
	db->welcome_msg_ready = 1;

	pktbuf_static(&msg, db->startup_params, sizeof(db->startup_params));
	pktbuf_put_string(&msg, "database");
	db->dbname = (char *)db->startup_params + pktbuf_written(&msg);
	pktbuf_put_string(&msg, "pgbouncer");
	db->startup_params_len = pktbuf_written(&msg);

	/* initialize regexes */
	res = regcomp(&rc_show, cmd_show_rx, REG_EXTENDED | REG_ICASE);
	if (res != 0)
		fatal("cmd show regex compilation error");
	res = regcomp(&rc_set_word, cmd_set_word_rx, REG_EXTENDED | REG_ICASE);
	if (res != 0)
		fatal("set/word regex compilation error");
	res = regcomp(&rc_set_str, cmd_set_str_rx, REG_EXTENDED | REG_ICASE);
	if (res != 0)
		fatal("set/str regex compilation error");
	res = regcomp(&rc_single, cmd_single_rx, REG_EXTENDED | REG_ICASE);
	if (res != 0)
		fatal("singleword regex compilation error");
}

void admin_pause_done(void)
{
	List *item, *tmp;
	PgSocket *admin;

	statlist_for_each_safe(item, &admin_pool->active_client_list, tmp) {
		admin = container_of(item, PgSocket, head);
		if (!admin->wait_for_response)
			continue;

		switch (cf_pause_mode) {
		case 1:
			admin_ready(admin, "PAUSE");
			break;
		case 2:
			admin_ready(admin, "SUSPEND");
			break;
		default:
			fatal("admin_pause_done: bad state");
		}
		admin->wait_for_response = 0;
	}

	if (statlist_empty(&admin_pool->active_client_list)
			&& cf_pause_mode == 2)
	{
		log_info("Admin disappeared when suspended, doing RESUME");
		cf_pause_mode = 0;
		resume_all();
	}
}

