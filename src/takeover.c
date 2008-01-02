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
 * Connect to running bouncer process, load fds from it, shut it down
 * and continue with them.
 *
 * Each row from SHOW FDS will have corresponding fd in ancillary message.
 *
 * Manpages: unix, sendmsg, recvmsg, cmsg, readv
 */

#include "bouncer.h"

/*
 * Takeover done, old process shut down,
 * kick this one running.
 */
static void takeover_finish(PgSocket *bouncer)
{
	disconnect_server(bouncer, false, "disko over");
	cf_reboot = 0;
	resume_all();
	log_info("disko over, resuming work");
}

/* parse msg for fd and info */
static void takeover_load_fd(MBuf *pkt, const struct cmsghdr *cmsg)
{
	int fd;
	char *task, *s_addr, *user, *db;
	char *client_enc, *std_string, *datestyle, *timezone;
	int oldfd, port, linkfd;
	int got;
	uint64_t ckey;
	PgAddr addr;
	bool res = false;

	memset(&addr, 0, sizeof(addr));

	if (cmsg->cmsg_level == SOL_SOCKET
		&& cmsg->cmsg_type == SCM_RIGHTS
		&& cmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
	{
		/* get the fd */
		memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
		log_debug("got fd: %d", fd);
	} else
		fatal("broken fd packet");

	/* parse row contents */
	got = scan_text_result(pkt, "issssiqissss", &oldfd, &task, &user, &db,
			       &s_addr, &port, &ckey, &linkfd,
			       &client_enc, &std_string, &datestyle, &timezone);
	if (task == NULL || s_addr == NULL)
		fatal("NULL data from old process");

	log_debug("FD row: fd=%d(%d) linkfd=%d task=%s user=%s db=%s enc=%s",
		  oldfd, fd, linkfd, task,
		  user ? user : "NULL", db ? db : "NULL",
		  client_enc ? client_enc : "NULL");

	/* fill address */
	addr.is_unix = strcmp(s_addr, "unix") == 0 ? true : false;
	if (addr.is_unix) {
		addr.port = cf_listen_port;
	} else {
		addr.ip_addr.s_addr = inet_addr(s_addr);
		addr.port = port;
	}

	/* decide what to do with it */
	if (strcmp(task, "client") == 0)
		res = use_client_socket(fd, &addr, db, user, ckey, oldfd, linkfd,
				  client_enc, std_string, datestyle, timezone);
	else if (strcmp(task, "server") == 0)
		res = use_server_socket(fd, &addr, db, user, ckey, oldfd, linkfd,
				  client_enc, std_string, datestyle, timezone);
	else if (strcmp(task, "pooler") == 0)
		res = use_pooler_socket(fd, addr.is_unix);
	else
		fatal("unknown task: %s", task);

	if (!res)
		fatal("socket takeover failed - no mem?");
}

static void takeover_create_link(PgPool *pool, PgSocket *client)
{
	List *item;
	PgSocket *server;

	statlist_for_each(item, &pool->active_server_list) {
		server = container_of(item, PgSocket, head);
		if (server->tmp_sk_oldfd == client->tmp_sk_linkfd) {
			server->link = client;
			client->link = server;
			return;
		}
	}
	fatal("takeover_create_link: failed to find pair");
}

/* clean the inappropriate places the old fds got stored in */
static void takeover_clean_socket_list(StatList *list)
{
	List *item;
	PgSocket *sk;
	statlist_for_each(item, list) {
		sk = container_of(item, PgSocket, head);
		if (sk->suspended) {
			sk->tmp_sk_oldfd = get_cached_time();
			sk->tmp_sk_linkfd = get_cached_time();
		}
	}
}

/* all fds loaded, create links */
static void takeover_postprocess_fds(void)
{
	List *item, *item2;
	PgSocket *client;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->admin)
			continue;
		statlist_for_each(item2, &pool->active_client_list) {
			client = container_of(item2, PgSocket, head);
			if (client->suspended && client->tmp_sk_linkfd)
				takeover_create_link(pool, client);
		}
	}
	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		takeover_clean_socket_list(&pool->active_client_list);
		takeover_clean_socket_list(&pool->active_server_list);
		takeover_clean_socket_list(&pool->idle_server_list);
	}
}

static void next_command(PgSocket *bouncer, MBuf *pkt)
{
	bool res = true;
	const char *cmd = mbuf_get_string(pkt);

	log_debug("takeover_recv_fds: 'C' body: %s", cmd);
	if (strcmp(cmd, "SUSPEND") == 0) {
		log_info("SUSPEND finished, sending SHOW FDS");
		SEND_generic(res, bouncer, 'Q', "s", "SHOW FDS;");
	} else if (strncmp(cmd, "SHOW", 4) == 0) {

		log_info("SHOW FDS finished, sending SHUTDOWN");

		/* all fds loaded, review them */
		takeover_postprocess_fds();

		/* all OK, kill old one */
		SEND_generic(res, bouncer, 'Q', "s", "SHUTDOWN;");
	} else
		fatal("got bad CMD from old bouncer: %s", cmd);

	if (!res)
		fatal("command send failed");
}

static void takeover_parse_data(PgSocket *bouncer,
				struct msghdr *msg, MBuf *data)
{
	struct cmsghdr *cmsg;
	PktHdr pkt;
	
	cmsg = msg->msg_controllen ? CMSG_FIRSTHDR(msg) : NULL;

	while (mbuf_avail(data) > 0) {
		if (!get_header(data, &pkt))
			fatal("cannot parse packet");

		/*
		 * There should not be partial reads from UNIX socket.
		 */
		if (incomplete_pkt(&pkt))
			fatal("unexpected partial packet");

		switch (pkt.type) {
		case 'T': /* RowDescription */
			log_debug("takeover_parse_data: 'T'");
			break;
		case 'D': /* DataRow */
			log_debug("takeover_parse_data: 'D'");
			if (cmsg) {
				takeover_load_fd(&pkt.data, cmsg);
				cmsg = CMSG_NXTHDR(msg, cmsg);
			} else
				fatal("got row without fd info");
			break;
		case 'Z': /* ReadyForQuery */
			log_debug("takeover_parse_data: 'Z'");
			break;
		case 'C': /* CommandComplete */
			log_debug("takeover_parse_data: 'C'");
			next_command(bouncer, &pkt.data);
			break;
		case 'E': /* ErrorMessage */
			log_server_error("old bouncer sent", &pkt);
			fatal("something failed");
		default:
			fatal("takeover_parse_data: unexpected pkt: '%c'", pkt_desc(&pkt));
		}
	}
}

/*
 * listen for data from old bouncer.
 *
 * use always sendmsg, to keep code simpler
 */
static void takeover_recv_cb(int sock, short flags, void *arg)
{
	PgSocket *bouncer = arg;
	uint8_t data_buf[2048];
	uint8_t cnt_buf[128];
	struct msghdr msg;
	struct iovec io;
	int res;
	MBuf data;

	memset(&msg, 0, sizeof(msg));
	io.iov_base = data_buf;
	io.iov_len = sizeof(data_buf);
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = cnt_buf;
	msg.msg_controllen = sizeof(cnt_buf);

	res = safe_recvmsg(sock, &msg, 0);
	if (res > 0) {
		mbuf_init(&data, data_buf, res);
		takeover_parse_data(bouncer, &msg, &data);
	} else if (res == 0) {
		takeover_finish(bouncer);
	} else {
		if (errno == EAGAIN)
			return;
		fatal_perror("safe_recvmsg");
	}
}

/*
 * login finished, send first command,
 * replace recv callback with custom recvmsg() based one.
 */
bool takeover_login(PgSocket *bouncer)
{
	bool res;

	slog_info(bouncer, "Login OK, sending SUSPEND");
	SEND_generic(res, bouncer, 'Q', "s", "SUSPEND;");
	if (res) {
		/* use own callback */
		sbuf_pause(&bouncer->sbuf);
		sbuf_continue_with_callback(&bouncer->sbuf, takeover_recv_cb);
	} else {
		disconnect_server(bouncer, false, "failed to send command");
	}
	return res;
}

/* launch connection to running process */
void takeover_init(void)
{
	PgDatabase *db = find_database("pgbouncer");
	PgPool *pool = get_pool(db, db->forced_user);

	if (!pool)
		fatal("no admin pool?");

	log_info("takeover_init: launching connection");
	launch_new_connection(pool);
}

