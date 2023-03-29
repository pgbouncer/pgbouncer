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
 * Connect to running bouncer process, load fds from it, shut it down
 * and continue with them.
 *
 * Each row from SHOW FDS will have corresponding fd in ancillary message.
 *
 * Manpages: unix, sendmsg, recvmsg, cmsg, readv
 */

#include "bouncer.h"

#include <usual/safeio.h>

/*
 * Takeover done, old process shut down,
 * kick this one running.
 */

static PgSocket *old_bouncer = NULL;

void takeover_finish(void)
{
	uint8_t buf[512];
	int fd = sbuf_socket(&old_bouncer->sbuf);
	bool res;
	ssize_t got;

	log_info("sending SHUTDOWN;");
	socket_set_nonblocking(fd, 0);
	SEND_generic(res, old_bouncer, 'Q', "s", "SHUTDOWN;");
	if (!res)
		die("failed to send SHUTDOWN;");

	while (1) {
		got = safe_recv(fd, buf, sizeof(buf), 0);
		if (got == 0)
			break;
		if (got < 0)
			die("sky is falling - error while waiting result from SHUTDOWN: %s", strerror(errno));
	}

	disconnect_server(old_bouncer, false, "disko over");
	old_bouncer = NULL;

	if (cf_pidfile && cf_pidfile[0]) {
		log_info("waiting for old pidfile to go away");
		while (1) {
			struct stat st;
			if (stat(cf_pidfile, &st) < 0) {
				if (errno == ENOENT)
					break;
			}
			usleep(USEC/10);
		}
	}

	log_info("old process killed, resuming work");
	resume_all();
}

static void takeover_finish_part1(PgSocket *bouncer)
{
	Assert(old_bouncer == NULL);

	/* unregister bouncer from libevent */
	if (!sbuf_pause(&bouncer->sbuf))
		fatal_perror("sbuf_pause failed");
	old_bouncer = bouncer;
	cf_reboot = 0;
	log_info("disko over, going background");
}

/* parse msg for fd and info */
static void takeover_load_fd(struct MBuf *pkt, const struct cmsghdr *cmsg)
{
	int fd;
	char *task, *saddr, *user, *db;
	char *client_enc, *std_string, *datestyle, *intervalstyle, *timezone,
		*password, *scram_client_key, *scram_server_key;
	int scram_client_key_len, scram_server_key_len;
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
	} else {
		fatal("broken fd packet");
	}

	/* parse row contents */
	got = scan_text_result(pkt, "issssiqissssssbb", &oldfd, &task, &user, &db,
			       &saddr, &port, &ckey, &linkfd,
			       &client_enc, &std_string, &datestyle,
			       &intervalstyle, &timezone,
			       &password,
			       &scram_client_key_len,
			       &scram_client_key,
			       &scram_server_key_len,
			       &scram_server_key);
	if (got < 0)
		die("invalid data from old process");
	if (task == NULL || saddr == NULL)
		die("incomplete data from old process");

	log_debug("FD row: fd=%d(%d) linkfd=%d task=%s user=%s db=%s enc=%s",
		  oldfd, fd, linkfd, task,
		  user ? user : "NULL", db ? db : "NULL",
		  client_enc ? client_enc : "NULL");

	if (!password)
		password = "";

	/* fill address */
	if (strcmp(saddr, "unix") == 0) {
		pga_set(&addr, AF_UNIX, cf_listen_port);
	} else {
		if (!pga_pton(&addr, saddr, port))
			fatal("failed to convert address: %s", saddr);
	}

	/* decide what to do with it */
	if (strcmp(task, "client") == 0) {
		res = use_client_socket(fd, &addr, db, user, ckey, oldfd, linkfd,
				  client_enc, std_string, datestyle,
				  intervalstyle, timezone, password,
				  scram_client_key, scram_client_key_len,
				  scram_server_key, scram_server_key_len);
	} else if (strcmp(task, "server") == 0) {
		res = use_server_socket(fd, &addr, db, user, ckey, oldfd, linkfd,
				  client_enc, std_string, datestyle, intervalstyle, timezone,
				  password,
				  scram_client_key, scram_client_key_len,
				  scram_server_key, scram_server_key_len);
	} else if (strcmp(task, "pooler") == 0) {
		res = use_pooler_socket(fd, pga_is_unix(&addr));
	} else {
		fatal("unknown task: %s", task);
	}

	free(scram_client_key);
	free(scram_server_key);

	if (!res)
		fatal("socket takeover failed");
}

static void takeover_create_link(PgPool *pool, PgSocket *client)
{
	struct List *item;
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
static void takeover_clean_socket_list(struct StatList *list)
{
	struct List *item;
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
	struct List *item, *item2;
	PgSocket *client;
	PgPool *pool;

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		if (pool->db->admin)
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

static void next_command(PgSocket *bouncer, struct MBuf *pkt)
{
	bool res = true;
	const char *cmd;

	if (!mbuf_get_string(pkt, &cmd))
		fatal("bad result pkt");

	log_debug("takeover_recv_fds: 'C' body: %s", cmd);
	if (strcmp(cmd, "SUSPEND") == 0) {
		log_info("SUSPEND finished, sending SHOW FDS");
		SEND_generic(res, bouncer, 'Q', "s", "SHOW FDS;");
	} else if (strncmp(cmd, "SHOW", 4) == 0) {
		/* all fds loaded, review them */
		takeover_postprocess_fds();
		log_info("SHOW FDS finished");

		takeover_finish_part1(bouncer);
	} else {
		fatal("got bad CMD from old bouncer: %s", cmd);
	}

	if (!res)
		fatal("command send failed");
}

static void takeover_parse_data(PgSocket *bouncer,
				struct msghdr *msg, struct MBuf *data)
{
	struct cmsghdr *cmsg;
	PktHdr pkt;

	cmsg = msg->msg_controllen ? CMSG_FIRSTHDR(msg) : NULL;

	while (mbuf_avail_for_read(data) > 0) {
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
 * use always recvmsg, to keep code simpler
 */
static void takeover_recv_cb(evutil_socket_t sock, short flags, void *arg)
{
	PgSocket *bouncer = container_of(arg, PgSocket, sbuf);
	uint8_t data_buf[STARTUP_BUF * 2];
	uint8_t cnt_buf[128];
	struct msghdr msg;
	struct iovec io;
	ssize_t res;
	struct MBuf data;

	memset(&msg, 0, sizeof(msg));
	io.iov_base = data_buf;
	io.iov_len = sizeof(data_buf);
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = cnt_buf;
	msg.msg_controllen = sizeof(cnt_buf);

	res = safe_recvmsg(sock, &msg, 0);
	if (res > 0) {
		mbuf_init_fixed_reader(&data, data_buf, res);
		takeover_parse_data(bouncer, &msg, &data);
	} else if (res == 0) {
		fatal("unexpected EOF");
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

	slog_info(bouncer, "login OK, sending SUSPEND");
	SEND_generic(res, bouncer, 'Q', "s", "SUSPEND;");
	if (res) {
		/* use own callback */
		if (!sbuf_pause(&bouncer->sbuf))
			fatal("sbuf_pause failed");
		res = sbuf_continue_with_callback(&bouncer->sbuf, takeover_recv_cb);
		if (!res)
			fatal("takeover_login: sbuf_continue_with_callback failed");
	} else {
		fatal("takeover_login: failed to send command");
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
	launch_new_connection(pool, /* evict_if_needed= */ true);
}

void takeover_login_failed(void)
{
	fatal("login failed");
}
