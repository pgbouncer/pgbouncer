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
 * Stream buffer
 *
 * The task is to copy data from one socket to another
 * efficiently, while allowing callbacks to look
 * at packet headers.
 */

#include "bouncer.h"

#include <usual/safeio.h>
#include <usual/slab.h>

//#include <postgresql/libpq-fe.h>

#ifdef USUAL_LIBSSL_FOR_TLS
#define USE_TLS
#endif

/* sbuf_main_loop() skip_recv values */
#define DO_RECV		false
#define SKIP_RECV	true

#define ACT_UNSET 0
#define ACT_SEND 1
#define ACT_SKIP 2
#define ACT_CALL 3

enum TLSState {
	SBUF_TLS_NONE,
	SBUF_TLS_DO_HANDSHAKE,
	SBUF_TLS_IN_HANDSHAKE,
	SBUF_TLS_OK,
};

#ifdef HAVE_SERVER_GSSENC
enum GSSEncState {
        SBUF_GSSENC_NONE,
        SBUF_GSSENC_DO_HANDSHAKE,
        SBUF_GSSENC_IN_HANDSHAKE,
        SBUF_GSSENC_OK,
};
#endif

enum WaitType {
	W_NONE = 0,
	W_CONNECT,
	W_RECV,
	W_SEND,
	W_ONCE
};

#define AssertSanity(sbuf) do { \
	Assert(iobuf_sane((sbuf)->io)); \
} while (0)

#define AssertActive(sbuf) do { \
	Assert((sbuf)->sock > 0); \
	AssertSanity(sbuf); \
} while (0)

/* declare static stuff */
static bool sbuf_queue_send(SBuf *sbuf) _MUSTCHECK;
static bool sbuf_send_pending(SBuf *sbuf) _MUSTCHECK;
static bool sbuf_process_pending(SBuf *sbuf) _MUSTCHECK;
static void sbuf_connect_cb(evutil_socket_t sock, short flags, void *arg);
static void sbuf_recv_cb(evutil_socket_t sock, short flags, void *arg);
static void sbuf_send_cb(evutil_socket_t sock, short flags, void *arg);
static void sbuf_try_resync(SBuf *sbuf, bool release);
static bool sbuf_wait_for_data(SBuf *sbuf) _MUSTCHECK;
static void sbuf_main_loop(SBuf *sbuf, bool skip_recv);
static bool sbuf_call_proto(SBuf *sbuf, int event) /* _MUSTCHECK */;
static bool sbuf_actual_recv(SBuf *sbuf, size_t len)  _MUSTCHECK;
static bool sbuf_after_connect_check(SBuf *sbuf)  _MUSTCHECK;
static bool handle_tls_handshake(SBuf *sbuf) /* _MUSTCHECK */;
#ifdef HAVE_SERVER_GSSENC
static bool handle_gssenc_handshake(SBuf *sbuf) /* _MUSTCHECK */;
#endif

/* regular I/O */
static ssize_t raw_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len);
static ssize_t raw_sbufio_send(struct SBuf *sbuf, const void *data, size_t len);
static int raw_sbufio_close(struct SBuf *sbuf);
static const SBufIO raw_sbufio_ops = {
	raw_sbufio_recv,
	raw_sbufio_send,
	raw_sbufio_close
};

/* I/O over TLS */
#ifdef USE_TLS
static ssize_t tls_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len);
static ssize_t tls_sbufio_send(struct SBuf *sbuf, const void *data, size_t len);
static int tls_sbufio_close(struct SBuf *sbuf);
static const SBufIO tls_sbufio_ops = {
	tls_sbufio_recv,
	tls_sbufio_send,
	tls_sbufio_close
};
static void sbuf_tls_handshake_cb(evutil_socket_t fd, short flags, void *_sbuf);
#endif

/* I/O over GSS Enc */
#ifdef HAVE_SERVER_GSSENC
#define Min(x, y)		((x) < (y) ? (x) : (y))
static ssize_t pg_GSS_write(SBuf *conn, const void *ptr, size_t len);
static ssize_t pqsecure_raw_write(SBuf *conn, const void *ptr, size_t len);
static ssize_t pg_GSS_read(SBuf *conn, void *ptr, size_t len);
/*static ssize_t gss_read(SBuf *conn, void *recv_buffer, size_t length, ssize_t *ret);*/
static ssize_t pqsecure_raw_read(SBuf *conn, void *ptr, size_t len);
static ssize_t gssenc_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len);
static ssize_t gssenc_sbufio_send(struct SBuf *sbuf, const void *data, size_t len);
static int gssenc_sbufio_close(struct SBuf *sbuf);
static const SBufIO gssenc_sbufio_ops = {
	gssenc_sbufio_recv,
	gssenc_sbufio_send,
	gssenc_sbufio_close
};
static int recv_token(int s, int *flags, gss_buffer_t tok);
static int send_token(int s, int flags, gss_buffer_t tok);
//static void sbuf_gssenc_handshake_cb(evutil_socket_t fd, short flags, void *_sbuf);
#endif

/*********************************
 * Public functions
 *********************************/

/* initialize SBuf with proto handler */
void sbuf_init(SBuf *sbuf, sbuf_cb_t proto_fn)
{
	memset(sbuf, 0, sizeof(SBuf));
	sbuf->proto_cb = proto_fn;
	sbuf->ops = &raw_sbufio_ops;
}

/* got new socket from accept() */
bool sbuf_accept(SBuf *sbuf, int sock, bool is_unix)
{
	bool res;

	Assert(iobuf_empty(sbuf->io) && sbuf->sock == 0);
	AssertSanity(sbuf);

	sbuf->sock = sock;
	if (!tune_socket(sock, is_unix))
		goto failed;

	if (!cf_reboot) {
		res = sbuf_wait_for_data(sbuf);
		if (!res)
			goto failed;
		/* socket should already have some data (linux only) */
		if (cf_tcp_defer_accept && !is_unix) {
			sbuf_main_loop(sbuf, DO_RECV);
			if (!sbuf->sock)
				return false;
		}
	}
	return true;
failed:
	sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
	return false;
}

/* need to connect() to get a socket */
bool sbuf_connect(SBuf *sbuf, const struct sockaddr *sa, socklen_t sa_len, time_t timeout_sec)
{
	int res, sock;
	struct timeval timeout;
	bool is_unix = sa->sa_family == AF_UNIX;

	Assert(iobuf_empty(sbuf->io) && sbuf->sock == 0);
	AssertSanity(sbuf);

	/*
	 * common stuff
	 */
	sock = socket(sa->sa_family, SOCK_STREAM, 0);
	if (sock < 0) {
		/* probably fd limit */
		goto failed;
	}

	if (!tune_socket(sock, is_unix))
		goto failed;

	sbuf->sock = sock;

	timeout.tv_sec = timeout_sec;
	timeout.tv_usec = 0;

	/* launch connection */
	res = safe_connect(sock, sa, sa_len);
	if (res == 0) {
		/* unix socket gives connection immediately */
		sbuf_connect_cb(sock, EV_WRITE, sbuf);
		return true;
	} else if (errno == EINPROGRESS || errno == EAGAIN) {
		/* tcp socket needs waiting */
		event_assign(&sbuf->ev, pgb_event_base, sock, EV_WRITE, sbuf_connect_cb, sbuf);
		res = event_add(&sbuf->ev, &timeout);
		if (res >= 0) {
			sbuf->wait_type = W_CONNECT;
			return true;
		}
	}

failed:
	log_warning("sbuf_connect failed: %s", strerror(errno));

	if (sock >= 0)
		safe_close(sock);
	sbuf->sock = 0;
	sbuf_call_proto(sbuf, SBUF_EV_CONNECT_FAILED);
	return false;
}

/* don't wait for data on this socket */
bool sbuf_pause(SBuf *sbuf)
{
	AssertActive(sbuf);
	Assert(sbuf->wait_type == W_RECV);

	if (event_del(&sbuf->ev) < 0) {
		log_warning("event_del: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_NONE;
	return true;
}

/* resume from pause, start waiting for data */
void sbuf_continue(SBuf *sbuf)
{
	bool do_recv = DO_RECV;
	bool res;
	AssertActive(sbuf);

	res = sbuf_wait_for_data(sbuf);
	if (!res) {
		/* drop if problems */
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
		return;
	}

	/*
	 * It's tempting to try to avoid the recv() but that would
	 * only work if no code wants to see full packet.
	 *
	 * This is not true in ServerParameter case.
	 */
	/*
	 * if (sbuf->recv_pos - sbuf->pkt_pos >= SBUF_SMALL_PKT)
	 *	do_recv = false;
	 */

	sbuf_main_loop(sbuf, do_recv);
}

/*
 * Resume from pause and give socket over to external
 * callback function.
 *
 * The callback will be called with arg given to sbuf_init.
 */
bool sbuf_continue_with_callback(SBuf *sbuf, event_callback_fn user_cb)
{
	int err;

	AssertActive(sbuf);

	event_assign(&sbuf->ev, pgb_event_base, sbuf->sock, EV_READ | EV_PERSIST,
		  user_cb, sbuf);

	err = event_add(&sbuf->ev, NULL);
	if (err < 0) {
		log_warning("sbuf_continue_with_callback: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_RECV;
	return true;
}

bool sbuf_use_callback_once(SBuf *sbuf, short ev, event_callback_fn user_cb)
{
	int err;
	AssertActive(sbuf);

	if (sbuf->wait_type != W_NONE) {
		err = event_del(&sbuf->ev);
		sbuf->wait_type = W_NONE; /* make sure its called only once */
		if (err < 0) {
			log_warning("sbuf_queue_once: event_del failed: %s", strerror(errno));
			return false;
		}
	}

	/* setup one one-off event handler */
	event_assign(&sbuf->ev, pgb_event_base, sbuf->sock, ev, user_cb, sbuf);
	err = event_add(&sbuf->ev, NULL);
	if (err < 0) {
		log_warning("sbuf_queue_once: event_add failed: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_ONCE;
	return true;
}

/* socket cleanup & close: keeps .handler and .arg values */
bool sbuf_close(SBuf *sbuf)
{
	if (sbuf->wait_type) {
		Assert(sbuf->sock);
		/* event_del() acts funny occasionally, debug it */
		errno = 0;
		if (event_del(&sbuf->ev) < 0) {
			if (errno) {
				log_warning("event_del: %s", strerror(errno));
			} else {
				log_warning("event_del: libevent error");
			}
			/* we can retry whole sbuf_close() if needed */
			/* if (errno == ENOMEM) return false; */
		}
	}
	sbuf_op_close(sbuf);
	sbuf->dst = NULL;
	sbuf->sock = 0;
	sbuf->pkt_remain = 0;
	sbuf->pkt_action = sbuf->wait_type = 0;
	if (sbuf->io) {
		slab_free(iobuf_cache, sbuf->io);
		sbuf->io = NULL;
	}
	return true;
}

/* proto_fn tells to send some bytes to socket */
void sbuf_prepare_send(SBuf *sbuf, SBuf *dst, unsigned amount)
{
	AssertActive(sbuf);
	Assert(sbuf->pkt_remain == 0);
	/* Assert(sbuf->pkt_action == ACT_UNSET || sbuf->pkt_action == ACT_SEND || iobuf_amount_pending(&sbuf->io)); */
	Assert(amount > 0);

	sbuf->pkt_action = ACT_SEND;
	sbuf->pkt_remain = amount;
	sbuf->dst = dst;
}

/* proto_fn tells to skip some amount of bytes */
void sbuf_prepare_skip(SBuf *sbuf, unsigned amount)
{
	AssertActive(sbuf);
	Assert(sbuf->pkt_remain == 0);
	/* Assert(sbuf->pkt_action == ACT_UNSET || iobuf_send_pending_avail(&sbuf->io)); */
	Assert(amount > 0);

	sbuf->pkt_action = ACT_SKIP;
	sbuf->pkt_remain = amount;
}

/* proto_fn tells to skip some amount of bytes */
void sbuf_prepare_fetch(SBuf *sbuf, unsigned amount)
{
	AssertActive(sbuf);
	Assert(sbuf->pkt_remain == 0);
	/* Assert(sbuf->pkt_action == ACT_UNSET || iobuf_send_pending_avail(&sbuf->io)); */
	Assert(amount > 0);

	sbuf->pkt_action = ACT_CALL;
	sbuf->pkt_remain = amount;
	/* sbuf->dst = NULL; // FIXME ?? */
}

/*************************
 * Internal functions
 *************************/

/*
 * Call proto callback with proper struct MBuf.
 *
 * If callback returns true it used one of sbuf_prepare_* on sbuf,
 * and processing can continue.
 *
 * If it returned false it used sbuf_pause(), sbuf_close() or simply
 * wants to wait for next event loop (e.g. too few data available).
 * Callee should not touch sbuf in that case and just return to libevent.
 */
static bool sbuf_call_proto(SBuf *sbuf, int event)
{
	struct MBuf mbuf;
	IOBuf *io = sbuf->io;
	bool res;

	AssertSanity(sbuf);
	Assert(event != SBUF_EV_READ || iobuf_amount_parse(io) > 0);

	/* if pkt callback, limit only with current packet */
	if (event == SBUF_EV_PKT_CALLBACK) {
		iobuf_parse_limit(io, &mbuf, sbuf->pkt_remain);
	} else if (event == SBUF_EV_READ) {
		iobuf_parse_all(io, &mbuf);
	} else {
		memset(&mbuf, 0, sizeof(mbuf));
	}
	res = sbuf->proto_cb(sbuf, event, &mbuf);

	AssertSanity(sbuf);
	Assert(event != SBUF_EV_READ || !res || sbuf->sock > 0);

	return res;
}

/* let's wait for new data */
static bool sbuf_wait_for_data(SBuf *sbuf)
{
	int err;

	event_assign(&sbuf->ev, pgb_event_base, sbuf->sock, EV_READ | EV_PERSIST, sbuf_recv_cb, sbuf);
	err = event_add(&sbuf->ev, NULL);
	if (err < 0) {
		log_warning("sbuf_wait_for_data: event_add failed: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_RECV;
	return true;
}

static void sbuf_recv_forced_cb(evutil_socket_t sock, short flags, void *arg)
{
	SBuf *sbuf = arg;

	sbuf->wait_type = W_NONE;

	if (sbuf_wait_for_data(sbuf)) {
		sbuf_recv_cb(sock, flags, arg);
	} else {
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
	}
}

static bool sbuf_wait_for_data_forced(SBuf *sbuf)
{
	int err;
	struct timeval tv_min;

	tv_min.tv_sec = 0;
	tv_min.tv_usec = 1;

	if (sbuf->wait_type != W_NONE) {
		event_del(&sbuf->ev);
		sbuf->wait_type = W_NONE;
	}

	event_assign(&sbuf->ev, pgb_event_base, sbuf->sock, EV_READ, sbuf_recv_forced_cb, sbuf);
	err = event_add(&sbuf->ev, &tv_min);
	if (err < 0) {
		log_warning("sbuf_wait_for_data: event_add failed: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_ONCE;
	return true;
}

/* libevent EV_WRITE: called when dest socket is writable again */
static void sbuf_send_cb(evutil_socket_t sock, short flags, void *arg)
{
	SBuf *sbuf = arg;
	bool res;

	/* sbuf was closed before in this loop */
	if (!sbuf->sock)
		return;

	AssertSanity(sbuf);
	Assert(sbuf->wait_type == W_SEND);

	sbuf->wait_type = W_NONE;

	/* prepare normal situation for sbuf_main_loop */
	res = sbuf_wait_for_data(sbuf);
	if (res) {
		/* here we should certainly skip recv() */
		sbuf_main_loop(sbuf, SKIP_RECV);
	} else {
		/* drop if problems */
		sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
	}
}

/* socket is full, wait until it's writable again */
static bool sbuf_queue_send(SBuf *sbuf)
{
	int err;
	AssertActive(sbuf);
	Assert(sbuf->wait_type == W_RECV);

	/* if false is returned, the socket will be closed later */

	/* stop waiting for read events */
	err = event_del(&sbuf->ev);
	sbuf->wait_type = W_NONE; /* make sure its called only once */
	if (err < 0) {
		log_warning("sbuf_queue_send: event_del failed: %s", strerror(errno));
		return false;
	}

	/* instead wait for EV_WRITE on destination socket */
	event_assign(&sbuf->ev, pgb_event_base, sbuf->dst->sock, EV_WRITE, sbuf_send_cb, sbuf);
	err = event_add(&sbuf->ev, NULL);
	if (err < 0) {
		log_warning("sbuf_queue_send: event_add failed: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_SEND;

	return true;
}

/*
 * There's data in buffer to be sent. Returns bool if processing can continue.
 *
 * Does not look at pkt_pos/remain fields, expects them to be merged to send_*
 */
static bool sbuf_send_pending(SBuf *sbuf)
{
	int avail;
	ssize_t res;
	IOBuf *io = sbuf->io;

	AssertActive(sbuf);
	Assert(sbuf->dst || iobuf_amount_pending(io) == 0);

try_more:
	/* how much data is available for sending */
	avail = iobuf_amount_pending(io);
	if (avail == 0)
		return true;

	if (sbuf->dst->sock == 0) {
		log_error("sbuf_send_pending: no dst sock?");
		return false;
	}

	/* actually send it */
	//res = iobuf_send_pending(io, sbuf->dst->sock);
	res = sbuf_op_send(sbuf->dst, io->buf + io->done_pos, avail);
	if (res > 0) {
		io->done_pos += res;
	} else if (res < 0) {
		if (errno == EAGAIN) {
			if (!sbuf_queue_send(sbuf))
				/* drop if queue failed */
				sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
		} else {
			sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
		}
		return false;
	}

	AssertActive(sbuf);

	/*
	 * Should do sbuf_queue_send() immediately?
	 *
	 * To be sure, let's run into EAGAIN.
	 */
	goto try_more;
}

/* process as much data as possible */
static bool sbuf_process_pending(SBuf *sbuf)
{
	unsigned avail;
	IOBuf *io = sbuf->io;
	bool full = iobuf_amount_recv(io) <= 0;
	bool res;

	while (1) {
		AssertActive(sbuf);

		/*
		 * Enough for now?
		 *
		 * The (avail <= SBUF_SMALL_PKT) check is to avoid partial pkts.
		 * As SBuf should not assume knowledge about packets,
		 * the check is not done in !full case.  Packet handler can
		 * then still notify about partial packet by returning false.
		 */
		avail = iobuf_amount_parse(io);
		if (avail == 0 || (full && avail <= SBUF_SMALL_PKT))
			break;

		/*
		 * If start of packet, process packet header.
		 */
		if (sbuf->pkt_remain == 0) {
			res = sbuf_call_proto(sbuf, SBUF_EV_READ);
			if (!res)
				return false;
			Assert(sbuf->pkt_remain > 0);
		}

		if (sbuf->pkt_action == ACT_SKIP || sbuf->pkt_action == ACT_CALL) {
			/* send any pending data before skipping */
			if (iobuf_amount_pending(io) > 0) {
				res = sbuf_send_pending(sbuf);
				if (!res)
					return res;
			}
		}

		if (avail > sbuf->pkt_remain)
			avail = sbuf->pkt_remain;

		switch (sbuf->pkt_action) {
		case ACT_SEND:
			iobuf_tag_send(io, avail);
			break;
		case ACT_CALL:
			res = sbuf_call_proto(sbuf, SBUF_EV_PKT_CALLBACK);
			if (!res)
				return false;
			/* fallthrough */
			/* after callback, skip pkt */
		case ACT_SKIP:
			iobuf_tag_skip(io, avail);
			break;
		}
		sbuf->pkt_remain -= avail;
	}

	return sbuf_send_pending(sbuf);
}

/* reposition at buffer start again */
static void sbuf_try_resync(SBuf *sbuf, bool release)
{
	IOBuf *io = sbuf->io;

	if (io) {
		log_noise("resync(%d): done=%u, parse=%u, recv=%u",
			  sbuf->sock,
			  io->done_pos, io->parse_pos, io->recv_pos);
	}
	AssertActive(sbuf);

	if (!io)
		return;

	if (release && iobuf_empty(io)) {
		slab_free(iobuf_cache, io);
		sbuf->io = NULL;
	} else {
		iobuf_try_resync(io, SBUF_SMALL_PKT);
	}
}

/* actually ask kernel for more data */
static bool sbuf_actual_recv(SBuf *sbuf, size_t len)
{
	ssize_t got;
	IOBuf *io = sbuf->io;
	uint8_t *dst = io->buf + io->recv_pos;
	unsigned avail = iobuf_amount_recv(io);
	if (len > avail)
		len = avail;
	got = sbuf_op_recv(sbuf, dst, len);
	if (got > 0) {
		io->recv_pos += got;
	} else if (got == 0) {
		/* eof from socket */
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
		return false;
	} else if (got < 0 && errno != EAGAIN) {
		/* some error occurred */
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
		return false;
	}
	return true;
}

/* callback for libevent EV_READ */
static void sbuf_recv_cb(evutil_socket_t sock, short flags, void *arg)
{
	SBuf *sbuf = arg;
	sbuf_main_loop(sbuf, DO_RECV);
}

static bool allocate_iobuf(SBuf *sbuf)
{
	if (sbuf->io == NULL) {
		sbuf->io = slab_alloc(iobuf_cache);
		if (sbuf->io == NULL) {
			sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
			return false;
		}
		iobuf_reset(sbuf->io);
	}
	return true;
}

/*
 * Main recv-parse-send-repeat loop.
 *
 * Reason for skip_recv is to avoid extra recv().  The problem with it
 * is EOF from socket.  Currently that means that the pending data is
 * dropped.  Fortunately server sockets are not paused and dropping
 * data from client is no problem.  So only place where skip_recv is
 * important is sbuf_send_cb().
 */
static void sbuf_main_loop(SBuf *sbuf, bool skip_recv)
{
	unsigned free, ok;
	int loopcnt = 0;

	/* sbuf was closed before in this event loop */
	if (!sbuf->sock)
		return;

	/* reading should be disabled when waiting */
	Assert(sbuf->wait_type == W_RECV);
	AssertSanity(sbuf);

	if (!allocate_iobuf(sbuf))
		return;

	/* avoid recv() if asked */
	if (skip_recv)
		goto skip_recv;

try_more:
	/* make room in buffer */
	sbuf_try_resync(sbuf, false);

	/* avoid spending too much time on single socket */
	if (cf_sbuf_loopcnt > 0 && loopcnt >= cf_sbuf_loopcnt) {
		bool _ignore;

		log_debug("loopcnt full");
		/*
		 * sbuf_process_pending() avoids some data if buffer is full,
		 * but as we exit processing loop here, we need to retry
		 * after resync to process all data. (result is ignored)
		 */
		_ignore = sbuf_process_pending(sbuf);
		(void) _ignore;

		sbuf_wait_for_data_forced(sbuf);
		return;
	}
	loopcnt++;

	/*
	 * here used to be if (free > SBUF_SMALL_PKT) check
	 * but with skip_recv switch its should not be needed anymore.
	 */
	free = iobuf_amount_recv(sbuf->io);
	if (free > 0) {
		/*
		 * When suspending, try to hit packet boundary ASAP.
		 */
		if (cf_pause_mode == P_SUSPEND
		    && sbuf->pkt_remain > 0
		    && sbuf->pkt_remain < free)
		{
			free = sbuf->pkt_remain;
		}

		/* now fetch the data */
		ok = sbuf_actual_recv(sbuf, free);
		if (!ok)
			return;
	}

skip_recv:
	/* now handle it */
	ok = sbuf_process_pending(sbuf);
	if (!ok)
		return;

	/* if the buffer is full, there can be more data available */
	if (iobuf_amount_recv(sbuf->io) <= 0)
		goto try_more;

	/* clean buffer */
	sbuf_try_resync(sbuf, true);
	/* notify proto that all is sent */
	if (sbuf_is_empty(sbuf))
		sbuf_call_proto(sbuf, SBUF_EV_FLUSH);

	if (sbuf->tls_state == SBUF_TLS_DO_HANDSHAKE) {
		sbuf->pkt_action = SBUF_TLS_IN_HANDSHAKE;
		handle_tls_handshake(sbuf);
	}
#ifdef HAVE_SERVER_GSSENC
	if (sbuf->gssenc_state == SBUF_GSSENC_DO_HANDSHAKE) {
		sbuf->pkt_action = SBUF_GSSENC_IN_HANDSHAKE;
		handle_gssenc_handshake(sbuf);
	}
#endif
}

/* check if there is any error pending on socket */
static bool sbuf_after_connect_check(SBuf *sbuf)
{
	int optval = 0, err;
	socklen_t optlen = sizeof(optval);

	err = getsockopt(sbuf->sock, SOL_SOCKET, SO_ERROR, (void*)&optval, &optlen);
	if (err < 0) {
		log_debug("sbuf_after_connect_check: getsockopt: %s",
			  strerror(errno));
		return false;
	}
	if (optval != 0) {
		log_debug("sbuf_after_connect_check: pending error: %s",
			  strerror(optval));
		return false;
	}
	return true;
}

/* callback for libevent EV_WRITE when connecting */
static void sbuf_connect_cb(evutil_socket_t sock, short flags, void *arg)
{
	SBuf *sbuf = arg;

	Assert(sbuf->wait_type == W_CONNECT || sbuf->wait_type == W_NONE);
	sbuf->wait_type = W_NONE;

	if (flags & EV_WRITE) {
		if (!sbuf_after_connect_check(sbuf))
			goto failed;
		if (!sbuf_call_proto(sbuf, SBUF_EV_CONNECT_OK))
			return;
		if (!sbuf_wait_for_data(sbuf))
			goto failed;
		return;
	}
failed:
	sbuf_call_proto(sbuf, SBUF_EV_CONNECT_FAILED);
}

/* send some data to listening socket */
bool sbuf_answer(SBuf *sbuf, const void *buf, size_t len)
{
	ssize_t res;
	if (sbuf->sock <= 0)
		return false;
	res = sbuf_op_send(sbuf, buf, len);
	if (res < 0) {
		log_debug("sbuf_answer: error sending: %s", strerror(errno));
	} else if ((unsigned)res != len) {
		log_debug("sbuf_answer: partial send: len=%zu sent=%zd", len, res);
	}
	return (unsigned)res == len;
}

/*
 * Standard IO ops.
 */

static ssize_t raw_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len)
{
	return safe_recv(sbuf->sock, dst, len, 0);
}

static ssize_t raw_sbufio_send(struct SBuf *sbuf, const void *data, size_t len)
{
	return safe_send(sbuf->sock, data, len, 0);
}

static int raw_sbufio_close(struct SBuf *sbuf)
{
	if (sbuf->sock > 0) {
		safe_close(sbuf->sock);
		sbuf->sock = 0;
	}
	return 0;
}

/*
 * TLS support.
 */

#ifdef USE_TLS

/*
 * These global variables contain the currently applied TLS configurations.
 * They might differ from the current configuration if there was an error
 * applying the configured parameters (e.g. cert file not found).
 */
static struct tls *client_accept_base;
static struct tls_config *client_accept_conf;
int client_accept_sslmode;
static struct tls_config *server_connect_conf;
int server_connect_sslmode;


/*
 * TLS setup
 */

static bool setup_tls(struct tls_config *conf, const char *pfx, int sslmode,
		      const char *protocols, const char *ciphers,
		      const char *keyfile, const char *certfile, const char *cafile,
		      const char *dheparams, const char *ecdhecurve,
		      bool does_connect)
{
	int err;
	if (*protocols) {
		uint32_t protos = TLS_PROTOCOLS_ALL;
		err = tls_config_parse_protocols(&protos, protocols);
		if (err) {
			log_error("invalid %s_protocols: %s", pfx, protocols);
			return false;
		}
		tls_config_set_protocols(conf, protos);
	}
	if (*ciphers) {
		err = tls_config_set_ciphers(conf, ciphers);
		if (err) {
			log_error("invalid %s_ciphers: %s", pfx, ciphers);
			return false;
		}
	}
	if (*dheparams) {
		err = tls_config_set_dheparams(conf, dheparams);
		if (err) {
			log_error("invalid %s_dheparams: %s", pfx, dheparams);
			return false;
		}
	}
	if (*ecdhecurve) {
		err = tls_config_set_ecdhecurve(conf, ecdhecurve);
		if (err) {
			log_error("invalid %s_ecdhecurve: %s", pfx, ecdhecurve);
			return false;
		}
	}
	if (*cafile) {
		err = tls_config_set_ca_file(conf, cafile);
		if (err) {
			log_error("invalid %s_ca_file: %s", pfx, cafile);
			return false;
		}
	}
	if (*keyfile) {
		err = tls_config_set_key_file(conf, keyfile);
		if (err) {
			log_error("invalid %s_key_file: %s", pfx, keyfile);
			return false;
		}
	}
	if (*certfile) {
		err = tls_config_set_cert_file(conf, certfile);
		if (err) {
			log_error("invalid %s_cert_file: %s", pfx, certfile);
			return false;
		}
	}

	if (does_connect) {
		/* TLS client, check server? */
		if (sslmode == SSLMODE_VERIFY_FULL) {
			tls_config_verify(conf);
		} else if (sslmode == SSLMODE_VERIFY_CA) {
			tls_config_verify(conf);
			tls_config_insecure_noverifyname(conf);
		} else {
			tls_config_insecure_noverifycert(conf);
			tls_config_insecure_noverifyname(conf);
		}
	} else {
		/* TLS server, check client? */
		if (sslmode == SSLMODE_VERIFY_FULL) {
			tls_config_verify_client(conf);
		} else if (sslmode == SSLMODE_VERIFY_CA) {
			tls_config_verify_client(conf);
		} else {
			tls_config_verify_client_optional(conf);
		}
	}

	return true;
}

bool sbuf_tls_setup(void)
{
	int err;
	/*
	 * These variables store the new TLS configurations, based on the latest
	 * settings provided by the user. Once they have been configured completely
	 * without errors they are assigned to the globals at the end of this
	 * function. This way the globals never contain partially configured TLS
	 * configurations.
	 */
	struct tls_config *new_client_accept_conf = NULL;
	struct tls_config *new_server_connect_conf = NULL;
	struct tls *new_client_accept_base = NULL;

	if (cf_client_tls_sslmode != SSLMODE_DISABLED) {
		if (!*cf_client_tls_key_file || !*cf_client_tls_cert_file) {
			log_error("To allow TLS connections from clients, client_tls_key_file and client_tls_cert_file must be set.");
			return false;
		}
	}
	if (cf_auth_type == AUTH_CERT) {
		if (cf_client_tls_sslmode != SSLMODE_VERIFY_FULL) {
			log_error("auth_type=cert requires client_tls_sslmode=SSLMODE_VERIFY_FULL");
			return false;
		}
		if (*cf_client_tls_ca_file == '\0') {
			log_error("auth_type=cert requires client_tls_ca_file");
			return false;
		}
	} else if (cf_client_tls_sslmode > SSLMODE_VERIFY_CA && *cf_client_tls_ca_file == '\0') {
		log_error("client_tls_sslmode requires client_tls_ca_file");
		return false;
	}

	err = tls_init();
	if (err)
		fatal("tls_init failed");

	if (cf_server_tls_sslmode != SSLMODE_DISABLED) {
		new_server_connect_conf = tls_config_new();
		if (!new_server_connect_conf) {
			log_error("tls_config_new failed 1");
			return false;
		}

		if (!setup_tls(new_server_connect_conf, "server_tls", cf_server_tls_sslmode,
			       cf_server_tls_protocols, cf_server_tls_ciphers,
			       cf_server_tls_key_file, cf_server_tls_cert_file,
			       cf_server_tls_ca_file, "", "", true))
			goto failed;
	}

	if (cf_client_tls_sslmode != SSLMODE_DISABLED) {
		new_client_accept_conf = tls_config_new();
		if (!new_client_accept_conf) {
			log_error("tls_config_new failed 2");
			goto failed;
		}

		if (!setup_tls(new_client_accept_conf, "client_tls", cf_client_tls_sslmode,
			       cf_client_tls_protocols, cf_client_tls_ciphers,
			       cf_client_tls_key_file, cf_client_tls_cert_file,
			       cf_client_tls_ca_file, cf_client_tls_dheparams,
			       cf_client_tls_ecdhecurve, false))
			goto failed;

		new_client_accept_base = tls_server();
		if (!new_client_accept_base) {
			log_error("server_base failed");
			goto failed;
		}
		err = tls_configure(new_client_accept_base, new_client_accept_conf);
		if (err) {
			log_error("TLS setup failed: %s", tls_error(new_client_accept_base));
			goto failed;
		}
	}

	/*
	 * To change server TLS settings all connections are marked as dirty. This
	 * way they are recycled and the new TLS settings will be used. Otherwise
	 * old TLS settings, possibly less secure, could be used for old
	 * connections indefinitly. If TLS is disabled, and it was disabled before
	 * as well then recycling connections is not necessary, since we know none
	 * of the settings have changed. In all other cases we recycle the
	 * connections to be on the safe side, even though it's possible nothing
	 * has changed.
	 */
	if (server_connect_conf || new_server_connect_conf) {
		struct List *item;
		PgPool *pool;
		statlist_for_each(item, &pool_list) {
			pool = container_of(item, PgPool, head);
			tag_pool_dirty(pool);
		}
	}

	tls_free(client_accept_base);
	tls_config_free(client_accept_conf);
	tls_config_free(server_connect_conf);
	client_accept_base = new_client_accept_base;
	client_accept_conf = new_client_accept_conf;
	client_accept_sslmode = cf_client_tls_sslmode;
	server_connect_conf = new_server_connect_conf;
	server_connect_sslmode = cf_server_tls_sslmode;
	return true;
failed:
	tls_free(new_client_accept_base);
	tls_config_free(new_client_accept_conf);
	tls_config_free(new_server_connect_conf);
	return false;
}

/*
 * TLS handshake
 */

static bool handle_tls_handshake(SBuf *sbuf)
{
	int err;

	err = tls_handshake(sbuf->tls);
	log_noise("tls_handshake: err=%d", err);
	if (err == TLS_WANT_POLLIN) {
		return sbuf_use_callback_once(sbuf, EV_READ, sbuf_tls_handshake_cb);
	} else if (err == TLS_WANT_POLLOUT) {
		return sbuf_use_callback_once(sbuf, EV_WRITE, sbuf_tls_handshake_cb);
	} else if (err == 0) {
		sbuf->tls_state = SBUF_TLS_OK;
		sbuf_call_proto(sbuf, SBUF_EV_TLS_READY);
		return true;
	} else {
		log_warning("TLS handshake error: %s", tls_error(sbuf->tls));
		return false;
	}
}

static void sbuf_tls_handshake_cb(evutil_socket_t fd, short flags, void *_sbuf)
{
	SBuf *sbuf = _sbuf;
	sbuf->wait_type = W_NONE;
	if (!handle_tls_handshake(sbuf))
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
}

/*
 * Accept TLS connection.
 */

bool sbuf_tls_accept(SBuf *sbuf)
{
	int err;

	if (!sbuf_pause(sbuf))
		return false;

	sbuf->ops = &tls_sbufio_ops;

	err = tls_accept_fds(client_accept_base, &sbuf->tls, sbuf->sock, sbuf->sock);
	log_noise("tls_accept_fds: err=%d", err);
	if (err < 0) {
		log_warning("TLS accept error: %s", tls_error(sbuf->tls));
		return false;
	}

	sbuf->tls_state = SBUF_TLS_DO_HANDSHAKE;
	return true;
}

/*
 * Connect to remote TLS host.
 */

bool sbuf_tls_connect(SBuf *sbuf, const char *hostname)
{
	struct tls *ctls;
	int err;

	if (!sbuf_pause(sbuf))
		return false;

	if (cf_server_tls_sslmode != SSLMODE_VERIFY_FULL)
		hostname = NULL;

	ctls = tls_client();
	if (!ctls)
		return false;
	err = tls_configure(ctls, server_connect_conf);
	if (err < 0) {
		log_error("tls client config failed: %s", tls_error(ctls));
		tls_free(ctls);
		return false;
	}

	sbuf->tls = ctls;
	sbuf->tls_host = hostname;
	sbuf->ops = &tls_sbufio_ops;

	err = tls_connect_fds(sbuf->tls, sbuf->sock, sbuf->sock, sbuf->tls_host);
	if (err < 0) {
		log_warning("TLS connect error: %s", tls_error(sbuf->tls));
		return false;
	}

	sbuf->tls_state = SBUF_TLS_DO_HANDSHAKE;
	return true;
}

/*
 * TLS IO ops.
 */

static ssize_t tls_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len)
{
	ssize_t out = 0;

	if (sbuf->tls_state != SBUF_TLS_OK) {
		errno = EIO;
		return -1;
	}

	out = tls_read(sbuf->tls, dst, len);
	log_noise("tls_read: req=%zu out=%zd", len, out);
	if (out >= 0) {
		return out;
	} else if (out == TLS_WANT_POLLIN) {
		errno = EAGAIN;
	} else if (out == TLS_WANT_POLLOUT) {
		log_warning("tls_sbufio_recv: got TLS_WANT_POLLOUT");
		errno = EIO;
	} else {
		log_warning("tls_sbufio_recv: %s", tls_error(sbuf->tls));
		errno = EIO;
	}
	return -1;
}

static ssize_t tls_sbufio_send(struct SBuf *sbuf, const void *data, size_t len)
{
	ssize_t out;

	if (sbuf->tls_state != SBUF_TLS_OK) {
		errno = EIO;
		return -1;
	}

	out = tls_write(sbuf->tls, data, len);
	log_noise("tls_write: req=%zu out=%zd", len, out);
	if (out >= 0) {
		return out;
	} else if (out == TLS_WANT_POLLOUT) {
		errno = EAGAIN;
	} else if (out == TLS_WANT_POLLIN) {
		log_warning("tls_sbufio_send: got TLS_WANT_POLLIN");
		errno = EIO;
	} else {
		log_warning("tls_sbufio_send: %s", tls_error(sbuf->tls));
		errno = EIO;
	}
	return -1;
}

static int tls_sbufio_close(struct SBuf *sbuf)
{
	log_noise("tls_close");
	if (sbuf->tls) {
		tls_close(sbuf->tls);
		tls_free(sbuf->tls);
		sbuf->tls = NULL;
	}
	if (sbuf->sock > 0) {
		safe_close(sbuf->sock);
		sbuf->sock = 0;
	}
	return 0;
}

// TODO: handle gssapi somehow, respecting macros etc
void sbuf_cleanup(void)
{
	tls_free(client_accept_base);
	tls_config_free(client_accept_conf);
	tls_config_free(server_connect_conf);
	client_accept_conf = NULL;
	server_connect_conf = NULL;
	client_accept_base = NULL;
}

#else

int client_accept_sslmode = SSLMODE_DISABLED;
int server_connect_sslmode = SSLMODE_DISABLED;

bool sbuf_tls_setup(void) { return true; }
bool sbuf_tls_accept(SBuf *sbuf) { return false; }
bool sbuf_tls_connect(SBuf *sbuf, const char *hostname) { return false; }

void sbuf_cleanup(void)
{
}

static bool handle_tls_handshake(SBuf *sbuf)
{
	return false;
}

#endif

/*
 * Server GSS Encryption support.
 */

#ifdef HAVE_SERVER_GSSENC
static int gssenc_sbufio_close(struct SBuf *sbuf)
{
	log_noise("gss_close");
	if (sbuf->gss) {
// TODO: free gss memory
//		tls_close(sbuf->tls);
//		tls_free(sbuf->tls);
		sbuf->gss = NULL;
	}
	if (sbuf->sock > 0) {
		safe_close(sbuf->sock);
		sbuf->sock = 0;
	}
	return 0;
}

/*
static ssize_t gssenc_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len)
{
		gss_buffer_desc recv_buf = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc unwrap_buf = GSS_C_EMPTY_BUFFER;
        int conf_state, ret, token_flags;
        OM_uint32 maj, min;
		socket_set_nonblocking(sbuf_socket(sbuf), 0);
		maj = 0;
		min = 0;
        log_noise("gssenc_sbufio_recv start");
        ret = recv_token(sbuf->sock, &token_flags, &recv_buf);
        if (ret < 0)
            return -1;
        log_noise("gssenc_sbufio_recv token received");
        maj = gss_unwrap(&min, sbuf->gss, &recv_buf, &unwrap_buf, &conf_state, (gss_qop_t *) NULL);
        if (GSS_ERROR(maj)) {
            log_warning("gssenc_sbufio_recv - gss_wrap() error major 0x%x minor 0x%x\n", maj, min);
            return -1;
        }
		memcpy(dst, unwrap_buf.value, unwrap_buf.length);
        log_noise("gssenc_sbufio_recv end %d", (int) unwrap_buf.length);
	    return unwrap_buf.length;
}
*/

static ssize_t gssenc_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len)
{
	ssize_t out = 0;

	if (sbuf->gssenc_state != SBUF_GSSENC_OK) {
		errno = EIO;
		return -1;
	}

	out = pg_GSS_read(sbuf, dst, len);
	log_noise("pg_GSS_read: req=%zu out=%zd", len, out);
	if (out >= 0) {
		return out;
	} else if (out == GSSENC_WANT_POLLIN) {
		errno = EAGAIN;
	} else if (out == GSSENC_WANT_POLLOUT) {
		log_warning("gssenc_sbufio_recv: got GSSENC_WANT_POLLOUT");
		errno = EIO;
	} else {
		log_warning("gssenc_sbufio_recv: error");
		errno = EIO;
	}
	return -1;
}

/*static ssize_t gssenc_sbufio_send(struct SBuf *sbuf, const void *data, size_t len)
{
	gss_buffer_desc in_buf, out_buf = GSS_C_EMPTY_BUFFER;
	OM_uint32 maj, min;
	int ret, state;
	socket_set_nonblocking(sbuf_socket(sbuf), 0);
	log_noise("gssenc_sbufio_send start");
	in_buf.length = len;
	in_buf.value = (char *) data;
	out_buf.value = NULL;
	out_buf.length = 0;
	maj = gss_wrap(&min, sbuf->gss, 1, GSS_C_QOP_DEFAULT, &in_buf, &state, &out_buf);
	if (GSS_ERROR(maj)) {
		log_noise("gssenc_sbufio_send - gss_wrap() error major 0x%x minor 0x%x\n", maj, min);
		return -1;
	}
	ret = send_token(sbuf->sock, 0, &out_buf);
	if (ret < 0)
	    log_error("gssenc_sbufio_send ret %d\n", ret);
        log_noise("gssenc_sbufio_send end %d\n", (int) len);
	return (ssize_t) len;
}*/

static ssize_t gssenc_sbufio_send(struct SBuf *sbuf, const void *data, size_t len)
{
	ssize_t out;

	if (sbuf->gssenc_state != SBUF_GSSENC_OK) {
		errno = EIO;
		return -1;
	}

	out = pg_GSS_write(sbuf, data, len);
	log_noise("pg_GSS_write: req=%zu out=%zd", len, out);
	if (out >= 0) {
		return out;
	} else if (out == GSSENC_WANT_POLLOUT) {
		errno = EAGAIN;
	} else if (out == GSSENC_WANT_POLLIN) {
		log_warning("gssenc_sbufio_send: got GSSENC_WANT_POLLIN");
		errno = EIO;
	} else {
		log_warning("gssenc_sbufio_send: EIO");
		errno = EIO;
	}
	return -1;
}
/*
 * Require encryption support, as well as mutual authentication and
 * tamperproofing measures.
 */
#define GSS_REQUIRED_FLAGS GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | \
	GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG

/*
 * Handle the encryption/decryption of data using GSSAPI.
 *
 * In the encrypted data stream on the wire, we break up the data
 * into packets where each packet starts with a uint32-size length
 * word (in network byte order), then encrypted data of that length
 * immediately following.  Decryption yields the same data stream
 * that would appear when not using encryption.
 *
 * Encrypted data typically ends up being larger than the same data
 * unencrypted, so we use fixed-size buffers for handling the
 * encryption/decryption which are larger than PQComm's buffer will
 * typically be to minimize the times where we have to make multiple
 * packets (and therefore multiple recv/send calls for a single
 * read/write call to us).
 *
 * NOTE: The client and server have to agree on the max packet size,
 * because we have to pass an entire packet to GSSAPI at a time and we
 * don't want the other side to send arbitrarily huge packets as we
 * would have to allocate memory for them to then pass them to GSSAPI.
 *
 * Therefore, these two #define's are effectively part of the protocol
 * spec and can't ever be changed.
 */
#define PQ_GSS_SEND_BUFFER_SIZE 16384
#define PQ_GSS_RECV_BUFFER_SIZE 16384

/*
 * We need these state variables per-connection.  To allow the functions
 * in this file to look mostly like those in be-secure-gssapi.c, set up
 * these macros.
 */
#define PqGSSSendBuffer (conn->gss_SendBuffer)
#define PqGSSSendLength (conn->gss_SendLength)
#define PqGSSSendNext (conn->gss_SendNext)
#define PqGSSSendConsumed (conn->gss_SendConsumed)
#define PqGSSRecvBuffer (conn->gss_RecvBuffer)
#define PqGSSRecvLength (conn->gss_RecvLength)
#define PqGSSResultBuffer (conn->gss_ResultBuffer)
#define PqGSSResultLength (conn->gss_ResultLength)
#define PqGSSResultNext (conn->gss_ResultNext)
#define PqGSSMaxPktSize (conn->gss_MaxPktSize)

/*
 * Attempt to write len bytes of data from ptr to a GSSAPI-encrypted connection.
 *
 * The connection must be already set up for GSSAPI encryption (i.e., GSSAPI
 * transport negotiation is complete).
 *
 * On success, returns the number of data bytes consumed (possibly less than
 * len).  On failure, returns -1 with errno set appropriately.  If the errno
 * indicates a non-retryable error, a message is added to conn->errorMessage.
 * For retryable errors, caller should call again (passing the same data)
 * once the socket is ready.
 */
static ssize_t
pg_GSS_write(SBuf *conn, const void *ptr, size_t len)
{
	OM_uint32	major,
				minor;
	gss_buffer_desc input,
				output = GSS_C_EMPTY_BUFFER;
	ssize_t		ret = -1;
	size_t		bytes_sent = 0;
	size_t		bytes_to_encrypt;
	size_t		bytes_encrypted;
	gss_ctx_id_t gctx = conn->gss;

	/*
	 * When we get a failure, we must not tell the caller we have successfully
	 * transmitted everything, else it won't retry.  Hence a "success"
	 * (positive) return value must only count source bytes corresponding to
	 * fully-transmitted encrypted packets.  The amount of source data
	 * corresponding to the current partly-transmitted packet is remembered in
	 * PqGSSSendConsumed.  On a retry, the caller *must* be sending that data
	 * again, so if it offers a len less than that, something is wrong.
	 */
	if (len < ((unsigned int)PqGSSSendConsumed))
	{
		log_error("GSSAPI caller failed to retransmit all data needing to be retried");
		errno = EINVAL;
		return -1;
	}

	/* Discount whatever source data we already encrypted. */
	bytes_to_encrypt = len - PqGSSSendConsumed;
	bytes_encrypted = PqGSSSendConsumed;

	/*
	 * Loop through encrypting data and sending it out until it's all done or
	 * pqsecure_raw_write() complains (which would likely mean that the socket
	 * is non-blocking and the requested send() would block, or there was some
	 * kind of actual error).
	 */
	while (bytes_to_encrypt || PqGSSSendLength)
	{
		int			conf_state = 0;
		uint32		netlen;

		/*
		 * Check if we have data in the encrypted output buffer that needs to
		 * be sent (possibly left over from a previous call), and if so, try
		 * to send it.  If we aren't able to, return that fact back up to the
		 * caller.
		 */
		if (PqGSSSendLength)
		{
			ssize_t		ret;
			ssize_t		amount = PqGSSSendLength - PqGSSSendNext;

			ret = pqsecure_raw_write(conn, PqGSSSendBuffer + PqGSSSendNext, amount);
			if (ret <= 0)
			{
				/*
				 * Report any previously-sent data; if there was none, reflect
				 * the pqsecure_raw_write result up to our caller.  When there
				 * was some, we're effectively assuming that any interesting
				 * failure condition will recur on the next try.
				 */
				if (bytes_sent)
					return bytes_sent;
				return ret;
			}

			/*
			 * Check if this was a partial write, and if so, move forward that
			 * far in our buffer and try again.
			 */
			if (ret != amount)
			{
				PqGSSSendNext += ret;
				continue;
			}

			/* We've successfully sent whatever data was in that packet. */
			bytes_sent += PqGSSSendConsumed;

			/* All encrypted data was sent, our buffer is empty now. */
			PqGSSSendLength = PqGSSSendNext = PqGSSSendConsumed = 0;
		}

		/*
		 * Check if there are any bytes left to encrypt.  If not, we're done.
		 */
		if (!bytes_to_encrypt)
			break;

		/*
		 * Check how much we are being asked to send, if it's too much, then
		 * we will have to loop and possibly be called multiple times to get
		 * through all the data.
		 */
		if (bytes_to_encrypt > PqGSSMaxPktSize)
			input.length = PqGSSMaxPktSize;
		else
			input.length = bytes_to_encrypt;

		input.value = (char *) ptr + bytes_encrypted;

		output.value = NULL;
		output.length = 0;

		/*
		 * Create the next encrypted packet.  Any failure here is considered a
		 * hard failure, so we return -1 even if bytes_sent > 0.
		 */
		major = gss_wrap(&minor, gctx, 1, GSS_C_QOP_DEFAULT,
						 &input, &conf_state, &output);
		if (major != GSS_S_COMPLETE)
		{
//			pg_GSS_error(libpq_gettext("GSSAPI wrap error"), conn, major, minor);
			log_error("GSSAPI wrap error major 0x%u, minor 0x%u", major, minor);
			errno = EIO;		/* for lack of a better idea */
			goto cleanup;
		}

		if (conf_state == 0)
		{
			log_error("outgoing GSSAPI message would not use confidentiality");
			errno = EIO;		/* for lack of a better idea */
			goto cleanup;
		}

		if (output.length > PQ_GSS_SEND_BUFFER_SIZE - sizeof(uint32))
		{
			log_error("client tried to send oversize GSSAPI packet (%zu > %zu)",
							  (size_t) output.length,
							  PQ_GSS_SEND_BUFFER_SIZE - sizeof(uint32));
			errno = EIO;		/* for lack of a better idea */
			goto cleanup;
		}

		bytes_encrypted += input.length;
		bytes_to_encrypt -= input.length;
		PqGSSSendConsumed += input.length;

		/* 4 network-order bytes of length, then payload */
		netlen = htonl(output.length);
		memcpy(PqGSSSendBuffer + PqGSSSendLength, &netlen, sizeof(uint32));
		PqGSSSendLength += sizeof(uint32);

		memcpy(PqGSSSendBuffer + PqGSSSendLength, output.value, output.length);
		PqGSSSendLength += output.length;

		/* Release buffer storage allocated by GSSAPI */
		gss_release_buffer(&minor, &output);
	}

	/* If we get here, our counters should all match up. */
	Assert(bytes_sent == len);
	Assert(bytes_sent == bytes_encrypted);

	ret = bytes_sent;

cleanup:
	/* Release GSSAPI buffer storage, if we didn't already */
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);
	return ret;
}

/*
 * Low-level implementation of pqsecure_write.
 *
 * This is used directly for an unencrypted connection.  For encrypted
 * connections, this does the physical I/O on behalf of pgtls_write or
 * pg_GSS_write.
 *
 * This function reports failure (i.e., returns a negative result) only
 * for retryable errors such as EINTR.  Looping for such cases is to be
 * handled at some outer level, maybe all the way up to the application.
 * For hard failures, we set conn->write_failed and store an error message
 * in conn->write_err_msg, but then claim to have written the data anyway.
 * This is because we don't want to report write failures so long as there
 * is a possibility of reading from the server and getting an error message
 * that could explain why the connection dropped.  Many TCP stacks have
 * race conditions such that a write failure may or may not be reported
 * before all incoming data has been read.
 *
 * Note that this error behavior happens below the SSL management level when
 * we are using SSL.  That's because at least some versions of OpenSSL are
 * too quick to report a write failure when there's still a possibility to
 * get a more useful error from the server.
 */
static ssize_t
pqsecure_raw_write(SBuf *conn, const void *ptr, size_t len)
{
	ssize_t		n;
	int			flags = 0;
	int			result_errno = 0;

	/*
	 * If we already had a write failure, we will never again try to send data
	 * on that connection.  Even if the kernel would let us, we've probably
	 * lost message boundary sync with the server.  conn->write_failed
	 * therefore persists until the connection is reset, and we just discard
	 * all data presented to be written.
	 */
	if (conn->write_failed)
		return len;

	n = send(conn->sock, ptr, len, flags);

	if (n < 0)
	{
		result_errno = errno;

		/* Set error message if appropriate */
		switch (result_errno)
		{
			case EAGAIN:
				errno = result_errno;
				return GSSENC_WANT_POLLOUT;
			case EINTR:
				/* no error message, caller is expected to retry */
				break;

			case ECONNRESET:
				conn->write_failed = true;
				/* Store error message in conn->write_err_msg, if possible */
				/* (strdup failure is OK, we'll cope later) */
				log_error("server closed the connection unexpectedly\n"
									   "\tThis probably means the server terminated abnormally\n"
									   "\tbefore or while processing the request.\n");
				/* Now claim the write succeeded */
				n = len;
				break;

			default:
				conn->write_failed = true;
				/* Store error message in conn->write_err_msg, if possible */
				/* (strdup failure is OK, we'll cope later) */
				log_error("could not send data to server");
				/* Now claim the write succeeded */
				n = len;
				break;
		}
	}

	/* ensure we return the intended errno to caller */
	errno = result_errno;

	return n;
}

/*
 * Read up to len bytes of data into ptr from a GSSAPI-encrypted connection.
 *
 * The connection must be already set up for GSSAPI encryption (i.e., GSSAPI
 * transport negotiation is complete).
 *
 * Returns the number of data bytes read, or on failure, returns -1
 * with errno set appropriately.  If the errno indicates a non-retryable
 * error, a message is added to conn->errorMessage.  For retryable errors,
 * caller should call again once the socket is ready.
 */
static ssize_t
pg_GSS_read(SBuf *conn, void *ptr, size_t len)
{
	OM_uint32	major,
				minor;
	gss_buffer_desc input = GSS_C_EMPTY_BUFFER,
				output = GSS_C_EMPTY_BUFFER;
	ssize_t		ret;
	size_t		bytes_returned = 0;
	gss_ctx_id_t gctx = conn->gss;

	/*
	 * The plan here is to read one incoming encrypted packet into
	 * PqGSSRecvBuffer, decrypt it into PqGSSResultBuffer, and then dole out
	 * data from there to the caller.  When we exhaust the current input
	 * packet, read another.
	 */
	while (bytes_returned < len)
	{
		int			conf_state = 0;

		/* Check if we have data in our buffer that we can return immediately */
		if (PqGSSResultNext < PqGSSResultLength)
		{
			size_t		bytes_in_buffer = PqGSSResultLength - PqGSSResultNext;
			size_t		bytes_to_copy = Min(bytes_in_buffer, len - bytes_returned);

			/*
			 * Copy the data from our result buffer into the caller's buffer,
			 * at the point where we last left off filling their buffer.
			 */
			memcpy((char *) ptr + bytes_returned, PqGSSResultBuffer + PqGSSResultNext, bytes_to_copy);
			PqGSSResultNext += bytes_to_copy;
			bytes_returned += bytes_to_copy;

			/*
			 * At this point, we've either filled the caller's buffer or
			 * emptied our result buffer.  Either way, return to caller.  In
			 * the second case, we could try to read another encrypted packet,
			 * but the odds are good that there isn't one available.  (If this
			 * isn't true, we chose too small a max packet size.)  In any
			 * case, there's no harm letting the caller process the data we've
			 * already returned.
			 */
			break;
		}

		/* Result buffer is empty, so reset buffer pointers */
		PqGSSResultLength = PqGSSResultNext = 0;

		/*
		 * Because we chose above to return immediately as soon as we emit
		 * some data, bytes_returned must be zero at this point.  Therefore
		 * the failure exits below can just return -1 without worrying about
		 * whether we already emitted some data.
		 */
		Assert(bytes_returned == 0);

		/*
		 * At this point, our result buffer is empty with more bytes being
		 * requested to be read.  We are now ready to load the next packet and
		 * decrypt it (entirely) into our result buffer.
		 */

		/* Collect the length if we haven't already */
		if (PqGSSRecvLength < (int) sizeof(uint32))
		{
			ret = pqsecure_raw_read(conn, PqGSSRecvBuffer + PqGSSRecvLength,
									sizeof(uint32) - PqGSSRecvLength);

			/* If ret <= 0, pqsecure_raw_read already set the correct errno */
			if (ret <= 0)
				return ret;

			PqGSSRecvLength += ret;

			/* If we still haven't got the length, return to the caller */
			if (PqGSSRecvLength < (int) sizeof(uint32))
			{
				errno = EWOULDBLOCK;
				return GSSENC_WANT_POLLIN;
			}
		}

		/* Decode the packet length and check for overlength packet */
		input.length = ntohl(*(uint32 *) PqGSSRecvBuffer);

		if (input.length > PQ_GSS_RECV_BUFFER_SIZE - sizeof(uint32))
		{
			log_error("oversize GSSAPI packet sent by the server (%zu > %zu)",
							  (size_t) input.length,
							  PQ_GSS_RECV_BUFFER_SIZE - sizeof(uint32));
			errno = EIO;		/* for lack of a better idea */
			return -1;
		}

		/*
		 * Read as much of the packet as we are able to on this call into
		 * wherever we left off from the last time we were called.
		 */
		ret = pqsecure_raw_read(conn, PqGSSRecvBuffer + PqGSSRecvLength,
								input.length - (PqGSSRecvLength - sizeof(uint32)));
		/* If ret <= 0, pqsecure_raw_read already set the correct errno */
		if (ret <= 0)
			return ret;

		PqGSSRecvLength += ret;

		/* If we don't yet have the whole packet, return to the caller */
		if (PqGSSRecvLength - sizeof(uint32) < input.length)
		{
			errno = EWOULDBLOCK;
			return GSSENC_WANT_POLLIN;
		}

		/*
		 * We now have the full packet and we can perform the decryption and
		 * refill our result buffer, then loop back up to pass data back to
		 * the caller.  Note that error exits below here must take care of
		 * releasing the gss output buffer.
		 */
		output.value = NULL;
		output.length = 0;
		input.value = PqGSSRecvBuffer + sizeof(uint32);

		major = gss_unwrap(&minor, gctx, &input, &output, &conf_state, NULL);
		if (major != GSS_S_COMPLETE)
		{
			log_error("GSSAPI unwrap error major 0x%u, minor 0x%u", major, minor);
			ret = -1;
			errno = EIO;		/* for lack of a better idea */
			goto cleanup;
		}

		if (conf_state == 0)
		{
			log_error("incoming GSSAPI message did not use confidentiality");
			ret = -1;
			errno = EIO;		/* for lack of a better idea */
			goto cleanup;
		}

		memcpy(PqGSSResultBuffer, output.value, output.length);
		PqGSSResultLength = output.length;

		/* Our receive buffer is now empty, reset it */
		PqGSSRecvLength = 0;

		/* Release buffer storage allocated by GSSAPI */
		gss_release_buffer(&minor, &output);
	}

	ret = bytes_returned;

cleanup:
	/* Release GSSAPI buffer storage, if we didn't already */
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);
	return ret;
}

/*
 * Simple wrapper for reading from pqsecure_raw_read.
 *
 * This takes the same arguments as pqsecure_raw_read, plus an output parameter
 * to return the number of bytes read.  This handles if blocking would occur and
 * if we detect EOF on the connection.
 */
/*
static ssize_t gss_read(SBuf *conn, void *recv_buffer, size_t length, ssize_t *ret)
{
	*ret = pqsecure_raw_read(conn, recv_buffer, length);
	if (*ret < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return GSSENC_WANT_POLLIN;
		else
			return -1;
	}

	// Check for EOF
	if (*ret == 0)
		return GSSENC_WANT_POLLIN;

	return *ret;
}
*/

static ssize_t
pqsecure_raw_read(SBuf *conn, void *ptr, size_t len)
{
	ssize_t		n;
	int			result_errno = 0;

	n = recv(conn->sock, ptr, len, 0);

	if (n < 0)
	{
		result_errno = errno;

		/* Set error message if appropriate */
		switch (result_errno)
		{
			case EAGAIN:
			case EINTR:
				/* no error message, caller is expected to retry */
				result_errno = errno;
				return GSSENC_WANT_POLLIN;
				break;

			case EPIPE:
			case ECONNRESET:
				log_error("server closed the connection unexpectedly\n"
												   "\tThis probably means the server terminated abnormally\n"
												   "\tbefore or while processing the request.\n");
				break;

			default:
				log_error("could not receive data from server");
				break;
		}
	}

	/* ensure we return the intended errno to caller */
	errno = result_errno;

	return n;
}

static void release_buffer(gss_buffer_t buf)
{
    free(buf->value);
    buf->value = NULL;
    buf->length = 0;
}

static int write_all(int fildes, const void *data, unsigned int nbyte)
{
    int ret;
    const char *ptr, *buf = data;

    for (ptr = buf; nbyte; ptr += ret, nbyte -= ret) {
        ret = send(fildes, ptr, nbyte, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return (ret);
        } else if (ret == 0) {
            return (ptr - buf);
        }
    }

    return (ptr - buf);
}

/*
 * Function: send_token
 *
 * Purpose: Writes a token to a file descriptor.
 *
 * Arguments:
 *
 *      s               (r) an open file descriptor
 *      flags           (r) the flags to write
 *      tok             (r) the token to write
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * If the flags are non-null, send_token writes the token flags (a
 * single byte, even though they're passed in in an integer). Next,
 * the token length (as a network long) and then the token data are
 * written to the file descriptor s.  It returns 0 on success, and -1
 * if an error occurs or if it could not write all the data.
 */

static int send_token(int s, int flags, gss_buffer_t tok)
{
    int     ret;
    unsigned char char_flags = (unsigned char) flags;
    unsigned char lenbuf[4];

    if (char_flags) {
        ret = write_all(s, (char *) &char_flags, 1);
        if (ret != 1) {
            log_error("sending token flags");
            return -1;
        }
    }
    if (tok->length > 0xffffffffUL)
        abort();
    lenbuf[0] = (tok->length >> 24) & 0xff;
    lenbuf[1] = (tok->length >> 16) & 0xff;
    lenbuf[2] = (tok->length >> 8) & 0xff;
    lenbuf[3] = tok->length & 0xff;

    ret = write_all(s, lenbuf, 4);
    if (ret < 0) {
        log_error("sending token length");
        return -1;
    } else if (ret != 4) {
        return -1;
    }

    ret = write_all(s, tok->value, tok->length);
    if (ret < 0) {
        log_error("sending token data");
        return -1;
    } else if ((size_t)ret != tok->length) {
        return -1;
    }

    return tok->length;
}

static int read_all(int fildes, void *data, unsigned int nbyte)
{
    int     ret;
    char   *ptr, *buf = data;
    fd_set  rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(fildes, &rfds);
    tv.tv_sec = 300;
    tv.tv_usec = 0;

    for (ptr = buf; nbyte; ptr += ret, nbyte -= ret) {
        if (select(FD_SETSIZE, &rfds, NULL, NULL, &tv) <= 0
            || !FD_ISSET(fildes, &rfds))
            return (ptr - buf);
        ret = recv(fildes, ptr, nbyte, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return (ret);
        } else if (ret == 0) {
            return (ptr - buf);
        }
    }

    return (ptr - buf);
}

/*
 * Function: recv_token
 *
 * Purpose: Reads a token from a file descriptor.
 *
 * Arguments:
 *
 *      s               (r) an open file descriptor
 *      flags           (w) the read flags
 *      tok             (w) the read token
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * recv_token reads the token flags (a single byte, even though
 * they're stored into an integer, then reads the token length (as a
 * network long), allocates memory to hold the data, and then reads
 * the token data from the file descriptor s.  It blocks to read the
 * length and data, if necessary.  On a successful return, the token
 * should be freed with gss_release_buffer.  It returns 0 on success,
 * and -1 if an error occurs or if it could not read all the data.
 */
static int
recv_token(int s, int * flags, gss_buffer_t tok)
{
    int     ret;
    unsigned char char_flags;
    unsigned char lenbuf[4];

    ret = read_all(s, (char *) &char_flags, 1);
    if (ret < 0) {
        log_error("reading token flags");
        return -1;
    } else if (!ret) {
        return -1;
    } else {
        *flags = (int) char_flags;
    }

    if (char_flags == 0) {
        lenbuf[0] = 0;
        ret = read_all(s, &lenbuf[1], 3);
        if (ret < 0) {
            log_error("reading token length");
            return -1;
        } else if (ret != 3) {
            return -1;
        }
    } else {
        ret = read_all(s, lenbuf, 4);
        if (ret < 0) {
            log_error("reading token length");
            return -1;
        } else if (ret != 4) {
            return -1;
        }
    }

    tok->length = ((lenbuf[0] << 24)
                   | (lenbuf[1] << 16)
                   | (lenbuf[2] << 8)
                   | lenbuf[3]);
    tok->value = (char *) malloc(tok->length ? tok->length : 1);
    if (tok->length && tok->value == NULL) {
        return -1;
    }

    ret = read_all(s, (char *) tok->value, tok->length);
    if (ret < 0) {
        log_error("reading token data");
        free(tok->value);
        return -1;
    } else if ((size_t)ret != tok->length) {
        fprintf(stderr, "sending token data: %d of %d bytes written\n",
                ret, (int) tok->length);
        free(tok->value);
        return -1;
    }

    return tok->length+4;
}

/*
 * Connect to remote GSS Enc host.
 */

bool sbuf_gssenc_connect(SBuf *conn, const char *hostname)
{
    int initiator_established = 0, ret;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    OM_uint32 major, minor, ret_flags;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    gss_name_t target_name = GSS_C_NO_NAME;
    int token_flags;

    socket_set_nonblocking(sbuf_socket(conn), 0);

	if (PqGSSSendBuffer == NULL)
	{
		PqGSSSendBuffer = malloc(PQ_GSS_SEND_BUFFER_SIZE);
		PqGSSRecvBuffer = malloc(PQ_GSS_RECV_BUFFER_SIZE);
		PqGSSResultBuffer = malloc(PQ_GSS_RECV_BUFFER_SIZE);
		if (!PqGSSSendBuffer || !PqGSSRecvBuffer || !PqGSSResultBuffer)
		{
			log_error("out of memory");
			return false;
		}
		PqGSSSendLength = PqGSSSendNext = PqGSSSendConsumed = 0;
		PqGSSRecvLength = PqGSSResultLength = PqGSSResultNext = 0;
	}

    /* Applications should set target_name to a real value. */
    name_buf.value = "postgres/kerberized-postgres@EXAMPLE.COM";
    name_buf.length = strlen(name_buf.value);
    major = gss_import_name(&minor, &name_buf,
                            GSS_KRB5_NT_PRINCIPAL_NAME, &target_name);
    if (GSS_ERROR(major)) {
        log_noise("Could not import name\n");
        return false;
    }

	if (!sbuf_pause(conn))
		return false;

    /* Mutual authentication will require a token from acceptor to
     * initiator and thus a second call to gss_init_sec_context(). */

    while (!initiator_established) {
        /* The initiator_cred_handle, mech_type, time_req,
         * input_chan_bindings, actual_mech_type, and time_rec
         * parameters are not needed in many cases.  We pass
         * GSS_C_NO_CREDENTIAL, GSS_C_NO_OID, 0, NULL, NULL, and NULL
         * for them, respectively. */
        major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctx,
                                     target_name, GSS_C_NO_OID,
                                     GSS_REQUIRED_FLAGS, 0, NULL, &input_token,
                                     NULL, &output_token, &ret_flags,
                                     NULL);
        /* This was allocated by recv_token() and is no longer
         * needed.  Free it now to avoid leaks if the loop continues. */
        release_buffer(&input_token);

        /* Always send a token if we are expecting another input token
         * (GSS_S_CONTINUE_NEEDED is set) or if it is nonempty. */
        if ((major & GSS_S_CONTINUE_NEEDED) ||
            output_token.length > 0) {
//            ret = send_token(conn->sock, NULL, &output_token);
            ret = send_token(conn->sock, 0, &output_token);
            if (ret < 0)
                goto cleanup;
        }
        /* Check for errors after sending the token so that we will send
         * error tokens. */
        if (GSS_ERROR(major)) {
            log_warning("gss_init_sec_context() error major 0x%x\n", major);
            goto cleanup;
        }
        /* Free the output token's storage; we don't need it anymore.
         * gss_release_buffer() is safe to call on the output buffer
         * from gss_int_sec_context(), even if there is no storage
         * associated with that buffer. */
        (void)gss_release_buffer(&minor, &output_token);

        if (major & GSS_S_CONTINUE_NEEDED) {
            ret = recv_token(conn->sock, &token_flags, &input_token);
            if (ret < 0)
                goto cleanup;
        } else if (major == GSS_S_COMPLETE) {
            initiator_established = 1;
        } else {
            /* This situation is forbidden by RFC 2743.  Bail out. */
            log_warning("major not complete or continue but not error\n");
            goto cleanup;
        }
    }   /* while (!initiator_established) */
    if ((ret_flags & (GSS_REQUIRED_FLAGS)) != (GSS_REQUIRED_FLAGS)) {
        log_warning("Negotiated context does not support requested flags\n");
        goto cleanup;
    }
    log_noise("Initiator's context negotiation successful\n");

	conn->gss = ctx;
	conn->ops = &gssenc_sbufio_ops;

    // Turn async back on
	socket_set_nonblocking(sbuf_socket(conn), 1);

	conn->gssenc_state = SBUF_GSSENC_DO_HANDSHAKE;
	/*
	 * Determine the max packet size which will fit in our buffer, after
	 * accounting for the length.  pg_GSS_write will need this.
	 */
	major = gss_wrap_size_limit(&minor, conn->gss, 1, GSS_C_QOP_DEFAULT,
								PQ_GSS_SEND_BUFFER_SIZE - sizeof(uint32),
								&PqGSSMaxPktSize);
	log_noise("Max packet size: %u", PqGSSMaxPktSize);
	return true;

cleanup:
    /* We are required to release storage for nonzero-length output
     * tokens.  gss_release_buffer() zeros the length, so we
     * will not attempt to release the same buffer twice. */
    if (output_token.length > 0)
        (void)gss_release_buffer(&minor, &output_token);
    /* Do not request a context deletion token; pass NULL. */
    (void)gss_delete_sec_context(&minor, &ctx, NULL);
    (void)gss_release_name(&minor, &target_name);
    return true;
}

static bool handle_gssenc_handshake(SBuf *sbuf)
{
	sbuf->gssenc_state = SBUF_GSSENC_OK;
//	sbuf_use_callback_once(sbuf, EV_READ, sbuf_gssenc_handshake_cb);
//	sbuf_use_callback_once(sbuf, EV_WRITE, sbuf_gssenc_handshake_cb);
	sbuf_call_proto(sbuf, SBUF_EV_GSSENC_READY);
	return true;	
}

//static void sbuf_gssenc_handshake_cb(evutil_socket_t fd, short flags, void *_sbuf)
//{
//	SBuf *sbuf = _sbuf;
//	sbuf->wait_type = W_NONE;
//	if (!handle_gssenc_handshake(sbuf))
//		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
//}
#else
//int client_accept_sslmode = SSLMODE_DISABLED;
//int server_connect_sslmode = SSLMODE_DISABLED;

//bool sbuf_tls_setup(void) { return true; }
//bool sbuf_tls_accept(SBuf *sbuf) { return false; }
bool sbuf_gssenc_connect(SBuf *sbuf, const char *hostname) { return false; }
#endif