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
 * event types for protocol handler
 */
typedef enum {
	SBUF_EV_READ,		/* got new packet */
	SBUF_EV_RECV_FAILED,	/* error */
	SBUF_EV_SEND_FAILED,	/* error */
	SBUF_EV_CONNECT_FAILED,	/* error */
	SBUF_EV_CONNECT_OK,	/* got connection */
	SBUF_EV_FLUSH,		/* data is sent, buffer empty */
	SBUF_EV_PKT_CALLBACK,	/* next part of pkt data */
} SBufEvent;

/*
 * If less that this amount of data is pending, then
 * prefer to merge it with next recv().
 *
 * It needs to be larger than data handler wants
 * to see completely.  Generally just header,
 * but currently also ServerParam pkt.
 */
#define SBUF_SMALL_PKT	64

/*
 * How much proto handler may want to enlarge the packet.
 */
#define SBUF_MAX_REWRITE 16

/* fwd def */
typedef struct SBuf SBuf;

/* callback should return true if it used one of sbuf_prepare_* on sbuf,
   false if it used sbuf_pause(), sbuf_close() or simply wants to wait for
   next event loop (eg. too few data available). */
typedef bool (*sbuf_cb_t)(SBuf *sbuf,
			SBufEvent evtype,
			MBuf *mbuf,
			void *arg);

/* for some reason, libevent has no typedef for callback */
typedef void (*sbuf_libevent_cb)(int, short, void *);

/*
 * Stream Buffer.
 *
 * Stream is divided to packets.  On each packet start
 * protocol handler is called that decides what to do.
 */
struct SBuf {
	struct event ev;	/* libevent handle */

	bool is_unix;		/* is it unix socket */
	bool wait_send;		/* debug var, otherwise useless */
	uint8_t pkt_action;	/* method for handling current pkt */

	int sock;		/* fd for this socket */

	int recv_pos;		/* end of received data */
	int pkt_pos;		/* packet processing pos */
	int send_pos;		/* how far is data sent */

	int pkt_remain;		/* total packet length remaining */
	int send_remain;	/* total data to be sent remaining */

	sbuf_cb_t proto_cb;	/* protocol callback */
	void *proto_cb_arg;	/* extra arg to callback */

	SBuf *dst;		/* target SBuf for current packet */

	uint8_t buf[0];		/* data buffer follows (cf_sbuf_len + SBUF_MAX_REWRITE) */
};

#define sbuf_socket(sbuf) ((sbuf)->sock)

void sbuf_init(SBuf *sbuf, sbuf_cb_t proto_fn, void *arg);
bool sbuf_accept(SBuf *sbuf, int read_sock, bool is_unix)  _MUSTCHECK;
bool sbuf_connect(SBuf *sbuf, const PgAddr *addr, const char *unix_dir, int timeout_sec)  _MUSTCHECK;

void sbuf_pause(SBuf *sbuf);
void sbuf_continue(SBuf *sbuf);
void sbuf_close(SBuf *sbuf);

/* proto_fn can use those functions to order behaviour */
void sbuf_prepare_send(SBuf *sbuf, SBuf *dst, int amount);
void sbuf_prepare_skip(SBuf *sbuf, int amount);
void sbuf_prepare_fetch(SBuf *sbuf, int amount);

bool sbuf_answer(SBuf *sbuf, const void *buf, int len)  _MUSTCHECK;

bool sbuf_continue_with_callback(SBuf *sbuf, sbuf_libevent_cb cb)  _MUSTCHECK;

/*
 * Returns true if SBuf is has no data buffered
 * and is not in a middle of a packet.
 */
static inline bool sbuf_is_empty(SBuf *sbuf)
{
	return sbuf->send_pos == sbuf->recv_pos
		&& sbuf->pkt_remain == 0;
}

bool sbuf_rewrite_header(SBuf *sbuf, int old_len,
			 const uint8_t *new_hdr, int new_len)  _MUSTCHECK;

