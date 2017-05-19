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
	SBUF_EV_TLS_READY	/* TLS was established */
} SBufEvent;

/*
 * If less than this amount of data is pending, then
 * prefer to merge it with next recv().
 *
 * It needs to be larger than data handler wants
 * to see completely.  Generally just header,
 * but currently also ServerParam pkt.
 */
#define SBUF_SMALL_PKT	64

struct tls;

/* fwd def */
typedef struct SBuf SBuf;
typedef struct SBufIO SBufIO;

/* callback should return true if it used one of sbuf_prepare_* on sbuf,
   false if it used sbuf_pause(), sbuf_close() or simply wants to wait for
   next event loop (eg. too few data available). */
typedef bool (*sbuf_cb_t)(SBuf *sbuf,
			SBufEvent evtype,
			struct MBuf *mbuf);

/* for some reason, libevent has no typedef for callback */
typedef void (*sbuf_libevent_cb)(int, short, void *);

struct SBufIO {
	int (*sbufio_recv)(SBuf *sbuf, void *buf, unsigned int len);
	int (*sbufio_send)(SBuf *sbuf, const void *data, unsigned int len);
	int (*sbufio_close)(SBuf *sbuf);
};

/*
 * Stream Buffer.
 *
 * Stream is divided to packets.  On each packet start
 * protocol handler is called that decides what to do.
 */
struct SBuf {
	struct event ev;	/* libevent handle */

	uint8_t wait_type;	/* track wait state */
	uint8_t pkt_action;	/* method for handling current pkt */
	uint8_t tls_state;	/* progress of tls */

	int sock;		/* fd for this socket */

	unsigned pkt_remain;	/* total packet length remaining */

	sbuf_cb_t proto_cb;	/* protocol callback */

	SBuf *dst;		/* target SBuf for current packet */

	IOBuf *io;		/* data buffer, lazily allocated */

	const SBufIO *ops;	/* normal vs. TLS */
	struct tls *tls;	/* TLS context */
	const char *tls_host;	/* target hostname */
};

#define sbuf_socket(sbuf) ((sbuf)->sock)

void sbuf_init(SBuf *sbuf, sbuf_cb_t proto_fn);
bool sbuf_accept(SBuf *sbuf, int read_sock, bool is_unix)  _MUSTCHECK;
bool sbuf_connect(SBuf *sbuf, const struct sockaddr *sa, int sa_len, int timeout_sec)  _MUSTCHECK;

void sbuf_tls_setup(void);
bool sbuf_tls_accept(SBuf *sbuf)  _MUSTCHECK;
bool sbuf_tls_connect(SBuf *sbuf, const char *hostname)  _MUSTCHECK;

bool sbuf_pause(SBuf *sbuf) _MUSTCHECK;
void sbuf_continue(SBuf *sbuf);
bool sbuf_close(SBuf *sbuf) _MUSTCHECK;

/* proto_fn can use those functions to order behaviour */
void sbuf_prepare_send(SBuf *sbuf, SBuf *dst, unsigned amount);
void sbuf_prepare_skip(SBuf *sbuf, unsigned amount);
void sbuf_prepare_fetch(SBuf *sbuf, unsigned amount);

bool sbuf_answer(SBuf *sbuf, const void *buf, unsigned len)  _MUSTCHECK;

bool sbuf_continue_with_callback(SBuf *sbuf, sbuf_libevent_cb cb)  _MUSTCHECK;
bool sbuf_use_callback_once(SBuf *sbuf, short ev, sbuf_libevent_cb user_cb) _MUSTCHECK;

/*
 * Returns true if SBuf is has no data buffered
 * and is not in a middle of a packet.
 */
static inline bool sbuf_is_empty(SBuf *sbuf)
{
	return iobuf_empty(sbuf->io) && sbuf->pkt_remain == 0;
}

static inline bool sbuf_is_closed(SBuf *sbuf)
{
	return sbuf->sock == 0;
}

/*
 * Lowlevel operations.
 */

static inline int sbuf_op_recv(SBuf *sbuf, void *buf, unsigned int len)
{
	return sbuf->ops->sbufio_recv(sbuf, buf, len);
}

static inline int sbuf_op_send(SBuf *sbuf, const void *buf, unsigned int len)
{
	return sbuf->ops->sbufio_send(sbuf, buf, len);
}

static inline int sbuf_op_close(SBuf *sbuf)
{
	return sbuf->ops->sbufio_close(sbuf);
}

void sbuf_cleanup(void);

