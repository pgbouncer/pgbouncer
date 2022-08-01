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

#include <usual/mbuf.h>

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
	SBUF_EV_GSSENC_READY,	/* GSSENC was established */
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

#ifdef HAVE_SERVER_GSSENC

#define GSSENC_WANT_POLLOUT -3
#define GSSENC_WANT_POLLIN -2

#endif

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

struct SBufIO {
	ssize_t (*sbufio_recv)(SBuf *sbuf, void *buf, size_t len);
	ssize_t (*sbufio_send)(SBuf *sbuf, const void *data, size_t len);
	int (*sbufio_close)(SBuf *sbuf);
};

/*
 * Stream Buffer.
 *
 * Stream is divided to packets.  On each packet start
 * protocol handler is called that decides what to do.
 */
typedef unsigned int uint32;	/* == 32 bits */

struct SBuf {
	struct event ev;	/* libevent handle */

	uint8_t wait_type;	/* track wait state */
	uint8_t pkt_action;	/* method for handling current pkt */
	uint8_t tls_state;	/* progress of tls */
	uint8_t gssenc_state;	/* progress of gssenc */

	int sock;		/* fd for this socket */

	unsigned pkt_remain;	/* total packet length remaining */

	sbuf_cb_t proto_cb;	/* protocol callback */

	SBuf *dst;		/* target SBuf for current packet */

	IOBuf *io;		/* data buffer, lazily allocated */

	const SBufIO *ops;	/* normal vs. TLS vs. GSS */
	struct tls *tls;	/* TLS context */
	struct gss_ctx_id_struct *gss;
#ifdef HAVE_SERVER_GSSENC
	char	   *gss_SendBuffer; /* Encrypted data waiting to be sent */
	int			gss_SendLength; /* End of data available in gss_SendBuffer */
	int			gss_SendNext;	/* Next index to send a byte from
								 * gss_SendBuffer */
	int			gss_SendConsumed;	/* Number of *unencrypted* bytes consumed
									 * for current contents of gss_SendBuffer */
	char	   *gss_RecvBuffer; /* Received, encrypted data */
	int			gss_RecvLength; /* End of data available in gss_RecvBuffer */
	char	   *gss_ResultBuffer;	/* Decryption of data in gss_RecvBuffer */
	int			gss_ResultLength;	/* End of data available in
									 * gss_ResultBuffer */
	int			gss_ResultNext; /* Next index to read a byte from
								 * gss_ResultBuffer */
	uint32		gss_MaxPktSize; /* Maximum size we can encrypt and fit the
								 * results into our output buffer */
	bool		write_failed;	/* have we had a write failure on sock? */
#endif
	const char *tls_host;	/* target hostname */
};

#define sbuf_socket(sbuf) ((sbuf)->sock)

void sbuf_init(SBuf *sbuf, sbuf_cb_t proto_fn);
bool sbuf_accept(SBuf *sbuf, int read_sock, bool is_unix)  _MUSTCHECK;
bool sbuf_connect(SBuf *sbuf, const struct sockaddr *sa, socklen_t sa_len, time_t timeout_sec)  _MUSTCHECK;

/*
 * client_accept_sslmode is the currently applied sslmode that is used to
 * accept client connections. This is usually the same as
 * cf_client_tls_sslmode, except when changing the TLS configuration failed for
 * some reason (e.g. cert file not found). In this exceptional case,
 * cf_client_tls_sslmode will be the new sslmode, which is not actually
 * applied. And client_accept_sslmode is the still applied previous version. So
 * usually you should use this variable over cf_client_tls_sslmode.
 */
extern int client_accept_sslmode;
/*
 * Same as client_accept_sslmode, but for server connections.
 */
extern int server_connect_sslmode;

bool sbuf_gssenc_connect(SBuf *sbuf, char *gssapi_spn)  _MUSTCHECK;
bool sbuf_tls_setup(void);
bool sbuf_tls_accept(SBuf *sbuf)  _MUSTCHECK;
bool sbuf_tls_connect(SBuf *sbuf, const char *hostname)  _MUSTCHECK;

bool sbuf_pause(SBuf *sbuf) _MUSTCHECK;
void sbuf_continue(SBuf *sbuf);
bool sbuf_close(SBuf *sbuf) _MUSTCHECK;

/* proto_fn can use those functions to order behaviour */
void sbuf_prepare_send(SBuf *sbuf, SBuf *dst, unsigned amount);
void sbuf_prepare_skip(SBuf *sbuf, unsigned amount);
void sbuf_prepare_fetch(SBuf *sbuf, unsigned amount);

bool sbuf_answer(SBuf *sbuf, const void *buf, size_t len)  _MUSTCHECK;

bool sbuf_continue_with_callback(SBuf *sbuf, event_callback_fn cb)  _MUSTCHECK;
bool sbuf_use_callback_once(SBuf *sbuf, short ev, event_callback_fn user_cb) _MUSTCHECK;

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

static inline ssize_t sbuf_op_recv(SBuf *sbuf, void *buf, size_t len)
{
	return sbuf->ops->sbufio_recv(sbuf, buf, len);
}

static inline ssize_t sbuf_op_send(SBuf *sbuf, const void *buf, size_t len)
{
	return sbuf->ops->sbufio_send(sbuf, buf, len);
}

static inline int sbuf_op_close(SBuf *sbuf)
{
	return sbuf->ops->sbufio_close(sbuf);
}

void sbuf_cleanup(void);
