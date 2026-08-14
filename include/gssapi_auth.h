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
 * GSSAPI (Kerberos) authentication and encryption support.
 */

/* Safety limit on GSSAPI auth token size */
#define GSSAPI_MAX_TOKEN_SIZE (65536)

/*
 * GSSAPI encryption protocol constants.
 * These match the postgres source (be-secure-gssapi.c, fe-secure-gssapi.c)
 * and are effectively part of the protocol spec.
 */
#define PQ_GSS_MAX_PACKET_SIZE  16384	/* encrypted on-wire packet, includes uint32 header */
#define PQ_GSS_AUTH_BUFFER_SIZE 65536	/* handshake token buffer, includes uint32 header */

/*
 * Which socket event the encryption handshake is waiting on next.  The handshake
 * is event-driven: a round that cannot fully send its output token yet asks the
 * sbuf layer to re-arm EV_WRITE; otherwise it waits for the peer's next token on
 * EV_READ.  This mirrors the WANT_POLLIN/WANT_POLLOUT handling of the TLS layer.
 */
#define GSSENC_HS_READ  0
#define GSSENC_HS_WRITE 1

void gssapi_auth_init(void);

/* Client-side: pgbouncer acts as GSSAPI acceptor for connecting clients */
bool gssapi_accept_send_request(PgSocket *client)  _MUSTCHECK;
bool gssapi_accept_continue(PgSocket *client, const uint8_t *token,
			    unsigned token_len)     _MUSTCHECK;
void gssapi_accept_cleanup(PgSocket *client);

/* Server-side: pgbouncer acts as GSSAPI initiator to a postgres backend */
bool gssapi_initiate_begin(PgSocket *server)       _MUSTCHECK;
bool gssapi_initiate_continue(PgSocket *server, const uint8_t *token,
			      unsigned token_len)  _MUSTCHECK;
void gssapi_initiate_cleanup(PgSocket *server);

/* GSSAPI encryption: wrap/unwrap for sbuf I/O layer */
ssize_t gssenc_recv(PgSocket *sk, void *buf, size_t len);
ssize_t gssenc_send(PgSocket *sk, const void *buf, size_t len);

/* GSSAPI encryption: handshake */
bool gssenc_accept_start(PgSocket *client)  _MUSTCHECK;
bool gssenc_accept_handshake(PgSocket *client)  _MUSTCHECK;
bool gssenc_have_initiator_cred(PgSocket *server)  _MUSTCHECK;
bool gssenc_connect_start(PgSocket *server)  _MUSTCHECK;
bool gssenc_connect_handshake(PgSocket *server)  _MUSTCHECK;
void gssenc_cleanup(PgSocket *sk);

/* GSSAPI encryption: identity extraction from encryption context */
bool gssenc_extract_and_verify_identity(PgSocket *client)  _MUSTCHECK;
