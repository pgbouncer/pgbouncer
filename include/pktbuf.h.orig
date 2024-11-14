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
 * Safe & easy creation of PostgreSQL packets.
 */

typedef struct PktBuf PktBuf;
struct PktBuf {
	uint8_t *buf;
	int buf_len;
	int write_pos;
	int pktlen_pos;

	int send_pos;
	struct event *ev;
	PgSocket *queued_dst;

	bool failed:1;
	bool sending:1;
	bool fixed_buf:1;
};

/*
 * pktbuf creation
 */
PktBuf *pktbuf_dynamic(int start_len)	_MUSTCHECK;
void pktbuf_static(PktBuf *buf, uint8_t *data, int len);

void pktbuf_free(PktBuf *buf);

void pktbuf_reset(struct PktBuf *pkt);
struct PktBuf *pktbuf_temp(void);


/*
 * sending
 */
bool pktbuf_send_immediate(PktBuf *buf, PgSocket *sk)	_MUSTCHECK;
bool pktbuf_send_queued(PktBuf *buf, PgSocket *sk)  _MUSTCHECK;

/*
 * low-level ops
 */
void pktbuf_start_packet(PktBuf *buf, int type);
void pktbuf_put_char(PktBuf *buf, char val);
void pktbuf_put_uint16(PktBuf *buf, uint16_t val);
void pktbuf_put_uint32(PktBuf *buf, uint32_t val);
void pktbuf_put_uint64(PktBuf *buf, uint64_t val);
void pktbuf_put_string(PktBuf *buf, const char *str);
void pktbuf_put_bytes(PktBuf *buf, const void *data, int len);
void pktbuf_finish_packet(PktBuf *buf);
#define pktbuf_written(buf) ((buf)->write_pos)


/*
 * Packet writing
 */
void pktbuf_write_generic(PktBuf *buf, int type, const char *fmt, ...);
void pktbuf_write_RowDescription(PktBuf *buf, const char *tupdesc, ...);
void pktbuf_write_DataRow(PktBuf *buf, const char *tupdesc, ...);
void pktbuf_write_ExtQuery(PktBuf *buf, const char *query, int nargs, ...);

/*
 * Shortcuts for actual packets.
 */
#define pktbuf_write_ParameterStatus(buf, key, val) \
	pktbuf_write_generic(buf, 'S', "ss", key, val)

#define pktbuf_write_AuthenticationOk(buf) \
	pktbuf_write_generic(buf, 'R', "i", 0)

#define pktbuf_write_ReadyForQuery(buf) \
	pktbuf_write_generic(buf, 'Z', "c", 'I')

#define pktbuf_write_CommandComplete(buf, desc) \
	pktbuf_write_generic(buf, 'C', "s", desc)

#define pktbuf_write_BackendKeyData(buf, key) \
	pktbuf_write_generic(buf, 'K', "b", key, 8)

#define pktbuf_write_CancelRequest(buf, key) \
	pktbuf_write_generic(buf, PKT_CANCEL, "b", key, 8)

#define pktbuf_write_StartupMessage(buf, user, parms, parms_len) \
	pktbuf_write_generic(buf, PKT_STARTUP, "bsss", parms, parms_len, "user", user, "")

#define pktbuf_write_PasswordMessage(buf, psw) \
	pktbuf_write_generic(buf, 'p', "s", psw)

#define pkgbuf_write_SASLInitialResponseMessage(buf, mech, cir) \
	pktbuf_write_generic(buf, 'p', "sib", mech, strlen(cir), cir, strlen(cir))

#define pkgbuf_write_SASLResponseMessage(buf, cr) \
	pktbuf_write_generic(buf, 'p', "b", cr, strlen(cr))

#define pktbuf_write_Notice(buf, msg) \
	pktbuf_write_generic(buf, 'N', "sscss", "SNOTICE", "C00000", 'M', msg, "");

#define pktbuf_write_SSLRequest(buf) \
	pktbuf_write_generic(buf, PKT_SSLREQ, "")

/*
 * Shortcut for creating DataRow in memory.
 */

#define BUILD_DataRow(reslen, dst, dstlen, args...) do { \
	PktBuf _buf; \
	pktbuf_static(&_buf, dst, dstlen); \
	pktbuf_write_DataRow(&_buf, ## args); \
	reslen = _buf.failed ? -1 : _buf.write_pos; \
} while (0)

/*
 * Shortcuts for immediate send of one packet.
 */

#define SEND_wrap(buflen, pktfn, res, sk, args...) do { \
	uint8_t _data[buflen]; PktBuf _buf; \
	pktbuf_static(&_buf, _data, sizeof(_data)); \
	pktfn(&_buf, ## args); \
	res = pktbuf_send_immediate(&_buf, sk); \
} while (0)

#define SEND_RowDescription(res, sk, args...) \
	SEND_wrap(512, pktbuf_write_RowDescription, res, sk, ## args)

#define SEND_generic(res, sk, args...) \
	SEND_wrap(512, pktbuf_write_generic, res, sk, ## args)

#define SEND_ReadyForQuery(res, sk) \
	SEND_wrap(8, pktbuf_write_ReadyForQuery, res, sk)

#define SEND_CancelRequest(res, sk, key) \
	SEND_wrap(16, pktbuf_write_CancelRequest, res, sk, key)

#define SEND_PasswordMessage(res, sk, psw) \
	SEND_wrap(MAX_PASSWORD + 8, pktbuf_write_PasswordMessage, res, sk, psw)

#define SEND_SASLInitialResponseMessage(res, sk, mech, cir) \
	SEND_wrap(512, pkgbuf_write_SASLInitialResponseMessage, res, sk, mech, cir)

#define SEND_SASLResponseMessage(res, sk, cr) \
	SEND_wrap(512, pkgbuf_write_SASLResponseMessage, res, sk, cr)

void pktbuf_cleanup(void);
