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
 * Packet writing and sending.
 */

#include "bouncer.h"


/*
 * PostgreSQL type OIDs for result sets
 */
#define BYTEAOID 17
#define INT8OID 20
#define INT4OID 23
#define TEXTOID 25
#define NUMERICOID 1700


void pktbuf_free(PktBuf *buf)
{
	if (!buf || buf->fixed_buf)
		return;

	log_debug("pktbuf_free(%p)", buf);
	free(buf->buf);
	free(buf->ev);
	free(buf);
}

PktBuf *pktbuf_dynamic(int start_len)
{
	PktBuf *buf = zmalloc(sizeof(PktBuf));
	log_debug("pktbuf_dynamic(%d): %p", start_len, buf);
	if (!buf)
		return NULL;

	buf->ev = zmalloc(sizeof(*buf->ev));
	if (!buf->ev) {
		pktbuf_free(buf);
		return NULL;
	}
	buf->buf = malloc(start_len);
	if (!buf->buf) {
		pktbuf_free(buf);
		return NULL;
	}
	buf->buf_len = start_len;
	return buf;
}

void pktbuf_reset(struct PktBuf *pkt)
{
	pkt->failed = false;
	pkt->write_pos = 0;
	pkt->pktlen_pos = 0;
	pkt->send_pos = 0;
	pkt->sending = false;
}

void pktbuf_static(PktBuf *buf, uint8_t *data, int len)
{
	memset(buf, 0, sizeof(*buf));
	buf->buf = data;
	buf->buf_len = len;
	buf->fixed_buf = true;
}

static PktBuf *temp_pktbuf;

struct PktBuf *pktbuf_temp(void)
{
	if (!temp_pktbuf)
		temp_pktbuf = pktbuf_dynamic(512);
	if (!temp_pktbuf)
		die("out of memory");
	pktbuf_reset(temp_pktbuf);
	return temp_pktbuf;
}

void pktbuf_cleanup(void)
{
	pktbuf_free(temp_pktbuf);
	temp_pktbuf = NULL;
}

bool pktbuf_send_immediate(PktBuf *buf, PgSocket *sk)
{
	uint8_t *pos = buf->buf + buf->send_pos;
	int amount = buf->write_pos - buf->send_pos;
	ssize_t res;

	if (buf->failed)
		return false;
	res = sbuf_op_send(&sk->sbuf, pos, amount);
	if (res < 0) {
		log_debug("pktbuf_send_immediate: %s", strerror(errno));
	}
	return res == amount;
}

static void pktbuf_send_func(evutil_socket_t fd, short flags, void *arg)
{
	PktBuf *buf = arg;
	SBuf *sbuf = &buf->queued_dst->sbuf;
	int amount, res;

	log_debug("pktbuf_send_func(%" PRId64 ", %d, %p)", (int64_t)fd, (int)flags, buf);

	if (buf->failed)
		return;

	amount = buf->write_pos - buf->send_pos;
	res = sbuf_op_send(sbuf, buf->buf + buf->send_pos, amount);
	if (res < 0) {
		if (errno == EAGAIN) {
			res = 0;
		} else {
			log_error("pktbuf_send_func: %s", strerror(errno));
			pktbuf_free(buf);
			return;
		}
	}
	buf->send_pos += res;

	if (buf->send_pos < buf->write_pos) {
		event_assign(buf->ev, pgb_event_base, fd, EV_WRITE, pktbuf_send_func, buf);
		res = event_add(buf->ev, NULL);
		if (res < 0) {
			log_error("pktbuf_send_func: %s", strerror(errno));
			pktbuf_free(buf);
		}
	} else {
		pktbuf_free(buf);
	}
}

bool pktbuf_send_queued(PktBuf *buf, PgSocket *sk)
{
	Assert(!buf->sending);
	Assert(!buf->fixed_buf);

	if (buf->failed) {
		pktbuf_free(buf);
		return send_pooler_error(sk, true, false, "result prepare failed");
	} else {
		buf->sending = true;
		buf->queued_dst = sk;
		pktbuf_send_func(sk->sbuf.sock, EV_WRITE, buf);
		return true;
	}
}

static void make_room(PktBuf *buf, int len)
{
	int newlen = buf->buf_len;
	int need = buf->write_pos + len;
	void *ptr;

	if (newlen >= need)
		return;

	if (buf->failed)
		return;

	if (buf->fixed_buf) {
		buf->failed = true;
		return;
	}

	while (newlen < need)
		newlen = newlen * 2;

	log_debug("make_room(%p, %d): realloc newlen=%d",
		  buf, len, newlen);
	ptr = realloc(buf->buf, newlen);
	if (!ptr) {
		buf->failed = true;
	} else {
		buf->buf = ptr;
		buf->buf_len = newlen;
	}
}

void pktbuf_put_char(PktBuf *buf, char val)
{
	make_room(buf, 1);
	if (buf->failed)
		return;

	buf->buf[buf->write_pos++] = val;
}

void pktbuf_put_uint16(PktBuf *buf, uint16_t val)
{
	make_room(buf, 4);
	if (buf->failed)
		return;

	buf->buf[buf->write_pos++] = (val >> 8) & 255;
	buf->buf[buf->write_pos++] = val & 255;
}

void pktbuf_put_uint32(PktBuf *buf, uint32_t val)
{
	uint8_t *pos;

	make_room(buf, 4);
	if (buf->failed)
		return;

	pos = buf->buf + buf->write_pos;
	pos[0] = (val >> 24) & 255;
	pos[1] = (val >> 16) & 255;
	pos[2] = (val >> 8) & 255;
	pos[3] = val & 255;
	buf->write_pos += 4;
}

void pktbuf_put_uint64(PktBuf *buf, uint64_t val)
{
	pktbuf_put_uint32(buf, val >> 32);
	pktbuf_put_uint32(buf, (uint32_t)val);
}

void pktbuf_put_bytes(PktBuf *buf, const void *data, int len)
{
	make_room(buf, len);
	if (buf->failed)
		return;
	memcpy(buf->buf + buf->write_pos, data, len);
	buf->write_pos += len;
}

void pktbuf_put_string(PktBuf *buf, const char *str)
{
	int len = strlen(str);
	pktbuf_put_bytes(buf, str, len + 1);
}

/*
 * write header, remember pos to write length later.
 */
void pktbuf_start_packet(PktBuf *buf, int type)
{
	if (buf->failed)
		return;

	if (type < 256) {
		/* new-style packet */
		pktbuf_put_char(buf, type);
		buf->pktlen_pos = buf->write_pos;
		pktbuf_put_uint32(buf, 0);
	} else {
		/* old-style packet */
		buf->pktlen_pos = buf->write_pos;
		pktbuf_put_uint32(buf, 0);
		pktbuf_put_uint32(buf, type);
	}
}

void pktbuf_finish_packet(PktBuf *buf)
{
	uint8_t *pos;
	unsigned len;

	if (buf->failed)
		return;

	len = buf->write_pos - buf->pktlen_pos;
	pos = buf->buf + buf->pktlen_pos;
	buf->pktlen_pos = 0;

	*pos++ = (len >> 24) & 255;
	*pos++ = (len >> 16) & 255;
	*pos++ = (len >> 8) & 255;
	*pos++ = len & 255;
}

/* types:
 * c - char/byte
 * h - uint16
 * i - uint32
 * q - uint64
 * s - Cstring
 * b - bytes
 */
void pktbuf_write_generic(PktBuf *buf, int type, const char *pktdesc, ...)
{
	va_list ap;
	int len;
	const char *adesc = pktdesc;
	uint8_t *bin;

	pktbuf_start_packet(buf, type);

	va_start(ap, pktdesc);
	while (*adesc) {
		switch (*adesc) {
		case 'c':
			pktbuf_put_char(buf, va_arg(ap, int));
			break;
		case 'h':
			pktbuf_put_uint16(buf, va_arg(ap, int));
			break;
		case 'i':
			pktbuf_put_uint32(buf, va_arg(ap, int));
			break;
		case 'q':
			pktbuf_put_uint64(buf, va_arg(ap, uint64_t));
			break;
		case 's':
			pktbuf_put_string(buf, va_arg(ap, char *));
			break;
		case 'b':
			bin = va_arg(ap, uint8_t *);
			len = va_arg(ap, int);
			pktbuf_put_bytes(buf, bin, len);
			break;
		default:
			fatal("bad pktdesc: %s", pktdesc);
		}
		adesc++;
	}
	va_end(ap);

	/* set correct length */
	pktbuf_finish_packet(buf);
}


/* send resultset column info
 * tupdesc keys:
 * 'i' - int4
 * 'q' - int8
 * 's' - string to text
 * 'b' - bytes to bytea
 * 'N' - uint64_t to numeric
 * 'T' - usec_t to date
 */
void pktbuf_write_RowDescription(PktBuf *buf, const char *tupdesc, ...)
{
	va_list ap;
	char *name;
	int i, ncol = strlen(tupdesc);

	log_noise("write RowDescription");

	pktbuf_start_packet(buf, 'T');

	pktbuf_put_uint16(buf, ncol);

	va_start(ap, tupdesc);
	for (i = 0; i < ncol; i++) {
		name = va_arg(ap, char *);

		/* Fields: name, reloid, colnr, oid, typsize, typmod, fmt */
		pktbuf_put_string(buf, name);
		pktbuf_put_uint32(buf, 0);
		pktbuf_put_uint16(buf, 0);
		if (tupdesc[i] == 's') {
			pktbuf_put_uint32(buf, TEXTOID);
			pktbuf_put_uint16(buf, -1);
		} else if (tupdesc[i] == 'b') {
			pktbuf_put_uint32(buf, BYTEAOID);
			pktbuf_put_uint16(buf, -1);
		} else if (tupdesc[i] == 'i') {
			pktbuf_put_uint32(buf, INT4OID);
			pktbuf_put_uint16(buf, 4);
		} else if (tupdesc[i] == 'q') {
			pktbuf_put_uint32(buf, INT8OID);
			pktbuf_put_uint16(buf, 8);
		} else if (tupdesc[i] == 'N') {
			pktbuf_put_uint32(buf, NUMERICOID);
			pktbuf_put_uint16(buf, -1);
		} else if (tupdesc[i] == 'T') {
			pktbuf_put_uint32(buf, TEXTOID);
			pktbuf_put_uint16(buf, -1);
		} else {
			fatal("bad tupdesc");
		}
		pktbuf_put_uint32(buf, -1);
		pktbuf_put_uint16(buf, 0);
	}
	va_end(ap);

	/* set correct length */
	pktbuf_finish_packet(buf);
}

/*
 * send DataRow.
 *
 * tupdesc keys:
 * 'i' - int4
 * 'q' - int8
 * 's' - string to text
 * 'b' - bytes to bytea
 * 'N' - uint64_t to numeric
 * 'T' - usec_t to date
 */
void pktbuf_write_DataRow(PktBuf *buf, const char *tupdesc, ...)
{
	int ncol = strlen(tupdesc);
	va_list ap;

	pktbuf_start_packet(buf, 'D');
	pktbuf_put_uint16(buf, ncol);

	va_start(ap, tupdesc);
	for (int i = 0; i < ncol; i++) {
		char tmp[100];	/* XXX good enough in practice */
		const char *val = NULL;

		if (tupdesc[i] == 'i') {
			snprintf(tmp, sizeof(tmp), "%d", va_arg(ap, int));
			val = tmp;
		} else if (tupdesc[i] == 'q' || tupdesc[i] == 'N') {
			snprintf(tmp, sizeof(tmp), "%" PRIu64, va_arg(ap, uint64_t));
			val = tmp;
		} else if (tupdesc[i] == 's') {
			val = va_arg(ap, char *);
		} else if (tupdesc[i] == 'b') {
			int blen = va_arg(ap, int);
			if (blen >= 0) {
				uint8_t *bval = va_arg(ap, uint8_t *);
				size_t required = 2 + blen * 2 + 1;

				if (required > sizeof(tmp))
					fatal("byte array too long (%zu > %zu)", required, sizeof(tmp));
				strcpy(tmp, "\\x");
				for (int j = 0; j < blen; j++)
					sprintf(tmp + (2 + j * 2), "%02x", bval[j]);
				val = tmp;
			}
			else {
				(void) va_arg(ap, uint8_t *);
				val = NULL;
			}
		} else if (tupdesc[i] == 'T') {
			usec_t time = va_arg(ap, usec_t);
			val = format_time_s(time, tmp, sizeof(tmp));
		} else {
			fatal("bad tupdesc: %s", tupdesc);
		}

		if (val) {
			int len = strlen(val);
			pktbuf_put_uint32(buf, len);
			pktbuf_put_bytes(buf, val, len);
		} else {
			/* NULL */
			pktbuf_put_uint32(buf, -1);
		}
	}
	va_end(ap);

	pktbuf_finish_packet(buf);
}

/*
 * Send Parse+Bind+Execute with string parameters.
 */
void pktbuf_write_ExtQuery(PktBuf *buf, const char *query, int nargs, ...)
{
	va_list ap;
	const char *val;
	int len, i;

	/* Parse */
	pktbuf_write_generic(buf, 'P', "csh", 0, query, 0);

	/* Bind */
	pktbuf_start_packet(buf, 'B');
	pktbuf_put_char(buf, 0);	/* portal name */
	pktbuf_put_char(buf, 0);	/* query name */
	pktbuf_put_uint16(buf, 0);	/* number of parameter format codes */
	pktbuf_put_uint16(buf, nargs);	/* number of parameter values */

	va_start(ap, nargs);
	for (i = 0; i < nargs; i++) {
		val = va_arg(ap, char *);
		len = strlen(val);
		pktbuf_put_uint32(buf, len);
		pktbuf_put_bytes(buf, val, len);
	}
	va_end(ap);

	pktbuf_put_uint16(buf, 0);	/* number of result-column format codes */
	pktbuf_finish_packet(buf);

	/* Describe */
	pktbuf_write_generic(buf, 'D', "cc", 'P', 0);

	/* Execute */
	pktbuf_write_generic(buf, 'E', "ci", 0, 0);

	/* Sync */
	pktbuf_write_generic(buf, 'S', "");
}
