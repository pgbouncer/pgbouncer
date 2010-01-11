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

static void pktbuf_free(PktBuf *buf)
{
	if (buf->fixed_buf)
		return;

	log_debug("pktbuf_free(%p)", buf);
	if (buf->buf)
		free(buf->buf);
	if (buf->ev)
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

void pktbuf_static(PktBuf *buf, uint8_t *data, int len)
{
	memset(buf, 0, sizeof(*buf));
	buf->buf = data;
	buf->buf_len = len;
	buf->fixed_buf = 1;
}

bool pktbuf_send_immidiate(PktBuf *buf, PgSocket *sk)
{
	int fd = sbuf_socket(&sk->sbuf);
	uint8_t *pos = buf->buf + buf->send_pos;
	int amount = buf->write_pos - buf->send_pos;
	int res;

	if (buf->failed)
		return false;
	res = safe_send(fd, pos, amount, 0);
	if (res < 0) {
		log_debug("pktbuf_send_immidiate: %s", strerror(errno));
	}
	return res == amount;
}

static void pktbuf_send_func(int fd, short flags, void *arg)
{
	PktBuf *buf = arg;
	int amount, res;

	log_debug("pktbuf_send_func(%d, %d, %p)", fd, (int)flags, buf);

	if (buf->failed)
		return;

	amount = buf->write_pos - buf->send_pos;
	res = safe_send(fd, buf->buf + buf->send_pos, amount, 0);
	if (res < 0) {
		if (res == EAGAIN) {
			res = 0;
		} else {
			log_error("pktbuf_send_func: %s", strerror(errno));
			pktbuf_free(buf);
			return;
		}
	}
	buf->send_pos += res;

	if (buf->send_pos < buf->write_pos) {
		event_set(buf->ev, fd, EV_WRITE, pktbuf_send_func, buf);
		res = event_add(buf->ev, NULL);
		if (res < 0) {
			log_error("pktbuf_send_func: %s", strerror(errno));
			pktbuf_free(buf);
		}
	} else
		pktbuf_free(buf);
}

bool pktbuf_send_queued(PktBuf *buf, PgSocket *sk)
{
	int fd = sbuf_socket(&sk->sbuf);

	Assert(!buf->sending);
	Assert(!buf->fixed_buf);

	if (buf->failed) {
		pktbuf_free(buf);
		return send_pooler_error(sk, true, "result prepare failed");
	} else {
		buf->sending = 1;
		pktbuf_send_func(fd, EV_WRITE, buf);
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
		buf->failed = 1;
		return;
	}
	
	while (newlen < need)
		newlen = newlen * 2;

	log_debug("make_room(%p, %d): realloc newlen=%d",
		  buf, len, newlen);
	ptr = realloc(buf->buf, newlen);
	if (!ptr) {
		buf->failed = 1;
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
 * 's' - string
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
		} else if (tupdesc[i] == 'i') {
			pktbuf_put_uint32(buf, INT4OID);
			pktbuf_put_uint16(buf, 4);
		} else if (tupdesc[i] == 'q') {
			pktbuf_put_uint32(buf, INT8OID);
			pktbuf_put_uint16(buf, 8);
		} else if (tupdesc[i] == 'T') {
			pktbuf_put_uint32(buf, TEXTOID);
			pktbuf_put_uint16(buf, -1);
		} else
			fatal("bad tupdesc");
		pktbuf_put_uint32(buf, 0);
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
 * 's' - string
 * 'T' - usec_t to date
 */
void pktbuf_write_DataRow(PktBuf *buf, const char *tupdesc, ...)
{
	char tmp[32];
	const char *val = NULL;
	int i, len, ncol = strlen(tupdesc);
	va_list ap;

	pktbuf_start_packet(buf, 'D');
	pktbuf_put_uint16(buf, ncol);

	va_start(ap, tupdesc);
	for (i = 0; i < ncol; i++) {
		if (tupdesc[i] == 'i') {
			sprintf(tmp, "%d", va_arg(ap, int));
			val = tmp;
		} else if (tupdesc[i] == 'q') {
			sprintf(tmp, "%" PRIu64, va_arg(ap, uint64_t));
			val = tmp;
		} else if (tupdesc[i] == 's') {
			val = va_arg(ap, char *);
		} else if (tupdesc[i] == 'T') {
			usec_t time = va_arg(ap, usec_t);
			val = format_time_s(time, tmp, sizeof(tmp));
		} else
			fatal("bad tupdesc: %s", tupdesc);

		if (val) {
			len = strlen(val);
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

