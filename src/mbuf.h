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
 * Safe and easy access to fixed memory buffer
 */

typedef struct MBuf MBuf;
struct MBuf {
	const uint8 *data;
	const uint8 *end;
	const uint8 *pos;
};

static inline void mbuf_init(MBuf *buf, const uint8 *ptr, int len)
{
	if (len < 0)
		fatal("fuckup");
	buf->data = buf->pos = ptr;
	buf->end = ptr + len;
}

static inline uint8 mbuf_get_char(MBuf *buf)
{
	if (buf->pos + 1 > buf->end)
		fatal("buffer overflow");
	return *buf->pos++;
}

static inline unsigned mbuf_get_uint16(MBuf *buf)
{
	unsigned val;
	if (buf->pos + 2 > buf->end)
		fatal("buffer overflow");
	val = *buf->pos++;
	val = (val << 8) | *buf->pos++;
	return val;
}

static inline unsigned mbuf_get_uint32(MBuf *buf)
{
	unsigned val;
	if (buf->pos + 4 > buf->end)
		fatal("buffer overflow");
	val = *buf->pos++;
	val = (val << 8) | *buf->pos++;
	val = (val << 8) | *buf->pos++;
	val = (val << 8) | *buf->pos++;
	return val;
}

static inline unsigned mbuf_get_uint64(MBuf *buf)
{
	uint64 i1, i2;
	i1 = mbuf_get_uint32(buf);
	i2 = mbuf_get_uint32(buf);
	return (i1 << 32) | i2;
}

static inline const uint8 * mbuf_get_bytes(MBuf *buf, unsigned len)
{
	const uint8 *res = buf->pos;
	if (len > buf->end - buf->pos)
		fatal("buffer overflow");
	buf->pos += len;
	return res;
}

static inline const char * mbuf_get_string(MBuf *buf)
{
	const char *res = (const char *)buf->pos;
	while (buf->pos < buf->end && *buf->pos)
		buf->pos++;
	if (buf->pos == buf->end)
		return NULL;
	buf->pos++;
	return res;
}

static inline unsigned mbuf_avail(MBuf *buf)
{
	return buf->end - buf->pos;
}

static inline unsigned mbuf_size(MBuf *buf)
{
	return buf->end - buf->data;
}

