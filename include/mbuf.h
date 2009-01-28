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
 * Safe and easy access to fixed memory buffer.
 */

/*
 * FIXME: the code should be converted so that
 * the fatal()-s can be replaced by Asserts().
 */

typedef struct MBuf MBuf;
struct MBuf {
	const uint8_t *data;
	const uint8_t *end;
	const uint8_t *pos;
};

static inline void mbuf_init(MBuf *buf, const uint8_t *ptr, int len)
{
	if (len < 0)
		fatal("fuckup");
	buf->data = buf->pos = ptr;
	buf->end = ptr + len;
}

static inline uint8_t mbuf_get_char(MBuf *buf)
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

static inline uint32_t mbuf_get_uint32(MBuf *buf)
{
	uint32_t val;
	if (buf->pos + 4 > buf->end)
		fatal("buffer overflow");
	val = *buf->pos++;
	val = (val << 8) | *buf->pos++;
	val = (val << 8) | *buf->pos++;
	val = (val << 8) | *buf->pos++;
	return val;
}

static inline uint64_t mbuf_get_uint64(MBuf *buf)
{
	uint64_t i1, i2;
	i1 = mbuf_get_uint32(buf);
	i2 = mbuf_get_uint32(buf);
	return (i1 << 32) | i2;
}

static inline const uint8_t * mbuf_get_bytes(MBuf *buf, unsigned len)
{
	const uint8_t *res = buf->pos;
	if (buf->pos + len > buf->end)
		fatal("buffer overflow");
	buf->pos += len;
	return res;
}

static inline unsigned mbuf_avail(const MBuf *buf)
{
	return buf->end - buf->pos;
}

static inline unsigned mbuf_size(const MBuf *buf)
{
	return buf->end - buf->data;
}

static inline const char * mbuf_get_string(MBuf *buf)
{
	const char *res = (const char *)buf->pos;
	const uint8_t *nul = memchr(res, 0, mbuf_avail(buf));
	if (!nul)
		return NULL;
	buf->pos = nul + 1;
	return res;
}

static inline void mbuf_copy(const MBuf *src, MBuf *dst)
{
	*dst = *src;
}

static inline void mbuf_slice(MBuf *src, unsigned len, MBuf *dst)
{
	if (len > mbuf_avail(src))
		fatal("buffer overflow");
	mbuf_init(dst, src->pos, len);
	src->pos += len;
}

