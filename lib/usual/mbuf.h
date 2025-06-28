
/** \file
 * Safe and easy access to memory buffer.
 */

#ifndef _USUAL_MBUF_H_
#define _USUAL_MBUF_H_

#include <usual/base.h>

#include <string.h>

/** MBuf structure.  Allocated by user, can be in stack. */
struct MBuf {
	uint8_t *data;
	unsigned read_pos;
	unsigned write_pos;
	unsigned alloc_len;
	bool reader;
	bool fixed;
};

/** Format fragment for *printf() */
#define MBUF_FMT        ".*s"
/** Argument layout for *printf() */
#define MBUF_ARG(m)     ((m) ? mbuf_written(m) : 6), ((m) ? (const char *)mbuf_data(m) : "(null)")

/*
 * Init functions
 */

/** Initialize R/O buffer to fixed memory area. */
static inline void mbuf_init_fixed_reader(struct MBuf *buf, const void *ptr, unsigned len)
{
	buf->data = (uint8_t *)ptr;
	buf->read_pos = 0;
	buf->write_pos = len;
	buf->alloc_len = len;
	buf->reader = true;
	buf->fixed = true;
}

/** Initialize R/W buffer to fixed memory area. */
static inline void mbuf_init_fixed_writer(struct MBuf *buf, void *ptr, unsigned len)
{
	buf->data = (uint8_t *)ptr;
	buf->read_pos = 0;
	buf->write_pos = 0;
	buf->alloc_len = len;
	buf->reader = false;
	buf->fixed = true;
}

/** Initialize R/W buffer to dynamically allocated memory area.  */
static inline void mbuf_init_dynamic(struct MBuf *buf)
{
	buf->data = NULL;
	buf->read_pos = 0;
	buf->write_pos = 0;
	buf->alloc_len = 0;
	buf->reader = false;
	buf->fixed = false;
}

/** Free dynamically allocated area, if exists. */
static inline void mbuf_free(struct MBuf *buf)
{
	if (buf->data) {
		if (!buf->fixed)
			free(buf->data);
		memset(buf, 0, sizeof(*buf));
	}
}

/*
 * Reset functions.
 */

/** Move read cursor to start of buffer. */
static inline void mbuf_rewind_reader(struct MBuf *buf)
{
	buf->read_pos = 0;
}

/** Move both read and write cursor to start of buffer. */
static inline void mbuf_rewind_writer(struct MBuf *buf)
{
	if (!buf->reader) {
		buf->read_pos = 0;
		buf->write_pos = 0;
	}
}

/*
 * Info functions.
 */

/** How many bytes can be read with read cursor. */
static inline unsigned mbuf_avail_for_read(const struct MBuf *buf)
{
	return buf->write_pos - buf->read_pos;
}

/** How many bytes can be written with write cursor, without realloc. */
static inline unsigned mbuf_avail_for_write(const struct MBuf *buf)
{
	if (!buf->reader && buf->alloc_len > buf->write_pos)
		return buf->alloc_len - buf->write_pos;
	return 0;
}

/** How many data bytes are in buffer. */
static inline unsigned mbuf_written(const struct MBuf *buf)
{
	return buf->write_pos;
}

/** How many bytes have been read from buffer */
static inline unsigned mbuf_consumed(const struct MBuf *buf)
{
	return buf->read_pos;
}

/** Return pointer to data area. */
static inline void *mbuf_data(const struct MBuf *buf)
{
	return buf->data;
}

/** Do the mbufs contain same data. */
static inline bool mbuf_eq(const struct MBuf *buf1, const struct MBuf *buf2)
{
	if (buf1 == buf2) return true;
	if (!buf1 || !buf2 || (mbuf_written(buf1) != mbuf_written(buf2)))
		return false;
	return memcmp(mbuf_data(buf1), mbuf_data(buf2), mbuf_written(buf1)) == 0;
}

/** Complare mbuf to asciiz string */
static inline bool mbuf_eq_str(const struct MBuf *buf1, const char *s)
{
	struct MBuf tmp;
	mbuf_init_fixed_reader(&tmp, s, strlen(s));
	return mbuf_eq(buf1, &tmp);
}

/*
 * Read functions.
 */

/** Read a byte from read cursor. */
_MUSTCHECK
static inline bool mbuf_get_byte(struct MBuf *buf, uint8_t *dst_p)
{
	if (buf->read_pos + 1 > buf->write_pos)
		return false;
	*dst_p = buf->data[buf->read_pos++];
	return true;
}

/** Read big-endian uint16 from read cursor. */
_MUSTCHECK
static inline bool mbuf_get_char(struct MBuf *buf, char *dst_p)
{
	if (buf->read_pos + 1 > buf->write_pos)
		return false;
	*dst_p = buf->data[buf->read_pos++];
	return true;
}

_MUSTCHECK
static inline bool mbuf_get_uint16be(struct MBuf *buf, uint16_t *dst_p)
{
	unsigned a, b;
	if (buf->read_pos + 2 > buf->write_pos)
		return false;
	a = buf->data[buf->read_pos++];
	b = buf->data[buf->read_pos++];
	*dst_p = (a << 8) | b;
	return true;
}

/** Read big-endian uint32 from read cursor. */
_MUSTCHECK
static inline bool mbuf_get_uint32be(struct MBuf *buf, uint32_t *dst_p)
{
	unsigned a, b, c, d;
	if (buf->read_pos + 4 > buf->write_pos)
		return false;
	a = buf->data[buf->read_pos++];
	b = buf->data[buf->read_pos++];
	c = buf->data[buf->read_pos++];
	d = buf->data[buf->read_pos++];
	*dst_p = (a << 24) | (b << 16) | (c << 8) | d;
	return true;
}

/** Get reference to len bytes from read cursor. */
_MUSTCHECK
static inline bool mbuf_get_uint64be(struct MBuf *buf, uint64_t *dst_p)
{
	uint32_t a, b;
	if (!mbuf_get_uint32be(buf, &a)
	    || !mbuf_get_uint32be(buf, &b))
		return false;
	*dst_p = ((uint64_t)a << 32) | b;
	return true;
}

_MUSTCHECK
static inline bool mbuf_get_bytes(struct MBuf *buf, unsigned len, const uint8_t **dst_p)
{
	if (buf->read_pos + len > buf->write_pos)
		return false;
	*dst_p = buf->data + buf->read_pos;
	buf->read_pos += len;
	return true;
}

/** Get reference to asciiz string from read cursor. */
_MUSTCHECK
static inline bool mbuf_get_chars(struct MBuf *buf, unsigned len, const char **dst_p)
{
	if (buf->read_pos + len > buf->write_pos)
		return false;
	*dst_p = (char *)buf->data + buf->read_pos;
	buf->read_pos += len;
	return true;
}

_MUSTCHECK
static inline bool mbuf_get_string(struct MBuf *buf, const char **dst_p)
{
	const char *res = (char *)buf->data + buf->read_pos;
	const uint8_t *nul = memchr(res, 0, mbuf_avail_for_read(buf));
	if (!nul)
		return false;
	*dst_p = res;
	buf->read_pos = nul + 1 - buf->data;
	return true;
}

/*
 * Write functions.
 */

/** Allocate more room if needed and the mbuf allows. */
_MUSTCHECK
bool mbuf_make_room(struct MBuf *buf, unsigned len);

/** Write a byte to write cursor. */
_MUSTCHECK
static inline bool mbuf_write_byte(struct MBuf *buf, uint8_t val)
{
	if (buf->write_pos + 1 > buf->alloc_len
	    && !mbuf_make_room(buf, 1))
		return false;
	buf->data[buf->write_pos++] = val;
	return true;
}

/** Write len bytes to write cursor. */
_MUSTCHECK
static inline bool mbuf_write(struct MBuf *buf, const void *ptr, unsigned len)
{
	if (buf->write_pos + len > buf->alloc_len
	    && !mbuf_make_room(buf, len))
		return false;
	if (len > 0)
		memcpy(buf->data + buf->write_pos, ptr, len);
	buf->write_pos += len;
	return true;
}

/** writes full contents of another mbuf, without touching it */
_MUSTCHECK
static inline bool mbuf_write_raw_mbuf(struct MBuf *dst, struct MBuf *src)
{
	return mbuf_write(dst, src->data, src->write_pos);
}

/** writes partial contents of another mbuf, with touching it */
_MUSTCHECK
static inline bool mbuf_write_mbuf(struct MBuf *dst, struct MBuf *src, unsigned len)
{
	const uint8_t *data;
	if (!mbuf_get_bytes(src, len, &data))
		return false;
	if (!mbuf_write(dst, data, len)) {
		src->read_pos -= len;
		return false;
	}
	return true;
}

/** Fiil mbuf with byte value */
_MUSTCHECK
static inline bool mbuf_fill(struct MBuf *buf, uint8_t byte, unsigned len)
{
	if (buf->write_pos + len > buf->alloc_len
	    && !mbuf_make_room(buf, len))
		return false;
	memset(buf->data + buf->write_pos, byte, len);
	buf->write_pos += len;
	return true;
}

/** remove some data from mbuf */
_MUSTCHECK
static inline bool mbuf_cut(struct MBuf *buf, unsigned ofs, unsigned len)
{
	if (buf->reader)
		return false;
	if (ofs + len < buf->write_pos) {
		unsigned endofs = ofs + len;
		memmove(buf->data + ofs, buf->data + endofs, buf->write_pos - endofs);
		buf->write_pos -= len;
	} else if (ofs < buf->write_pos) {
		buf->write_pos = ofs;
	}
	return true;
}

static inline void mbuf_copy(const struct MBuf *src, struct MBuf *dst)
{
	*dst = *src;
}

_MUSTCHECK
static inline bool mbuf_slice(struct MBuf *src, unsigned len, struct MBuf *dst)
{
	if (len > mbuf_avail_for_read(src))
		return false;
	mbuf_init_fixed_reader(dst, src->data + src->read_pos, len);
	src->read_pos += len;
	return true;
}

#endif
