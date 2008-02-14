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
 * Temporary buffer for single i/o.
 *
 * Pattern:
 *
 *	iobuf_get_and_reset()
 * start:
 *	iobuf_recv()
 * loop:
 *	if (new_pkt)
 *		iobuf_parse()
 *
 *	if (send) {
 *		iobuf_tag_send()
 *	} else {
 *		send_pending()
 *		iobuf_tag_skip()
 *	}
 *	if (more-unparsed)
 *		goto loop;
 *	send_pending();
 */	

extern int cf_sbuf_len;

/*
 * 0 .. done_pos         -- sent
 * done_pos .. parse_pos -- parsed, to send
 * parse_pos .. recv_pos -- received, to parse
 */
struct iobuf {
	unsigned done_pos;
	unsigned parse_pos;
	unsigned recv_pos;
	uint8_t buf[FLEX_ARRAY];
};
typedef struct iobuf IOBuf;

static inline bool iobuf_sane(const IOBuf *io)
{
	return (io == NULL) ||
		(  io->parse_pos >= io->done_pos
		&& io->recv_pos >= io->parse_pos
		&& (unsigned)cf_sbuf_len >= io->recv_pos);
}

static inline bool iobuf_empty(const IOBuf *io)
{
	return io == NULL || io->done_pos == io->recv_pos;
}

/* unsent amount */
static inline unsigned iobuf_amount_pending(const IOBuf *buf)
{
	return buf->parse_pos - buf->done_pos;
}

/* max possible to parse (tag_send/tag_skip) */
static inline unsigned iobuf_amount_parse(const IOBuf *buf)
{
	return buf->recv_pos - buf->parse_pos;
}

/* max possible to recv */
static inline unsigned iobuf_amount_recv(const IOBuf *buf)
{
	return cf_sbuf_len - buf->recv_pos;
}

/* put all unparsed to mbuf */
static inline unsigned iobuf_parse_all(const IOBuf *buf, MBuf *mbuf)
{
	unsigned avail = iobuf_amount_parse(buf);
	const uint8_t *pos = buf->buf + buf->parse_pos;
	mbuf_init(mbuf, pos, avail);
	return avail;
}

/* put all unparsed to mbuf, with size limit */
static inline unsigned iobuf_parse_limit(const IOBuf *buf, MBuf *mbuf, unsigned limit)
{
	unsigned avail = iobuf_amount_parse(buf);
	const uint8_t *pos = buf->buf + buf->parse_pos;
	if (avail > limit)
		avail = limit;
	mbuf_init(mbuf, pos, avail);
	return avail;
}

/* recv */
static inline int _MUSTCHECK iobuf_recv_limit(IOBuf *io, int fd, unsigned len)
{
	uint8_t *pos = io->buf + io->recv_pos;
	int got;
	unsigned avail = iobuf_amount_recv(io);

	if (len > avail)
		len = avail;

	Assert(len > 0);

	got = safe_recv(fd, pos, len, 0);
	if (got > 0)
		io->recv_pos += got;
	return got;
}

static inline int _MUSTCHECK iobuf_recv_max(IOBuf *io, int fd)
{
	return iobuf_recv_limit(io, fd, iobuf_amount_recv(io));
}

/* send tagged data */
static inline int _MUSTCHECK iobuf_send_pending(IOBuf *io, int fd)
{
	uint8_t *pos = io->buf + io->done_pos;
	int len, res;

	len = io->parse_pos - io->done_pos;
	Assert(len > 0);

	res = safe_send(fd, pos, len, 0);
	if (res > 0)
		io->done_pos += res;
	return res;
}

static inline void iobuf_tag_send(IOBuf *io, unsigned len)
{
	Assert(len > 0 && len <= iobuf_amount_parse(io));

	io->parse_pos += len;
}

static inline void iobuf_tag_skip(IOBuf *io, unsigned len)
{
	Assert(io->parse_pos == io->done_pos); /* no send pending */
	Assert(len > 0 && len <= iobuf_amount_parse(io));

	io->parse_pos += len;
	io->done_pos = io->parse_pos;
}

static inline void iobuf_try_resync(IOBuf *io, unsigned small_pkt)
{
	unsigned avail = io->recv_pos - io->done_pos;
	if (avail == 0) {
		if (io->recv_pos > 0)
			io->recv_pos = io->parse_pos = io->done_pos = 0;
	} else if (avail < small_pkt && io->done_pos > 0) {
		memmove(io->buf, io->buf + io->done_pos, avail);
		io->parse_pos -= io->done_pos;
		io->recv_pos = avail;
		io->done_pos = 0;
	}
}

static inline void iobuf_reset(IOBuf *io)
{
	io->recv_pos = io->parse_pos = io->done_pos = 0;
}

