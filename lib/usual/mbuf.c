
/*
 * Safe and easy access to memory buffer.
 */

#include <usual/mbuf.h>

bool mbuf_make_room(struct MBuf *buf, unsigned len)
{
	unsigned new_alloc = buf->alloc_len;
	void *ptr;

	/* is it a dynamic buffer */
	if (buf->reader || buf->fixed)
		return false;

	/* maybe there is enough room already */
	if (buf->write_pos + len <= buf->alloc_len)
		return true;

	if (new_alloc == 0)
		new_alloc = 128;

	/* calc new alloc size */
	while (new_alloc < buf->write_pos + len)
		new_alloc *= 2;

	/* realloc */
	ptr = realloc(buf->data, new_alloc);
	if (!ptr)
		return false;
	buf->data = ptr;
	buf->alloc_len = new_alloc;
	return true;
}
