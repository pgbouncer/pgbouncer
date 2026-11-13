
/*
 * Safe and easy access to memory buffer.
 */

#include <usual/mbuf.h>

#include <limits.h>

#include <usual/logging.h>

bool mbuf_make_room(struct MBuf *buf, unsigned len)
{
	/*
	 * Deliberately uint64_t: alloc_len, write_pos and len are all unsigned,
	 * and the growth loop below used to double new_alloc in unsigned too, so
	 * once new_alloc reached 2^31 the next doubling overflowed to 0 and the
	 * loop never terminated.  Compute in a wider type and reject sizes that
	 * the unsigned alloc_len cannot represent.
	 */
	uint64_t new_alloc = buf->alloc_len;
	uint64_t need = (uint64_t)buf->write_pos + len;
	void *ptr;

	/* is it a dynamic buffer */
	if (buf->reader || buf->fixed)
		return false;

	/* maybe there is enough room already */
	if (need <= buf->alloc_len)
		return true;

	/* the result must stay addressable through the unsigned alloc_len */
	if (need > UINT_MAX)
		return false;

	if (new_alloc == 0)
		new_alloc = 128;

	/* calc new alloc size */
	while (new_alloc < need) {
		new_alloc *= 2;
		/*
		 * The doubling can overshoot UINT_MAX while need itself still fits;
		 * settle for exactly need so the result stays storable in alloc_len.
		 */
		if (new_alloc > UINT_MAX) {
			new_alloc = need;
			break;
		}
	}

	log_debug("mbuf_make_room(%p, %u): realloc new_alloc=%" PRIu64,
		  buf, len, new_alloc);

	/* realloc */
	ptr = realloc(buf->data, new_alloc);
	if (!ptr)
		return false;
	buf->data = ptr;
	buf->alloc_len = new_alloc;
	return true;
}
