/*
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

/** @file
 *
 * Minimal dict.
 */

#ifndef _USUAL_MDICT_H_
#define _USUAL_MDICT_H_

#include <usual/cxalloc.h>
#include <usual/mbuf.h>

/** Dict reference */
struct MDict;

/** Create new emtpy dict */
struct MDict *mdict_new(CxMem *cx);

/** Free dict */
void mdict_free(struct MDict *dict);

/** Get value as MBuf from string */
const struct MBuf *mdict_get_buf(struct MDict *dict, const char *key, unsigned klen);

/** Get value from dict */
const char *mdict_get_str(struct MDict *dict, const char *key, unsigned klen);

/** Put string to dict */
bool mdict_put_str(struct MDict *dict, const char *key, unsigned klen, const char *val, unsigned vlen);

/** Remove a key from dict */
bool mdict_del_key(struct MDict *dict, const char *key, unsigned klen);

/** Signature for walker callback */
typedef bool (*mdict_walker_f)(void *arg, const struct MBuf *k, const struct MBuf *v);

/** Walk over dict */
bool mdict_walk(struct MDict *dict, mdict_walker_f cb_func, void *cb_arg);

/*
 * Simple API that calculates strlen inline.
 */

/** Get value from dict */
static inline const char *mdict_get(struct MDict *dict, const char *key)
{
	return mdict_get_str(dict, key, strlen(key));
}

/** Put zero-terminated key and value to dict */
static inline bool mdict_put(struct MDict *dict, const char *key, const char *val)
{
	unsigned klen = strlen(key);
	unsigned vlen = val ? strlen(val) : 0;
	return mdict_put_str(dict, key, klen, val, vlen);
}

/** Put MBuf to dict */
static inline bool mdict_put_buf(struct MDict *dict, const char *key, const struct MBuf *buf)
{
	unsigned klen = strlen(key);
	const char *val = buf ? mbuf_data(buf) : NULL;
	unsigned vlen = buf ? mbuf_written(buf) : 0;
	return mdict_put_str(dict, key, klen, val, vlen);
}

/** Remove value from dict */
static inline bool mdict_del(struct MDict *dict, const char *key)
{
	return mdict_del_key(dict, key, strlen(key));
}

/** Urldecode string and add keys with values to dict */
bool mdict_urldecode(struct MDict *dict, const char *str, unsigned len);

/** Urlencode dict to string */
bool mdict_urlencode(struct MDict *dict, struct MBuf *dst);

#endif
