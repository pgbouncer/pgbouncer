/*
 * A string to string dictionary.
 */

#include <usual/mdict.h>

#include <usual/cbtree.h>
#include <usual/mbuf.h>
#include <usual/string.h>
#include <usual/ctype.h>

struct MDict {
	struct CBTree *tree;
	CxMem *cx;
};

struct MDictElem {
	struct MBuf key;
	struct MBuf val;
};

/* hook for CBTree */
static size_t mdict_getkey(void *ctx, void *obj, const void **dst_p)
{
	struct MDictElem *el = obj;
	*dst_p = mbuf_data(&el->key);
	return mbuf_written(&el->key);
}

static bool mdict_free_obj(void *ctx, void *obj)
{
	struct MDictElem *el = obj;
	struct MDict *dict = ctx;
	cx_free(dict->cx, mbuf_data(&el->key));
	cx_free(dict->cx, mbuf_data(&el->val));
	cx_free(dict->cx, el);
	return true;
}

struct MDict *mdict_new(CxMem *cx)
{
	struct MDict *dict;
	dict = cx_alloc(cx, sizeof(struct MDict));
	if (!dict)
		return NULL;
	dict->cx = cx;
	dict->tree = cbtree_create(mdict_getkey, mdict_free_obj, dict, cx);
	if (!dict->tree) {
		cx_free(cx, dict);
		return NULL;
	}
	return dict;
}

void mdict_free(struct MDict *dict)
{
	if (dict) {
		cbtree_destroy(dict->tree);
		cx_free(dict->cx, dict);
	}
}

const struct MBuf *mdict_get_buf(struct MDict *dict, const char *key, unsigned klen)
{
	struct MDictElem *el = cbtree_lookup(dict->tree, key, klen);
	if (!el)
		return NULL;
	return &el->val;
}

const char *mdict_get_str(struct MDict *dict, const char *key, unsigned klen)
{
	const struct MBuf *val = mdict_get_buf(dict, key, klen);
	return val ? mbuf_data(val) : NULL;
}

bool mdict_put_str(struct MDict *dict, const char *key, unsigned klen, const char *val, unsigned vlen)
{
	char *kptr, *vptr = NULL;
	struct MDictElem *el;

	if (val) {
		vptr = cx_alloc(dict->cx, vlen + 1);
		if (!vptr)
			return false;
		memcpy(vptr, val, vlen);
		vptr[vlen] = 0;
	}
	el = cbtree_lookup(dict->tree, key, klen);
	if (el) {
		cx_free(dict->cx, mbuf_data(&el->val));
		mbuf_init_fixed_reader(&el->val, vptr, vlen);
	} else {
		kptr = cx_alloc(dict->cx, klen + 1);
		if (!kptr)
			return false;
		memcpy(kptr, key, klen);
		kptr[klen] = 0;

		el = cx_alloc(dict->cx, sizeof(*el));
		if (!el)
			return false;

		mbuf_init_fixed_reader(&el->key, kptr, klen);
		mbuf_init_fixed_reader(&el->val, vptr, vlen);
		if (!cbtree_insert(dict->tree, el))
			return false;
	}
	return true;
}

bool mdict_del_key(struct MDict *dict, const char *key, unsigned klen)
{
	return cbtree_delete(dict->tree, key, klen);
}

/*
 * walk over key-val pairs
 */

struct WalkerCtx {
	mdict_walker_f cb_func;
	void *cb_arg;
};

static bool walk_helper(void *arg, void *elem)
{
	struct WalkerCtx *ctx = arg;
	struct MDictElem *el = elem;
	return ctx->cb_func(ctx->cb_arg, &el->key, &el->val);
}

bool mdict_walk(struct MDict *dict, mdict_walker_f cb_func, void *cb_arg)
{
	struct WalkerCtx ctx;
	ctx.cb_func = cb_func;
	ctx.cb_arg = cb_arg;
	return cbtree_walk(dict->tree, walk_helper, &ctx);
}

/*
 * urldecode
 */

static int gethex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void *urldec_str(CxMem *cx, const char **src_p, const char *end, unsigned *len_p)
{
	const char *s;
	char *d, *dst;
	int c, len = 0;

	/* estimate size */
	for (s = *src_p; s < end; s++) {
		if (*s == '%')
			s += 2;
		else if (*s == '&' || *s == '=')
			break;
		len++;
	}

	/* allocate room */
	d = dst = cx_alloc(cx, len + 1);
	if (!dst)
		return NULL;

	/* write out */
	for (s = *src_p; s < end; ) {
		if (*s == '%') {
			int h1, h2;
			if (s + 3 > end)
				goto err;
			h1 = gethex(s[1]);
			h2 = gethex(s[2]);
			if (h1 < 0 || h2 < 0)
				goto err;
			c = (h1 << 4) | h2;
			s += 3;
			*d++ = c;
		} else if (*s == '+') {
			*d++ = ' ';
			s++;
		} else if (*s == '&' || *s == '=') {
			break;
		} else {
			*d++ = *s++;
		}
	}
	*d = 0;
	*len_p = d - dst;
	*src_p = s;
	return dst;
err:
	cx_free(cx, dst);
	return NULL;
}

bool mdict_urldecode(struct MDict *dict, const char *str, unsigned len)
{
	const char *s = str;
	const char *end = s + len;
	char *k, *v;
	unsigned klen, vlen;
	struct MDictElem *el;

	while (s < end) {
		v = NULL;
		vlen = 0;
		el = NULL;

		/* read key */
		k = urldec_str(dict->cx, &s, end, &klen);
		if (!k)
			goto fail;

		/* read value */
		if (s < end && *s == '=') {
			s++;
			v = urldec_str(dict->cx, &s, end, &vlen);
			if (!v)
				goto fail;
		}
		if (s < end && *s == '&')
			s++;

		/* insert value */
		el = cbtree_lookup(dict->tree, k, klen);
		if (el) {
			cx_free(dict->cx, mbuf_data(&el->val));
			mbuf_init_fixed_reader(&el->val, v, vlen);
		} else {
			el = cx_alloc(dict->cx, sizeof(*el));
			if (!el)
				goto fail;

			mbuf_init_fixed_reader(&el->key, k, klen);
			mbuf_init_fixed_reader(&el->val, v, vlen);
			if (!cbtree_insert(dict->tree, el))
				goto fail;
		}
	}
	return true;
fail:
	if (k) cx_free(dict->cx, k);
	if (v) cx_free(dict->cx, v);
	if (el) cx_free(dict->cx, el);
	return false;
}

/*
 * urlencode
 */

struct UrlEncCtx {
	struct MBuf *dst;
	bool is_first;
};

static bool urlenc_str(struct MBuf *dst, const struct MBuf *str)
{
	static const char hextbl[] = "0123456789abcdef";
	unsigned len = mbuf_written(str);
	const unsigned char *s = mbuf_data(str);
	const unsigned char *end = s + len;
	bool ok;
	for (; s < end; s++) {
		if (*s == ' ') {
			ok = mbuf_write_byte(dst, '+');
		} else if ((*s < 128) && isalnum(*s)) {
			ok = mbuf_write_byte(dst, *s);
		} else if (*s == '.' || *s == '_') {
			ok = mbuf_write_byte(dst, *s);
		} else {
			ok = mbuf_write_byte(dst, '%');
			ok = ok && mbuf_write_byte(dst, hextbl[*s >> 4]);
			ok = ok && mbuf_write_byte(dst, hextbl[*s & 15]);
		}
		if (!ok)
			return false;
	}
	return true;
}

static bool urlenc_elem(void *arg, const struct MBuf *key, const struct MBuf *val)
{
	struct UrlEncCtx *ctx = arg;
	bool ok;

	if (ctx->is_first) {
		ctx->is_first = false;
	} else {
		ok = mbuf_write_byte(ctx->dst, '&');
		if (!ok)
			return false;
	}

	ok = urlenc_str(ctx->dst, key);
	if (!ok)
		return false;
	if (mbuf_data(val) != NULL) {
		ok = mbuf_write_byte(ctx->dst, '=');
		if (!ok)
			return false;
		ok = urlenc_str(ctx->dst, val);
		if (!ok)
			return false;
	}
	return true;
}

bool mdict_urlencode(struct MDict *dict, struct MBuf *dst)
{
	struct UrlEncCtx ctx;
	ctx.is_first = true;
	ctx.dst = dst;
	return mdict_walk(dict, urlenc_elem, &ctx);
}
