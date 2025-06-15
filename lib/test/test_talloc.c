#include "test_common.h"

#include <usual/string.h>
#include <usual/talloc.h>
#include <usual/mbuf.h>
#include <usual/list.h>

#undef TALLOC_POS
#define TALLOC_POS(x) x

static int delta;
static int dcount;
static int ptr_nr_counter;

#define CK_MAGIC 0x1EEF

static char log_buf[1024];
static LIST(trace_alloc_list);

struct CheckHeader {
	short magic;
	short ptr_nr;
	int size;
	struct List trace_node;
};

static void m_log(char code, struct CheckHeader *hdr)
{
	char buf[32];
	const char *sep = log_buf[0] ? ", " : "";
	size_t res;
	tt_assert(hdr->magic == CK_MAGIC);
	snprintf(buf, sizeof(buf), "%s%c:%u", sep, code, hdr->ptr_nr);
	res = strlcat(log_buf, buf, sizeof(log_buf));
	tt_assert(res < sizeof(log_buf));
end:;
}

static void *log_alloc(void *ctx, size_t len)
{
	struct CheckHeader *chdr;
	delta += len;
	chdr = cx_alloc(ctx, len + sizeof(*chdr));
	if (!chdr)
		return NULL;
	memset(chdr, 0x89, len + sizeof(*chdr));
	chdr->magic = CK_MAGIC;
	chdr->ptr_nr = ++ptr_nr_counter;
	chdr->size = len;
	list_init(&chdr->trace_node);
	list_append(&trace_alloc_list, &chdr->trace_node);
	m_log('A', chdr);
	return chdr + 1;
}

static void *log_realloc(void *ctx, void *ptr, size_t len)
{
	int olen;
	struct CheckHeader *chdr = ptr;
	chdr--;

	m_log('R', chdr);

	olen = chdr->size;
	list_del(&chdr->trace_node);
	chdr = cx_realloc(ctx, chdr, len + sizeof(*chdr));
	list_append(&trace_alloc_list, &chdr->trace_node);
	chdr->size = len;
	delta -= olen;
	delta += len;
	return chdr + 1;
}

static void log_free(void *ctx, void *ptr)
{
	struct CheckHeader *chdr = ptr;
	chdr--;
	m_log('F', chdr);
	delta -= chdr->size;
	list_del(&chdr->trace_node);
	memset(ptr, 0x95, chdr->size);
	chdr->size = chdr->magic = 0;
	cx_free(ctx, chdr);
}

static const struct CxOps log_ops = {
	log_alloc,
	log_realloc,
	log_free,
};

static const struct CxMem log_libc = {
	&log_ops,
	(void*)&cx_libc_allocator,
};

static void log_reset(void)
{
	struct CheckHeader *chdr;
	struct List *el;

	while (!list_empty(&trace_alloc_list)) {
		//printf("memleak\n");
		el = list_first(&trace_alloc_list);
		chdr = container_of(el, struct CheckHeader, trace_node);
		list_del(&chdr->trace_node);
		memset(chdr, 0x95, chdr->size);
		cx_free(NULL, chdr);
	}
	log_buf[0] = 0;
	delta = 0;
	ptr_nr_counter = 0;
}

#define log_check(x) do { str_check(log_buf, x); log_buf[0] = 0; } while (0)
#define log_check_full(x) do { str_check(log_buf, x); int_check(delta, 0); log_reset(); } while (0)
#define log_check_quick() do {  int_check(delta, 0); log_reset(); } while (0)

static void *create_top(void)
{
	log_reset();
	return talloc_from_cx(&log_libc, 10, "top");
}

static int destructor1(void *ptr)
{
	dcount++;
	return 0;
}

static int destructor2(void *ptr)
{
	dcount++;
	talloc_free(ptr);
	return 0;
}

struct DumpState {
	struct MBuf *dst;
	int prev_depth;
	bool failed;
};

static void dump_cb(const void *ptr, int depth, int max_depth, int is_ref, void *cb_arg)
{
	struct DumpState *st = cb_arg;
	const char *name;

	if (depth == st->prev_depth) {
		if (!mbuf_write_byte(st->dst, ','))
			goto failed;
	}
	while (st->prev_depth < depth) {
		if (!mbuf_write_byte(st->dst, '['))
			goto failed;
		st->prev_depth++;
	}
	while (st->prev_depth > depth) {
		if (!mbuf_write_byte(st->dst, ']'))
			goto failed;
		st->prev_depth--;
	}
	if (is_ref) {
		if (!mbuf_write_byte(st->dst, '>'))
			goto failed;
	}
	name = talloc_get_name(ptr);
	if (!mbuf_write(st->dst, name, strlen(name)))
		goto failed;
	return;
failed:
	st->failed = true;
}

static const char *dump_talloc(void *ptr)
{
	struct DumpState state;
	struct MBuf dst;
	static char buf[1024];

	mbuf_init_fixed_writer(&dst, buf, sizeof(buf));
	state.dst = &dst;
	state.prev_depth = 0;

	talloc_report_depth_cb(ptr, 1, 100, dump_cb, &state);

	while (state.prev_depth > 0) {
		if (!mbuf_write_byte(state.dst, ']'))
			return "failed";
		state.prev_depth--;
	}

	if (!mbuf_write_byte(state.dst, 0))
		return "failed";
	return buf;
}


static void test_talloc_basic(void *zzz)
{
	void *p, *p2, *p3;
	void *top;
	const char *name1 = "name1";
	struct CheckHeader *chp;

	/* basic */
	top = create_top();
	tt_assert(top != NULL);
	p2 = talloc_size(top, 16);
	tt_assert(p2 != NULL);
	p = talloc_named_const(top, 16, "p");
	tt_assert(p != NULL);
	p3 = talloc_size(top, 16);
	tt_assert(p3 != NULL);
	p = talloc_realloc_fn(p, p, 500);
	//talloc_set_name_const(p, "p-realloc");
	str_check(dump_talloc(top), "[top[talloc_size,talloc_realloc_fn,talloc_size]]");
	tt_assert(p);
	talloc_free(top);
	log_check_quick();

	/* name */
	top = create_top();
	tt_assert(top != NULL);
	str_check(talloc_get_name(top), "top");
	talloc_set_name_const(top, name1);
	tt_assert(talloc_get_name(top) == name1);
	talloc_set_name(top, "foo: %d", 10);
	str_check(talloc_get_name(top), "foo: 10");
	tt_assert(talloc_check_name(top, "xx") == NULL);
	tt_assert(talloc_check_name(top, "foo: 10") == top);
	talloc_free(top);
	log_check_full("A:1, A:2, F:2, F:1");

	top = create_top();
	p = talloc(top, struct CheckHeader);
	str_check(dump_talloc(top), "[top[struct CheckHeader]]");
	talloc_free(top);
	log_check_full("A:1, A:2, F:2, F:1");

	/* init & NULL ctx */
	top = talloc_init("test std init: %d", 1);
	tt_assert(talloc_check_name(top, "test std init: 1"));
	p = talloc(top, struct CheckHeader);
	tt_assert(p != NULL);
	tt_assert(talloc_get_size(p) == sizeof(struct CheckHeader));
	tt_assert(talloc_check_name(p, "struct CheckHeader"));
	talloc_free(top);

	/* other inits */
	top = create_top();
	tt_assert(top != NULL);
	p = talloc_named_const(top, 10, name1);
	tt_assert(talloc_check_name(p, name1));
	p2 = talloc_named(p, 10, "test: %d", 1);
	tt_assert(talloc_check_name(p2, "test: 1"));
	p3 = talloc_zero_named_const(p2, 1024, "zero");
	tt_assert(talloc_check_name(p3, "zero"));

	tt_assert(talloc_parent(p3) == p2);
	tt_assert(talloc_parent_name(p2) == name1);
	tt_assert(talloc_is_parent(p2, p3));
	tt_assert(talloc_is_parent(top, p2));

	talloc_free(top);
	log_check_quick();

	/* destructor */
	top = create_top();
	p = talloc_named_const(top, 10, name1);
	p2 = talloc_named_const(top, 10, name1);
	p3 = talloc_named_const(top, 10, name1);
	tt_assert(top && p && p2 && p3);
	talloc_set_destructor(p, NULL);
	talloc_set_destructor(p2, destructor1);
	talloc_set_destructor(p3, destructor2);
	talloc_free(p3);
	int_check(dcount, 1);
	talloc_free(top);
	int_check(delta, 0);
	int_check(dcount, 2);

	/* types */
	top = create_top();
	chp = talloc_ptrtype(top, chp);
	tt_assert(chp);
	talloc_free(top);
	int_check(delta, 0);
end:;
}

static void test_talloc_strings(void *zzz)
{
	char *a, *b, *c;
	const char *x = "foo\0bar";
	void *top;

	log_reset();

	top = create_top();

	a = talloc_memdup(top, x, 8);
	tt_assert(a && talloc_get_size(a) == 8);
	tt_assert(memcmp(a, x, 8) == 0);

	b = talloc_strdup(top, "baz");
	tt_assert(b && talloc_get_size(b) == 4);


	a = talloc_strdup_append(a, "zzz");
	str_check(a, "foozzz");

	c = talloc_memdup(top, x, 8);
	c = talloc_strdup_append_buffer(c, "zzz");
	int_check(talloc_get_size(c), 11);
	tt_assert(memcmp(c, "foo\0barzzz", 11) == 0);

	a = talloc_strndup(top, "qwe", 2);
	int_check(talloc_get_size(a), 3);
	str_check(a, "qw");

	talloc_free(top);
	log_check_quick();
end:;
}

static int destruct_calls;
static int test_destructor(void *ptr)
{
	destruct_calls++;
	return 0;
}

static void test_talloc_refs(void *zzz)
{
	CxMem *cx = &log_libc;
	void *top, *top2;
	void *p1, *p2, *p3, *ref;
	int err;

	talloc_enable_null_tracking();

	/* simple ref, freed from new parent */
	top = talloc_from_cx(cx, 0, "top");	tt_assert(top != NULL);
	p1 = talloc_strdup(top, "p1");		tt_assert(p1);
	p2 = talloc_strdup(top, "p2");		tt_assert(p2);
	ref = talloc_reference(p2, p1);		tt_assert(ref == p1);
	str_check(dump_talloc(top), "[top[p1,p2[>p1]]]");
	err = talloc_free(p2);			tt_assert(err == 0);
	str_check(dump_talloc(top), "[top[p1]]");
	err = talloc_free(top);			tt_assert(err == 0);
	log_check_full("A:1, A:2, A:3, A:4, F:4, F:3, F:2, F:1");

	/* simple ref, free old parent */
	top = talloc_from_cx(cx, 0, "top");	tt_assert(top != NULL);
	p1 = talloc_strdup(top, "p1");		tt_assert(p1);
	p2 = talloc_strdup(top, "p2");		tt_assert(p2);
	ref = talloc_reference(p2, p1);		tt_assert(ref == p1);
	str_check(dump_talloc(top), "[top[p1,p2[>p1]]]");
	err = talloc_free(p1);			tt_assert(err == -1);
	err = talloc_unlink(top, p1);		tt_assert(err == 0);
	str_check(dump_talloc(top), "[top[p2[p1]]]");
	err = talloc_free(top);			tt_assert(err == 0);
	log_check_full("A:1, A:2, A:3, A:4, F:4, F:2, F:3, F:1");

	/* ref loop */
	top = talloc_from_cx(cx, 0, "top");	tt_assert(top != NULL);
	top2 = talloc_strdup(top, "top2");
	p1 = talloc_strdup(top2, "p1");		tt_assert(p1);
	p2 = talloc_strdup(p1, "p2");		tt_assert(p2);
	p3 = talloc_strdup(p1, "p3");		tt_assert(p2);
	talloc_set_destructor(top2, test_destructor);
	talloc_set_destructor(p2, test_destructor);
	ref = talloc_reference(p3, p1);		tt_assert(ref == p1);
	str_check(dump_talloc(top), "[top[top2[p1[p2,p3[>p1]]]]]");

	/* fail */
	//printf("\n");
	//talloc_set_debug(1);
	talloc_free(top2);
	talloc_set_debug(0);

	str_check(dump_talloc(top), "[top]");
	//str_check(dump_talloc(NULL), "[]");
	talloc_free(top);
	//str_check(dump_talloc(NULL), "[UNNAMED[p1[p2,p3[>p1]]]]");
	//int_check(destruct_calls, 2);
	//log_check_full("A:1, A:2, A:3, A:4, A:5, A:6, F:6, F:2, F:1");
	log_reset();

	talloc_disable_null_tracking();
end:;
}

static void test_talloc_memlimit(void *pppp)
{
	void *top, *l1, *l2, *l3, *tmp;
	int err;

	/* create memlimit ptr */
	top = talloc_from_cx(&log_libc, 0, "top");	tt_assert(top);
	l1 = talloc_strdup(top, "l1");		tt_assert(l1);
	err = talloc_set_memlimit(l1, 1000);	tt_assert(err == 0);

	/* too large */
	tmp = talloc_size(l1, 1000);		tt_assert(tmp == NULL);
	str_check(dump_talloc(top), "[top[l1[.memlimit]]]");

	/* ok */
	l2 = talloc_named_const(l1, 500, "l2");	tt_assert(l2);
	/* second level, too large */
	tmp = talloc_size(l2, 500);		tt_assert(tmp == NULL);
	str_check(dump_talloc(top), "[top[l1[.memlimit,l2]]]");

	/* steal into memlimit */
	l3 = talloc_named_const(top, 500, "l3");
	tmp = talloc_steal(l2, l3);		tt_assert(tmp == l3);
	str_check(dump_talloc(top), "[top[l1[.memlimit,l2[l3]]]]");
	tmp = talloc_size(l2, 10);		tt_assert(tmp == NULL);

	/* steal away from memlimit */
	tmp = talloc_steal(top, l3);		tt_assert(tmp == l3);
	str_check(dump_talloc(top), "[top[l1[.memlimit,l2]l3]]");
	tmp = talloc_size(l2, 10);		tt_assert(tmp);

	talloc_free(top);
	log_check_quick();
end:;
}

static void test_talloc_reparent(void *zzz)
{
	CxMem *cx = &log_libc;
	void *top;
	void *p1, *p2, *p3, *ref;
	int err;

	log_reset();
	top = talloc_from_cx(cx, 10, "top");	tt_assert(top);
	p1 = talloc_strdup(top, "p1");		tt_assert(p1);
	p2 = talloc_strdup(p1, "p2");		tt_assert(p2);
	p3 = talloc_strdup(p2, "p3");		tt_assert(p3);
	ref = talloc_reference(p1, p3);		tt_assert(ref == p3);
	str_check(dump_talloc(top), "[top[p1[>p3,p2[p3]]]]");
	err = talloc_free(p2);			tt_assert(err == 0);
	str_check(dump_talloc(top), "[top[p1[p3]]]");
	talloc_free(top);
	log_check_quick();
end:;
}

struct testcase_t talloc_tests[] = {
	{ "basic", test_talloc_basic },
	{ "strings", test_talloc_strings },
	{ "refs", test_talloc_refs },
	{ "memlimit", test_talloc_memlimit },
	{ "reparent", test_talloc_reparent },
	END_OF_TESTCASES
};
