/*
 * Small POSIX-only regex engine.
 *
 * Copyright (c) 2009  Marko Kreen
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
 * Simple recursive matcher, only features are small size
 * and POSIX compatibility.
 *
 * ERE syntax: . * ^ $ [] [[:cname:]] () {} | + ?
 * BRE syntax: . * ^ $ [] [[:cname:]] \(\) \{\} \1-9
 *
 * With REG_RELAXED_SYNTAX, following common escapes will be available:
 *    \b\B\d\D\s\S\w\W   BRE: \|   ERE: \1-9
 *
 * With REG_RELAXED_MATCHING it returns the first match found after applying
 * leftmost-longest to all elements.  It skips the combinatorics to turn it
 * into guaranteed-longest match.
 *
 * Skipped POSIX features:
 * - collation classes: [[. .]]
 * - equivalence classes: [[= =]]
 * - char ranges by locale order: [a-z]  (byte order will be used)
 * - multi-byte chars: UTF-8
 */

#include <usual/regex.h>

#ifndef USE_SYSTEM_REGEX

#include <usual/mempool.h>
#include <usual/ctype.h>
#include <string.h>
#include <stdio.h>

#undef STRICT

/* either dynamic or static decision */
#define STRICT (ctx->strict)

/* how many regmatch_t can be reported */
#define MAX_GROUPS              128

/* max count we want to store, means 'infinite' for simple atoms */
#define MAX_COUNT               0x7fff

/* max count for simple atoms: char, any or class */
#define SIMPLE_MAXCNT(op) (((op)->maxcnt == MAX_COUNT) ? 0x7FFFFFFF : (op)->maxcnt)

#define is_word(c) (isalnum(c) || (c) == '_')

struct Op;
struct ExecCtx;
struct GMatch;

/* Operation type */
enum OpType {
	/* ops that take count */
	OP_CHAR,
	OP_ANY,
	OP_CLASS,
	OP_GROUP,
	OP_BREF,
	/* ops that dont take count */
	OP_BOL,
	OP_EOL,
	OP_WCHANGE,
	OP_NWCHANGE,
	OP_GMATCH,
	OP_FULLMATCH,
};
#define NONCOUNT_OPS_START  OP_BOL

/* regex_t->internal */
struct RegexInt {
	struct Op *root;
	struct Op *glist;
	struct MemPool *pool;
	int flags;
};

/* match function and its setter */
typedef int (*matcher_f)(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm);
static void set_op_type(struct Op *op, enum OpType op_type);

/* List of tokens to be AND-ed together */
struct AndList {
	struct AndList *next;
	struct Op *op_list;
};

/* extra data for group Op */
struct GroupData {
	struct Op *parent;	/* parent group or NULL for first group */
	struct AndList *or_list;/* alternative AndLists */
	struct Op *glist_prev;	/* prev group Op */
	bool has_refs;		/* if bref references it */
};

/* char class data */
struct ClassData {
	uint32_t bitmap[256 / 32];
};

/* operation data */
struct Op {
	struct Op *next;
	matcher_f matcher;
	uint16_t mincnt;
	uint16_t maxcnt;
	uint8_t type;
	union {
		uint8_t grp_no;		/* OP_GROUP: group nr, 0-toplevel */
		char lit;		/* OP_CHAR */
		uint8_t bref;		/* OP_BREF */
	};
	union {
		struct ClassData cdata;
		struct GroupData gdata;
	};
};
#define OP_BASE (offsetof(struct Op, cdata))

/*
 * Operations on ClassData
 */

static bool class_isset(const struct ClassData *cd, unsigned char c)
{
	return cd->bitmap[c / 32] & (1 << (c % 32));
}

static void class_set(struct ClassData *cd, unsigned char c)
{
	cd->bitmap[c / 32] |= (1 << (c % 32));
}

static void class_negate(struct ClassData *cd)
{
	int i;
	class_set(cd, 0);
	for (i = 0; i < 256/32; i++) cd->bitmap[i] ^= -1;
}

/*
 * Parsing code
 */

/* top-level context */
struct ParseCtx {
	regex_t *rx;
	struct RegexInt *rxi;
	struct Op *last_group;
	struct AndList *last_andlist;
	struct Op *last_elem;	/* last op in current OR branch */
	bool gotcnt;		/* count was attached to last op */
	bool strict;		/* strict syntax */
};

static struct AndList *new_andlist(struct ParseCtx *ctx, struct Op *g)
{
	struct AndList *al = mempool_alloc(&ctx->rxi->pool, sizeof(*al));
	if (!al)
		return NULL;
	if (ctx->last_andlist) {
		ctx->last_andlist->next = al;
	} else {
		g->gdata.or_list = al;
	}
	ctx->last_andlist = al;
	return al;
}

static struct Op *new_op(struct ParseCtx *ctx, enum OpType t, int extra)
{
	struct Op *op = mempool_alloc(&ctx->rxi->pool, OP_BASE + extra);
	if (!op)
		return NULL;
	set_op_type(op, t);
	op->mincnt = op->maxcnt = 1;
	ctx->gotcnt = false;

	/* append */
	if (ctx->last_elem) {
		ctx->last_elem->next = op;
	} else if (ctx->last_andlist) {
		ctx->last_andlist->op_list = op;
	} else if (ctx->last_group) {
		struct AndList *alist;
		alist = new_andlist(ctx, ctx->last_group);
		if (!alist)
			return NULL;
		alist->op_list = op;
	}
	ctx->last_elem = op;

	if (t == OP_GROUP) {
		struct Op *parent = ctx->last_group;
		int gno = ++ctx->rx->re_nsub;
		op->grp_no = gno;
		op->gdata.parent = parent;
		op->gdata.glist_prev = ctx->rxi->glist;
		ctx->rxi->glist = op;
		ctx->last_group = op;
		ctx->last_andlist = NULL;
		ctx->last_elem = NULL;
		if (!ctx->rxi->root)
			ctx->rxi->root = op;
	}
	return op;
}

static int op_char(struct ParseCtx *ctx, unsigned c)
{
	struct Op *op = new_op(ctx, OP_CHAR, 0);
	if (!op)
		return REG_ESPACE;
	op->lit = c;
	if ((ctx->rxi->flags & REG_ICASE) && isalpha(c))
		op->lit = tolower(c);
	return 0;
}

static int op_bref(struct ParseCtx *ctx, unsigned c)
{
	struct Op *g, *op;

	op = new_op(ctx, OP_BREF, 0);
	if (!op)
		return REG_ESPACE;
	op->bref = c - '0';

	/* check if valid ref */
	for (g = ctx->last_group; g; g = g->gdata.parent) {
		if (g->grp_no == op->bref)
			return REG_ESUBREG;
	}
	/* tag the group as referenced */
	for (g = ctx->rxi->glist; g; g = g->gdata.glist_prev) {
		if (g->grp_no == op->bref) {
			g->gdata.has_refs = true;
			return 0;
		}
	}
	return REG_ESUBREG;
}

static int op_simple(struct ParseCtx *ctx, enum OpType t)
{
	struct Op *op = new_op(ctx, t, 0);
	if (!op)
		return REG_ESPACE;
	return 0;
}

static int op_count_simple(struct ParseCtx *ctx, int min, int max)
{
	struct Op *op = ctx->last_elem;
	if (!op || ctx->gotcnt)
		return REG_BADRPT;
	if (op->type >= NONCOUNT_OPS_START)
		return REG_BADRPT;
	ctx->gotcnt = true;
	op->mincnt = min;
	op->maxcnt = max;
	return 0;
}

static int op_count_full(struct ParseCtx *ctx, const char **re)
{
	unsigned a, b;
	char *end = (char *)*re;
	bool ext = ctx->rxi->flags & REG_EXTENDED;
	int err;

	/* apply sanity check */
	err = op_count_simple(ctx, 1, 1);
	if (err)
		return err;

	/* parse */
	a = b = strtoul(*re, &end, 10);
	if (end == *re)
		return REG_EBRACE;
	if (*end == ',') {
		*re = end + 1;
		end = (char *)*re;
		b = strtoul(*re, &end, 10);
		if (end == *re)
			b = MAX_COUNT;
	}
	if (a > b || b > MAX_COUNT || a >= MAX_COUNT)
		return REG_BADBR;

	/* check for correct termination */
	if (ext && end[0] == '}') {
		*re = end + 1;
		goto done;
	} else if (!ext && end[0] == '\\' && end[1] == '}') {
		*re = end + 2;
		goto done;
	}

	/* bad fmt, decide between error codes */
	return strchr(end, '}') ? REG_BADBR : REG_EBRACE;

done:
	ctx->last_elem->mincnt = a;
	ctx->last_elem->maxcnt = b;
	return 0;
}

static int op_gstart(struct ParseCtx *ctx)
{
	struct Op *op;
	op = new_op(ctx, OP_GROUP, sizeof(struct GroupData));
	if (!op)
		return REG_ESPACE;
	if (op->grp_no >= MAX_GROUPS)
		return REG_BADPAT;
	return 0;
}

static int finish_branch(struct ParseCtx *ctx)
{
	int err;

	/* disallow empty OR fragments, but not empty groups */
	if (!ctx->last_elem && ctx->last_andlist && STRICT)
		return REG_BADPAT;

	if (ctx->last_group->gdata.parent)
		err = op_simple(ctx, OP_GMATCH);
	else
		err = op_simple(ctx, OP_FULLMATCH);
	if (err)
		return err;
	ctx->last_elem = NULL;
	return 0;
}

static int op_gend(struct ParseCtx *ctx)
{
	struct Op *op = ctx->last_group;
	struct AndList *alist;
	int err;

	if (!op)
		return REG_EPAREN;

	err = finish_branch(ctx);
	if (err)
		return err;
	ctx->last_group = op->gdata.parent;
	ctx->last_elem = op;

	/* recover previous andlist... */
	alist = ctx->last_group->gdata.or_list;
	while (alist && alist->next)
		alist = alist->next;
	ctx->last_andlist = alist;

	return 0;
}

static int op_or(struct ParseCtx *ctx)
{
	struct Op *gop = ctx->last_group;
	struct AndList *alist;
	int err;

	/* disallow empty OR branches */
	if (!ctx->last_elem && STRICT)
		return REG_BADPAT;

	/* start new branch */
	err = finish_branch(ctx);
	if (err)
		return err;
	alist = new_andlist(ctx, gop);
	if (!alist)
		return REG_ESPACE;
	ctx->last_andlist = alist;
	ctx->last_elem = NULL;

	return 0;
}

/*
 * Parse bracketed classes.
 */

static void add_char(struct ClassData *cd, unsigned char c, bool icase)
{
	if (icase && isalpha(c)) {
		class_set(cd, tolower(c));
		class_set(cd, toupper(c));
	} else {
		class_set(cd, c);
	}
}

struct NamedClass {
	const char name[7];
	unsigned char name_len;
	int (*check_func)(int c);
};
static const struct NamedClass ctype_list[] = {
	{ "alnum", 5, isalnum },
	{ "alpha", 5, isalpha },
	{ "blank", 5, isblank },
	{ "cntrl", 5, iscntrl },
	{ "digit", 5, isdigit },
	{ "graph", 5, isgraph },
	{ "lower", 5, islower },
	{ "print", 5, isprint },
	{ "punct", 5, ispunct },
	{ "space", 5, isspace },
	{ "upper", 5, isupper },
	{ "xdigit", 6, isxdigit },
};

static int fill_class(struct ClassData *cd, const char *name, const char **s_p, bool icase)
{
	unsigned c;
	const struct NamedClass *cc = ctype_list;
	for (c = 0; c < ARRAY_NELEM(ctype_list); c++) {
		cc = ctype_list + c;
		if (strncmp(name, cc->name, cc->name_len) != 0)
			continue;
		name += cc->name_len;
		if (name[0] == ':' && name[1] == ']')
			goto found;
		break;
	}
	return *name ? REG_ECTYPE : REG_EBRACK;
found:
	/* fill map */
	for (c = 1; c < 256; c++) {
		if (cc->check_func(c))
			add_char(cd, c, icase);
	}
	*s_p = name + 2;
	return 0;
}

#define MAP_RANGE 0x7FFF0001
#define MAP_END 0x7FFF0002
#define MAP_OTHER 0x7FFF0003

static int get_map_token(struct ParseCtx *ctx, const char **s_p, unsigned *dst_p,
			 bool start, struct ClassData *cd, bool icase)
{
	const char *s = *s_p;
	unsigned res;
	if (*s == '-') {
		if (start || s[1] == ']')
			res = '-';
		else
			res = MAP_RANGE;
		s += 1;
	} else if (*s == ']' && !start) {
		res = MAP_END;
		s++;
	} else if (*s == '[' && (s[1] == '.' || s[1] == ':' || s[1] == '=')) {
		if (s[1] == ':') {
			s += 2;
			*dst_p = MAP_OTHER;
			return fill_class(cd, s, s_p, icase);
		}
		return REG_BADPAT;
	} else {
		res = (unsigned char)*s++;
	}
	*dst_p = res;
	*s_p = s;
	return 0;
}

static int op_class(struct ParseCtx *ctx, const char **re)
{
	const char *s = *re;
	struct ClassData *cd;
	struct Op *op;
	bool not = false, icase = ctx->rxi->flags & REG_ICASE;
	const char *start;
	unsigned tk, c, prevtk = 0;
	bool is_range = false;
	int err;

	if (*s == '^') {
		s++;
		not = true;
	}
	start = s;

	op = new_op(ctx, OP_CLASS, sizeof(struct ClassData));
	if (!op)
		return REG_ESPACE;
	cd = &op->cdata;

	if (not && (ctx->rxi->flags & REG_NEWLINE))
		class_set(cd, '\n');

	while (*s) {
		err = get_map_token(ctx, &s, &tk, s == start, cd, icase);
		if (err)
			return err;

		if (tk == MAP_END) {
			if (prevtk)
				add_char(cd, prevtk, icase);
			goto done;
		} else if (tk == MAP_OTHER) {
			if (is_range)
				return REG_ERANGE;
			if (prevtk)
				add_char(cd, prevtk, icase);
			prevtk = 0;
		} else if (tk == MAP_RANGE) {
			if (!prevtk)
				return REG_ERANGE;
			is_range = true;
		} else if (is_range) {
			if (tk < prevtk)
				return REG_ERANGE;
			for (c = prevtk; c <= tk; c++)
				add_char(cd, c, icase);
			is_range = false;
			prevtk = 0;
		} else {
			if (prevtk)
				add_char(cd, prevtk, icase);
			prevtk = tk;
		}
	}
	return REG_EBRACK;
done:
	*re = s;
	if (not) class_negate(cd);
	return 0;
}

static int op_class_const(struct ParseCtx *ctx, const char *def)
{
	const char *p = def + 1;
	return op_class(ctx, &p);
}

/*
 * Top-level syntax
 */

static int parse_relaxed_escapes(struct ParseCtx *ctx, char c)
{
	if (STRICT)
		return REG_BADPAT;
	switch (c) {
	case 'b': return op_simple(ctx, OP_WCHANGE);
	case 'B': return op_simple(ctx, OP_NWCHANGE);
	case 'w': return op_class_const(ctx, "[_[:alnum:]]");
	case 'W': return op_class_const(ctx, "[^_[:alnum:]]");
	case 'd': return op_class_const(ctx, "[[:digit:]]");
	case 'D': return op_class_const(ctx, "[^[:digit:]]");
	case 's': return op_class_const(ctx, "[[:space:]]");
	case 'S': return op_class_const(ctx, "[^[:space:]]");
	}
	return REG_BADPAT;
}

static int parse_posix_ext(struct ParseCtx *ctx, const char *re)
{
	int err = 0;
	unsigned c;
	int glevel = 0;
loop:
	if (err)
		return err;
	c = *re++;
	switch (c) {
	case 0:
		return (glevel == 0) ? 0 : REG_EPAREN;
	case '(':
		glevel++;
		err = op_gstart(ctx);
		break;
	case ')':
		if (glevel > 0) {
			glevel--;
			err = op_gend(ctx);
		} else {
			err = op_char(ctx, c);	/* POSIX bug */
		}
		break;
	case '|':
		err = op_or(ctx);
		break;
	case '*':
		err = op_count_simple(ctx, 0, MAX_COUNT);
		break;
	case '?':
		err = op_count_simple(ctx, 0, 1);
		break;
	case '+':
		err = op_count_simple(ctx, 1, MAX_COUNT);
		break;
	case '[':
		err = op_class(ctx, &re);
		break;
	case '{':
		err = op_count_full(ctx, &re);
		break;
	case '.':
		err = op_simple(ctx, OP_ANY);
		break;
	case '^':
		err = op_simple(ctx, OP_BOL);
		break;
	case '$':
		err = op_simple(ctx, OP_EOL);
		break;
	case '\\':
		goto escaped;
	default:
		err = op_char(ctx, c);
	}
	goto loop;

escaped:
	c = *re++;
	if (c == 0)
		err = REG_EESCAPE;
	else if (c >= '0' && c <= '9')
		err = STRICT ? REG_BADPAT : op_bref(ctx, c);
	else if (isalpha(c))
		err = parse_relaxed_escapes(ctx, c);
	else
		err = op_char(ctx, c);
	goto loop;
}

static int parse_posix_basic(struct ParseCtx *ctx, const char *re)
{
	int err = 0;
	unsigned c;
	int glevel = 0;
loop:
	if (err)
		return err;
	c = *re++;
	switch (c) {
	case 0:
		return (glevel == 0) ? 0 : REG_EPAREN;
	case '*':
		if (ctx->last_elem && ctx->last_elem->type != OP_BOL)
			err = op_count_simple(ctx, 0, MAX_COUNT);
		else
			err = op_char(ctx, '*');
		break;
	case '.':
		err = op_simple(ctx, OP_ANY);
		break;
	case '[':
		err = op_class(ctx, &re);
		break;
	case '^':
		if (!ctx->last_elem)
			err = op_simple(ctx, OP_BOL);
		else
			err = op_char(ctx, c);
		break;
	case '$':
		if (!*re || (re[0] == '\\' && re[1] == ')'))
			err = op_simple(ctx, OP_EOL);
		else
			err = op_char(ctx, c);
		break;
	case '\\':
		goto escaped;
	default:
		err = op_char(ctx, c);
	}
	goto loop;

escaped:
	c = *re++;
	switch (c) {
	case 0:
		return REG_EESCAPE;
	case '(':
		glevel++;
		err = op_gstart(ctx);
		break;
	case ')':
		glevel--;
		if (glevel < 0)
			return REG_EPAREN;
		err = op_gend(ctx);
		break;
	case '{':
		err = op_count_full(ctx, &re);
		break;
	case '.': case '^': case '$': case '*':
	case '[': case ']': case '\\':
		err = op_char(ctx, c);
		break;
	case '1': case '2': case '3': case '4': case '5':
	case '6': case '7': case '8': case '9':
		err = op_bref(ctx, c);
		break;
	case '|':
		err = STRICT ? REG_BADPAT : op_or(ctx);
		break;
	default:
		err = parse_relaxed_escapes(ctx, c);
	}
	goto loop;
}

/*
 * Public compiling API.
 */

int regcomp(regex_t *rx, const char *re, int flags)
{
	struct ParseCtx ctx;
	struct RegexInt *rxi;
	int err;
	struct MemPool *pool = NULL;

	/* do it first, to allow regfree() */
	memset(rx, 0, sizeof(*rx));

	if (flags & ~(REG_EXTENDED | REG_ICASE | REG_NOSUB | REG_NEWLINE | REG_RELAXED))
		return REG_BADPAT;
	if (!*re)
		return REG_BADPAT;
	rxi = mempool_alloc(&pool, sizeof(*rxi));
	if (!rxi)
		return REG_ESPACE;
	rx->internal = rxi;
	rxi->pool = pool;

	/* initialize rx and local context */
	memset(&ctx, 0, sizeof(ctx));
	ctx.rx = rx;
	ctx.rxi = rxi;
	ctx.strict = !(flags & REG_RELAXED_SYNTAX);
	rxi->flags = flags;

	/* setup group #0 */
	rx->re_nsub = -1;
	err = op_gstart(&ctx);
	if (err)
		goto failed;

	/* launch proper parser */
	if (flags & REG_EXTENDED)
		err = parse_posix_ext(&ctx, re);
	else
		err = parse_posix_basic(&ctx, re);

	/* finalize group #0 */
	if (!err)
		err = finish_branch(&ctx);

	/* relax if details are not needed */
	if (flags & REG_NOSUB) {
		rxi->flags |= REG_RELAXED_MATCHING;
		rx->re_nsub = 0;
	}
failed:
	/* clean up if problems */
	if (err)
		regfree(rx);
	return err;
}

/*
 * Matching code
 */

/* historical best match */
struct HMatch {
	const char *hist_start;
	const char *hist_end;
	int rep_len;		/* if repeated seq, full len thus far */
};

/* per-group-match context */
struct GMatch {
	struct GMatch *parent;	/* parent group */
	const struct Op *owner;	/* Op for this group */
	const char *start;	/* match start */
	const char *end;	/* match end, NULL if no match */
	struct GMatch *prevgm;	/* older stack entry */
	struct HMatch hm_next;	/* best match for following stack entry */
	int count;		/* match nr in repeated seq */
};

/* top context */
struct ExecCtx {
	const regex_t *rx;
	const struct RegexInt *rxi;
	const char *str_start;
	regmatch_t *pmatch;
	int nmatch;
	int flags;
	bool strict;
	const char *last_endpos;
	struct HMatch hm_first[MAX_GROUPS];
	struct GMatch *gm_stack[MAX_GROUPS];
	struct GMatch *gm_cache[MAX_GROUPS];
};

static void push_gm(struct ExecCtx *ctx, struct GMatch *gm)
{
	int gno = gm->owner->grp_no;
	gm->prevgm = ctx->gm_stack[gno];
	ctx->gm_stack[gno] = gm;
}

static void pop_gm(struct ExecCtx *ctx, struct GMatch *gm)
{
	int gno = gm->owner->grp_no;
	ctx->gm_stack[gno] = gm->prevgm;
}

static inline int do_match(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	return op->matcher(ctx, op, str, gm);
}

static int scan_next(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm, int curcnt, int alen)
{
	int err = REG_NOMATCH;
	bool gotmatch = false;

	if (curcnt == op->mincnt)
		return do_match(ctx, op->next, str, gm);

	for (; curcnt >= op->mincnt; curcnt--) {
		err = do_match(ctx, op->next, str, gm);
		if (STRICT && err == 0)
			gotmatch = true;
		else if (err != REG_NOMATCH)
			break;
		str -= alen;
	}
	if (err == REG_NOMATCH && gotmatch)
		err = 0;
	return err;
}

static int match_char(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	bool icase = (ctx->flags & REG_ICASE);
	int c, i, maxcnt = SIMPLE_MAXCNT(op);

	for (i = 0; (i < maxcnt) && str[i]; i++) {
		c = icase ? tolower((unsigned char)str[i]) : str[i];
		if (c != op->lit)
			break;
	}
	return scan_next(ctx, op, str + i, gm, i, 1);
}

static int match_any(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	bool nl = (ctx->flags & REG_NEWLINE);
	int i, maxcnt = SIMPLE_MAXCNT(op);

	for (i = 0; (i < maxcnt) && str[i]; i++) {
		if (nl && str[i] == '\n')
			break;
	}
	return scan_next(ctx, op, str + i, gm, i, 1);
}

static int match_class(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	int i, maxcnt = SIMPLE_MAXCNT(op);

	for (i = 0; (i < maxcnt); i++) {
		if (!class_isset(&op->cdata, str[i]))
			break;
	}
	return scan_next(ctx, op, str + i, gm, i, 1);
}

static int match_bol(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	if (str == ctx->str_start && !(ctx->flags & REG_NOTBOL))
		return do_match(ctx, op->next, str, gm);
	else if (str != ctx->str_start && str[-1] == '\n' && (ctx->flags & REG_NEWLINE))
		return do_match(ctx, op->next, str, gm);
	return REG_NOMATCH;
}

static int match_eol(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	if (*str == '\n' && (ctx->flags & REG_NEWLINE))
		return do_match(ctx, op->next, str, gm);
	else if (*str == 0 && !(ctx->flags & REG_NOTEOL))
		return do_match(ctx, op->next, str, gm);
	return REG_NOMATCH;
}

static int match_wchange(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	bool prevw = (str == ctx->str_start) ? false : is_word(str[-1]);
	bool curw = is_word(str[0]);
	bool ischange = prevw ^ curw;

	if ((op->type == OP_WCHANGE) ? ischange : !ischange)
		return do_match(ctx, op->next, str, gm);
	return REG_NOMATCH;
}

static int match_bref(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	bool icase = ctx->flags & REG_ICASE;
	int i;
	struct GMatch *bgm = ctx->gm_stack[op->bref];
	int blen = (bgm && bgm->end) ? (bgm->end - bgm->start) : -1;

	/* handle no-match, zero-len, zero-count */
	if (blen < 0 && op->mincnt > 0)
		return REG_NOMATCH;
	if (blen <= 0 || op->maxcnt == 0)
		return do_match(ctx, op->next, str, gm);

	/* find max matches */
	for (i = 0; (i < op->maxcnt) && *str; i++) {
		if (icase && strncasecmp(str, bgm->start, blen) != 0)
			break;
		else if (!icase && strncmp(str, bgm->start, blen) != 0)
			break;
		str += blen;
	}
	return scan_next(ctx, op, str, gm, i, blen);
}

static int match_group(struct ExecCtx *ctx, const struct Op *op, const char *str, struct GMatch *gm)
{
	int err = REG_NOMATCH;
	bool gotmatch = false;
	struct GMatch gthis;

	/* per-group-match context */
	memset(&gthis, 0, sizeof(gthis));
	gthis.owner = op;
	gthis.start = str;
	gthis.parent = gm;
	if (gm && gm->owner == op) {
		gthis.parent = gm->parent;
		gthis.count = gm->count + 1;
	}
	gm = &gthis;
	push_gm(ctx, gm);

	if (op->maxcnt > 0) {
		struct AndList *alist = op->gdata.or_list;
		/* check all branches, unless relaxed matching */
		while (alist) {
			err = do_match(ctx, alist->op_list, str, gm);
			if (err == 0 && STRICT) {
				gm->end = NULL;
				gotmatch = true;
			} else if (err != REG_NOMATCH) {
				break;
			}
			alist = alist->next;
		}
	}

	/* is no-match allowed? */
	if ((op->mincnt == 0) && (gm->count == 0)
	    && (err == REG_NOMATCH || (err == 0 && STRICT))) {
		gm->end = NULL;
		err = do_match(ctx, op->next, str, gm->parent);
	}

	pop_gm(ctx, gm);
	return gotmatch ? 0 : err;
}

static int match_gend(struct ExecCtx *ctx, const struct Op *f_op, const char *str, struct GMatch *gm)
{
	int err = REG_NOMATCH;
	const struct Op *op = gm->owner;
	bool zeromatch = (str == gm->start);
	bool gotmatch = false;

	/* ignore follow-up empty matches, unless it has backrefs */
	if (zeromatch && gm->count > 0 && gm->count >= op->mincnt && !gm->owner->gdata.has_refs)
		return REG_NOMATCH;

	/* tag as matched */
	gm->end = str;

	/* try more repeats, stop if count full or last match was zero-length */
	if (gm->count + 1 < op->maxcnt && !zeromatch) {
		err = match_group(ctx, op, str, gm);
		if (err == 0 && STRICT)
			gotmatch = true;
		else if (err != REG_NOMATCH)
			return err;
	}

	/* fail if not enough repeats */
	if (!zeromatch && gm->count + 1 < op->mincnt)
		return err;

	/* continue with parent branch */
	err = do_match(ctx, op->next, str, gm->parent);
	if (err == REG_NOMATCH && gotmatch)
		err = 0;
	return err;
}

/*
 * The juice of POSIX - match weighting.
 */

static int gmatch_hist_cmp(struct ExecCtx *ctx, int gno, struct GMatch *gm, int replen)
{
	struct HMatch *hm = (gm->prevgm) ? &gm->prevgm->hm_next : &ctx->hm_first[gno];
	int gmlen = (gm->end) ? (gm->end - gm->start) : -1;
	int hmlen = (hm->hist_end) ? (hm->hist_end - hm->hist_start) : -1;
	int gmreplen = (gmlen >= 0) ? (gmlen + replen) : replen;
	int hmreplen = ((hmlen >= 0) ? hmlen : 0) + hm->rep_len;
	int gmofs = (gm->end) ? (gm->start - ctx->str_start) : -1;
	int hmofs = (hm->hist_start) ? (hm->hist_start - ctx->str_start) : -1;

	/* prefer rightmost match, to allow preceding elements match more */
	int res = (gmofs - hmofs);

	/* prefer longer repeated match */
	if (res == 0 && gm->count == 0)
		res = (gmreplen - hmreplen);

	/* prefer longer single match */
	if (res == 0)
		res = (gmlen - hmlen);

	return res;
}

static int cmp_gmatches(struct ExecCtx *ctx, int gno, struct GMatch *gm, int replen)
{
	int cmp = 0, gmlen;
	if (gm) {
		/* need to compare preceding groups first */
		gmlen = gm->end ? gm->end - gm->start : 0;
		cmp = cmp_gmatches(ctx, gno, gm->prevgm,
				   (gm->count == 0) ? 0 : (replen + gmlen));
		/* actual comparision */
		if (!cmp) cmp = gmatch_hist_cmp(ctx, gno, gm, replen);
	}
	return cmp;
}

static int gm_resolve_tie(struct ExecCtx *ctx, int gno)
{
	struct GMatch *gm = ctx->gm_stack[gno];
	if (!gm)/* 0-count match is better than no match */
		return ctx->hm_first[gno].hist_start ? -1 : 0;

	return cmp_gmatches(ctx, gno, gm, 0);
}

static void fill_history(struct ExecCtx *ctx, int gno)
{
	struct HMatch *hm;
	int gmlen, rep_len = 0;
	struct GMatch *gm = ctx->gm_stack[gno];
	while (STRICT && gm) {
		hm = (gm->prevgm) ? &gm->prevgm->hm_next : &ctx->hm_first[gno];
		hm->hist_start = gm->start;
		hm->hist_end = gm->end;
		hm->rep_len = rep_len;
		gmlen = gm->end ? (gm->end - gm->start) : 0;
		rep_len += gmlen;
		if (gm->count == 0)
			rep_len = 0;
		gm = gm->prevgm;
	}
}

static void publish_gm(struct ExecCtx *ctx, int gno)
{
	struct GMatch *gm = ctx->gm_stack[gno];
	regmatch_t *rm = ctx->pmatch + gno;

	/* ignore non-matches */
	while (gm && !gm->end)
		gm = gm->prevgm;

	/* require it to be inside reported parent */
	if (gm && gm->parent) {
		int pno = gm->parent->owner->grp_no;
		if (gm->parent != ctx->gm_cache[pno])
			gm = NULL;
	}
	ctx->gm_cache[gno] = gm;

	/* publish new match */
	if (gm) {
		rm->rm_so = gm->start - ctx->str_start;
		rm->rm_eo = gm->end - ctx->str_start;
	} else {
		rm->rm_so = -1;
		rm->rm_eo = -1;
	}
}

/* compare and publish */
static int got_full_match(struct ExecCtx *ctx, const struct Op *f_op, const char *str, struct GMatch *gm)
{
	int gno, cmp;

	/* tag group as matched */
	gm->end = str;

	/* ignore shorter matches */
	if (ctx->last_endpos && str < ctx->last_endpos)
		return 0;

	/* longer or equal length */
	if (str > ctx->last_endpos) {
		ctx->last_endpos = str;
		goto better_match;
	} else if (STRICT && ctx->nmatch > 1) {
		for (gno = 0; gno < ctx->nmatch; gno++) {
			cmp = gm_resolve_tie(ctx, gno);
			if (cmp < 0)
				break;
			if (cmp > 0)
				goto better_match;
		}
	}
	return 0;

better_match:
	for (gno = 0; gno < ctx->nmatch; gno++) {
		publish_gm(ctx, gno);
		fill_history(ctx, gno);
	}
	return 0;
}

/* fill in proper matcher */
static void set_op_type(struct Op *op, enum OpType op_type)
{
	static const matcher_f mlist[] = {
		match_char, match_any, match_class, match_group, match_bref,
		match_bol, match_eol, match_wchange, match_wchange,
		match_gend, got_full_match
	};
	op->matcher = mlist[op_type];
	op->type = op_type;
}

/*
 * Public matching API
 */

int regexec(const regex_t *rx, const char *str, size_t nmatch, regmatch_t pmatch[], int eflags)
{
	int err;
	struct ExecCtx ctx;

	if (eflags & ~(REG_NOTBOL | REG_NOTEOL))
		return REG_BADPAT;

	/* init local context */
	memset(&ctx, 0, sizeof(ctx));
	ctx.pmatch = pmatch;
	ctx.nmatch = nmatch;
	ctx.str_start = str;
	ctx.rx = rx;
	ctx.rxi = rx->internal;
	ctx.flags = ctx.rxi->flags | eflags;

	/* reset pmatch area */
	if (!(ctx.flags & REG_NOSUB))
		memset(pmatch, -1, nmatch * sizeof(regmatch_t));

	/* decide pmatch area that will be used */
	if (!pmatch || (ctx.flags & REG_NOSUB))
		ctx.nmatch = 0;
	else if (nmatch > (size_t)rx->re_nsub + 1)
		ctx.nmatch = rx->re_nsub + 1;
	ctx.strict = !(ctx.flags & REG_RELAXED_MATCHING) && (ctx.nmatch > 0);

	/* execute search */
	str--;
	do {
		str++;
		err = do_match(&ctx, ctx.rxi->root, str, NULL);
	} while ((err == REG_NOMATCH) && *str);

	return err;
}

/*
 * Free parse tree
 */

void regfree(regex_t *rx)
{
	struct RegexInt *rxi;
	if (rx) {
		rxi = rx->internal;
		if (rxi)
			mempool_destroy(&rxi->pool);
		memset(rx, 0, sizeof(*rx));
	}
}

/*
 * Error strings
 */

size_t regerror(int err, const regex_t *rx, char *dst, size_t dstlen)
{
	static const char errlist[][9] = {
		"NOERROR",	/* 0 */
		"NOMATCH",	/* 1 */
		"BADBR",	/* 2 */
		"BADPAT",	/* 3 */
		"BADRPT",	/* 4 */
		"EBRACE",	/* 5 */
		"EBRACK",	/* 6 */
		"ECOLLATE",	/* 7 */
		"ECTYPE",	/* 8 */
		"EESCAPE",	/* 9 */
		"EPAREN",	/* 10 */
		"ERANGE",	/* 11 */
		"ESPACE",	/* 12 */
		"ESUBREG",	/* 13 */
	};
	const char *s = "EUNKNOWN";
	if ((size_t)err < ARRAY_NELEM(errlist))
		s = errlist[err];
	return snprintf(dst, dstlen, "%s", s);
}

#endif /* !USE_SYSTEM_REGEX */
