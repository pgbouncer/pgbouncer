/*
 * Host-Based-Access-control file support.
 *
 * Copyright (c) 2015 Marko Kreen
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

#include "bouncer.h"

#include <usual/cxextra.h>
#include <usual/cbtree.h>
#include <usual/fileutil.h>
#include <usual/socket.h>
#include <usual/string.h>

/*
 * StrSet
 */

struct StrSetNode {
	unsigned int s_len;
	char s_val[FLEX_ARRAY];
};

struct StrSet {
	CxMem *pool;
	unsigned count;
	unsigned alloc;
	struct StrSetNode **nodes;
	struct CBTree *cbtree;
};

struct StrSet *strset_new(CxMem *cx);
void strset_free(struct StrSet *set);
bool strset_add(struct StrSet *set, const char *str, unsigned int len);
bool strset_contains(struct StrSet *set, const char *str, unsigned int len);

struct StrSet *strset_new(CxMem *cx)
{
	struct StrSet *set;
	CxMem *pool;

	pool = cx_new_pool(cx, 1024, 0);
	if (!pool)
		return NULL;
	set = cx_alloc(pool, sizeof *set);
	if (!set)
		return NULL;
	set->pool = pool;
	set->cbtree = NULL;
	set->count = 0;
	set->alloc = 10;
	set->nodes = cx_alloc0(pool, set->alloc * sizeof(struct StrSet *));
	if (!set->nodes) {
		cx_destroy(pool);
		return NULL;
	}
	return set;
}

static size_t strset_node_key(void *ctx, void *obj, const void **ptr_p)
{
	struct StrSetNode *node = obj;
	*ptr_p = node->s_val;
	return node->s_len;
}

bool strset_add(struct StrSet *set, const char *str, unsigned int len)
{
	struct StrSetNode *node;
	unsigned int i;
	bool ok;

	if (strset_contains(set, str, len))
		return true;

	node = cx_alloc(set->pool, offsetof(struct StrSetNode, s_val) + len + 1);
	if (!node)
		return false;
	node->s_len = len;
	memcpy(node->s_val, str, len);
	node->s_val[len] = 0;

	if (set->count < set->alloc) {
		set->nodes[set->count++] = node;
		return true;
	}

	if (!set->cbtree) {
		set->cbtree = cbtree_create(strset_node_key, NULL, set, set->pool);
		if (!set->cbtree)
			return false;
		for (i = 0; i < set->count; i++) {
			ok = cbtree_insert(set->cbtree, set->nodes[i]);
			if (!ok)
				return false;
		}
	}
	ok = cbtree_insert(set->cbtree, node);
	if (!ok)
		return false;
	set->count++;
	return true;
}

bool strset_contains(struct StrSet *set, const char *str, unsigned int len)
{
	unsigned int i;
	struct StrSetNode *node;
	if (set->cbtree)
		return cbtree_lookup(set->cbtree, str, len) != NULL;
	for (i = 0; i < set->count; i++) {
		node = set->nodes[i];
		if (node->s_len != len)
			continue;
		if (memcmp(node->s_val, str, len) == 0)
			return true;
	}
	return false;
}

void strset_free(struct StrSet *set)
{
	if (set)
		cx_destroy(set->pool);
}

/*
 * Parse HBA tokens.
 */

enum TokType {
	TOK_STRING,
	TOK_IDENT,
	TOK_COMMA,
	TOK_FAIL,
	TOK_EOL
};

struct TokParser {
	const char *pos;
	enum TokType cur_tok;
	char *cur_tok_str;

	char *buf;
	size_t buflen;
};

static bool tok_buf_check(struct TokParser *p, size_t len)
{
	size_t tmplen;
	char *tmp;
	if (p->buflen >= len)
		return true;
	tmplen = len*2;
	tmp = realloc(p->buf, tmplen);
	if (!tmp)
		return false;
	p->buf = tmp;
	p->buflen = tmplen;
	return true;
}

static enum TokType next_token(struct TokParser *p)
{
	const char *s, *s2;
	char *dst;
	if (p->cur_tok == TOK_EOL)
		return TOK_EOL;
	p->cur_tok_str = NULL;
	p->cur_tok = TOK_FAIL;

	while (p->pos[0] && isspace((unsigned char)p->pos[0]))
		p->pos++;

	if (p->pos[0] == '#' || p->pos[0] == '\0') {
		p->cur_tok = TOK_EOL;
		p->pos = NULL;
	} else if (p->pos[0] == ',') {
		p->cur_tok = TOK_COMMA;
		p->pos++;
	} else if (p->pos[0] == '"') {
		for (s = p->pos + 1; s[0]; s++) {
			if (s[0] == '"') {
				if (s[1] == '"')
					s++;
				else
					break;
			}
		}
		if (s[0] != '"' || !tok_buf_check(p, s - p->pos))
			return TOK_FAIL;
		dst = p->buf;
		for (s2 = p->pos + 1; s2 < s; s2++) {
			*dst++ = *s2;
			if (*s2 == '"') s2++;
		}
		*dst = 0;
		p->pos = s + 1;
		p->cur_tok = TOK_STRING;
		p->cur_tok_str = p->buf;
	} else {
		for (s = p->pos + 1; *s; s++) {
			if (*s == ',' || *s == '#' || *s == '"')
				break;
			if (isspace((unsigned char)*s))
				break;
		}
		if (!tok_buf_check(p, s - p->pos + 1))
			return TOK_FAIL;
		memcpy(p->buf, p->pos, s - p->pos);
		p->buf[s - p->pos] = 0;
		p->pos = s;
		p->cur_tok = TOK_IDENT;
		p->cur_tok_str = p->buf;
	}
	return p->cur_tok;
}

static void eat_all(struct TokParser *p)
{
	p->cur_tok = TOK_EOL;
}

static bool eat(struct TokParser *p, enum TokType ttype)
{
	if (p->cur_tok == ttype) {
		next_token(p);
		return true;
	}
	return false;
}

/* Do not get next token, just check value */
static bool check_kw(struct TokParser *p, const char *kw)
{
	if (p->cur_tok == TOK_IDENT && strcmp(kw, p->cur_tok_str) == 0) {
		return true;
	}
	return false;
}

static bool eat_kw(struct TokParser *p, const char *kw)
{
	if (p->cur_tok == TOK_IDENT && strcmp(kw, p->cur_tok_str) == 0) {
		next_token(p);
		return true;
	}
	return false;
}

static bool expect(struct TokParser *tp, enum TokType ttype, const char **str_p)
{
	if (tp->cur_tok == ttype) {
		*str_p = tp->buf;
		return true;
	}
	return false;
}

static char *path_join(const char *p1, const char *p2)
{
	size_t len1, len2;
	char *res = NULL, *pos;

	if (p2[0] == '/' || p1[0] == 0 || !memcmp(p1, ".", 2))
		return strdup(p2);
	len1 = strlen(p1);
	len2 = strlen(p2);
	res = malloc(len1 + len2 + 2 + 1);
	if (res) {
		memcpy(res, p1, len1);
		pos = res + len1;
		if (pos[-1] != '/')
			*pos++ = '/';
		memcpy(pos, p2, len2 + 1);
	}
	return res;
}

static char *path_join_dirname(const char *parent, const char *fn)
{
	char *tmp, *res;
	const char *basedir;
	if (fn[0] == '/')
		return strdup(fn);
	tmp = strdup(parent);
	if (!tmp)
		return NULL;
	basedir = dirname(tmp);
	res = path_join(basedir, fn);
	free(tmp);
	return res;
}

static void init_parser(struct TokParser *p)
{
	memset(p, 0, sizeof(*p));
}

static void parse_from_string(struct TokParser *p, const char *str)
{
	p->pos = str;
	p->cur_tok = TOK_COMMA;
	p->cur_tok_str = NULL;
	next_token(p);
}

static void free_parser(struct TokParser *p)
{
	free(p->buf);
	p->buf = NULL;
}

static bool parse_names(struct HBAName *hname, struct TokParser *p, bool is_db, const char *parent_filename);
static bool parse_ident_name(const char **ident_name, struct TokParser *tp, bool *is_name_all);

static bool parse_namefile(struct HBAName *hname, const char *fn, bool is_db)
{
	FILE *f;
	ssize_t len;
	char *ln = NULL;
	size_t buflen = 0;
	bool ok = false;
	struct TokParser tp;

	init_parser(&tp);

	f = fopen(fn, "r");
	if (!f) {
		return false;
	}
	for (;;) {
		len = getline(&ln, &buflen, f);
		if (len < 0) {
			ok = true;
			break;
		}
		parse_from_string(&tp, ln);
		if (!parse_names(hname, &tp, is_db, fn))
			break;
	}
	free_parser(&tp);
	free(ln);
	fclose(f);
	return ok;
}

static bool parse_ident_name(const char **ident_name, struct TokParser *tp, bool *is_name_all)
{
	if (eat_kw(tp, "all")) {
		*is_name_all = true;
		return true;
	}

	if (!expect(tp, TOK_IDENT, ident_name)) {
		if (!expect(tp, TOK_STRING, ident_name)) {
			return false;
		}
	}

	return true;
}

static bool parse_names(struct HBAName *hname, struct TokParser *tp, bool is_db, const char *parent_filename)
{
	const char *tok;
	while (1) {
		if (eat_kw(tp, "all")) {
			hname->flags |= NAME_ALL;
			goto eat_comma;
		}
		if (is_db) {
			if (eat_kw(tp, "sameuser")) {
				hname->flags |= NAME_SAMEUSER;
				goto eat_comma;
			}
			if (eat_kw(tp, "samerole")) {
				log_warning("samerole is not supported");
				return false;
			}
			if (eat_kw(tp, "samegroup")) {
				log_warning("samegroup is not supported");
				return false;
			}
			if (eat_kw(tp, "replication")) {
				hname->flags |= NAME_REPLICATION;
				goto eat_comma;
			}
		}

		if (expect(tp, TOK_IDENT, &tok)) {
			if (tok[0] == '+') {
				return false;
			}

			if (tok[0] == '@') {
				bool ok;
				char *fn;
				fn = path_join_dirname(parent_filename, tok + 1);
				if (!fn)
					return false;
				ok = parse_namefile(hname, fn, is_db);
				free(fn);
				if (!ok)
					return false;
				next_token(tp);
				goto eat_comma;
			}
			/* fallthrough */
		} else if (expect(tp, TOK_STRING, &tok)) {
			/* fallthrough */
		} else {
			return false;
		}

		/*
		 * TOK_IDENT or TOK_STRING as plain name.
		 */

		if (!hname->name_set) {
			hname->name_set = strset_new(NULL);
			if (!hname->name_set)
				return false;
		}
		if (!strset_add(hname->name_set, tok, strlen(tok)))
			return false;
		next_token(tp);
eat_comma:
		if (!eat(tp, TOK_COMMA))
			break;
	}
	return true;
}

static void rule_free(struct HBARule *rule)
{
	strset_free(rule->db_name.name_set);
	strset_free(rule->user_name.name_set);
	free(rule->auth_options);
	free(rule);
}

static bool parse_addr(struct HBAAddress *haddress, const char *addr)
{
	if (inet_pton(AF_INET6, addr, haddress->addr)) {
		haddress->family = AF_INET6;
	} else if (inet_pton(AF_INET, addr, haddress->addr)) {
		haddress->family = AF_INET;
	} else {
		return false;
	}
	return true;
}

static bool parse_nmask(struct HBAAddress *haddress, const char *nmask)
{
	char *end = NULL;
	unsigned long bits;
	unsigned int i;
	errno = 0;
	bits = strtoul(nmask, &end, 10);
	if (errno || *end) {
		return false;
	}
	if (haddress->family == AF_INET && bits > 32) {
		return false;
	}
	if (haddress->family == AF_INET6 && bits > 128) {
		return false;
	}
	for (i = 0; i < bits/8; i++)
		haddress->mask[i] = 255;
	if (bits % 8)
		haddress->mask[i] = 255 << (8 - (bits % 8));
	return true;
}

static bool bad_mask(struct HBAAddress *haddress)
{
	int i, bytes = haddress->family == AF_INET ? 4 : 16;
	uint8_t res = 0;
	for (i = 0; i < bytes; i++)
		res |= haddress->addr[i] & (255 ^ haddress->mask[i]);
	return !!res;
}

static bool match_map(struct HBARule *rule, struct Ident *ident, const char *mapname)
{
	struct List *el;
	struct IdentMap *map;

	if (!ident)
		return false;

	list_for_each(el, &ident->maps) {
		map = container_of(el, struct IdentMap, node);

		if (strcmp(map->map_name, mapname) == 0) {
			rule->identmap = map;
			return true;
		}
	}

	return false;
}

static bool parse_map_definition(struct HBARule *rule, struct Ident *ident, struct TokParser *tp, int linenr)
{
	const char *str;
	char *val;

	if (!expect(tp, TOK_IDENT, &str))
		return true;

	val = strchr(str, '=');

	if (val == NULL || strncmp(str, "map=", 4) != 0) {
		log_warning("hba line %d: Ident map %s is malformed. It is not in map=value format.", linenr, str);
		return false;
	}

	val++;

	next_token(tp);

	if (!match_map(rule, ident, val)) {
		log_warning("hba line %d: Ident map %s is not found in ident config file", linenr, val);
		return false;
	}

	return true;
}
static void mapping_free(struct Mapping *mapping)
{
	free(mapping->system_user_name);
	free(mapping->postgres_user_name);
	free(mapping);
}

static void ident_map_free(struct IdentMap *ident_map)
{
	struct List *el, *tmp;
	struct Mapping *mapping;

	if (!ident_map)
		return;

	list_for_each_safe(el, &ident_map->mappings, tmp) {
		mapping = container_of(el, struct Mapping, node);
		list_del(&mapping->node);
		mapping_free(mapping);
	}

	free(ident_map->map_name);
	free(ident_map);
}

static bool find_ident_map(struct Ident *ident, const char *mapname, struct IdentMap **ident_map)
{
	struct List *el;

	list_for_each(el, &ident->maps) {
		*ident_map = container_of(el, struct IdentMap, node);

		if (!strcmp((*ident_map)->map_name, mapname))
			return true;
	}

	return false;
}

static bool parse_ident_line(struct Ident *ident, struct TokParser *tp, int linenr)
{
	const char *map_name = NULL;
	char *map_name_copy = NULL;
	const char *system_user_name = NULL;
	const char *postgres_user_name = NULL;
	struct IdentMap *ident_map = NULL;
	struct Mapping *mapping = NULL;

	bool is_name_all = false;

	if (eat(tp, TOK_EOL)) {
		return true;
	}

	mapping = calloc(1, sizeof(*mapping));

	if (!mapping) {
		log_warning("ident: no mem for parsing mapping");
		return false;
	}

	if (!expect(tp, TOK_IDENT, &map_name)) {
		goto failed;
	}

	map_name_copy = strdup(map_name);
	if (!map_name_copy) {
		log_warning("ident: no mem for map_name");
		goto failed;
	}

	next_token(tp);

	if (!expect(tp, TOK_IDENT, &system_user_name)) {
		if (!expect(tp, TOK_STRING, &system_user_name))
			goto failed;
	}

	mapping->system_user_name = strdup(system_user_name);
	if (!mapping->system_user_name) {
		log_warning("ident: no mem for system_user_name");
		goto failed;
	}

	next_token(tp);


	if (!parse_ident_name(&postgres_user_name, tp, &is_name_all)) {
		goto failed;
	}

	if (is_name_all) {
		mapping->name_flags |= NAME_ALL;
	} else {
		mapping->postgres_user_name = strdup(postgres_user_name);
		if (!mapping->postgres_user_name) {
			log_warning("ident: no mem for postgres_user_name");
			goto failed;
		}
	}

	next_token(tp);

	if (!eat(tp, TOK_EOL)) {
		log_warning("ident line %d: unsupported parameters", linenr);
		goto failed;
	}


	if (find_ident_map(ident, map_name_copy, &ident_map)) {
		list_append(&ident_map->mappings, &mapping->node);
		free(map_name_copy);
		map_name_copy = NULL;
	} else {
		ident_map = calloc(1, sizeof(*ident_map));

		if (!ident_map) {
			log_warning("ident: no mem for parsing ident_map");
			goto failed;
		}

		ident_map->map_name = map_name_copy;
		map_name_copy = NULL;
		list_init(&ident_map->mappings);
		list_append(&ident_map->mappings, &mapping->node);
		list_append(&ident->maps, &ident_map->node);
	}

	return true;

failed:
	mapping_free(mapping);
	ident_map_free(ident_map);
	free(map_name_copy);
	return false;
}

static bool parse_line(struct HBA *hba, struct Ident *ident, struct TokParser *tp, int linenr, const char *parent_filename)
{
	const char *addr = NULL, *mask = NULL;
	enum RuleType rtype;
	char *nmask = NULL;
	struct HBARule *rule = NULL;

	if (eat_kw(tp, "local")) {
		rtype = RULE_LOCAL;
	} else if (eat_kw(tp, "host")) {
		rtype = RULE_HOST;
	} else if (eat_kw(tp, "hostssl")) {
		rtype = RULE_HOSTSSL;
	} else if (eat_kw(tp, "hostnossl")) {
		rtype = RULE_HOSTNOSSL;
	} else if (eat(tp, TOK_EOL)) {
		return true;
	} else {
		log_warning("hba line %d: unknown type", linenr);
		return false;
	}

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		log_warning("hba: no mem for rule");
		return false;
	}
	rule->rule_type = rtype;

	if (!parse_names(&rule->db_name, tp, true, parent_filename))
		goto failed;
	if (!parse_names(&rule->user_name, tp, true, parent_filename))
		goto failed;

	if (rtype == RULE_LOCAL) {
		rule->address.family = AF_UNIX;
	} else if (eat_kw(tp, "all")) {
		rule->address.flags |= ADDRESS_ALL;
	} else {
		if (!expect(tp, TOK_IDENT, &addr)) {
			log_warning("hba line %d: did not find address - %d - '%s'", linenr, tp->cur_tok, tp->buf);
			goto failed;
		}
		nmask = strchr(addr, '/');
		if (nmask) {
			*nmask++ = 0;
		}

		if (!parse_addr(&rule->address, addr)) {
			log_warning("hba line %d: failed to parse address - %s", linenr, addr);
			goto failed;
		}

		if (nmask) {
			if (!parse_nmask(&rule->address, nmask)) {
				log_warning("hba line %d: invalid mask", linenr);
				goto failed;
			}
			next_token(tp);
		} else {
			next_token(tp);
			if (!expect(tp, TOK_IDENT, &mask)) {
				log_warning("hba line %d: did not find mask", linenr);
				goto failed;
			}
			if (!inet_pton(rule->address.family, mask, rule->address.mask)) {
				log_warning("hba line %d: failed to parse mask: %s", linenr, mask);
				goto failed;
			}
			next_token(tp);
		}
		if (bad_mask(&rule->address)) {
			char buf1[128], buf2[128];
			log_warning("address does not match mask in %s line #%d: %s / %s", parent_filename, linenr,
				    inet_ntop(rule->address.family, rule->address.addr, buf1, sizeof buf1),
				    inet_ntop(rule->address.family, rule->address.mask, buf2, sizeof buf2));
		}
	}

	if (eat_kw(tp, "trust")) {
		rule->rule_method = AUTH_TYPE_TRUST;
	} else if (eat_kw(tp, "reject")) {
		rule->rule_method = AUTH_TYPE_REJECT;
	} else if (eat_kw(tp, "md5")) {
		rule->rule_method = AUTH_TYPE_MD5;
	} else if (eat_kw(tp, "password")) {
		rule->rule_method = AUTH_TYPE_PLAIN;
	} else if (eat_kw(tp, "peer")) {
		rule->rule_method = AUTH_TYPE_PEER;
	} else if (eat_kw(tp, "cert")) {
		rule->rule_method = AUTH_TYPE_CERT;
	} else if (eat_kw(tp, "scram-sha-256")) {
		rule->rule_method = AUTH_TYPE_SCRAM_SHA_256;
	} else if (check_kw(tp, "ldap")) {
		rule->rule_method = AUTH_TYPE_LDAP;
	} else {
		log_warning("hba line %d: unsupported method: buf=%s", linenr, tp->buf);
		goto failed;
	}

	if (rule->rule_method == AUTH_TYPE_LDAP) {
		if ((rule->auth_options = strdup(tp->pos)) == NULL) {
			log_warning("hba line %d: cannot get auth_options: buf=%s", linenr, tp->pos);
			goto failed;
		}
		eat_all(tp);
	}

	if (!parse_map_definition(rule, ident, tp, linenr)) {
		goto failed;
	}

	if (!eat(tp, TOK_EOL)) {
		log_warning("hba line %d: unsupported parameters", linenr);
		goto failed;
	}

	rule->hba_linenr = linenr;
	list_append(&hba->rules, &rule->node);
	return true;
failed:
	rule_free(rule);
	return false;
}

struct Ident *ident_load_map(const char *fn)
{
	struct Ident *ident = NULL;
	FILE *f = NULL;
	char *ln = NULL;
	size_t lnbuf = 0;
	ssize_t len;
	int linenr;

	struct TokParser tp;

	if (fn == NULL)
		return NULL;

	init_parser(&tp);

	ident = malloc(sizeof *ident);
	if (!ident)
		goto out;

	list_init(&ident->maps);

	f = fopen(fn, "r");

	if (!f) {
		log_error("could not open ident config file %s: %s", fn, strerror(errno));
		goto out;
	}

	for (linenr = 1; ; linenr++) {
		len = getline(&ln, &lnbuf, f);
		if (len < 0)
			break;

		parse_from_string(&tp, ln);

		if (!parse_ident_line(ident, &tp, linenr)) {
			/* Tell the admin where to look for the problem. */
			log_warning("could not parse ident config line %d", linenr);
			/* Ignore line, but parse to the end. */
			continue;
		}
	}

out:
	free_parser(&tp);
	free(ln);

	if (f)
		fclose(f);
	return ident;
}

struct HBA *hba_load_rules(const char *fn, struct Ident *ident)
{
	struct HBA *hba = NULL;
	FILE *f = NULL;
	char *ln = NULL;
	size_t lnbuf = 0;
	ssize_t len;
	int linenr;
	struct TokParser tp;

	init_parser(&tp);

	hba = malloc(sizeof *hba);
	if (!hba)
		goto out;

	list_init(&hba->rules);

	f = fopen(fn, "r");
	if (!f) {
		log_error("could not open hba config file %s: %s", fn, strerror(errno));
		goto out;
	}

	for (linenr = 1; ; linenr++) {
		len = getline(&ln, &lnbuf, f);
		if (len < 0)
			break;
		parse_from_string(&tp, ln);
		if (!parse_line(hba, ident, &tp, linenr, fn)) {
			/* Tell the admin where to look for the problem. */
			log_warning("could not parse hba config line %d", linenr);
			/* Ignore line, but parse to the end. */
			continue;
		}
	}
out:
	free_parser(&tp);
	free(ln);
	if (f)
		fclose(f);
	return hba;
}

void ident_free(struct Ident *ident)
{
	struct List *el, *tmp;
	struct IdentMap *map;

	if (!ident)
		return;

	list_for_each_safe(el, &ident->maps, tmp) {
		map = container_of(el, struct IdentMap, node);
		list_del(&map->node);
		ident_map_free(map);
	}
	free(ident);
}

void hba_free(struct HBA *hba)
{
	struct List *el, *tmp;
	struct HBARule *rule;
	if (!hba)
		return;
	list_for_each_safe(el, &hba->rules, tmp) {
		rule = container_of(el, struct HBARule, node);
		list_del(&rule->node);
		rule_free(rule);
	}
	free(hba);
}

static bool name_match(struct HBAName *hname, const char *name, unsigned int namelen, const char *pair)
{
	if (hname->flags & NAME_ALL)
		return true;
	if ((hname->flags & NAME_SAMEUSER) && strcmp(name, pair) == 0)
		return true;
	if (hname->name_set)
		return strset_contains(hname->name_set, name, namelen);
	return false;
}

static bool match_inet4(const struct HBAAddress *haddress, PgAddr *addr)
{
	const uint32_t *src, *base, *mask;
	if (pga_family(addr) != AF_INET)
		return false;
	src = (uint32_t *)&addr->sin.sin_addr.s_addr;
	base = (uint32_t *)haddress->addr;
	mask = (uint32_t *)haddress->mask;
	return (src[0] & mask[0]) == base[0];
}

static bool match_inet6(const struct HBAAddress *haddress, PgAddr *addr)
{
	const uint32_t *src, *base, *mask;
	if (pga_family(addr) != AF_INET6)
		return false;
	src = (uint32_t *)addr->sin6.sin6_addr.s6_addr;
	base = (uint32_t *)haddress->addr;
	mask = (uint32_t *)haddress->mask;
	return (src[0] & mask[0]) == base[0] && (src[1] & mask[1]) == base[1] &&
	       (src[2] & mask[2]) == base[2] && (src[3] & mask[3]) == base[3];
}

static bool address_match(const struct HBAAddress *haddress, PgAddr *addr)
{
	if (haddress->flags & ADDRESS_ALL)
		return true;
	switch (haddress->family) {
	case AF_INET:
		return match_inet4(haddress, addr);
	case AF_INET6:
		return match_inet6(haddress, addr);
	default:
		return false;
	}
}

struct HBARule * hba_eval(struct HBA *hba, PgAddr *addr, bool is_tls, ReplicationType replication, const char *dbname, const char *username)
{
	struct List *el;
	struct HBARule *rule;
	unsigned int dbnamelen = strlen(dbname);
	unsigned int unamelen = strlen(username);

	if (!hba)
		return NULL;

	list_for_each(el, &hba->rules) {
		rule = container_of(el, struct HBARule, node);

		/* match address */
		if (pga_is_unix(addr)) {
			if (rule->rule_type != RULE_LOCAL)
				continue;
		} else if (rule->rule_type == RULE_LOCAL) {
			continue;
		} else if (rule->rule_type == RULE_HOSTSSL && !is_tls) {
			continue;
		} else if (rule->rule_type == RULE_HOSTNOSSL && is_tls) {
			continue;
		} else if (!address_match(&rule->address, addr)) {
			continue;
		}

		/* match db & user */
		if (replication == REPLICATION_PHYSICAL) {
			if (!(rule->db_name.flags & NAME_REPLICATION)) {
				continue;
			}
		} else {
			if (!name_match(&rule->db_name, dbname, dbnamelen, username))
				continue;
		}
		if (!name_match(&rule->user_name, username, unamelen, dbname))
			continue;

		/* rule matches */
		return rule;
	}
	return NULL;
}
