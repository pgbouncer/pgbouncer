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
#include <regex.h>

enum RuleType {
	RULE_LOCAL,
	RULE_HOST,
	RULE_HOSTSSL,
	RULE_HOSTNOSSL,
};

#define NAME_ALL	1
#define NAME_SAMEUSER	2

struct NameSlot {
	size_t strlen;
	char str[];
};

struct HBAName {
	unsigned int flags;
	struct StrSet *name_set;
};

struct HBAOpts {
  char *name;
  char *value;

	char *usermap;
	char *pamservice;
	bool pam_use_hostname;
	bool ldaptls;
	char *ldapserver;
	int	 ldapport;
	char *ldapbinddn;
	char *ldapbindpasswd;
	char *ldapsearchattribute;
	char *ldapbasedn;
	int  ldapscope;
	char *ldapprefix;
	char *ldapsuffix;
	bool clientcert;
	char *krb_realm;
	bool include_realm;
	bool compat_realm;
	bool upn_username;
	char *radiusserver;
	char *radiussecret;
	char *radiusidentifier;
	int  radiusport;
};

struct HBARule {
	struct List node;
	enum RuleType rule_type;
	int rule_method;
	int rule_af;
	uint8_t rule_addr[16];
	uint8_t rule_mask[16];
	struct HBAName db_name;
	struct HBAName user_name;
  struct HBAOpts auth_opts;
};

struct HBA {
	struct List rules;
};

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
bool parse_hba_auth_opt( struct HBARule *rule, char *buf);

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
	tmp = realloc(p->buf, tmplen+1);
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
		for (s = p->pos+1; s[0]; s++) {
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
		for (s2 = p->pos+1; s2 < s; s2++) {
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
		if (!tok_buf_check(p, s - p->pos))
			return TOK_FAIL;
		memcpy(p->buf, p->pos, s - p->pos);
		p->buf[s - p->pos] = 0;
		p->pos = s;
		p->cur_tok = TOK_IDENT;
		p->cur_tok_str = p->buf;

	}
	return p->cur_tok;
}

static bool eat(struct TokParser *p, enum TokType ttype)
{
	if (p->cur_tok == ttype) {
		next_token(p);
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

static bool parse_namefile(struct HBAName *hname, const char *fn, bool is_db)
{
	FILE *f;
	ssize_t len;
	char *ln = NULL;
	size_t buflen = 0;
	int linenr;
	bool ok = false;
	struct TokParser tp;

	init_parser(&tp);

	f = fopen(fn, "r");
	if (!f) {
		free(fn);
		return false;
	}
	for (linenr = 1; ; linenr++) {
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
	free(fn);
	free(ln);
	fclose(f);
	return ok;
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
				return false;
			}
			if (eat_kw(tp, "samegroup")) {
				return false;
			}
			if (eat_kw(tp, "replication")) {
				return false;
			}
		}

		if (expect(tp, TOK_IDENT, &tok)) {
			if (tok[0] == '+') {
				return false;
			}

			if (tok[0] == '@') {
				bool ok;
				const char *fn;
				fn = path_join_dirname(parent_filename, tok + 1);
				if (!fn)
					return false;
				ok = parse_namefile(hname, fn, is_db);
				free(fn);
				if (!ok)
					return false;
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
	free(rule);
}

static bool parse_addr(struct HBARule *rule, const char *addr)
{
	if (inet_pton(AF_INET6, addr, rule->rule_addr)) {
		rule->rule_af = AF_INET6;
	} else if (inet_pton(AF_INET, addr, rule->rule_addr)) {
		rule->rule_af = AF_INET;
	} else {
		return false;
	}
	return true;
}

static bool parse_nmask(struct HBARule *rule, const char *nmask)
{
	char *end = NULL;
	unsigned long bits;
	unsigned int i;
	errno = 0;
	bits = strtoul(nmask, &end, 10);
	if (errno || *end) {
		return false;
	}
	if (rule->rule_af == AF_INET && bits > 32) {
		return false;
	}
	if (rule->rule_af == AF_INET6 && bits > 128) {
		return false;
	}
	for (i = 0; i < bits/8; i++)
		rule->rule_mask[i] = 255;
	if (bits % 8)
		rule->rule_mask[i] = 255 << (8 - (bits % 8));
	return true;
}

static bool bad_mask(struct HBARule *rule)
{
	int i, bytes = rule->rule_af == AF_INET ? 4 : 16;
	uint8_t res = 0;
	for (i = 0; i < bytes; i++)
		res |= rule->rule_addr[i] & (255 ^ rule->rule_mask[i]);
	return !!res;
}

static bool parse_line(struct HBA *hba, struct TokParser *tp, int linenr, const char *parent_filename)
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

	rule = calloc(sizeof(*rule), 1);
	if (!rule) {
		log_warning("hba: no mem for rule");
		goto failed;
	}
	rule->rule_type = rtype;

	if (!parse_names(&rule->db_name, tp, true, parent_filename))
		goto failed;
	if (!parse_names(&rule->user_name, tp, true, parent_filename))
		goto failed;

	if (rtype == RULE_LOCAL) {
		rule->rule_af = AF_UNIX;
	} else {
		if (!expect(tp, TOK_IDENT, &addr)) {
			log_warning("hba line %d: did not find address - %d - '%s'", linenr, tp->cur_tok, tp->buf);
			goto failed;
		}
		nmask = strchr(addr, '/');
		if (nmask) {
			*nmask++ = 0;
		}

		if (!parse_addr(rule, addr)) {
			log_warning("hba line %d: failed to parse address - %s", linenr, addr);
			goto failed;
		}
		
		if (nmask) {
			if (!parse_nmask(rule, nmask)) {
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
			if (!inet_pton(rule->rule_af, mask, rule->rule_mask)) {
				log_warning("hba line %d: failed to parse mask: %s", linenr, mask);
				goto failed;
			}
			next_token(tp);
		}
		if (bad_mask(rule)) {
			char buf1[128], buf2[128];
			log_warning("Addres does not match mask in %s line #%d: %s / %s", parent_filename, linenr,
				    inet_ntop(rule->rule_af, rule->rule_addr, buf1, sizeof buf1),
				    inet_ntop(rule->rule_af, rule->rule_mask, buf2, sizeof buf2));
		}
	}

	if (eat_kw(tp, "trust")) {
		rule->rule_method = AUTH_TRUST;
	} else if (eat_kw(tp, "reject")) {
		rule->rule_method = AUTH_REJECT;
	} else if (eat_kw(tp, "md5")) {
		rule->rule_method = AUTH_MD5;
	} else if (eat_kw(tp, "password")) {
		rule->rule_method = AUTH_PLAIN;
	} else if (eat_kw(tp, "peer")) {
		rule->rule_method = AUTH_PEER;
	} else if (eat_kw(tp, "cert")) {
		rule->rule_method = AUTH_CERT;
	} else {
		log_warning("hba line %d: unsupported method: buf=%s", linenr, tp->buf);
		goto failed;
	}

  if(parse_hba_auth_opt( rule, tp->buf ))
  {
    while(eat(tp,TOK_IDENT))
    {
      parse_hba_auth_opt( rule, tp->buf );
    }
  }

	if (!eat(tp, TOK_EOL)) {
		log_warning("hba line %d: unsupported parameters", linenr);
		goto failed;
	}

	list_append(&hba->rules, &rule->node);
	return true;
failed:
	rule_free(rule);
	return false;
}

struct HBA *hba_load_rules(const char *fn)
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
	if (!f)
		goto out;

	for (linenr = 1; ; linenr++) {
		len = getline(&ln, &lnbuf, f);
		if (len < 0)
			break;
		parse_from_string(&tp, ln);
		if (!parse_line(hba, &tp, linenr, fn)) {
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

static bool match_inet4(const struct HBARule *rule, PgAddr *addr)
{
	const uint32_t *src, *base, *mask;
	if (pga_family(addr) != AF_INET)
		return false;
	src = (uint32_t *)&addr->sin.sin_addr.s_addr;
	base = (uint32_t *)rule->rule_addr;
	mask = (uint32_t *)rule->rule_mask;
	return (src[0] & mask[0]) == base[0];
}

static bool match_inet6(const struct HBARule *rule, PgAddr *addr)
{
	const uint32_t *src, *base, *mask;
	if (pga_family(addr) != AF_INET6)
		return false;
	src = (uint32_t *)addr->sin6.sin6_addr.s6_addr;
	base = (uint32_t *)rule->rule_addr;
	mask = (uint32_t *)rule->rule_mask;
	return (src[0] & mask[0]) == base[0] && (src[1] & mask[1]) == base[1] &&
		(src[2] & mask[2]) == base[2] && (src[3] & mask[3]) == base[3];
}

int hba_eval(struct HBA *hba, PgSocket *client)
{
	struct List *el;
	struct HBARule *rule;
  PgAddr *addr;
  bool is_tls;
  const char *dbname;
  char *username;
	unsigned int dbnamelen ;
	unsigned int unamelen ;

  addr     = &client->remote_addr;
  is_tls   = !!client->sbuf.tls;
  dbname   = client->db->name;
  username = client->auth_user->name;

  dbnamelen = strlen(dbname);
  unamelen = strlen(username);
	if (!hba)
		return AUTH_REJECT;

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
		} else if (rule->rule_af == AF_INET) {
			if (!match_inet4(rule, addr))
				continue;
		} else if (rule->rule_af == AF_INET6) {
			if (!match_inet6(rule, addr))
				continue;
		} else {
			continue;
		}

		/* match db & user */
		if (!name_match(&rule->db_name, dbname, dbnamelen, username))
			continue;
		if (!name_match(&rule->user_name, username, unamelen, dbname))
			continue;

    /* apply usermap */
    if( rule->auth_opts.name )
    {
      if( (rule->rule_method == AUTH_CERT) && is_tls )
      {
        // Compare to the CN entry returned in client.c
        if(get_usermap_tls(client->auth_user->matched_name,client->auth_user->name,rule->auth_opts.value))
        {
          client->auth_user->has_map = true;
        }
      }
      else if ( rule->rule_method == AUTH_PEER ) {
        // Save the current name
        /* client->auth_user->matched_name = *username; */
        get_usermap(username,rule->auth_opts.value);
      }
    }

		/* rule matches */
		return rule->rule_method;
	}
	return AUTH_REJECT;
}

bool parse_hba_auth_opt( struct HBARule *rule, char *buf)
{
  char *name = strdup(buf);
  char *val  = strchr(name, '=');
  bool res = false;

  if ( val != NULL ) {
    *val++ = 0;
    if ( strcmp( name, "map") == 0) {
      if( 
          rule->rule_method != AUTH_PEER &&
          rule->rule_method != AUTH_CERT
        )
      {
        res = false;
        goto exit;
      }
      rule->auth_opts.name  = strdup(name);
      rule->auth_opts.value = strdup(val);
      res = true;
    }
    else if (strcmp(name, "clientcert") == 0)
    {
      /*
       * Since we require ctHostSSL, this really can never happen on
       * non-SSL-enabled builds, so don't bother checking for USE_SSL.
       */
      if ( rule->rule_type != RULE_HOSTSSL )
      {
        log_error("clientcert can only be configured for \"hostssl\" rows");
        res = false;
        goto exit;
      }
      if (strcmp(val, "1") == 0)
      {
        // TODO : Check
        // if (!secure_loaded_verify_locations())
        // {
        //   ereport(LOG,
        //       (errcode(ERRCODE_CONFIG_FILE_ERROR),
        //        errmsg("client certificates can only be checked if a root certificate store is available"),
        //        errhint("Make sure the configuration parameter \"%s\" is set.", "ssl_ca_file"),
        //        errcontext("line %d of configuration file \"%s\"",
        //          line_num, HbaFileName)));
        //   return false;
        // }
        rule->auth_opts.clientcert = true;
        res = true;
      }
      else
      {
        if ( rule->rule_method == AUTH_CERT )
        {
          log_error("clientcert can not be set to 0 when using \"cert\" authentication");
          res = false;
          goto exit;
        }
        rule->auth_opts.clientcert = false;
        res = true;
      }
    }
    else if (strcmp(name, "pamservice") == 0)
    {
      /* REQUIRE_AUTH_OPTION(uaPAM, "pamservice", "pam"); */
      rule->auth_opts.pamservice = strdup(val);
      res = true;
    }
    else if (strcmp(name, "pam_use_hostname") == 0)
    {
      /* REQUIRE_AUTH_OPTION(uaPAM, "pam_use_hostname", "pam"); */
      if (strcmp(val, "1") == 0)
      {
        rule->auth_opts.pam_use_hostname = true;
      }
      else
      {
        rule->auth_opts.pam_use_hostname = false;
      }

      res = true;

    }
    else if (strcmp(name, "ldapurl") == 0)
    {
// #ifdef LDAP_API_FEATURE_X_OPENLDAP
//       LDAPURLDesc *urldata;
//       int			rc;
// #endif
// 
//       REQUIRE_AUTH_OPTION(uaLDAP, "ldapurl", "ldap");
// #ifdef LDAP_API_FEATURE_X_OPENLDAP
//       rc = ldap_url_parse(val, &urldata);
//       if (rc != LDAP_SUCCESS)
//       {
//         ereport(LOG,
//             (errcode(ERRCODE_CONFIG_FILE_ERROR),
//              errmsg("could not parse LDAP URL \"%s\": %s", val, ldap_err2string(rc))));
//         return false;
//       }
// 
//       if (strcmp(urldata->lud_scheme, "ldap") != 0)
//       {
//         ereport(LOG,
//             (errcode(ERRCODE_CONFIG_FILE_ERROR),
//              errmsg("unsupported LDAP URL scheme: %s", urldata->lud_scheme)));
//         ldap_free_urldesc(urldata);
//         return false;
//       }
// 
//       hbaline->ldapserver = pstrdup(urldata->lud_host);
//       hbaline->ldapport = urldata->lud_port;
//       hbaline->ldapbasedn = pstrdup(urldata->lud_dn);
// 
//       if (urldata->lud_attrs)
//         hbaline->ldapsearchattribute = pstrdup(urldata->lud_attrs[0]);		/* only use first one */
//       hbaline->ldapscope = urldata->lud_scope;
//       if (urldata->lud_filter)
//       {
//         ereport(LOG,
//             (errcode(ERRCODE_CONFIG_FILE_ERROR),
//              errmsg("filters not supported in LDAP URLs")));
//         ldap_free_urldesc(urldata);
//         return false;
//       }
//       ldap_free_urldesc(urldata);
// #else							/* not OpenLDAP */
//       ereport(LOG,
//           (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
//            errmsg("LDAP URLs not supported on this platform")));
// #endif   /* not OpenLDAP */
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldaptls") == 0)
    {
    //   REQUIRE_AUTH_OPTION(uaLDAP, "ldaptls", "ldap");
    //   if (strcmp(val, "1") == 0)
    //     hbaline->ldaptls = true;
    //   else
    //     hbaline->ldaptls = false;
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldapserver") == 0)
    {
    //  REQUIRE_AUTH_OPTION(uaLDAP, "ldapserver", "ldap");
    //  hbaline->ldapserver = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldapport") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaLDAP, "ldapport", "ldap");
      // hbaline->ldapport = atoi(val);
      // if (hbaline->ldapport == 0)
      // {
      //   ereport(LOG,
      //       (errcode(ERRCODE_CONFIG_FILE_ERROR),
      //        errmsg("invalid LDAP port number: \"%s\"", val),
      //        errcontext("line %d of configuration file \"%s\"",
      //          line_num, HbaFileName)));
      //   return false;
      // }
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldapbinddn") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaLDAP, "ldapbinddn", "ldap");
      // hbaline->ldapbinddn = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldapbindpasswd") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaLDAP, "ldapbindpasswd", "ldap");
      // hbaline->ldapbindpasswd = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldapsearchattribute") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaLDAP, "ldapsearchattribute", "ldap");
      // hbaline->ldapsearchattribute = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldapbasedn") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaLDAP, "ldapbasedn", "ldap");
      // hbaline->ldapbasedn = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldapprefix") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaLDAP, "ldapprefix", "ldap");
      // hbaline->ldapprefix = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "ldapsuffix") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaLDAP, "ldapsuffix", "ldap");
      // hbaline->ldapsuffix = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "krb_realm") == 0)
    {
      // if (rule->auth_method != uaGSS &&
      //     rule->auth_method != uaSSPI)
        // INVALID_AUTH_OPTION("krb_realm", gettext_noop("gssapi and sspi"));
        // hbaline->krb_realm = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "include_realm") == 0)
    {
      // if (hbaline->auth_method != uaGSS &&
      //     hbaline->auth_method != uaSSPI)
      //   INVALID_AUTH_OPTION("include_realm", gettext_noop("gssapi and sspi"));
      if (strcmp(val, "1") == 0)
      {
        rule->auth_opts.include_realm = true;
      }
      else
      {
        rule->auth_opts.include_realm = false;
      }
      res = true;
    }
    else if (strcmp(name, "compat_realm") == 0)
    {
      // if (hbaline->auth_method != uaSSPI)
      //   INVALID_AUTH_OPTION("compat_realm", gettext_noop("sspi"));
      // if (strcmp(val, "1") == 0)
      //   hbaline->compat_realm = true;
      // else
      //   hbaline->compat_realm = false;
        res = false;
        goto exit;
    }
    else if (strcmp(name, "upn_username") == 0)
    {
      // if (hbaline->auth_method != uaSSPI)
      //   INVALID_AUTH_OPTION("upn_username", gettext_noop("sspi"));
      // if (strcmp(val, "1") == 0)
      //   hbaline->upn_username = true;
      // else
      //   hbaline->upn_username = false;
        res = false;
        goto exit;
    }
    else if (strcmp(name, "radiusserver") == 0)
    {
     // struct addrinfo *gai_result;
     //   struct addrinfo hints;
     //   int			ret;
  
     //   REQUIRE_AUTH_OPTION(uaRADIUS, "radiusserver", "radius");
  
     //   MemSet(&hints, 0, sizeof(hints));
     //   hints.ai_socktype = SOCK_DGRAM;
     //   hints.ai_family = AF_UNSPEC;
  
     //   ret = pg_getaddrinfo_all(val, NULL, &hints, &gai_result);
     //   if (ret || !gai_result)
     //   {
     //     ereport(LOG,
     //         (errcode(ERRCODE_CONFIG_FILE_ERROR),
     //          errmsg("could not translate RADIUS server name \"%s\" to address: %s",
     //            val, gai_strerror(ret)),
     //          errcontext("line %d of configuration file \"%s\"",
     //            line_num, HbaFileName)));
     //     if (gai_result)
     //       pg_freeaddrinfo_all(hints.ai_family, gai_result);
     //     return false;
     //   }
     //   pg_freeaddrinfo_all(hints.ai_family, gai_result);
     //   hbaline->radiusserver = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "radiusport") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaRADIUS, "radiusport", "radius");
      // hbaline->radiusport = atoi(val);
      // if (hbaline->radiusport == 0)
      // {
      //   ereport(LOG,
      //       (errcode(ERRCODE_CONFIG_FILE_ERROR),
      //        errmsg("invalid RADIUS port number: \"%s\"", val),
      //        errcontext("line %d of configuration file \"%s\"",
      //          line_num, HbaFileName)));
      //   return false;
      // }
        res = false;
        goto exit;
    }
    else if (strcmp(name, "radiussecret") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaRADIUS, "radiussecret", "radius");
      // hbaline->radiussecret = pstrdup(val);
        res = false;
        goto exit;
    }
    else if (strcmp(name, "radiusidentifier") == 0)
    {
      // REQUIRE_AUTH_OPTION(uaRADIUS, "radiusidentifier", "radius");
      // hbaline->radiusidentifier = pstrdup(val);
        res = false;
        goto exit;
    }
    else
    {
      log_error("unrecognized authentication option name: \"%s\"", name);
      res = false;
      goto exit;
    }
  }

exit:
  free(name);
  return res;
}

void hba_load_map( char *fn ,  struct MapList *mlist)
{
  struct HBAIdent *map_ident = NULL;
	FILE *f = NULL;
	char *ln = NULL;
	size_t lnbuf = 0;
	ssize_t len;
	int linenr;
	struct TokParser tp;

  if (!mlist) {
    return;
  }

  list_init(&mlist->maps);
	init_parser(&tp);

	f = fopen(fn, "r");
	if (!f)
  {
		free(fn);
    log_error("no ident file, please set cf_auth_ident_file");
    return;
  }

	for (linenr = 1; ; linenr++) {
    map_ident = calloc(sizeof(*map_ident), 1);
    if (!map_ident) {
      log_warning("hba: no mem for map_ident");
      fclose(f);
      goto finish;
    }

		len = getline(&ln, &lnbuf, f);
		if (len < 0)
    {
      free(map_ident);
			break;
    }

    parse_from_string(&tp, ln);
    
    if( tp.cur_tok == TOK_EOL   ||
        tp.cur_tok == TOK_FAIL  ||
        tp.cur_tok == TOK_COMMA
      )
    {
      free(map_ident);
      continue;
    }

    map_ident->mapname = strdup(tp.cur_tok_str);
    if(!eat(&tp, TOK_IDENT))
    {
      free(map_ident);
      continue;
    }

    map_ident->sys_name = strdup(tp.cur_tok_str);
    if(!eat(&tp, TOK_IDENT))
    {
      free(map_ident);
      continue;
    }


    map_ident->db_name = strdup(tp.cur_tok_str);

    list_append(&mlist->maps, &map_ident->node);

		/* if (!parse_line(hba, &tp, linenr, fn)) { */
		/* 	 Ignore line, but parse to the end. */ 
		/* 	continue; */
		/* } */
	}

	if (!eat(&tp, TOK_IDENT)) {
		log_warning("Malformed line %d", linenr);
	}

finish:
  map_ident = NULL;
  free(ln);
  fclose(f);
  free_parser(&tp);
  return;
}

void get_usermap( char *uname, char *map_name )
{
  // Chercher une règle mname matchant uname 
  struct List *el;
  struct HBAIdent *map;
  extern struct MapList *map_list;
  char *regex;
  int nm_len,err;
  regex_t preg;

  if( !map_list )
  {
    return;
  }

  list_for_each(el, &map_list->maps){

    map = container_of(el, struct HBAIdent, node);
    if ( strcmp( map->mapname, map_name) != 0 ) {
      continue;
    }

    if( strcmp( uname, map->sys_name) == 0 )
    {

      if( strlen(map->db_name) <= MAX_USERNAME )
      {
        strcpy( uname, map->db_name);
      }
      return;
      
    } else if ( map->sys_name[0] == '/' )
    {
      //regex case
      nm_len = 0;
      while( map->sys_name[nm_len] != '\0' )
      {
        nm_len++;
      }
      nm_len--;
      
      regex = strdup(map->sys_name+1);
      /* regex[nm_len-1] = '\0'; */

      // Compile
      err = regcomp (&preg, regex, REG_EXTENDED);
      if( !err )
      {
        int match;
        match = regexec (&preg, uname, 0, NULL, 0);
        regfree (&preg);

        if (match == 0)
        {
          
          if( strlen(map->db_name) <= MAX_USERNAME )
          {
            strcpy( uname, map->db_name);
          }
          return;
        }
        else if (match == REG_NOMATCH)
        {
          return;
        } 
        else
        {
          char *text;
          size_t size;

          size = regerror (err, &preg, NULL, 0);
          text = malloc (sizeof (*text) * size);
          if (text)
          {
            regerror (err, &preg, text, size);
            log_warning( "%s\n",text);
            free (text);
          }
          else
          {
            log_warning("No memory for text");
          }
          return;
        }
      }
      else
      {
        log_warning("Couldnt compile regex, no memory left");
      }

      return;
    }
  }
  // No rule found
  return;

}

bool get_usermap_tls( char *CN, char* uname, char *map_name )
{
  char *name = strdup(CN);
  get_usermap(name, map_name);

  if( strcmp(name, uname) == 0)
  {
    // There's a rule matching and submitted user
    return true;
  }

  free(name);
  return false;
}
