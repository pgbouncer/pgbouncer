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

#define NAME_ALL                1
#define NAME_SAMEUSER           2
#define NAME_REPLICATION        4

enum RuleType {
	RULE_LOCAL,
	RULE_HOST,
	RULE_HOSTSSL,
	RULE_HOSTNOSSL,
};

struct NameSlot {
	size_t strlen;
	char str[];
};
struct HBAName {
	unsigned int flags;
	struct StrSet *name_set;
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
	struct IdentMap *identmap;
	int hba_linenr;
};

struct HBA {
	struct List rules;
};

struct Mapping {
	struct List node;
	char *system_user_name;
	char *postgres_user_name;
	unsigned int name_flags;
};

struct IdentMap {
	struct List node;
	char *map_name;
	struct List mappings;
};

struct Ident {
	struct List maps;
};

struct Ident *ident_load_map(const char *fn);
void ident_free(struct Ident *ident);
struct HBA *hba_load_rules(const char *fn, struct Ident *ident);
void hba_free(struct HBA *hba);
struct HBARule *hba_eval(struct HBA *hba, PgAddr *addr, bool is_tls, ReplicationType replication, const char *dbname, const char *username);
