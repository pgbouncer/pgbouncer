/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
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

#include "bouncer.h"

static void ps_free_list(struct PSList* list) {
	unsigned i;
	for (i = 0; i < list->len; i++)
		free(list->elem[i]);
	free(list->elem);
	list->elem = NULL;
	list->len = 0;
	list->cap = 0;
}

static void ps_add_to_list(struct PSList* list, const char* s) {
	unsigned i;
	unsigned newcap;
	char** newelem;

	for (i = 0; i < list->len; i++) {
		if (strcmp(list->elem[i], s) == 0) {
			/* already exists */
			return; 
		}
	}
	if (i == list->cap) {
		/* grow */
		newcap = list->cap * 2;
		if (newcap == 0)
			newcap = 2;
		newelem = realloc(list->elem, newcap * sizeof(char*));
		/* TODO: handle realloc failure */
		list->elem = newelem;
		list->cap = newcap;
	}

	list->elem[i] = strdup(s);
	/* TODO: handle strdup failure */
	list->len++;
}

static void ps_remove_from_list(struct PSList* list, const char* s) {
	unsigned i;
	for (i = 0; i < list->len; i++) {
		if (strcmp(list->elem[i], s) == 0) {
			free(list->elem[i]);
			memmove(&list->elem[i], &list->elem[i + 1], list->len - 1 - i);
			list->len--;
			return;
		}
	}
}

void ps_register(PgSocket *client, const char* ps) {
	ps_add_to_list(&client->prepared_statements, ps);

	if (cf_log_prepared_statements)
		slog_debug(client, "Register prepared statement '%s' (size = %d)", ps, (int) ps_size(client));
}

void ps_unregister(PgSocket *client, const char* ps) {
	ps_remove_from_list(&client->prepared_statements, ps);

	if (cf_log_prepared_statements)
		slog_debug(client, "Unregister prepared statement '%s' (size = %d)", ps, (int) ps_size(client));
}

unsigned ps_size(PgSocket *client) {
	return client->prepared_statements.len;
}

void ps_free(PgSocket *client) {
	ps_free_list(&client->prepared_statements);
}

/*
#define HTAB_KEY_T unsigned
#define HTAB_VAL_T char *
#include <usual/hashtab-impl.h>
#include <usual/hashing/xxhash.h>

static bool hash_str_eq(const htab_val_t curval, const void *arg) {
	const char* s1 = curval;
	const char* s2 = arg;
	return strcmp(s1, s2) == 0;
}

static htab_key_t hash_str(const char* s) {
	return xxhash(s, strlen(s), 0);
}

static void ps_unregister_string(PgSocket *client, const char* ps) {
	if (!client->prepared_statements)
		return;

	hashtab_delete(client->prepared_statements, hash_str(ps), ps);
}

static void ps_register(PgSocket *client, const char* ps) {
	if (!client->prepared_statements)
		client->prepared_statements = hashtab_create(32, hash_str_eq, NULL);

	hashtab_lookup(client->prepared_statements, hash_str(ps), true, ps);
}

void ps_register(PgSocket *client, PktHdr *pkt) {
	if (!client->prepared_statements) {
		client->prepared_statements = hashtab_create(32, hash_str_eq, NULL);
	}
}

void ps_unregister(PgSocket *client, PktHdr *pkt) {
	if (!client->prepared_statements)
		return;

	hashtab_delete(client->prepared_statements, hash_str())
}

void ps_free(PgSocket *client) {
	if (client->prepared_statements) {
		hashtab_destroy(client->prepared_statements);
		client->prepared_statements = NULL;
	}
}

*/