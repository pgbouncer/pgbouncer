#include "bouncer.h"
#include "objects.h"

#include <stddef.h>
#include <stdio.h>

STATLIST(pool_list);
STATLIST(peer_pool_list);

static unsigned int freed_pools;

static void free_empty_pool(PgPool *pool)
{
	freed_pools++;
	statlist_remove(&pool_list, &pool->head);
}

bool server_login_retry_pending(PgPool *pool, usec_t now)
{
	(void)pool;
	(void)now;
	return false;
}

#include "../src/janitor_auth_cache.h"

#define CHECK(expr) do { \
		if (!(expr)) { \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1; \
		} \
} while (0)

int main(void)
{
	static const struct {
		bool peer;
		size_t queue_offset;
	} cases[] = {
		{ false, offsetof(PgPool, active_client_list) },
		{ false, offsetof(PgPool, waiting_client_list) },
		{ false, offsetof(PgPool, active_cancel_req_list) },
		{ false, offsetof(PgPool, waiting_cancel_req_list) },
		{ true, offsetof(PgPool, active_cancel_req_list) },
		{ true, offsetof(PgPool, waiting_cancel_req_list) },
	};
	unsigned int count = 0;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		/* Expired, unexpired, absent, and (for regular pools) pool credentials. */
		for (int kind = 0; kind < (cases[i].peer ? 3 : 4); kind++) {
			PgCredentials login = { 0 }, owner = { 0 };
			PgSocket client = { 0 };
			PgPool pool = { 0 };
			struct StatList *queue = (struct StatList *)((char *)&pool + cases[i].queue_offset);

			statlist_init(&pool_list, "pools");
			statlist_init(&peer_pool_list, "peer pools");
			statlist_init(&pool.active_client_list, "active");
			statlist_init(&pool.waiting_client_list, "waiting");
			statlist_init(&pool.active_cancel_req_list, "active cancels");
			statlist_init(&pool.waiting_cancel_req_list, "waiting cancels");
			owner.auth_cache_expired = true;
			login.auth_cache_expired = kind == 0;
			pool.user_credentials = cases[i].peer ? NULL : &owner;
			client.login_user_credentials = kind == 2 ? NULL : kind == 3 ? &owner : &login;
			statlist_append(cases[i].peer ? &peer_pool_list : &pool_list, &pool.head);
			statlist_append(queue, &client.head);
			freed_pools = 0;

			mark_pool_credentials(1);
			CHECK(login.auth_cache_has_client == (kind == 0));
			CHECK(owner.auth_cache_has_client == (kind == 3));
			CHECK(owner.auth_cache_has_pool == !cases[i].peer);
			CHECK(freed_pools == 0);

			statlist_remove(queue, &client.head);
			login.auth_cache_has_client = false;
			owner.auth_cache_has_client = false;
			owner.auth_cache_has_pool = false;
			mark_pool_credentials(1);
			CHECK(!login.auth_cache_has_client && !owner.auth_cache_has_client);
			CHECK(!owner.auth_cache_has_pool);
			CHECK(freed_pools == !cases[i].peer);
			count++;
		}
	}
	printf("janitor auth cache: %u cases passed\n", count);
	return 0;
}
