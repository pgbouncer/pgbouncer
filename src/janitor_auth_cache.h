/* Private pool scanning used by auth cache cleanup. */
static void mark_client_credentials(struct StatList *clients)
{
	struct List *item;
	PgSocket *client;

	statlist_for_each(item, clients) {
		client = container_of(item, PgSocket, head);
		if (client->login_user_credentials && client->login_user_credentials->auth_cache_expired)
			client->login_user_credentials->auth_cache_has_client = true;
	}
}

static void mark_pool_credentials(usec_t now)
{
	struct List *item, *tmp;
	PgPool *pool;

	statlist_for_each_safe(item, &pool_list, tmp) {
		pool = container_of(item, PgPool, head);
		/* A forced-user pool can hold clients authenticated with other credentials. */
		mark_client_credentials(&pool->active_client_list);
		mark_client_credentials(&pool->waiting_client_list);
		/* Cancel requests can retain login credentials from another pool. */
		mark_client_credentials(&pool->active_cancel_req_list);
		mark_client_credentials(&pool->waiting_cancel_req_list);
		if (!pool->user_credentials || !pool->user_credentials->auth_cache_expired)
			continue;
		if (pool_client_count(pool) == 0 && pool_server_count(pool) == 0 &&
		    statlist_empty(&pool->active_cancel_req_list) &&
		    statlist_empty(&pool->waiting_cancel_req_list) &&
		    !pool->user_credentials->auth_cache_has_client &&
		    !server_login_retry_pending(pool, now))
			free_empty_pool(pool);
		else
			pool->user_credentials->auth_cache_has_pool = true;
	}
	statlist_for_each(item, &peer_pool_list) {
		pool = container_of(item, PgPool, head);
		mark_client_credentials(&pool->active_cancel_req_list);
		mark_client_credentials(&pool->waiting_cancel_req_list);
	}
}
