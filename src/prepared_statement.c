/*
 * Contains code for handling prepared statement related packets.
 *
 * The main entrypoints are the handle_xxx_command functions. They do the
 * translation from prepared statement names of the client to the equivalent
 * prepared statement name on the server.
 */

#include "bouncer.h"

#include <usual/crypto/csrandom.h>
#include <usual/hashtab-impl.h>
#include <usual/slab.h>

static uint64_t next_unique_query_id;

/*
 * Like uthash HASH_DELETE, but doesn't remove item from hash table just
 * unlink element from the doubly-linked-list.
 */
#define HASH_UNLINK(hh, head, delptr)                                                                   \
	do {                                                                                                                            \
		struct UT_hash_handle *_hd_hh_del = &(delptr)->hh;                              \
		if (_hd_hh_del->prev != NULL) {                                                                 \
			HH_FROM_ELMT((head)->hh.tbl, _hd_hh_del->prev)->next = _hd_hh_del->next; \
		} else {                                                                                                                \
			DECLTYPE_ASSIGN(head, _hd_hh_del->next);                                        \
		}                                                                                                                               \
		if (_hd_hh_del->next != NULL) {                                                                 \
			HH_FROM_ELMT((head)->hh.tbl, _hd_hh_del->next)->prev = _hd_hh_del->prev; \
		} else {                                                                                                                \
			_hd_hh_del->tbl->tail = HH_FROM_ELMT(_hd_hh_del->tbl, _hd_hh_del->prev); \
		}                                                                                                                               \
	} while (0)

#define HASH_FIND_UINT64(head, findint, out) \
	HASH_FIND(hh, head, findint, sizeof(uint64_t), out)
#define HASH_ADD_UINT64(head, intfield, add) \
	HASH_ADD(hh, head, intfield, sizeof(uint64_t), add)

/*
 * Benchmarking showed that HASH_BER is one of the fastest hash functions for our
 * usecases
 */
#undef HASH_FUNCTION
#define HASH_FUNCTION HASH_BER

/*
 * Converts a PgParsePacket to a malloc-ed PgPreparedStatement. The
 * PgPreparedStatement can be stored in the global prepared statement cache.
 */
static PgPreparedStatement *create_prepared_statement(PgParsePacket *pkt)
{
	PgPreparedStatement *ps = malloc(
		sizeof(PgPreparedStatement)
		+ pkt->query_and_parameters_len);
	if (ps == NULL)
		return NULL;

	ps->query_id = next_unique_query_id;
	ps->use_count = 0;
	ps->query_and_parameters_len = pkt->query_and_parameters_len;
	memcpy(ps->query_and_parameters,
	       pkt->query_and_parameters,
	       pkt->query_and_parameters_len);
	return ps;
}


/*
 * Creates a PgClientPreparedStatement from a PgPreparedStatement. The
 * PgClientPreparedStatement can be stored inside the client its prepared
 * statement hashmap.
 */
static PgClientPreparedStatement *create_client_prepared_statement(char const *name, PgPreparedStatement *ps)
{
	size_t name_len = strlen(name) + 1;
	PgClientPreparedStatement *client_ps = malloc(
		sizeof(PgClientPreparedStatement) + name_len);
	if (client_ps == NULL)
		return NULL;

	memcpy(client_ps->stmt_name, name, name_len);
	client_ps->ps = ps;
	ps->use_count += 1;
	return client_ps;
}

/*
 * Creates a PgServerPreparedStatement from a PgPreparedStatement. The
 * PgClientPreparedStatement can be stored inside the server its prepared
 * statement hashmap.
 */
static PgServerPreparedStatement *create_server_prepared_statement(PgPreparedStatement *ps)
{
	PgServerPreparedStatement *server_ps = slab_alloc(server_prepared_statement_cache);
	if (server_ps == NULL)
		return NULL;

	server_ps->ps = ps;
	server_ps->query_id = ps->query_id;
	ps->use_count += 1;
	return server_ps;
}

static PgPreparedStatement *get_prepared_statement(PgParsePacket *pkt, bool *found)
{
	PgPreparedStatement *ps = NULL;
	HASH_FIND(hh,
		  prepared_statements,
		  pkt->query_and_parameters,
		  pkt->query_and_parameters_len,
		  ps);
	if (ps != NULL) {
		*found = true;
		return ps;
	}

	ps = create_prepared_statement(pkt);
	if (ps == NULL)
		return NULL;

	HASH_ADD(hh,
		 prepared_statements,
		 query_and_parameters,
		 ps->query_and_parameters_len,
		 ps);
	ps->stmt_name_len = (uint8_t)snprintf(
		ps->stmt_name,
		sizeof ps->stmt_name,
		PREPARED_STMT_NAME_FORMAT,
		ps->query_id);
	next_unique_query_id += 1;
	*found = false;

	return ps;
}

/*
 * This is equivalent of sbuf_prepare_skip() but it also handles the case where
 * we used our special callbacke packet buffering logic.
 */
static void skip_possibly_completely_buffered_packet(PgSocket *client, PktHdr *pkt)
{
	/*
	 * Now we need to make sure the original packet is not sent to the server.
	 */
	if (client->packet_cb_state.flag == CB_HANDLE_COMPLETE_PACKET) {
		/*
		 * If we used special callback packet buffering, then we don't need to
		 * do anything. Because the callback already "consumed" the data from
		 * the SBuf.
		 */
		return;
	}
	/*
	 * If we used the regular packet buffering, then we do still need to tell
	 * SBuf that we handled the packet.
	 */
	sbuf_prepare_skip(&client->sbuf, pkt->len);
}


/*
 * Unregister prepared statement at server
 */
void unregister_prepared_statement(PgSocket *server, PgServerPreparedStatement *server_ps)
{
	HASH_DEL(server->server_prepared_statements, server_ps);
	if (--server_ps->ps->use_count == 0) {
		HASH_DEL(prepared_statements, server_ps->ps);
		free(server_ps->ps);
	}
	slab_free(server_prepared_statement_cache, server_ps);
}

/*
 * Register prepared statement in the server its cache. If the cache is full, we
 * evict the least recently used query/queries before adding a new one.
 *
 * NOTE: Before calling this a matching outstanding request should have been
 * added to the server its queue.
 */
static bool register_prepared_statement(PgSocket *client, PgSocket *server, PgServerPreparedStatement *server_ps)
{
	struct PgServerPreparedStatement *current, *tmp;
	unsigned int cached_query_count = HASH_COUNT(server->server_prepared_statements);
	OutstandingRequest *outstanding_request;
	struct List *el;

	if (server_ps == NULL)
		return false;

	if (cached_query_count >= (unsigned int)cf_prepared_statement_cache_size) {
		int res;
		/*
		 * Remove least recently used statements. To do so we can
		 * simply return the first N items from the hash table, because
		 * we maintain its order as an LRU.
		 * (see ensure_statement_is_prepared_on_server for details)
		 */
		HASH_ITER(hh, server->server_prepared_statements, current, tmp) {
			QUEUE_CloseStmt(res, client, server, current->ps->stmt_name);
			if (!res) {
				return false;
			}

			slog_noise(server, "prepared statement '%s' deleted from server cache", current->ps->stmt_name);
			unregister_prepared_statement(server, current);

			if (--cached_query_count < (unsigned int)cf_prepared_statement_cache_size)
				break;
		}
	}

	slog_noise(server, "prepared statement " PREPARED_STMT_NAME_FORMAT " added to server cache, %d cached items", server_ps->ps->query_id, cached_query_count + 1);
	HASH_ADD_UINT64(server->server_prepared_statements, query_id, server_ps);

	/*
	 * Now we need to link the outstanding request to the server_ps, so
	 * that it can be unregistered if the request fails.
	 */
	el = statlist_last(&server->outstanding_requests);
	Assert(el);
	outstanding_request = container_of(el, OutstandingRequest, node);
	Assert(outstanding_request->type == 'P');
	Assert(outstanding_request->server_ps == NULL);
	outstanding_request->server_ps = server_ps;


	return true;
}

/*
 * Handle a Parse packet for a named prepared statement
 *
 * This adds the prepared statement to the client's hash of prepared statements.
 * If the exact same prepared statement (query + argument types) was previously
 * prepared by another client on this server, then we don't actually send
 * anything to the server but instead reuse that one. Otherwise we prepare it on
 * the server and add it to the server's hash of prepared statements.
 */
bool handle_parse_command(PgSocket *client, PktHdr *pkt)
{
	PgSocket *server = client->link;
	PgParsePacket pp;
	PgServerPreparedStatement *server_ps = NULL;
	PgClientPreparedStatement *client_ps = NULL;
	PgPreparedStatement *ps;
	PktBuf *buf;
	bool found = false;

	Assert(server);

	if (!unmarshall_parse_packet(client, pkt, &pp))
		return false;

	HASH_FIND_STR(client->client_prepared_statements, pp.name, client_ps);
	if (client_ps) {
		slog_error(client, "prepared statement '%s' was already prepared", pp.name);
		/*
		 * It would be nice if we would not completely close the client
		 * connection here, but instead only sent an error after which
		 * the client could continue. This is what Postgres does.
		 * However, doing that in a way which works with query
		 * pipelining is not trivial. So for now we take the easy way
		 * out and simply close the connection. This is no problem for
		 * most clients anyway, since they will only issue Parse for
		 * with currently unused names.
		 */
		disconnect_client(client, true, "prepared statement name is already in use");
	}

	/* update stats */
	client->pool->stats.ps_client_parse_count++;

	/* Lookup query in global hash */
	ps = get_prepared_statement(&pp, &found);
	if (ps == NULL)
		goto oom;

	/* Register statement on client */
	client_ps = create_client_prepared_statement(pp.name, ps);
	if (client_ps == NULL)
		goto oom;
	HASH_ADD_STR(client->client_prepared_statements, stmt_name, client_ps);

	if (found) {
		/* Such query was already prepared */
		HASH_FIND_UINT64(server->server_prepared_statements, &ps->query_id, server_ps);
		if (server_ps) {
			/* Statement was already prepared on this server, do not forward packet */
			slog_debug(client, "handle_parse_command: mapping statement '%s' to '%s' (query '%s')",
				   client_ps->stmt_name, ps->stmt_name, ps->query_and_parameters);

			/*
			 * Insert an entry into the request queue, so we can send a fake
			 * response to the client at the point where they expect it.
			 */
			if (!add_outstanding_request(client, 'P', RA_FAKE))
				goto oom;
			goto success;
		}
	}
	/* Statement was not prepared on this server, sent modified P packet */
	slog_debug(client, "handle_parse_command: creating mapping for statement '%s' to '%s' (query '%s')",
		   client_ps->stmt_name, ps->stmt_name, ps->query_and_parameters);

	buf = pktbuf_temp();
	pktbuf_write_Parse(buf, ps->stmt_name, ps->query_and_parameters, ps->query_and_parameters_len);
	if (!sbuf_queue_packet(&client->sbuf, &server->sbuf, buf))
		goto oom;

	/* update stats */
	client->pool->stats.ps_server_parse_count++;

	/*
	 * Track the Parse command that we send to server and forward the response
	 * to the client, because they expect one.
	 */
	if (!add_outstanding_request(client, 'P', RA_FORWARD))
		goto oom;

	/* Register statement on server */
	server_ps = create_server_prepared_statement(ps);
	if (!register_prepared_statement(client, server, server_ps))
		goto oom;

success:
	skip_possibly_completely_buffered_packet(client, pkt);
	return true;

oom:
	disconnect_client(client, true, "out of memory");
	/*
	 * We also disconnect the server, because we probably messed with its state
	 * at this prepared statement state at this point. And rolling that back is
	 * hard.
	 */
	disconnect_server(client->link, true, "out of memory");
	return false;
}

/*
 * Get the given prepared statement from the client hash map. This returns NULL
 * and closes the client connection if no prepared statement with this name
 * could not be found.
 */
static PgClientPreparedStatement *get_client_prepared_statement(PgSocket *client, const char *name)
{
	PgClientPreparedStatement *client_ps;
	HASH_FIND_STR(client->client_prepared_statements, name, client_ps);
	if (!client_ps) {
		slog_error(client, "prepared statement '%s' not found", name);
		/*
		 * It would be nice if we would not completely close the client
		 * connection here, but instead only sent an error after which
		 * the client could continue. This is what Postgres does.
		 * However, doing that in a way which works with query
		 * pipelining is not trivial. So for now we take the easy way
		 * out and simply close the connection. This is no problem for
		 * most clients anyway, since they will only issue
		 * Bind/Describe for prepared statements that actually exist.
		 */
		disconnect_client(client, true, "prepared statement did not exist");
	}
	return client_ps;
}

/*
 * Prepare the given prepared statement on the server, if it isn't prepared
 * there yet. If it's already prepared on the server this call is essentially a
 * no-op, except that we mark the prepared statement as used in the LRU cache
 * of the server.
 *
 * This returns false if it cannot allocate any needed memory.
 */
static bool ensure_statement_is_prepared_on_server(PgSocket *server, PgPreparedStatement *ps)
{
	PgSocket *client = server->link;
	PgServerPreparedStatement *server_ps = NULL;
	PktBuf *buf;

	HASH_FIND_UINT64(server->server_prepared_statements, &ps->query_id, server_ps);
	if (server_ps) {
		/*
		 * The statement is already prepared. Move it to the start of
		 * the server its LRU double-linked list, except if there's
		 * only one statement prepared (because then it's already at
		 * the start by definition).
		 */
		if (HASH_COUNT(server->server_prepared_statements) != 1) {
			HASH_UNLINK(hh, server->server_prepared_statements, server_ps);
			HASH_APPEND_LIST(hh, server->server_prepared_statements, server_ps);
		}
		return true;
	}

	/* Statement is not prepared on this link, sent P packet now */
	slog_debug(server, "handle_bind_command: prepared statement '%s' (query '%s') not available on server, preparing '%s' before bind",
		   ps->stmt_name, ps->query_and_parameters, ps->stmt_name);

	/* update stats */
	client->pool->stats.ps_server_parse_count++;

	/*
	 * Track Parse command that we sent to server. But make sure the client
	 * does not receive the respective response, because they did not
	 * actually send a Parse request.
	 */
	if (!add_outstanding_request(client, 'P', RA_SKIP))
		return false;

	buf = pktbuf_temp();
	pktbuf_write_Parse(buf, ps->stmt_name, ps->query_and_parameters, ps->query_and_parameters_len);
	if (!sbuf_queue_packet(&client->sbuf, &server->sbuf, buf))
		return false;

	/* Register statement on server link */
	server_ps = create_server_prepared_statement(ps);
	if (!register_prepared_statement(client, server, server_ps))
		return false;

	return true;
}


/*
 * Handle a Bind packet for a named prepared statement
 *
 * Rewrites the given Bind packet to use the server-side statement name instead
 * of the client-side one. If the statement is not yet prepared on the server,
 * then we first send a Parse command to the server for the prepared statement
 * in question.
 */
bool handle_bind_command(PgSocket *client, PktHdr *pkt)
{
	PgSocket *server = client->link;
	PgBindPacket bp;
	PgClientPreparedStatement *client_ps = NULL;
	PgPreparedStatement *ps;
	PktBuf *buf;
	int diff;

	Assert(server);

	if (!unmarshall_bind_packet(client, pkt, &bp))
		return false;

	/* update stats */
	client->pool->stats.ps_bind_count++;

	client_ps = get_client_prepared_statement(client, bp.name);
	if (!client_ps)
		return false;
	ps = client_ps->ps;

	if (!ensure_statement_is_prepared_on_server(server, ps))
		goto oom;

	slog_debug(client, "handle_bind_command: mapped statement '%s' (query '%s') to '%s'",
		   bp.name, ps->query_and_parameters, ps->stmt_name);

	/*
	 * The Bind packet that we received from the client won't be sent as-is to
	 * the server. Instead we replace the statement name with our mapped name
	 * and also change the length if statement name is different length. Those
	 * are the only changes that we wish to make though, and the rest of the
	 * packet can be forwarded as is.
	 *
	 * So any further bytes that are already in the packet buffer we simply
	 * append to the newly created packet. If there's bytes of the packet that
	 * we have not buffered yet, then we forward those by using our general
	 * SBuf forwarding logic. We explicitely don't buffer the full packet,
	 * since the prepared statement arguments might be very large (and we don't
	 * need to change any of those).
	 */
	diff = strlen(bp.name) - ps->stmt_name_len;
	buf = pktbuf_temp();
	if (buf == NULL)
		goto oom;
	pktbuf_put_char(buf, pkt->type);
	pktbuf_put_uint32(buf, pkt->len - diff - 1);	/* length does not include type byte */
	pktbuf_put_string(buf, bp.portal);
	pktbuf_put_string(buf, ps->stmt_name);
	pktbuf_put_bytes(buf, pkt->data.data + pkt->data.read_pos,
			 pkt->data.write_pos - pkt->data.read_pos);
	if (!sbuf_queue_packet(&client->sbuf, &server->sbuf, buf))
		goto oom;

	/*
	 * Track the Bind command that we send to server and forward the response
	 * to the client, because they expect one.
	 */
	if (!add_outstanding_request(client, 'B', RA_FORWARD))
		goto oom;

	if (client->packet_cb_state.flag == CB_HANDLE_COMPLETE_PACKET) {
		/*
		 * If we used special callback buffering for this packet then there's
		 * no other bytes that we need to send. This is an exceptional case. It
		 * only happens when the statement name does not fit in pkt_buf.
		 */
		return true;
	}
	/*
	 * For all other cases we tell SBuf to skip over the bytes that were
	 * in the current packet buffer, but we do still want it to forward all the
	 * remaining bytes.
	 */
	sbuf_prepare_skip_then_send_leftover(&client->sbuf, &server->sbuf, pkt->data.write_pos, pkt->len);
	return true;

oom:
	disconnect_client(client, true, "out of memory");
	/*
	 * We also disconnect the server, because we probably messed with its state
	 * at this prepared statement state at this point. And rolling that back is
	 * hard.
	 */
	disconnect_server(client->link, true, "out of memory");
	return false;
}

/*
 * Handle a Describe packet for a named prepared statement
 *
 * Rewrites the given Describe packet to use the server-side statement name
 * instead of the client-side one. If the statement is not yet prepared on the
 * server, then we first send a Parse command to the server for the prepared
 * statement in question.
 */
bool handle_describe_command(PgSocket *client, PktHdr *pkt)
{
	PgSocket *server = client->link;
	PgDescribePacket dp;
	PgClientPreparedStatement *client_ps = NULL;
	PgPreparedStatement *ps;
	bool res;

	Assert(server);

	if (!unmarshall_describe_packet(client, pkt, &dp) || dp.type != 'S')
		return false;

	client_ps = get_client_prepared_statement(client, dp.name);
	if (!client_ps)
		return false;
	ps = client_ps->ps;

	if (!ensure_statement_is_prepared_on_server(server, ps))
		goto oom;

	slog_debug(client, "handle_describe_command: mapped statement '%s' (query '%s') to '%s'",
		   dp.name, ps->query_and_parameters, ps->stmt_name);

	/*
	 * Track the Describe command that we send to server and forward the
	 * response to the client, because they expect one.
	 */
	if (!add_outstanding_request(client, 'D', RA_FORWARD))
		goto oom;

	skip_possibly_completely_buffered_packet(client, pkt);
	QUEUE_DescribeStmt(res, client, server, ps->stmt_name);
	return res;
oom:
	disconnect_client(client, true, "out of memory");
	/*
	 * We also disconnect the server, because we probably messed with its state
	 * at this prepared statement state at this point. And rolling that back is
	 * hard.
	 */
	disconnect_server(client->link, true, "out of memory");
	return false;
}

/*
 * Handle a Close packet for a named prepared statement
 *
 * This does not actually close the mapped prepared statement on the server. But
 * it does remove the mapping from the client, so that the client can reuse the
 * name of this prepared statement for a new one.
 */
bool handle_close_statement_command(PgSocket *client, PktHdr *pkt, PgClosePacket *close_packet)
{
	PgClientPreparedStatement *client_ps = NULL;
	bool res = true;

	HASH_FIND_STR(client->client_prepared_statements, close_packet->name, client_ps);
	if (client_ps) {
		slog_noise(client, "handle_close_command: removed '%s' from cached prepared statements, items remaining %u", close_packet->name, HASH_COUNT(client->client_prepared_statements));
		HASH_DEL(client->client_prepared_statements, client_ps);
		if (--client_ps->ps->use_count == 0) {
			HASH_DEL(prepared_statements, client_ps->ps);
			free(client_ps->ps);
		}
		free(client_ps);
	}
	/* Do not forward packet to server */
	skip_possibly_completely_buffered_packet(client, pkt);

	if (!client->link) {
		slog_debug(client, "handle_close_statement_command: no outstanding requests so instantly answering client");
		SEND_CloseComplete(res, client);
		return res;
	}

	if (!add_outstanding_request(client, 'C', RA_FAKE)) {
		return false;
	}
	return true;
}

void free_client_prepared_statements(PgSocket *client)
{
	PgClientPreparedStatement *client_ps, *tmp;

	HASH_ITER(hh, client->client_prepared_statements, client_ps, tmp) {
		HASH_DEL(client->client_prepared_statements, client_ps);
		if (--client_ps->ps->use_count == 0) {
			HASH_DEL(prepared_statements, client_ps->ps);
			free(client_ps->ps);
		}
		free(client_ps);
	}

	free(client->client_prepared_statements);
	client->client_prepared_statements = NULL;
}

void free_server_prepared_statements(PgSocket *server)
{
	struct PgServerPreparedStatement *current, *tmp_s;

	HASH_ITER(hh, server->server_prepared_statements, current, tmp_s) {
		HASH_DEL(server->server_prepared_statements, current);
		if (--current->ps->use_count == 0) {
			HASH_DEL(prepared_statements, current->ps);
			free(current->ps);
		}
		slab_free(server_prepared_statement_cache, current);
	}

	free(server->server_prepared_statements);
	server->server_prepared_statements = NULL;
}
