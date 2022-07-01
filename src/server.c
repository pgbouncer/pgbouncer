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

/*
 * Handling of server connections
 */

#include "bouncer.h"
#include "usual/time.h"

#include <usual/slab.h>

#define ERRCODE_CANNOT_CONNECT_NOW "57P03"

static bool load_parameter(PgSocket *server, PktHdr *pkt, bool startup)
{
	const char *key, *val;
	PgSocket *client = server->link;

	/*
	 * Want to see complete packet.  That means SMALL_PKT
	 * in sbuf.c must be larger than max param pkt.
	 */
	if (incomplete_pkt(pkt))
		return false;

	if (!mbuf_get_string(&pkt->data, &key))
		goto failed;
	if (!mbuf_get_string(&pkt->data, &val))
		goto failed;
	slog_debug(server, "S: param: %s = %s", key, val);

	varcache_set(&server->vars, key, val);

	if (client) {
		slog_debug(client, "setting client var: %s='%s'", key, val);
		varcache_set(&client->vars, key, val);
	}

	if (startup) {
		if (!add_welcome_parameter(server->pool, key, val))
			goto failed_store;
	}

	return true;
failed:
	disconnect_server(server, true, "broken ParameterStatus packet");
	return false;
failed_store:
	disconnect_server(server, true, "failed to store ParameterStatus");
	return false;
}

/*
 * We cannot log in to the server at all. If we don't already have any usable
 * server connections, we disconnect all other clients in the pool that are
 * waiting for a server.
 */
void kill_pool_logins(PgPool *pool, const char *sqlstate, const char *msg)
{
	struct List *item, *tmp;
	PgSocket *client;
	/*
	 * The check for welcome_msg_ready is necessary because that indicates
	 * that the pool got tagged as dirty. It's possible that there's still
	 * working server connections in that case, but as soon as they get
	 * unassigned from their client they would be closed. So they don't
	 * really count as usable anymore.
	 */
	if (pool_connected_server_count(pool) != 0 && pool->welcome_msg_ready)
		return;

	statlist_for_each_safe(item, &pool->waiting_client_list, tmp) {
		client = container_of(item, PgSocket, head);
		disconnect_client_sqlstate(client, true, sqlstate, msg);
	}
}

/*
 * We cannot log in to the server at all. If we don't already have any usable
 * server connections, we disconnect all other clients in the pool that are
 * also waiting for a server. We disconnect them with exactly the same error
 * message and code as we received from the server.
 */
const char * kill_pool_logins_server_error(PgPool *pool, PktHdr *errpkt)
{
	const char *level, *sqlstate, *msg;

	parse_server_error(errpkt, &level, &msg, &sqlstate);
	log_warning("server login failed: %s %s", level, msg);

	/*
	 * Kill all waiting clients unless it's a temporary error, such as
	 * "database system is starting up".
	 */
	if (strcmp(sqlstate, ERRCODE_CANNOT_CONNECT_NOW) != 0) {
		log_noise("kill_pool_logins_server_error: sqlstate: %s", sqlstate);
		kill_pool_logins(pool, sqlstate, msg);
	}
	return msg;
}

/* process packets on server auth phase */
static bool handle_server_startup(PgSocket *server, PktHdr *pkt)
{
	SBuf *sbuf = &server->sbuf;
	const char *msg;
	bool res = false;
	const uint8_t *ckey;

	if (incomplete_pkt(pkt)) {
		disconnect_server(server, true, "partial pkt in login phase");
		return false;
	}

	/* ignore most that happens during connect_query */
	if (server->exec_on_connect) {
		switch (pkt->type) {
		case PqMsg_ReadyForQuery:
		case PqMsg_ParameterStatus:
			/* handle them below */
			break;

		case PqMsg_ErrorResponse:
			/* log & ignore errors */
			log_server_error("S: error while executing exec_on_query", pkt);
		/* fallthrough */
		default:	/* ignore rest */
			sbuf_prepare_skip(sbuf, pkt->len);
			return true;
		}
	}

	switch (pkt->type) {
	default:
		slog_error(server, "unknown pkt from server: '%c'", pkt_desc(pkt));
		disconnect_server(server, true, "unknown pkt from server");
		break;

	case PqMsg_ErrorResponse:
		/*
		 * If we cannot log into the server, then we drop all clients
		 * that are currently trying to log in because they will almost
		 * certainly hit the same error.
		 *
		 * However, we don't do this if it's a replication connection,
		 * because those can fail due to a variety of missing
		 * permissions specific to replication connections, such as
		 * missing REPLICATION role or missing pg_hba.conf line for the
		 * replication database. In such cases normal connections would
		 * still be able connect and query the database just fine, so
		 * we don't want to kill all of those just yet. If there really
		 * is a problem impacting all connections, we can wait for a
		 * normal connection to report this problem.
		 */
		if (!server->replication) {
			msg = kill_pool_logins_server_error(server->pool, pkt);
			disconnect_server(server, true, "%s", (char *)msg);
		} else {
			log_server_error("S: login failed", pkt);
			disconnect_server(server, true, "login failed");
		}
		break;

	/* packets that need closer look */

	case PqMsg_AuthenticationRequest:
		slog_debug(server, "calling login_answer");
		res = answer_authreq(server, pkt);
		if (!res)
			disconnect_server(server, false, "failed to answer authreq");
		break;

	case PqMsg_ParameterStatus:
		res = load_parameter(server, pkt, true);
		break;

	case PqMsg_ReadyForQuery:
		if (server->exec_on_connect) {
			server->exec_on_connect = false;
			/* deliberately ignore transaction status */
		} else if (server->pool->db->connect_query) {
			server->exec_on_connect = true;
			slog_debug(server, "server connect ok, send exec_on_connect");
			SEND_generic(res, server, PqMsg_Query, "s", server->pool->db->connect_query);
			if (!res)
				disconnect_server(server, false, "exec_on_connect query failed");
			break;
		}

		if (!valid_target_session_attrs(server)) {
			disconnect_server(server, true, "server does not satisfy target_session_attrs");
			break;
		}

		/* login ok */
		slog_debug(server, "server login ok, start accepting queries");
		server->ready = true;

		/* got all params */
		finish_welcome_msg(server);

		/* need to notify sbuf if server was closed */
		res = release_server(server);

		/* let the takeover process handle it */
		if (res && server->pool->db->admin)
			res = takeover_login(server);
		break;

	/* ignorable packets */

	case PqMsg_BackendKeyData:
		if (!mbuf_get_bytes(&pkt->data, BACKENDKEY_LEN, &ckey)) {
			disconnect_server(server, true, "bad cancel key");
			return false;
		}
		memcpy(server->cancel_key, ckey, BACKENDKEY_LEN);
		res = true;
		break;

	case PqMsg_NoticeResponse:
		slog_noise(server, "skipping pkt: %c", pkt_desc(pkt));
		res = true;
		break;
	}

	if (res)
		sbuf_prepare_skip(sbuf, pkt->len);

	return res;
}

/*
 * Compare connection attributes as returned by the server
 * against desired connection attributes. This matches the
 * behavior of libpq's `target_session_attrs` albeit only
 * implementing a subset of the functionality:
 * 1) It does not support `prefer-standby`.
 * 2) It requires PG 14+ to send connection parameters at startup.
 */
bool valid_target_session_attrs(PgSocket *server)
{
	VarCache *v = &server->vars;
	const struct PStr *in_hot_standby = v->var_list[VInHotStandby];
	const struct PStr *default_transaction_read_only = v->var_list[VDefaultTransactionReadOnly];
	enum TargetSessionAttrs target = server->pool->db->target_session_attrs;

	// If the server did not return the in_hot_standby and/or
	// default_transaction_read_only parameters, assume false.
	bool hot_standby = in_hot_standby && strcmp(in_hot_standby->str, "on") == 0;
	bool transaction_read_only = default_transaction_read_only && strcmp(default_transaction_read_only->str, "on") == 0;

	return (target == TARGET_SESSION_ANY) ||
	       (target == TARGET_SESSION_READWRITE && !transaction_read_only) ||
	       (target == TARGET_SESSION_READONLY && transaction_read_only) ||
	       (target == TARGET_SESSION_PRIMARY && !hot_standby) ||
	       (target == TARGET_SESSION_STANDBY && hot_standby);
}

/*
 * connection_pool_mode returns the pool_mode for the server. It specifically
 * forces session pooling if the server is a replication connection, because
 * replication connections require session pooling to work correctly.
 */
int connection_pool_mode(PgSocket *connection)
{
	if (connection->replication)
		return POOL_SESSION;
	return probably_wrong_pool_pool_mode(connection->pool);
}

/*
 * probably_wrong_pool_pool_mode returns the pool_mode for the pool.
 *
 * IMPORTANT: You should almost certainly not use this function directly,
 * because the pool_mode of a pool is not necessarily the same as the pool mode
 * of each of the clients and servers in the pool. Most importantly replication
 * connections in a transaction/statement pool will still use session pooling.
 *
 * Normally you should use connection_pool_mode()
 */
int probably_wrong_pool_pool_mode(PgPool *pool)
{
	int pool_mode = pool->user_credentials->global_user->pool_mode;
	if (pool_mode == POOL_INHERIT)
		pool_mode = pool->db->pool_mode;
	if (pool_mode == POOL_INHERIT)
		pool_mode = cf_pool_mode;
	return pool_mode;
}

int pool_pool_size(PgPool *pool)
{
	int user_pool_size = pool->user_credentials ? pool->user_credentials->global_user->pool_size : -1;
	if (user_pool_size >= 0)
		return user_pool_size;
	else if (pool->db->pool_size >= 0)
		return pool->db->pool_size;
	else
		return cf_default_pool_size;
}

/* min_pool_size of the pool's db */
int pool_min_pool_size(PgPool *pool)
{
	return database_min_pool_size(pool->db);
}

/* server_lifetime of the pool's db */
usec_t pool_server_lifetime(PgPool *pool)
{
	if (pool->db->server_lifetime == 0)
		return cf_server_lifetime;
	else
		return pool->db->server_lifetime;
}

/* min_pool_size of the db */
int database_min_pool_size(PgDatabase *db)
{
	if (db->min_pool_size < 0)
		return cf_min_pool_size;
	else
		return db->min_pool_size;
}

int pool_res_pool_size(PgPool *pool)
{
	int user_res_pool_size = pool->user_credentials ? pool->user_credentials->global_user->res_pool_size : -1;
	if (user_res_pool_size >= 0)
		return user_res_pool_size;
	else if (pool->db->res_pool_size >= 0)
		return pool->db->res_pool_size;
	else
		return cf_res_pool_size;
}

int database_max_client_connections(PgDatabase *db)
{
	if (db->max_db_client_connections <= 0)
		return cf_max_db_client_connections;
	else
		return db->max_db_client_connections;
}


int database_max_connections(PgDatabase *db)
{
	if (db->max_db_connections <= 0)
		return cf_max_db_connections;
	else
		return db->max_db_connections;
}

int user_max_connections(PgGlobalUser *user)
{
	if (user->max_user_connections <= 0)
		return cf_max_user_connections;
	else
		return user->max_user_connections;
}

int user_client_max_connections(PgGlobalUser *user)
{
	if (user->max_user_client_connections <= 0)
		return cf_max_user_client_connections;
	else
		return user->max_user_client_connections;
}

/* process packets on logged in connection */
static bool handle_server_work(PgSocket *server, PktHdr *pkt)
{
	bool ready = false;
	bool idle_tx = false;
	char state;
	SBuf *sbuf = &server->sbuf;
	PgSocket *client = server->link;
	bool async_response = false;
	struct List *item, *tmp;
	bool ignore_packet = false;

	Assert(!server->pool->db->admin);

	switch (pkt->type) {
	default:
		slog_error(server, "unknown pkt: '%c'", pkt_desc(pkt));
		disconnect_server(server, true, "unknown pkt");
		return false;

	/* pooling decisions will be based on this packet */
	case PqMsg_ReadyForQuery:

		/* if partial pkt, wait */
		if (!mbuf_get_char(&pkt->data, &state))
			return false;

		if (!pop_outstanding_request(server, (char[]) {PqMsg_Sync, PqMsg_Query, PqMsg_FunctionCall, '\0'}, &ignore_packet)
		    && server->query_failed) {
			if (!clear_outstanding_requests_until(server, (char[]) {PqMsg_Sync, '\0'}))
				return false;
		}
		server->query_failed = false;

		/* set ready only if no tx */
		if (state == 'I') {
			ready = true;
		} else if (connection_pool_mode(server) == POOL_STMT) {
			disconnect_server(server, true, "transaction blocks not allowed in statement pooling mode");
			return false;
		} else if (state == 'T' || state == 'E') {
			idle_tx = true;
		}
		break;

	case PqMsg_ParameterStatus:
		if (!load_parameter(server, pkt, false))
			return false;
		break;

	/*
	 * ErrorResponse and NoticeResponse packets currently set ->ready to false.  Correct would
	 * be to leave ->ready as-is, because overall TX state stays same.
	 * It matters for connections in IDLE or USED state which get dirty
	 * suddenly but should not as they are still usable.
	 *
	 * But the ErrorResponse or NoticeResponse packet between transactions signifies probably
	 * dying backend.  It is better to tag server as dirty and drop
	 * it later.
	 */
	case PqMsg_ErrorResponse:
		if (server->setting_vars) {
			/*
			 * the SET and user query will be different TX
			 * so we cannot report SET error to user.
			 */
			log_server_error("varcache_apply failed", pkt);

			/*
			 * client probably gave invalid values in startup pkt.
			 *
			 * no reason to keep such guys.
			 */
			disconnect_server(server, true, "invalid server parameter");
			return false;
		}

		/* ErrorResponse and CommandComplete show end of copy mode */
		if (server->copy_mode) {
			slog_debug(server, "COPY failed");
			server->copy_mode = false;

			/*
			 * Clear until next CopyDone or CopyFail message in the
			 * queue. This is needed to remove any Sync messages
			 * from the outstanding requests queue, for which we
			 * don't expect a response from the server.
			 *
			 * It isn't a problem if the CopyDone or CopyFail
			 * message has not been received yet. This message will
			 * be removed from the queue later when the server
			 * sends a ReadyForQuery message and we clear the queue
			 * until the next Sync.
			 *
			 * NOTE: CopyFail is the obvious error case, because
			 * here the client triggers a failure of the COPY.
			 * But CopyDone is also included in the search. The
			 * reason for that being that the server might fail the
			 * COPY for some reason unknown to the client (e.g. a
			 * unique constraint violation).
			 */
			if (!clear_outstanding_requests_until(server, (char[]) {PqMsg_CopyDone, PqMsg_CopyFail, '\0'}))
				return false;
		}

		server->query_failed = true;
		break;

	case PqMsg_CommandComplete:
		/* ErrorResponse and CommandComplete show end of copy mode */
		if (server->copy_mode) {
			slog_debug(server, "COPY finished");
			server->copy_mode = false;

			/*
			 * Clear until next CopyDone message in the queue. This
			 * is needed to remove any Sync messages from the
			 * outstanding requests queue, for which we don't
			 * expect a response from the server.
			 */
			if (!clear_outstanding_requests_until(server, (char[]) {PqMsg_CopyDone, '\0'}))
				return false;
		}
		/*
		 * Clean up prepared statements if needed if the client sent a
		 * DEALLOCATE ALL or a DISCARD ALL query. Not doing so would
		 * confuse our prepared statement handling, because we would
		 * expect certain queries to be prepared at the server that are
		 * not.
		 */
		if (is_prepared_statements_enabled(server)
		    && (pkt->len == 1 + 4 + 15 || pkt->len == 1 + 4 + 12)) {	/* size of complete DEALLOCATE/DISCARD ALL */
			const char *tag;
			if (mbuf_get_string(&pkt->data, &tag)) {
				if (strcmp(tag, "DEALLOCATE ALL") == 0 ||
				    strcmp(tag, "DISCARD ALL") == 0) {
					free_server_prepared_statements(server);
					if (client)
						free_client_prepared_statements(client);
				}
			} else {
				return false;
			}
		}
		pop_outstanding_request(server, (char[]) {PqMsg_Execute, '\0'}, &ignore_packet);

		break;

	case PqMsg_NoticeResponse:
		break;

	/* reply to LISTEN, don't change connection state */
	case PqMsg_NotificationResponse:
		idle_tx = server->idle_tx;
		ready = server->ready;
		async_response = true;
		break;

	/* copy mode */
	case PqMsg_CopyInResponse:
	case PqMsg_CopyBothResponse:
		slog_debug(server, "COPY started");
		server->copy_mode = true;
		break;
	case PqMsg_CopyOutResponse:
		break;
	/* chat packets */
	case PqMsg_ParseComplete:
		pop_outstanding_request(server, (char[]) {PqMsg_Parse, '\0'}, &ignore_packet);
		break;
	case PqMsg_BindComplete:
		pop_outstanding_request(server, (char[]) {PqMsg_Bind, '\0'}, &ignore_packet);
		break;
	case PqMsg_CloseComplete:
		pop_outstanding_request(server, (char[]) {PqMsg_Close, '\0'}, &ignore_packet);
		break;
	case PqMsg_NoData:
	case PqMsg_RowDescription:
		pop_outstanding_request(server, (char[]) {PqMsg_Describe, '\0'}, &ignore_packet);
		break;
	case PqMsg_ParameterDescription:
	case PqMsg_CopyDone:
	case PqMsg_CopyFail:
	case PqMsg_FunctionCallResponse:
		break;
	case PqMsg_EmptyQueryResponse:	/* EmptyQueryResponse is similar to CommandComplete, which is handled above */
	case PqMsg_PortalSuspended:
		pop_outstanding_request(server, (char[]) {PqMsg_Execute, '\0'}, &ignore_packet);
		break;

	/* data packets, there will be more coming */
	case PqMsg_CopyData:
	case PqMsg_DataRow:
		break;
	}
	server->idle_tx = idle_tx;
	server->ready = ready;
	server->pool->stats.server_bytes += pkt->len;

	if (server->setting_vars) {
		Assert(client);
		sbuf_prepare_skip(sbuf, pkt->len);
	} else if (client) {
		if (client->state == CL_LOGIN) {
			return handle_auth_query_response(client, pkt);
		} else if (ignore_packet) {
			slog_noise(server, "not forwarding packet with type '%c' from server", pkt->type);
			sbuf_prepare_skip(sbuf, pkt->len);
		} else {
			sbuf_prepare_send(sbuf, &client->sbuf, pkt->len);

			/*
			 * Compute query and transaction times
			 *
			 * For pipelined overlapping commands, we wait until
			 * the last command is done (outstanding_requests==0).
			 * That means, we count the time that PgBouncer is
			 * occupied in a series of pipelined commands, not the
			 * total time that all commands/queries take
			 * individually. For that, we would have to track the
			 * start time of each command separately in queue or
			 * similar, not only per client. (which would probably
			 * be a good future improvement)
			 */
			if (statlist_count(&server->outstanding_requests) == 0) {
				/* every statement (independent or in a transaction) counts as a query */
				if (ready || idle_tx) {
					if (client->query_start) {
						usec_t total;
						total = get_cached_time() - client->query_start;
						client->query_start = 0;
						server->pool->stats.query_time += total;
						slog_debug(client, "query time: %d us", (int)total);
					} else if (!async_response) {
						slog_warning(client, "FIXME: query end, but query_start == 0");
						Assert(false);
					}
				}

				/* statement ending in "idle" ends a transaction */
				if (ready) {
					if (client->xact_start) {
						usec_t total;
						total = get_cached_time() - client->xact_start;
						client->xact_start = 0;
						server->pool->stats.xact_time += total;
						slog_debug(client, "transaction time: %d us", (int)total);
					} else if (!async_response) {
						/* XXX This happens during takeover if the new process
						 * continues a transaction. */
						slog_warning(client, "FIXME: transaction end, but xact_start == 0");
					}
				}
			}
			statlist_for_each_safe(item, &server->outstanding_requests, tmp) {
				OutstandingRequest *request = container_of(item, OutstandingRequest, node);
				if (request->action != RA_FAKE)
					break;

				statlist_pop(&server->outstanding_requests);
				sbuf->extra_packet_queue_after = true;

				if (!queue_fake_response(client, request->type)) {
					/*
					 * The only reason the above could have failed is because
					 * of allocation errors. To actually be able to retry after
					 * these failures the next round we would need to restore
					 * the outstanding_requests queue to how it was before.
					 * Instead of doing that, we take the easy and known
					 * correct way out: Simply disconnecting the involved
					 * client and server.
					 */
					disconnect_client(client, true, "out of memory");
					disconnect_server(client->link, true, "out of memory");
					return false;
				}
				slab_free(outstanding_request_cache, request);
			}
		}
	} else {
		if (server->state != SV_TESTED) {
			slog_warning(server,
				     "got packet '%c' from server when not linked",
				     pkt_desc(pkt));
		}
		sbuf_prepare_skip(sbuf, pkt->len);
	}

	return true;
}

/* got connection, decide what to do */
static bool handle_connect(PgSocket *server)
{
	bool res = false;
	PgPool *pool = server->pool;
	char buf[PGADDR_BUF + 32];
	bool is_unix = pga_is_unix(&server->remote_addr);

	fill_local_addr(server, sbuf_socket(&server->sbuf), is_unix);

	if (cf_log_connections) {
		if (pga_is_unix(&server->remote_addr)) {
			slog_info(server, "new connection to server");
		} else {
			slog_info(server, "new connection to server (from %s)",
				  pga_str(&server->local_addr, buf, sizeof(buf)));
		}
	}

	/*
	 * If there are cancel requests waiting we first handle those. By handling
	 * these first we reduce the load on the server and we a server connection
	 * might actually become free to use for queries, because its query got
	 * canceled.
	 *
	 * Only if there are no cancel requests we proceed with the login procedure
	 * that's necessary to handle queries. Cancel requests need to be sent
	 * before the login procedure starts.
	 *
	 * A special case is when this is a peer pool, instead of a regular pool.
	 * Since only cancellation requests should be sent to peers.
	 */
	if (!statlist_empty(&pool->waiting_cancel_req_list)) {
		slog_debug(server, "use it for pending cancel req");
		if (forward_cancel_request(server)) {
			change_server_state(server, SV_ACTIVE_CANCEL);
			sbuf_continue(&server->sbuf);
		} else {
			/* notify disconnect_server() that connect did not fail */
			server->ready = true;
			disconnect_server(server, false, "failed to send cancel req");
		}
	} else if (pool->db->peer_id) {
		/* notify disconnect_server() that connect did not fail */
		server->ready = true;
		disconnect_server(server, false, "peer server was not necessary anymore, because client cancel connection was already closed");
	} else {
		/* proceed with login */
		if (server_connect_sslmode > SSLMODE_DISABLED && !is_unix) {
			slog_noise(server, "P: SSL request");
			res = send_sslreq_packet(server);
			if (res)
				server->wait_sslchar = true;
		} else {
			slog_noise(server, "P: startup");
			res = send_startup_packet(server);
		}
		if (!res)
			disconnect_server(server, false, "startup pkt failed");
	}
	return res;
}

static bool handle_sslchar(PgSocket *server, struct MBuf *data)
{
	uint8_t schar = '?';
	bool ok;

	server->wait_sslchar = false;

	ok = mbuf_get_byte(data, &schar);
	if (!ok || (schar != 'S' && schar != 'N')) {
		disconnect_server(server, false, "bad sslreq answer");
		return false;
	}
	/*
	 * At this point we should have no data already buffered.  If
	 * we do, it was received before we performed the SSL
	 * handshake, so it wasn't encrypted and indeed may have been
	 * injected by a man-in-the-middle.
	 */
	if (mbuf_avail_for_read(data) != 0) {
		disconnect_server(server, false, "received unencrypted data after SSL response");
		return false;
	}

	if (schar == 'S') {
		slog_noise(server, "launching tls");
		ok = sbuf_tls_connect(&server->sbuf, server->host);
	} else if (server_connect_sslmode >= SSLMODE_REQUIRE) {
		disconnect_server(server, false, "server refused SSL");
		return false;
	} else {
		/* proceed with non-TLS connection */
		ok = send_startup_packet(server);
	}

	if (ok) {
		sbuf_prepare_skip(&server->sbuf, 1);
	} else {
		disconnect_server(server, false, "sslreq processing failed");
	}
	return ok;
}

/* callback from SBuf */
bool server_proto(SBuf *sbuf, SBufEvent evtype, struct MBuf *data)
{
	bool res = false;
	PgSocket *server = container_of(sbuf, PgSocket, sbuf);
	PgPool *pool = server->pool;
	PktHdr pkt;
	char infobuf[96];

	Assert(is_server_socket(server));
	Assert(server->state != SV_FREE);

	/* may happen if close failed */
	if (server->state == SV_JUSTFREE)
		return false;

	switch (evtype) {
	case SBUF_EV_RECV_FAILED:
		if (server->state == SV_ACTIVE_CANCEL)
			disconnect_server(server, false, "successfully sent cancel request");
		else
			disconnect_server(server, false, "server conn crashed?");
		break;
	case SBUF_EV_SEND_FAILED:
		disconnect_client(server->link, false, "unexpected eof");
		break;
	case SBUF_EV_READ:
		if (server->wait_sslchar) {
			res = handle_sslchar(server, data);
			break;
		}
		if (incomplete_header(data)) {
			slog_noise(server, "S: got partial header, trying to wait a bit");
			break;
		}

		/* parse pkt header */
		if (!get_header(data, &pkt)) {
			disconnect_server(server, true, "bad pkt header");
			break;
		}
		slog_noise(server, "read pkt='%c', len=%u", pkt_desc(&pkt), pkt.len);

		server->request_time = get_cached_time();
		switch (server->state) {
		case SV_LOGIN:
			res = handle_server_startup(server, &pkt);
			break;
		case SV_TESTED:
		case SV_USED:
		case SV_ACTIVE:
		case SV_ACTIVE_CANCEL:
		case SV_BEING_CANCELED:
		case SV_IDLE:
			res = handle_server_work(server, &pkt);
			break;
		default:
			fatal("server_proto: server in bad state: %d", server->state);
		}
		break;
	case SBUF_EV_CONNECT_FAILED:
		Assert(server->state == SV_LOGIN);
		disconnect_server(server, false, "connect failed");
		break;
	case SBUF_EV_CONNECT_OK:
		slog_debug(server, "S: connect ok");
		Assert(server->state == SV_LOGIN);
		server->request_time = get_cached_time();
		res = handle_connect(server);
		break;
	case SBUF_EV_FLUSH:
		res = true;
		if (!server->ready)
			break;

		if (server->setting_vars) {
			PgSocket *client = server->link;
			Assert(client);

			/*
			 * It's possible that the client vars and server vars have
			 * different string representations, but still Postgres did not
			 * send a ParameterStatus packet. This happens when the server
			 * variable is the canonical version of the client variable, i.e.
			 * they mean the same just written slightly different. To make sure
			 * that the canonical version is also stored in the client, we now
			 * copy the server variables over to the client variables.
			 * See issue #776 for an example of this.
			 */
			varcache_set_canonical(server, client);

			server->setting_vars = false;
			log_noise("done setting vars unpausing client");
			sbuf_continue(&client->sbuf);
			break;
		}

		if (connection_pool_mode(server) != POOL_SESSION || server->state == SV_TESTED || server->resetting) {
			server->resetting = false;
			switch (server->state) {
			case SV_ACTIVE:
			case SV_ACTIVE_CANCEL:
			case SV_TESTED:
				/* keep link if client expects more responses */
				if (server->link) {
					if (statlist_count(&server->outstanding_requests) > 0)
						break;
				}

				/* retval does not matter here */
				release_server(server);
				break;
			default:
				slog_warning(server, "EV_FLUSH with state=%d", server->state);
			case SV_BEING_CANCELED:
			case SV_IDLE:
				break;
			}
		}
		break;
	case SBUF_EV_PKT_CALLBACK:
		slog_warning(server, "SBUF_EV_PKT_CALLBACK with state=%d", server->state);
		break;
	case SBUF_EV_TLS_READY:
		Assert(server->state == SV_LOGIN);

		tls_get_connection_info(server->sbuf.tls, infobuf, sizeof infobuf);
		if (cf_log_connections) {
			slog_info(server, "SSL established: %s", infobuf);
		} else {
			slog_noise(server, "SSL established: %s", infobuf);
		}

		server->request_time = get_cached_time();
		res = send_startup_packet(server);
		if (res)
			sbuf_continue(&server->sbuf);
		else
			disconnect_server(server, false, "TLS startup failed");
		break;
	}
	if (!res && pool->db->admin)
		takeover_login_failed();
	return res;
}
