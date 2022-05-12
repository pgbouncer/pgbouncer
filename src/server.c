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

/* we cannot log in at all, notify clients */
void kill_pool_logins(PgPool *pool, const char *msg)
{
	struct List *item, *tmp;
	PgSocket *client;

	statlist_for_each_safe(item, &pool->waiting_client_list, tmp) {
		client = container_of(item, PgSocket, head);
		if (!client->wait_for_welcome)
			continue;

		disconnect_client(client, true, "%s", msg);
	}
}

/* we cannot log in at all, notify clients with server error */
static void kill_pool_logins_server_error(PgPool *pool, PktHdr *errpkt)
{
	const char *level, *msg;

	parse_server_error(errpkt, &level, &msg);
	log_warning("server login failed: %s %s", level, msg);
	kill_pool_logins(pool, msg);
}

/* process packets on server auth phase */
static bool handle_server_startup(PgSocket *server, PktHdr *pkt)
{
	SBuf *sbuf = &server->sbuf;
	bool res = false;
	const uint8_t *ckey;

	if (incomplete_pkt(pkt)) {
		disconnect_server(server, true, "partial pkt in login phase");
		return false;
	}

	/* ignore most that happens during connect_query */
	if (server->exec_on_connect) {
		switch (pkt->type) {
		case 'Z':
		case 'S':	/* handle them below */
			break;

		case 'E':	/* log & ignore errors */
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

	case 'E':		/* ErrorResponse */
		if (!server->pool->welcome_msg_ready)
			kill_pool_logins_server_error(server->pool, pkt);
		else
			log_server_error("S: login failed", pkt);

		disconnect_server(server, true, "login failed");
		break;

	/* packets that need closer look */
	case 'R':		/* AuthenticationXXX */
		slog_debug(server, "calling login_answer");
		res = answer_authreq(server, pkt);
		if (!res)
			disconnect_server(server, false, "failed to answer authreq");
		break;

	case 'S':		/* ParameterStatus */
		res = load_parameter(server, pkt, true);
		break;

	case 'Z':		/* ReadyForQuery */
		if (server->exec_on_connect) {
			server->exec_on_connect = false;
			/* deliberately ignore transaction status */
		} else if (server->pool->db->connect_query) {
			server->exec_on_connect = true;
			slog_debug(server, "server connect ok, send exec_on_connect");
			SEND_generic(res, server, 'Q', "s", server->pool->db->connect_query);
			if (!res)
				disconnect_server(server, false, "exec_on_connect query failed");
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
	case 'K':		/* BackendKeyData */
		if (!mbuf_get_bytes(&pkt->data, BACKENDKEY_LEN, &ckey)) {
			disconnect_server(server, true, "bad cancel key");
			return false;
		}
		memcpy(server->cancel_key, ckey, BACKENDKEY_LEN);
		res = true;
		break;

	case 'N':		/* NoticeResponse */
		slog_noise(server, "skipping pkt: %c", pkt_desc(pkt));
		res = true;
		break;
	}

	if (res)
		sbuf_prepare_skip(sbuf, pkt->len);

	return res;
}

int pool_pool_mode(PgPool *pool)
{
	int pool_mode = pool->user->pool_mode;
	if (pool_mode == POOL_INHERIT)
		pool_mode = pool->db->pool_mode;
	if (pool_mode == POOL_INHERIT)
		pool_mode = cf_pool_mode;
	return pool_mode;
}

int pool_pool_size(PgPool *pool)
{
	if (pool->db->pool_size < 0)
		return cf_default_pool_size;
	else
		return pool->db->pool_size;
}

int pool_min_pool_size(PgPool *pool)
{
	if (pool->db->min_pool_size < 0)
		return cf_min_pool_size;
	else
		return pool->db->min_pool_size;
}

int pool_res_pool_size(PgPool *pool)
{
	if (pool->db->res_pool_size < 0)
		return cf_res_pool_size;
	else
		return pool->db->res_pool_size;
}

int database_max_connections(PgDatabase *db)
{
	if (db->max_db_connections <= 0) {
		return cf_max_db_connections;
        } else {
		return db->max_db_connections;
	}
}

int user_max_connections(PgUser *user)
{
	if (user->max_user_connections <= 0) {
		return cf_max_user_connections;
	} else {
		return user->max_user_connections;
	}
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

	Assert(!server->pool->db->admin);

	switch (pkt->type) {
	default:
		slog_error(server, "unknown pkt: '%c'", pkt_desc(pkt));
		disconnect_server(server, true, "unknown pkt");
		return false;

	/* pooling decisions will be based on this packet */
	case 'Z':		/* ReadyForQuery */

		/* if partial pkt, wait */
		if (!mbuf_get_char(&pkt->data, &state))
			return false;

		/* set ready only if no tx */
		if (state == 'I')
			ready = true;
		else if (pool_pool_mode(server->pool) == POOL_STMT) {
			disconnect_server(server, true, "transaction blocks not allowed in statement pooling mode");
			return false;
		} else if (state == 'T' || state == 'E') {
			idle_tx = true;
		}

		if (client && !server->setting_vars) {
			if (client->expect_rfq_count > 0) {
				client->expect_rfq_count--;
			} else if (server->state == SV_ACTIVE) {
				slog_debug(client, "unexpected ReadyForQuery - expect_rfq_count=%d", client->expect_rfq_count);
			}
		}
		break;

	case 'S':		/* ParameterStatus */
		if (!load_parameter(server, pkt, false))
			return false;
		break;

	/*
	 * 'E' and 'N' packets currently set ->ready to false.  Correct would
	 * be to leave ->ready as-is, because overall TX state stays same.
	 * It matters for connections in IDLE or USED state which get dirty
	 * suddenly but should not as they are still usable.
	 *
	 * But the 'E' or 'N' packet between transactions signifies probably
	 * dying backend.  It is better to tag server as dirty and drop
	 * it later.
	 */
	case 'E':		/* ErrorResponse */
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
		/* fallthrough */
	case 'C':		/* CommandComplete */

		/* ErrorResponse and CommandComplete show end of copy mode */
		if (server->copy_mode) {
			server->copy_mode = false;

			/* it's impossible to track sync count over copy */
			if (client)
				client->expect_rfq_count = 0;
		}
		break;

	case 'N':		/* NoticeResponse */
		break;

	/* reply to LISTEN, don't change connection state */
	case 'A':		/* NotificationResponse */
		idle_tx = server->idle_tx;
		ready = server->ready;
		async_response = true;
		break;

	/* copy mode */
	case 'G':		/* CopyInResponse */
	case 'H':		/* CopyOutResponse */
		server->copy_mode = true;
		break;
	/* chat packets */
	case '2':		/* BindComplete */
	case '3':		/* CloseComplete */
	case 'c':		/* CopyDone(F/B) */
	case 'f':		/* CopyFail(F/B) */
	case 'I':		/* EmptyQueryResponse == CommandComplete */
	case 'V':		/* FunctionCallResponse */
	case 'n':		/* NoData */
	case '1':		/* ParseComplete */
	case 's':		/* PortalSuspended */

	/* data packets, there will be more coming */
	case 'd':		/* CopyData(F/B) */
	case 'D':		/* DataRow */
	case 't':		/* ParameterDescription */
	case 'T':		/* RowDescription */
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
		} else {
			sbuf_prepare_send(sbuf, &client->sbuf, pkt->len);

			/*
			 * Compute query and transaction times
			 *
			 * For pipelined overlapping commands, we wait until
			 * the last command is done (expect_rfq_count==0).
			 * That means, we count the time that PgBouncer is
			 * occupied in a query or transaction, not the total
			 * time that all queries/transactions take
			 * individually.  For that, we would have to track the
			 * start time of each query separately in a queue or
			 * similar, not only per client.
			 */
			if (client->expect_rfq_count == 0) {
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
		}
	} else {
		if (server->state != SV_TESTED)
			slog_warning(server,
				     "got packet '%c' from server when not linked",
				     pkt_desc(pkt));
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
		if (pga_is_unix(&server->remote_addr))
			slog_info(server, "new connection to server");
		else
			slog_info(server, "new connection to server (from %s)",
				  pga_str(&server->local_addr, buf, sizeof(buf)));
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
		ok = sbuf_tls_connect(&server->sbuf, server->pool->db->host);
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

			server->setting_vars = false;
			sbuf_continue(&client->sbuf);
			break;
		}

		if (pool_pool_mode(pool) != POOL_SESSION || server->state == SV_TESTED || server->resetting) {
			server->resetting = false;
			switch (server->state) {
			case SV_ACTIVE:
			case SV_TESTED:
				/* keep link if client expects more Syncs */
				if (server->link) {
					if (server->link->expect_rfq_count > 0)
						break;
				}

				/* retval does not matter here */
				release_server(server);
				break;
			default:
				slog_warning(server, "EV_FLUSH with state=%d", server->state);
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
