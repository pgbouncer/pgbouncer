/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007 Marko Kreen, Skype Technologies OÜ
 * 
 * Permission to use, copy, modify, and distribute this software for any
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

static bool load_parameter(PgSocket *server, PktHdr *pkt)
{
	const char *key, *val;
	PgSocket *client = server->link;

	/*
	 * Want to see complete packet.  That means SMALL_PKT
	 * in sbuf.c must be larger than max param pkt.
	 */
	if (incomplete_pkt(pkt))
		return false;

	key = mbuf_get_string(&pkt->data);
	val = mbuf_get_string(&pkt->data);
	if (!key || !val) {
		disconnect_server(server, true, "broken ParameterStatus packet");
		return false;
	}
	slog_debug(server, "S: param: %s = %s", key, val);

	varcache_set(&server->vars, key, val);

	if (client) {
		slog_debug(client, "setting client var: %s='%s'", key, val);
		varcache_set(&client->vars, key, val);
	}

	return true;
}

/* process packets on server auth phase */
static bool handle_server_startup(PgSocket *server, PktHdr *pkt)
{
	SBuf *sbuf = &server->sbuf;
	bool res = false;

	if (incomplete_pkt(pkt)) {
		disconnect_server(server, true, "partial pkt in login phase");
		return false;
	}


	switch (pkt->type) {
	default:
		slog_error(server, "unknown pkt from server: '%c'", pkt_desc(pkt));
		disconnect_server(server, true, "unknown pkt from server");
		break;

	case 'E':		/* ErrorResponse */
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
		res = add_welcome_parameter(server, pkt);
		break;

	case 'Z':		/* ReadyForQuery */
		/* login ok */
		slog_debug(server, "server login ok, start accepting queries");
		server->ready = 1;

		/* got all params */
		finish_welcome_msg(server);

		res = release_server(server);

		/* let the takeover process handle it */
		if (res && server->pool->admin)
			res = takeover_login(server);
		break;

	/* ignorable packets */
	case 'K':		/* BackendKeyData */
		if (mbuf_avail(&pkt->data) >= BACKENDKEY_LEN)
			memcpy(server->cancel_key,
			       mbuf_get_bytes(&pkt->data, BACKENDKEY_LEN),
			       BACKENDKEY_LEN);
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

/* process packets on logged in connection */
static bool handle_server_work(PgSocket *server, PktHdr *pkt)
{
	bool ready = 0;
	char state;
	SBuf *sbuf = &server->sbuf;
	PgSocket *client = server->link;

	Assert(!server->pool->admin);

	switch (pkt->type) {
	default:
		slog_error(server, "unknown pkt: '%c'", pkt_desc(pkt));
		disconnect_server(server, true, "unknown pkt");
		return false;
	
	/* pooling decisions will be based on this packet */
	case 'Z':		/* ReadyForQuery */

		/* if partial pkt, wait */
		if (mbuf_avail(&pkt->data) == 0)
			return false;
		state = mbuf_get_char(&pkt->data);

		/* set ready only if no tx */
		if (state == 'I')
			ready = 1;
		else if (cf_pool_mode == POOL_STMT) {
			disconnect_server(server, true,
					  "Long transactions not allowed");
			return false;
		}
		break;

	case 'S':		/* ParameterStatus */
		if (!load_parameter(server, pkt))
			return false;
		break;

	/*
	 * 'E' and 'N' packets currently set ->ready to 0.  Correct would
	 * be to leave ->ready as-is, because overal TX state stays same.
	 * It matters for connections in IDLE or USED state which get dirty
	 * suddenly but should not as they are still usable.
	 *
	 * But the 'E' or 'N' packet between transactions signifies probably
	 * dying backend.  This its better to tag server as dirty and drop
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
	case 'N':		/* NoticeResponse */
		break;

	/* chat packets */
	case '2':		/* BindComplete */
	case '3':		/* CloseComplete */
	case 'c':		/* CopyDone(F/B) */
	case 'f':		/* CopyFail(F/B) */
	case 'I':		/* EmptyQueryResponse == CommandComplete */
	case 'V':		/* FunctionCallResponse */
	case 'n':		/* NoData */
	case 'G':		/* CopyInResponse */
	case 'H':		/* CopyOutResponse */
	case '1':		/* ParseComplete */
	case 'A':		/* NotificationResponse */
	case 's':		/* PortalSuspended */
	case 'C':		/* CommandComplete */

	/* data packets, there will be more coming */
	case 'd':		/* CopyData(F/B) */
	case 'D':		/* DataRow */
	case 't':		/* ParameterDescription */
	case 'T':		/* RowDescription */
		break;
	}
	server->ready = ready;
	server->pool->stats.server_bytes += pkt->len;

	if (server->setting_vars) {
		Assert(client);
		sbuf_prepare_skip(sbuf, pkt->len);
	} else if (client) {
		sbuf_prepare_send(sbuf, &client->sbuf, pkt->len);
		if (ready && client->query_start) {
			usec_t total;
			total = get_cached_time() - client->query_start;
			client->query_start = 0;
			server->pool->stats.query_time += total;
			slog_debug(client, "query time: %d us", (int)total);
		} else if (ready) {
			slog_warning(client, "FIXME: query end, but query_start == 0");
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

	fill_local_addr(server, sbuf_socket(&server->sbuf), server->remote_addr.is_unix);

	if (!statlist_empty(&pool->cancel_req_list)) {
		slog_debug(server, "use it for pending cancel req");
		/* if pending cancel req, send it */
		forward_cancel_request(server);
		/* notify disconnect_server() that connect did not fail */
		server->ready = 1;
		disconnect_server(server, false, "sent cancel req");
	} else {
		/* proceed with login */
		res = send_startup_packet(server);
		if (!res)
			disconnect_server(server, false, "startup pkt failed");
	}
	return res;
}

/* callback from SBuf */
bool server_proto(SBuf *sbuf, SBufEvent evtype, MBuf *data, void *arg)
{
	bool res = false;
	PgSocket *server = arg;
	PktHdr pkt;

	Assert(is_server_socket(server));
	Assert(server->state != SV_FREE);

	if (server->state == SV_JUSTFREE) {
		/* SBuf should catch the case */
		slog_warning(server, "state=SV_JUSTFREE, should not happen");
		return false;
	}

	switch (evtype) {
	case SBUF_EV_RECV_FAILED:
		disconnect_server(server, false, "server conn crashed?");
		break;
	case SBUF_EV_SEND_FAILED:
		disconnect_client(server->link, false, "unexpected eof");
		break;
	case SBUF_EV_READ:
		if (mbuf_avail(data) < NEW_HEADER_LEN) {
			slog_noise(server, "S: got partial header, trying to wait a bit");
			return false;
		}

		/* parse pkt header */
		if (!get_header(data, &pkt)) {
			disconnect_server(server, true, "bad pkt header");
			return false;
		}
		slog_noise(server, "S: pkt '%c', len=%d", pkt_desc(&pkt), pkt.len);

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
		res = true; /* unused actually */
		if (!server->ready)
			break;

		if (server->setting_vars) {
			PgSocket *client = server->link;
			Assert(client);

			server->setting_vars = 0;
			sbuf_continue(&client->sbuf);
			break;
		}
		
		if (cf_pool_mode  != POOL_SESSION || server->state == SV_TESTED) {
			switch (server->state) {
			case SV_ACTIVE:
			case SV_TESTED:
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
	}
	return res;
}

