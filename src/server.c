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

/* process packets on server auth phase */
static bool handle_server_startup(PgSocket *server, MBuf *pkt)
{
	unsigned pkt_type;
	unsigned pkt_len;
	SBuf *sbuf = &server->sbuf;
	bool res = false;

	if (!get_header(pkt, &pkt_type, &pkt_len)) {
		disconnect_server(server, true, "bad pkt in login phase");
		return false;
	}

	if (pkt_len > mbuf_avail(pkt) + 5) {
		disconnect_server(server, true, "partial pkt in login phase");
		return false;
	}

	log_noise("S: pkt '%c', len=%d", pkt_type, pkt_len);

	switch (pkt_type) {
	default:
		slog_error(server, "unknown pkt from server: '%c'", pkt_type);
		disconnect_server(server, true, "unknown pkt from server");
		break;
	case 'E':		/* ErrorResponse */
		log_server_error("S: login failed", pkt);
		disconnect_server(server, true, "login failed");
		break;

	/* packets that need closer look */
	case 'R':		/* AuthenticationXXX */
		log_debug("calling login_answer");
		res = answer_authreq(server, pkt_type, pkt_len, pkt);
		if (!res)
			disconnect_server(server, false, "failed to answer authreq");
		break;
	case 'S':		/* ParameterStatus */
		res = add_welcome_parameter(server, pkt_type, pkt_len, pkt);
		break;
	case 'Z':		/* ReadyForQuery */
		/* login ok */
		log_debug("server login ok, start accepting queries");
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
		if (mbuf_avail(pkt) >= 8)
			memcpy(server->cancel_key, mbuf_get_bytes(pkt, 8), 8);
		res = true;
		break;
	case 'N':		/* NoticeResponse */
		slog_noise(server, "skipping pkt: %c", pkt_type);
		res = true;
		break;
	}

	if (res)
		sbuf_prepare_skip(sbuf, pkt_len);

	return res;
}

/* process packets on logged in connection */
static bool handle_server_work(PgSocket *server, MBuf *pkt)
{
	unsigned pkt_type;
	unsigned pkt_len;
	bool flush = 0;
	bool ready = 0;
	char state;
	SBuf *sbuf = &server->sbuf;
	PgSocket *client = server->link;

	Assert(!server->pool->admin);

	if (!get_header(pkt, &pkt_type, &pkt_len)) {
		disconnect_server(server, true, "bad pkt header");
		return false;
	}
	slog_noise(server, "pkt='%c' len=%d", pkt_type, pkt_len);

	switch (pkt_type) {
	default:
		slog_error(server, "unknown pkt: '%c'", pkt_type);
		disconnect_server(server, true, "unknown pkt");
		return false;
	
	/* pooling decisions will be based on this packet */
	case 'Z':		/* ReadyForQuery */

		/* if partial pkt, wait */
		if (mbuf_avail(pkt) == 0)
			return false;
		state = mbuf_get_char(pkt);

		/* set ready only if no tx */
		if (state == 'I')
			ready = 1;
		else if (cf_pool_mode == POOL_STMT) {
			disconnect_server(server, true,
					  "Long transactions not allowed");
			return false;
		}

		/* above packers need to be sent immidiately */
		flush = 1;

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
	case 'N':		/* NoticeResponse */

	/*
	 * chat packets, but server (and thus pooler)
	 * is allowed to buffer them until Sync or Flush
	 * is sent by client.
	 */
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

		/* check if client wanted immidiate response */
		if (client && client->flush_req) {
			flush = 1;
			client->flush_req = 0;
		}

	/* data packets, there will be more coming */
	case 'd':		/* CopyData(F/B) */
	case 'D':		/* DataRow */
	case 't':		/* ParameterDescription */
	case 'S':		/* ParameterStatus */
	case 'T':		/* RowDescription */

		if (client) {
			sbuf_prepare_send(sbuf, &client->sbuf, pkt_len, flush);
		} else {
			if (server->state != SV_TESTED)
				log_warning("got packet '%c' from server"
						" when not linked", pkt_type);
			sbuf_prepare_skip(sbuf, pkt_len);
		}
		break;
	}
	server->ready = ready;

	/* update stats */
	server->pool->stats.server_bytes += pkt_len;
	if (server->ready && client) {
		usec_t total;
		Assert(client->query_start != 0);
		
		total = get_cached_time() - client->query_start;
		client->query_start = 0;
		server->pool->stats.query_time += total;
		slog_debug(client, "query time: %d us", (int)total);
	}

	return true;
}

/* got connection, decide what to do */
static bool handle_connect(PgSocket *server)
{
	bool res = false;
	PgPool *pool = server->pool;

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
bool server_proto(SBuf *sbuf, SBufEvent evtype, MBuf *pkt, void *arg)
{
	bool res = false;
	PgSocket *server = arg;

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
		if (mbuf_avail(pkt) < 5) {
			log_noise("S: got partial header, trying to wait a bit");
			return false;
		}

		server->request_time = get_cached_time();
		switch (server->state) {
		case SV_LOGIN:
			res = handle_server_startup(server, pkt);
			break;
		case SV_TESTED:
		case SV_USED:
		case SV_ACTIVE:
		case SV_IDLE:
			res = handle_server_work(server, pkt);
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
		log_debug("S: connect ok");
		Assert(server->state == SV_LOGIN);
		server->request_time = get_cached_time();
		res = handle_connect(server);
		break;
	case SBUF_EV_FLUSH:
		if (server->ready
		    && (cf_pool_mode  != POOL_SESSION
			|| server->state == SV_TESTED))
		{
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
		res = true; /* unused actually */
		break;
	}
	return res;
}

