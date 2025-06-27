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
 * Pieces that need to have detailed info about protocol.
 */

#include "bouncer.h"
#include "scram.h"

/*
 * parse protocol header from struct MBuf
 */

/*
 * Parses pkt header from buffer, returns false if failed.
 *
 * This handles both regular packets as well as startup/special
 * packets (which are actually v2-style packets).  Afterwards, the
 * type and the length is available in pkt independent of what kind
 * this packet is.
 */
bool get_header(struct MBuf *data, PktHdr *pkt)
{
	unsigned type;
	uint32_t len;
	unsigned got;
	unsigned avail;
	uint16_t len16;
	uint8_t type8;
	uint32_t code;
	struct MBuf hdr;
	const uint8_t *ptr;

	mbuf_copy(data, &hdr);

	if (mbuf_avail_for_read(&hdr) < NEW_HEADER_LEN) {
		log_noise("get_header: less than %d bytes available", NEW_HEADER_LEN);
		return false;
	}
	if (!mbuf_get_byte(&hdr, &type8))
		return false;
	type = type8;
	if (type != 0) {
		/*
		 * Regular (v3) packet, starts with type byte and
		 * 4-byte length.
		 */

		/* wire length does not include type byte */
		if (!mbuf_get_uint32be(&hdr, &len))
			return false;
		len++;
		got = NEW_HEADER_LEN;
	} else {
		/*
		 * Startup/special (formerly v2) packet, formally
		 * starts with 4-byte length.  We assume the first
		 * byte is zero because in current use they shouldn't
		 * be that long to have more than zero in the MSB.
		 */

		/* second byte should also be zero */
		if (!mbuf_get_byte(&hdr, &type8))
			return false;
		if (type8 != 0) {
			log_noise("get_header: unknown special pkt");
			return false;
		}

		/* don't tolerate partial pkt */
		if (mbuf_avail_for_read(&hdr) < OLD_HEADER_LEN - 2) {
			log_noise("get_header: less than %d bytes for special pkt", OLD_HEADER_LEN);
			return false;
		}

		if (!mbuf_get_uint16be(&hdr, &len16))
			return false;
		len = len16;

		/* 4-byte code follows */
		if (!mbuf_get_uint32be(&hdr, &code))
			return false;
		if (code == PKT_CANCEL) {
			type = PKT_CANCEL;
		} else if (code == PKT_SSLREQ) {
			type = PKT_SSLREQ;
		} else if (code == PKT_GSSENCREQ) {
			type = PKT_GSSENCREQ;
		} else if (code >= PKT_STARTUP_V3 && code < PKT_STARTUP_V3_UNSUPPORTED) {
			type = PKT_STARTUP_V3;
		} else if (code >= PKT_STARTUP_V3_UNSUPPORTED && code < PKT_STARTUP_V4) {
			type = PKT_STARTUP_V3_UNSUPPORTED;
		} else if (code == PKT_STARTUP_V2) {
			type = PKT_STARTUP_V2;
		} else {
			log_noise("get_header: unknown special pkt: len=%u code=%u", len, code);
			return false;
		}
		got = OLD_HEADER_LEN;
	}

	/* don't believe nonsense */
	if (len < got || len > cf_max_packet_size)
		return false;

	/* store pkt info */
	pkt->type = type;
	pkt->len = len;

	/* fill pkt with only data for this packet */
	if (len > mbuf_avail_for_read(data)) {
		avail = mbuf_avail_for_read(data);
	} else {
		avail = len;
	}
	if (!mbuf_slice(data, avail, &pkt->data))
		return false;

	/* tag header as read */
	return mbuf_get_bytes(&pkt->data, got, &ptr);
}


/*
 * Send error message packet to client.
 *
 * If level_fatal is true, use severity "FATAL", else "ERROR".  Although it is
 * not technically part of the protocol specification, some clients expect the
 * connection to be closed after receiving a FATAL error, and don't expect it
 * to be closed after an ERROR-level error.  So to be nice, level_fatal should
 * be true if the caller plans to close the connection after sending this
 * error.
 * Error code 08P01 (ERRCODE_PROTOCOL_VIOLATION) is used as default error code
 * if no SQLSTATE is provided.
 */
bool send_pooler_error(PgSocket *client, bool send_ready, const char *sqlstate, bool level_fatal, const char *msg)
{
	uint8_t tmpbuf[512];
	PktBuf buf;

	if (cf_log_pooler_errors)
		slog_warning(client, "pooler error: %s", msg);

	pktbuf_static(&buf, tmpbuf, sizeof(tmpbuf));
	pktbuf_write_generic(&buf, PqMsg_ErrorResponse, "cscscsc",
			     'S', level_fatal ? "FATAL" : "ERROR",
			     'C', sqlstate ? sqlstate : "08P01", 'M', msg, 0);
	if (send_ready)
		pktbuf_write_ReadyForQuery(&buf);
	return pktbuf_send_immediate(&buf, client);
}

/*
 * Parse server error message and log it.
 */
void parse_server_error(PktHdr *pkt, const char **level_p, const char **msg_p, const char **sqlstate_p)
{
	const char *level = NULL, *msg = NULL, *sqlstate = NULL, *val;
	uint8_t type;
	while (mbuf_avail_for_read(&pkt->data)) {
		if (!mbuf_get_byte(&pkt->data, &type))
			break;
		if (type == 0)
			break;
		if (!mbuf_get_string(&pkt->data, &val))
			break;
		if (type == 'S') {
			level = val;
		} else if (type == 'M') {
			msg = val;
		} else if (type == 'C') {
			sqlstate = val;
		}
	}
	*level_p = level;
	*msg_p = msg;
	*sqlstate_p = sqlstate;
}

void log_server_error(const char *note, PktHdr *pkt)
{
	const char *level = NULL, *msg = NULL, *sqlstate = NULL;

	parse_server_error(pkt, &level, &msg, &sqlstate);

	if (!msg || !level) {
		log_error("%s: partial error message, cannot log", note);
	} else {
		log_error("%s: %s: %s", note, level, msg);
	}
}


/*
 * Preparation of welcome message for client connection.
 */

/* add another server parameter packet to cache */
bool add_welcome_parameter(PgPool *pool, const char *key, const char *val)
{
	PktBuf *msg = pool->welcome_msg;

	if (pool->welcome_msg_ready)
		return true;

	if (!msg) {
		msg = pktbuf_dynamic(128);
		if (!msg)
			return false;
		pool->welcome_msg = msg;
	}

	/* first packet must be AuthOk */
	if (msg->write_pos == 0)
		pktbuf_write_AuthenticationOk(msg);

	/* if not stored in ->orig_vars, write full packet */
	if (!varcache_set(&pool->orig_vars, key, val))
		pktbuf_write_ParameterStatus(msg, key, val);

	return !msg->failed;
}

/* all parameters processed */
void finish_welcome_msg(PgSocket *server)
{
	PgPool *pool = server->pool;
	if (pool->welcome_msg_ready)
		return;
	pool->welcome_msg_ready = true;
}

bool welcome_client(PgSocket *client)
{
	int res;
	PgPool *pool = client->pool;
	const PktBuf *pmsg = pool->welcome_msg;
	PktBuf *msg;

	slog_noise(client, "P: welcome_client");

	/* copy prepared stuff around */
	msg = pktbuf_temp();
	pktbuf_put_bytes(msg, pmsg->buf, pmsg->write_pos);

	/* fill vars */
	varcache_fill_unset(&pool->orig_vars, client);
	varcache_add_params(msg, &client->vars);

	/* give each client its own cancel key */
	get_random_bytes(client->cancel_key, 8);

	/*
	 * If pgbouncer peering is enabled we change some of the random bits of the
	 * cancel key to non random values, otherwise the peering feature cannot be
	 * implemented in an efficient way. This reduces the randomness of the key
	 * somewhat, but it still leaves us with 45 bits of randomness. This should
	 * be enough for all practical attacks to be mitigated (there are still
	 * ~35 trillion random combinations of these bits).
	 */
	if (cf_peer_id > 0) {
		/*
		 * The 2nd and 3rd byte represent the peer id. Pgbouncers that are
		 * peered with this one can forward the request to us by reading this
		 * peer id when they receive this cancellation.
		 */
		client->cancel_key[1] = cf_peer_id & 0xFF;
		client->cancel_key[2] = (cf_peer_id >> 8) & 0xFF;

		/*
		 * Initially we set the two TTL mask bits to a 1, so that the cancel
		 * message can be forwarded to peers up to 3 times.
		 */
		client->cancel_key[7] |= CANCELLATION_TTL_MASK;
	}

	/*
	 * The first 32 bits of the cancel_key are considered a PID. Since
	 * actual PIDs are always positive we clear the sign bit. Most clients
	 * work fine when receiving a negative number in this PID part, but it
	 * turned out that pg_basebackup did not. This is fixed in
	 * pg_basebackup, but to avoid similar future problems with other
	 * clients we clear the sign bit. See this thread for more details:
	 * https://www.postgresql.org/message-id/flat/CAGECzQQOGvYfp8ziF4fWQ_o8s2K7ppaoWBQnTmdakn3s-4Z%3D5g%40mail.gmail.com
	 */
	client->cancel_key[0] &= 0x7F;

	pktbuf_write_BackendKeyData(msg, client->cancel_key);

	/* finish */
	pktbuf_write_ReadyForQuery(msg);
	if (msg->failed) {
		disconnect_client(client, true, "failed to prepare welcome message");
		return false;
	}

	/* send all together */
	res = pktbuf_send_immediate(msg, client);
	if (!res) {
		disconnect_client(client, true, "failed to send welcome message");
		return false;
	}
	return true;
}

/*
 * Password authentication for server
 */

static PgCredentials *get_srv_psw(PgSocket *server)
{
	PgDatabase *db = server->pool->db;
	PgCredentials *credentials = server->pool->user_credentials;

	/* if forced user without password, use userlist psw */
	if (!credentials->passwd[0] && db->forced_user_credentials) {
		PgCredentials *c2 = find_global_credentials(credentials->name);
		if (c2)
			return c2;
	}
	return credentials;
}

/* actual packet send */
static bool send_password(PgSocket *server, const char *enc_psw)
{
	bool res;
	SEND_PasswordMessage(res, server, enc_psw);
	return res;
}

static bool login_clear_psw(PgSocket *server)
{
	PgCredentials *credentials = get_srv_psw(server);
	slog_debug(server, "P: send clear password");
	return send_password(server, credentials->passwd);
}

static bool login_md5_psw(PgSocket *server, const uint8_t *salt)
{
	char txt[MD5_PASSWD_LEN + 1], *src;
	PgCredentials *credentials = get_srv_psw(server);

	slog_debug(server, "P: send md5 password");

	switch (get_password_type(credentials->passwd)) {
	case PASSWORD_TYPE_PLAINTEXT:
		if (!pg_md5_encrypt(credentials->passwd, credentials->name, strlen(credentials->name), txt))
			return false;
		src = txt + 3;
		break;
	case PASSWORD_TYPE_MD5:
		src = credentials->passwd + 3;
		break;
	default:
		slog_error(server, "cannot do MD5 authentication: wrong password type");
		kill_pool_logins(server->pool, NULL, "server login failed: wrong password type");
		return false;
	}

	if (!pg_md5_encrypt(src, (char *)salt, 4, txt))
		return false;

	return send_password(server, txt);
}

static bool login_scram_sha_256(PgSocket *server)
{
	PgCredentials *credentials = get_srv_psw(server);
	bool res;
	char *client_first_message = NULL;

	switch (get_password_type(credentials->passwd)) {
	case PASSWORD_TYPE_PLAINTEXT:
		/* ok */
		break;
	case PASSWORD_TYPE_SCRAM_SHA_256:
		if (!credentials->use_scram_keys) {
			slog_error(server, "cannot do SCRAM authentication: password is SCRAM secret but client authentication did not provide SCRAM keys");
			kill_pool_logins(server->pool, NULL, "server login failed: wrong password type");
			return false;
		}
		break;
	default:
		slog_error(server, "cannot do SCRAM authentication: wrong password type");
		kill_pool_logins(server->pool, NULL, "server login failed: wrong password type");
		return false;
	}

	if (server->scram_state.client_nonce) {
		slog_error(server, "protocol error: duplicate AuthenticationSASL message from server");
		return false;
	}

	client_first_message = build_client_first_message(&server->scram_state);
	if (!client_first_message)
		return false;

	slog_debug(server, "SCRAM client-first-message = \"%s\"", client_first_message);
	slog_debug(server, "P: send SASLInitialResponse");
	SEND_SASLInitialResponseMessage(res, server, "SCRAM-SHA-256", client_first_message);

	free(client_first_message);
	return res;
}

static bool login_scram_sha_256_cont(PgSocket *server, unsigned datalen, const uint8_t *data)
{
	PgCredentials *credentials = get_srv_psw(server);
	char *ibuf = NULL;
	char *input;
	char *server_nonce;
	int saltlen;
	char *salt = NULL;
	int iterations;
	bool res;
	char *client_final_message = NULL;

	if (!server->scram_state.client_nonce) {
		slog_error(server, "protocol error: AuthenticationSASLContinue without prior AuthenticationSASL");
		return false;
	}

	if (server->scram_state.server_first_message) {
		slog_error(server, "SCRAM exchange protocol error: received second AuthenticationSASLContinue");
		return false;
	}

	ibuf = malloc(datalen + 1);
	if (ibuf == NULL)
		return false;
	memcpy(ibuf, data, datalen);
	ibuf[datalen] = '\0';

	input = ibuf;
	slog_debug(server, "SCRAM server-first-message = \"%s\"", input);
	if (!read_server_first_message(server, input,
				       &server_nonce, &salt, &saltlen, &iterations))
		goto failed;

	client_final_message = build_client_final_message(&server->scram_state,
							  credentials, server_nonce,
							  salt, saltlen, iterations);

	free(salt);
	free(ibuf);

	slog_debug(server, "SCRAM client-final-message = \"%s\"", client_final_message);
	slog_debug(server, "P: send SASLResponse");
	SEND_SASLResponseMessage(res, server, client_final_message);

	free(client_final_message);
	return res;
failed:
	free(salt);
	free(ibuf);
	free(client_final_message);
	return false;
}

static bool login_scram_sha_256_final(PgSocket *server, unsigned datalen, const uint8_t *data)
{
	PgCredentials *credentials = get_srv_psw(server);
	char *ibuf = NULL;
	char *input;
	char ServerSignature[SHA256_DIGEST_LENGTH];

	if (!server->scram_state.server_first_message) {
		slog_error(server, "protocol error: AuthenticationSASLFinal without prior AuthenticationSASLContinue");
		return false;
	}

	ibuf = malloc(datalen + 1);
	if (ibuf == NULL)
		return false;
	memcpy(ibuf, data, datalen);
	ibuf[datalen] = '\0';

	input = ibuf;
	slog_debug(server, "SCRAM server-final-message = \"%s\"", input);
	if (!read_server_final_message(server, input, ServerSignature))
		goto failed;

	if (!verify_server_signature(&server->scram_state, credentials, ServerSignature)) {
		slog_error(server, "invalid server signature");
		kill_pool_logins(server->pool, NULL, "server login failed: invalid server signature");
		goto failed;
	}

	free(ibuf);
	return true;
failed:
	free(ibuf);
	return false;
}

/* answer server authentication request */
bool answer_authreq(PgSocket *server, PktHdr *pkt)
{
	uint32_t cmd;
	const uint8_t *salt;
	bool res = false;

	/* authreq body must contain 32bit cmd */
	if (mbuf_avail_for_read(&pkt->data) < 4)
		return false;

	if (!mbuf_get_uint32be(&pkt->data, &cmd))
		return false;
	switch (cmd) {
	case AUTH_REQ_OK:
		slog_debug(server, "S: auth ok");
		res = true;
		break;
	case AUTH_REQ_PASSWORD:
		slog_debug(server, "S: req cleartext password");
		res = login_clear_psw(server);
		break;
	case AUTH_REQ_MD5:
		slog_debug(server, "S: req md5-crypted psw");
		if (!mbuf_get_bytes(&pkt->data, 4, &salt))
			return false;
		res = login_md5_psw(server, salt);
		break;
	case AUTH_REQ_SASL:
	{
		bool selected_mechanism = false;

		slog_debug(server, "S: req SASL");

		do {
			const char *mech;

			if (!mbuf_get_string(&pkt->data, &mech))
				return false;
			if (!mech[0])
				break;
			slog_debug(server, "S: SASL advertised mechanism: %s", mech);
			if (strcmp(mech, "SCRAM-SHA-256") == 0)
				selected_mechanism = true;
		} while (!selected_mechanism);

		if (!selected_mechanism) {
			slog_error(server, "none of the server's SASL authentication mechanisms are supported");
			kill_pool_logins(server->pool, NULL, "server login failed: none of the server's SASL authentication mechanisms are supported");
		} else {
			res = login_scram_sha_256(server);
		}
		break;
	}
	case AUTH_REQ_SASL_CONT:
	{
		unsigned len;
		const uint8_t *data;

		slog_debug(server, "S: SASL cont");
		len = mbuf_avail_for_read(&pkt->data);
		if (!mbuf_get_bytes(&pkt->data, len, &data))
			return false;
		res = login_scram_sha_256_cont(server, len, data);
		break;
	}
	case AUTH_REQ_SASL_FIN:
	{
		unsigned len;
		const uint8_t *data;

		slog_debug(server, "S: SASL final");
		len = mbuf_avail_for_read(&pkt->data);
		if (!mbuf_get_bytes(&pkt->data, len, &data))
			return false;
		res = login_scram_sha_256_final(server, len, data);
		free_scram_state(&server->scram_state);
		break;
	}
	default:
		slog_error(server, "unknown/unsupported auth method: %u", cmd);
		res = false;
		break;
	}
	return res;
}

bool send_startup_packet(PgSocket *server)
{
	PgPool *pool = server->pool;
	PgDatabase *db = pool->db;
	const char *username = server->pool->user_credentials->name;
	PktBuf *pkt = pktbuf_temp();
	PgSocket *client = NULL;

	pktbuf_start_packet(pkt, PKT_STARTUP_V3);
	pktbuf_put_bytes(pkt, db->startup_params->buf, db->startup_params->write_pos);

	/*
	 * If the next client in the list is a replication connection, we need
	 * to do some special stuff for it.
	 */
	client = first_socket(&pool->waiting_client_list);
	if (client && client->replication && !sending_auth_query(client)) {
		server->replication = client->replication;
		pktbuf_put_string(pkt, "replication");
		slog_debug(server, "send_startup_packet: creating replication connection");
		pktbuf_put_string(pkt, replication_type_parameters[server->replication]);

		/*
		 * For a replication connection we apply the varcache in the
		 * startup instead of through SET commands after connecting.
		 * The main reason to do so is because physical replication
		 * connections don't allow SET commands. A second reason is
		 * because it allows us to skip running the SET logic
		 * completely, which normally requires waiting on multiple
		 * server responses. This SET logic is normally executed in the
		 * codepath where we link the client to the server
		 * (find_server), but because we link the client here already
		 * we don't run that code for replication connections. Adding
		 * the varcache parameters to the startup message allows us to
		 * skip the dance that involves sending Query packets and
		 * waiting for responses.
		 */
		varcache_apply_startup(pkt, client);
		if (client->startup_options) {
			pktbuf_put_string(pkt, "options");
			pktbuf_put_string(pkt, client->startup_options);
		}
	}

	pktbuf_put_string(pkt, "user");
	pktbuf_put_string(pkt, username);
	pktbuf_put_string(pkt, "");	/* terminator required in StartupMessage */
	pktbuf_finish_packet(pkt);

	if (!pktbuf_send_immediate(pkt, server)) {
		return false;
	}

	if (server->replication) {
		/*
		 * We link replication connections to a client directly when they are
		 * created. One reason for is because the startup parameters need to be
		 * forwarded, because physical replication connections don't allow SET
		 * commands. Another reason is so that we don't need a separate state.
		 */
		client->link = server;
		server->link = client;
	}

	return true;
}

bool send_sslreq_packet(PgSocket *server)
{
	int res;
	SEND_wrap(16, pktbuf_write_SSLRequest, res, server);
	return res;
}

/*
 * decode DataRow packet (opposite of pktbuf_write_DataRow)
 *
 * tupdesc keys:
 * 'i' - int4
 * 'q' - int8
 * 's' - text to string
 * 'b' - bytea to bytes (result is malloced)
 */
int scan_text_result(struct MBuf *pkt, const char *tupdesc, ...)
{
	uint16_t ncol;
	unsigned asked;
	va_list ap;

	asked = strlen(tupdesc);
	if (!mbuf_get_uint16be(pkt, &ncol))
		return -1;

	va_start(ap, tupdesc);
	for (unsigned i = 0; i < asked; i++) {
		const char *val = NULL;
		uint32_t len;

		if (i < ncol) {
			if (!mbuf_get_uint32be(pkt, &len)) {
				goto failed;
			}
			if ((int32_t)len < 0) {
				val = NULL;
			} else {
				if (!mbuf_get_chars(pkt, len, &val)) {
					goto failed;
				}
			}

			/* hack to zero-terminate the result */
			if (val) {
				char *xval = (char *)val - 1;
				memmove(xval, val, len);
				xval[len] = 0;
				val = xval;
			}
		} else {
			/* tuple was shorter than requested */
			val = NULL;
			len = -1;
		}

		switch (tupdesc[i]) {
		case 'i': {
			int *int_p;

			int_p = va_arg(ap, int *);
			*int_p = val ? atoi(val) : 0;
			break;
		}
		case 'q': {
			uint64_t *long_p;

			long_p = va_arg(ap, uint64_t *);
			*long_p = val ? atoll(val) : 0;
			break;
		}
		case 's': {
			const char **str_p;

			str_p = va_arg(ap, const char **);
			*str_p = val;
			break;
		}
		case 'b': {
			int *len_p = va_arg(ap, int *);
			uint8_t **bytes_p = va_arg(ap, uint8_t **);

			if (val) {
				int newlen;
				if (strncmp(val, "\\x", 2) != 0) {
					log_warning("invalid bytea value");
					goto failed;
				}

				newlen = (len - 2) / 2;
				*len_p = newlen;
				*bytes_p = malloc(newlen);
				if (!(*bytes_p)) {
					goto failed;
				}
				for (int j = 0; j < newlen; j++) {
					unsigned int b;
					sscanf(val + 2 + 2 * j, "%2x", &b);
					(*bytes_p)[j] = b;
				}
			} else {
				*len_p = -1;
				*bytes_p = NULL;
			}
			break;
		}
		default:
			fatal("bad tupdesc: %s", tupdesc);
		}
	}
	va_end(ap);

	return ncol;
failed:
	va_end(ap);
	return -1;
}
