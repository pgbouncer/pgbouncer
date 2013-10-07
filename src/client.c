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
 * Client connection handling
 */

#include "bouncer.h"

#include <usual/pgutil.h>

static const char *hdr2hex(const struct MBuf *data, char *buf, unsigned buflen)
{
	const uint8_t *bin = data->data + data->read_pos;
	unsigned int dlen;

	dlen = mbuf_avail_for_read(data);
	return bin2hex(bin, dlen, buf, buflen);
}

static bool check_client_passwd(PgSocket *client, const char *passwd)
{
	char md5[MD5_PASSWD_LEN + 1];
	const char *correct;
	PgUser *user = client->auth_user;

	/* disallow empty passwords */
	if (!*passwd || !*user->passwd)
		return false;

	switch (cf_auth_type) {
	case AUTH_PLAIN:
		return strcmp(user->passwd, passwd) == 0;
	case AUTH_CRYPT:
		correct = crypt(user->passwd, (char *)client->tmp_login_salt);
		return correct && strcmp(correct, passwd) == 0;
	case AUTH_MD5:
		if (strlen(passwd) != MD5_PASSWD_LEN)
			return false;
		if (!isMD5(user->passwd))
			pg_md5_encrypt(user->passwd, user->name, strlen(user->name), user->passwd);
		pg_md5_encrypt(user->passwd + 3, (char *)client->tmp_login_salt, 4, md5);
		return strcmp(md5, passwd) == 0;
	}
	return false;
}

/* mask to get offset into valid_crypt_salt[] */
#define SALT_MASK  0x3F

static const char valid_crypt_salt[] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static bool send_client_authreq(PgSocket *client)
{
	uint8_t saltlen = 0;
	int res;
	int auth = cf_auth_type;
	uint8_t randbuf[2];

	if (auth == AUTH_CRYPT) {
		saltlen = 2;
		get_random_bytes(randbuf, saltlen);
		client->tmp_login_salt[0] = valid_crypt_salt[randbuf[0] & SALT_MASK];
		client->tmp_login_salt[1] = valid_crypt_salt[randbuf[1] & SALT_MASK];
		client->tmp_login_salt[2] = 0;
	} else if (cf_auth_type == AUTH_MD5) {
		saltlen = 4;
		get_random_bytes((void*)client->tmp_login_salt, saltlen);
	} else if (auth == AUTH_ANY)
		auth = AUTH_TRUST;

	SEND_generic(res, client, 'R', "ib", auth, client->tmp_login_salt, saltlen);
	return res;
}

static void start_auth_request(PgSocket *client, const char *username)
{
	int res;
	char quoted_username[64], query[128];

	client->auth_user = client->db->auth_user;
	/* have to fetch user info from db */
	client->pool = get_pool(client->db, client->db->auth_user);
	if (!find_server(client)) {
		client->wait_for_user_conn = true;
		return;
	}
	slog_noise(client, "Doing auth_conn query");
	client->wait_for_user_conn = false;
	client->wait_for_user = true;
	if (!sbuf_pause(&client->sbuf)) {
		release_server(client->link);
		disconnect_client(client, true, "pause failed");
		return;
	}
	client->link->ready = 0;

	pg_quote_literal(quoted_username, username, sizeof(quoted_username));
	snprintf(query, sizeof(query), "SELECT usename, passwd FROM pg_shadow WHERE usename=%s", quoted_username);
	SEND_generic(res, client->link, 'Q', "s", query);
	if (!res)
		disconnect_server(client->link, false, "unable to send login query");
}

static bool finish_set_pool(PgSocket *client, bool takeover)
{
	PgUser *user = client->auth_user;
	/* pool user may be forced */
	if (client->db->forced_user) {
		user = client->db->forced_user;
	}
	client->pool = get_pool(client->db, user);
	if (!client->pool) {
		disconnect_client(client, true, "no memory for pool");
		return false;
	}

	if (cf_log_connections)
		slog_info(client, "login attempt: db=%s user=%s", client->db->name, client->auth_user->name);

	if (!check_fast_fail(client))
		return false;

	if (takeover)
		return true;

	if (client->pool->db->admin) {
		if (!admin_post_login(client))
			return false;
	}

	if (cf_auth_type <= AUTH_TRUST || client->own_user) {
		if (!finish_client_login(client))
			return false;
	} else {
		if (!send_client_authreq(client)) {
			disconnect_client(client, false, "failed to send auth req");
			return false;
		}
	}
	return true;
}

bool set_pool(PgSocket *client, const char *dbname, const char *username, const char *password, bool takeover)
{
	/* find database */
	client->db = find_database(dbname);
	if (!client->db) {
		client->db = register_auto_database(dbname);
		if (!client->db) {
			disconnect_client(client, true, "No such database: %s", dbname);
			if (cf_log_connections)
				slog_info(client, "login failed: db=%s user=%s", dbname, username);
			return false;
		}
		else {
			slog_info(client, "registered new auto-database: db = %s", dbname );
		}
	}

	/* are new connections allowed? */
	if (client->db->db_disabled) {
		disconnect_client(client, true, "database does not allow connections: %s", dbname);
		return false;
	}

	if (client->db->admin) {
		if (admin_pre_login(client, username))
			return finish_set_pool(client, takeover);
	}

	/* find user */
	if (cf_auth_type == AUTH_ANY) {
		/* ignore requested user */
		if (client->db->forced_user == NULL) {
			slog_error(client, "auth_type=any requires forced user");
			disconnect_client(client, true, "bouncer config error");
			return false;
		}
		client->auth_user = client->db->forced_user;
	} else {
		/* the user clients wants to log in as */
		client->auth_user = find_user(username);
		if (!client->auth_user && client->db->auth_user) {
			if (takeover) {
				client->auth_user = add_db_user(client->db, username, password);
				return finish_set_pool(client, takeover);
			}
			start_auth_request(client, username);
			return false;
		}
		if (!client->auth_user) {
			disconnect_client(client, true, "No such user: %s", username);
			if (cf_log_connections)
				slog_info(client, "login failed: db=%s user=%s", dbname, username);
			return false;
		}
	}
	return finish_set_pool(client, takeover);
}

bool handle_auth_response(PgSocket *client, PktHdr *pkt) {
	uint16_t columns;
	uint32_t length;
	const char *username, *password;
	PgUser user;
	PgSocket *server = client->link;

	switch(pkt->type) {
	case 'T':	/* RowDescription */
		if (!mbuf_get_uint16be(&pkt->data, &columns)) {
			disconnect_server(server, false, "bad packet");
			return false;
		}
		if (columns != 2u) {
			disconnect_server(server, false, "expected 1 column from login query, not %hu", columns);
			return false;
		}
		break;
	case 'D':	/* DataRow */
		memset(&user, 0, sizeof(user));
		if (!mbuf_get_uint16be(&pkt->data, &columns)) {
			disconnect_server(server, false, "bad packet");
			return false;
		}
		if (columns != 2u) {
			disconnect_server(server, false, "expected 1 column from login query, not %hu", columns);
			return false;
		}
		if (!mbuf_get_uint32be(&pkt->data, &length)) {
			disconnect_server(server, false, "bad packet");
			return false;
		}
		if (!mbuf_get_chars(&pkt->data, length, &username)) {
			disconnect_server(server, false, "bad packet");
			return false;
		}
		if (sizeof(user.name) - 1 < length)
			length = sizeof(user.name) - 1;
		memcpy(user.name, username, length);
		if (!mbuf_get_uint32be(&pkt->data, &length)) {
			disconnect_server(server, false, "bad packet");
			return false;
		}
		if (length == (uint32_t)-1) {
			// NULL - set an md5 password with an impossible value,
			// so that nothing will ever match
			password = "md5";
			length = 3;
		} else {
			if (!mbuf_get_chars(&pkt->data, length, &password)) {
				disconnect_server(server, false, "bad packet");
				return false;
			}
		}
		if (sizeof(user.passwd)  - 1 < length)
			length = sizeof(user.passwd) - 1;
		memcpy(user.passwd, password, length);

		client->auth_user = add_db_user(client->db, user.name, user.passwd);
		if (!client->auth_user) {
			disconnect_server(server, false, "unable to allocate new user for auth");
			return false;
		}
		break;
	case 'C':	/* CommandComplete */
		break;
	case 'Z':	/* ReadyForQuery */
		sbuf_prepare_skip(&client->link->sbuf, pkt->len);
		if (!client->auth_user) {
			if (cf_log_connections)
				slog_info(client, "login failed: db=%s", client->db->name);
			disconnect_client(client, true, "No such user");
		} else {
			slog_noise(client, "auth query complete");
			client->link->resetting = true;
			sbuf_continue(&client->sbuf);
		}
		// either sbuf_continue or disconnect_client could disconnect the server
		// way down in their bowels of other callbacks. so check that, and
		// return appropriately (similar to reuse_on_release)
		if (server->state == SV_FREE || server->state == SV_JUSTFREE)
			return false;
		return true;
	default:
		disconnect_server(server, false, "unexpected response from login query");
		return false;
	}
	sbuf_prepare_skip(&server->sbuf, pkt->len);
	return true;
}

static bool decide_startup_pool(PgSocket *client, PktHdr *pkt)
{
	const char *username = NULL, *dbname = NULL;
	const char *key, *val;
	bool ok;

	while (1) {
		ok = mbuf_get_string(&pkt->data, &key);
		if (!ok || *key == 0)
			break;
		ok = mbuf_get_string(&pkt->data, &val);
		if (!ok)
			break;

		if (strcmp(key, "database") == 0) {
			slog_debug(client, "got var: %s=%s", key, val);
			dbname = val;
		} else if (strcmp(key, "user") == 0) {
			slog_debug(client, "got var: %s=%s", key, val);
			username = val;
		} else if (varcache_set(&client->vars, key, val)) {
			slog_debug(client, "got var: %s=%s", key, val);
		} else if (strlist_contains(cf_ignore_startup_params, key)) {
			slog_debug(client, "ignoring startup parameter: %s=%s", key, val);
		} else {
			slog_warning(client, "unsupported startup parameter: %s=%s", key, val);
			disconnect_client(client, true, "Unsupported startup parameter: %s", key);
			return false;
		}
	}
	if (!username || !username[0]) {
		disconnect_client(client, true, "No username supplied");
		return false;
	}

	/* if missing dbname, default to username */
	if (!dbname || !dbname[0])
		dbname = username;

	/* check if limit allows, dont limit admin db
	   nb: new incoming conn will be attached to PgSocket, thus
	   get_active_client_count() counts it */
	if (get_active_client_count() > cf_max_client_conn) {
		if (strcmp(dbname, "pgbouncer") != 0) {
			disconnect_client(client, true, "no more connections allowed (max_client_conn)");
			return false;
		}
	}

	/* find pool */
	return set_pool(client, dbname, username, "", false);
}

/* decide on packets of client in login phase */
static bool handle_client_startup(PgSocket *client, PktHdr *pkt)
{
	const char *passwd;
	const uint8_t *key;
	bool ok;

	SBuf *sbuf = &client->sbuf;

	/* don't tolerate partial packets */
	if (incomplete_pkt(pkt)) {
		disconnect_client(client, true, "client sent partial pkt in startup phase");
		return false;
	}

	if (client->wait_for_welcome) {
		if  (finish_client_login(client)) {
			/* the packet was already parsed */
			sbuf_prepare_skip(sbuf, pkt->len);
			return true;
		} else
			return false;
	}

	switch (pkt->type) {
	case PKT_SSLREQ:
		slog_noise(client, "C: req SSL");
		slog_noise(client, "P: nak");

		/* reject SSL attempt */
		if (!sbuf_answer(&client->sbuf, "N", 1)) {
			disconnect_client(client, false, "failed to nak SSL");
			return false;
		}
		break;
	case PKT_STARTUP_V2:
		disconnect_client(client, true, "Old V2 protocol not supported");
		return false;
	case PKT_STARTUP:
		if (client->pool && !client->wait_for_user_conn && !client->wait_for_user) {
			disconnect_client(client, true, "client re-sent startup pkt");
			return false;
		}

		if (client->wait_for_user) {
			client->wait_for_user = false;
			if (!finish_set_pool(client, false))
				return false;
		} else if (!decide_startup_pool(client, pkt)) {
			return false;
		}

		break;
	case 'p':		/* PasswordMessage */
		/* haven't requested it */
		if (cf_auth_type <= AUTH_TRUST) {
			disconnect_client(client, true, "unrequested passwd pkt");
			return false;
		}

		ok = mbuf_get_string(&pkt->data, &passwd);
		if (ok && check_client_passwd(client, passwd)) {
			if (!finish_client_login(client))
				return false;
		} else {
			disconnect_client(client, true, "Auth failed");
			return false;
		}
		break;
	case PKT_CANCEL:
		if (mbuf_avail_for_read(&pkt->data) == BACKENDKEY_LEN
		    && mbuf_get_bytes(&pkt->data, BACKENDKEY_LEN, &key))
		{
			memcpy(client->cancel_key, key, BACKENDKEY_LEN);
			accept_cancel_request(client);
		} else
			disconnect_client(client, false, "bad cancel request");
		return false;
	default:
		disconnect_client(client, false, "bad packet");
		return false;
	}
	sbuf_prepare_skip(sbuf, pkt->len);
	client->request_time = get_cached_time();
	return true;
}

/* decide on packets of logged-in client */
static bool handle_client_work(PgSocket *client, PktHdr *pkt)
{
	SBuf *sbuf = &client->sbuf;

	switch (pkt->type) {

	/* one-packet queries */
	case 'Q':		/* Query */
		if (cf_disable_pqexec) {
			slog_error(client, "Client used 'Q' packet type.");
			disconnect_client(client, true, "PQexec disallowed");
			return false;
		}
	case 'F':		/* FunctionCall */

	/* request immediate response from server */
	case 'H':		/* Flush */
	case 'S':		/* Sync */

	/* copy end markers */
	case 'c':		/* CopyDone(F/B) */
	case 'f':		/* CopyFail(F/B) */

	/*
	 * extended protocol allows server (and thus pooler)
	 * to buffer packets until sync or flush is sent by client
	 */
	case 'P':		/* Parse */
	case 'E':		/* Execute */
	case 'C':		/* Close */
	case 'B':		/* Bind */
	case 'D':		/* Describe */
	case 'd':		/* CopyData(F/B) */

		/* update stats */
		if (!client->query_start) {
			client->pool->stats.request_count++;
			client->query_start = get_cached_time();
		}

		if (client->pool->db->admin)
			return admin_handle_client(client, pkt);

		/* aquire server */
		if (!find_server(client))
			return false;

		client->pool->stats.client_bytes += pkt->len;

		/* tag the server as dirty */
		client->link->ready = false;
		client->link->idle_tx = false;

		/* forward the packet */
		sbuf_prepare_send(sbuf, &client->link->sbuf, pkt->len);
		break;

	/* client wants to go away */
	default:
		slog_error(client, "unknown pkt from client: %d/0x%x", pkt->type, pkt->type);
		disconnect_client(client, true, "unknown pkt");
		return false;
	case 'X': /* Terminate */
		disconnect_client(client, false, "client close request");
		return false;
	}
	return true;
}

/* callback from SBuf */
bool client_proto(SBuf *sbuf, SBufEvent evtype, struct MBuf *data)
{
	bool res = false;
	PgSocket *client = container_of(sbuf, PgSocket, sbuf);
	PktHdr pkt;


	Assert(!is_server_socket(client));
	Assert(client->sbuf.sock);
	Assert(client->state != CL_FREE);

	/* may happen if close failed */
	if (client->state == CL_JUSTFREE)
		return false;

	switch (evtype) {
	case SBUF_EV_CONNECT_OK:
	case SBUF_EV_CONNECT_FAILED:
		/* ^ those should not happen */
	case SBUF_EV_RECV_FAILED:
		disconnect_client(client, false, "client unexpected eof");
		break;
	case SBUF_EV_SEND_FAILED:
		disconnect_server(client->link, false, "Server connection closed");
		break;
	case SBUF_EV_READ:
		if (mbuf_avail_for_read(data) < NEW_HEADER_LEN && client->state != CL_LOGIN) {
			slog_noise(client, "C: got partial header, trying to wait a bit");
			return false;
		}

		if (!get_header(data, &pkt)) {
			char hex[8*2 + 1];
			disconnect_client(client, true, "bad packet header: '%s'",
					  hdr2hex(data, hex, sizeof(hex)));
			return false;
		}
		slog_noise(client, "pkt='%c' len=%d", pkt_desc(&pkt), pkt.len);

		client->request_time = get_cached_time();
		switch (client->state) {
		case CL_LOGIN:
			res = handle_client_startup(client, &pkt);
			break;
		case CL_ACTIVE:
			if (client->wait_for_welcome)
				res = handle_client_startup(client, &pkt);
			else
				res = handle_client_work(client, &pkt);
			break;
		case CL_WAITING:
			fatal("why waiting client in client_proto()");
		default:
			fatal("bad client state: %d", client->state);
		}
		break;
	case SBUF_EV_FLUSH:
		/* client is not interested in it */
		break;
	case SBUF_EV_PKT_CALLBACK:
		/* unused ATM */
		break;
	}
	return res;
}

