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
 * Client connection handling
 */

#include "bouncer.h"

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
		correct = pg_crypt(user->passwd, (char *)client->salt);
		return strcmp(correct, passwd) == 0;
	case AUTH_MD5:
		if (strlen(passwd) != MD5_PASSWD_LEN)
			return false;
		if (!isMD5(user->passwd))
			pg_md5_encrypt(user->passwd, user->name, strlen(user->name), user->passwd);
		pg_md5_encrypt(user->passwd + 3, client->salt, 4, md5);
		return strcmp(md5, passwd) == 0;
	}
	return false;
}

bool
set_pool(PgSocket *client, const char *dbname, const char *username)
{
	PgDatabase *db;
	PgUser *user;

	/* find database */
	db = find_database(dbname);
	if (!db) {
		disconnect_client(client, true, "No such database");
		return false;
	}

	/* find user */
	if (cf_auth_type == AUTH_ANY) {
		/* ignore requested user */
		user = NULL;

		if (db->forced_user == NULL) {
			disconnect_client(client, true, "bouncer config error");
			log_error("auth_type=any requires forced user");
			return false;
		}
		client->auth_user = db->forced_user;
	} else {
		/* the user clients wants to log in as */
		user = find_user(username);
		if (!user) {
			disconnect_client(client, true, "No such user");
			return false;
		}
		client->auth_user = user;
	}

	/* pool user may be forced */
	if (db->forced_user)
		user = db->forced_user;
	client->pool = get_pool(db, user);
	if (!client->pool) {
		disconnect_client(client, true, "no mem for pool");
		return false;
	}

	return true;
}

static bool decide_startup_pool(PgSocket *client, MBuf *pkt)
{
	const char *username = NULL, *dbname = NULL;
	const char *key, *val;

	while (1) {
		key = mbuf_get_string(pkt);
		if (!key || *key == 0)
			break;
		val = mbuf_get_string(pkt);
		if (!val)
			break;

		if (strcmp(key, "database") == 0)
			dbname = val;
		else if (strcmp(key, "user") == 0)
			username = val;
	}
	if (!username) {
		disconnect_client(client, true, "No username supplied");
		return false;
	}
	if (!dbname) {
		disconnect_client(client, true, "No database supplied");
		return false;
	}

	if (cf_log_connections)
		slog_info(client, "login request: db=%s user=%s", dbname, username);

	/* check if limit allows, dont limit admin db
	   nb: new incoming conn will be attached to PgSocket, thus
	   get_active_client_count() counts it */
	if (get_active_client_count() > cf_max_client_conn) {
		if (strcmp(dbname, "pgbouncer") != 0) {
			disconnect_client(client, true, "no more conns allowed");
			return false;
		}
	}
	return set_pool(client, dbname, username);
}

static const char valid_crypt_salt[] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static bool send_client_authreq(PgSocket *client)
{
	uint8 saltlen = 0;
	int res;
	int auth = cf_auth_type;

	if (auth == AUTH_CRYPT) {
		saltlen = 2;
		get_random_bytes((void*)client->salt, saltlen);
		client->salt[0] = valid_crypt_salt[client->salt[0] & 0x3f];
		client->salt[1] = valid_crypt_salt[client->salt[1] & 0x3f];
		client->salt[2] = 0;
	} else if (cf_auth_type == AUTH_MD5) {
		saltlen = 4;
		get_random_bytes((void*)client->salt, saltlen);
	} else if (auth == AUTH_ANY)
		auth = AUTH_TRUST;

	SEND_generic(res, client, 'R', "ib", auth, client->salt, saltlen);
	return res;
}

/* decide on packets of client in login phase */
static bool handle_client_startup(PgSocket *client, MBuf *pkt)
{
	unsigned pkt_type;
	unsigned pkt_len;
	const char *passwd;

	SBuf *sbuf = &client->sbuf;

	/* dont tolerate partial packets */
	if (!get_header(pkt, &pkt_type, &pkt_len)) {
		disconnect_client(client, true, "client sent bad pkt header");
		return false;
	}

	if (client->wait_for_welcome) {
		if  (finish_client_login(client)) {
			/* the packet was already parsed */
			sbuf_prepare_skip(sbuf, pkt_len);
			return true;
		} else
			return false;
	}

	slog_noise(client, "pkt='%c' len=%d",
		   pkt_type < 256 ? pkt_type : '?', pkt_len);

	switch (pkt_type) {
	case PKT_SSLREQ:
		log_noise("C: req SSL");
		log_noise("P: nak");

		/* reject SSL attempt */
		if (!sbuf_answer(&client->sbuf, "N", 1)) {
			disconnect_client(client, false, "failed to nak SSL");
			return false;
		}
		break;
	case PKT_STARTUP:
		if (mbuf_avail(pkt) < pkt_len - 8) {
			disconnect_client(client, true, "client sent partial pkt in startup");
			return false;
		}
		if (client->pool) {
			disconnect_client(client, true, "client re-sent startup pkt");
			return false;
		}

		if (!decide_startup_pool(client, pkt))
			return false;

		if (client->pool->admin) {
			if (!admin_pre_login(client))
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
		break;
	case 'p':		/* PasswordMessage */
		if (mbuf_avail(pkt) < pkt_len - 5) {
			disconnect_client(client, true, "client sent partial pkt in startup");
			return false;
		}

		/* havent requested it */
		if (cf_auth_type <= AUTH_TRUST) {
			disconnect_client(client, true, "unreqested passwd pkt");
			return false;
		}

		passwd = mbuf_get_string(pkt);
		if (passwd && check_client_passwd(client, passwd)) {
			if (!finish_client_login(client))
				return false;
		} else {
			disconnect_client(client, true, "Login failed");
			return false;
		}
		break;
	case PKT_CANCEL:
		if (mbuf_avail(pkt) == 8) {
			const uint8 *key = mbuf_get_bytes(pkt, 8);
			memcpy(client->cancel_key, key, 8);
			accept_cancel_request(client);
		} else
			disconnect_client(client, false, "bad cancel request");
		return false;
	default:
		disconnect_client(client, false, "bad pkt");
		return false;
	}
	sbuf_prepare_skip(sbuf, pkt_len);
	client->request_time = get_cached_time();
	return true;
}

/* decide on packets of logged-in client */
static bool handle_client_work(PgSocket *client, MBuf *pkt)
{
	unsigned pkt_type;
	unsigned pkt_len;
	bool flush = 0;
	SBuf *sbuf = &client->sbuf;

	if (!get_header(pkt, &pkt_type, &pkt_len)) {
		disconnect_client(client, true, "bad pkt header");
		return false;
	}
	slog_noise(client, "pkt='%c' len=%d", pkt_type, pkt_len);

	switch (pkt_type) {

	/* request immidiate response from server */
	case 'H':		/* Flush */
		client->flush_req = 1;
	case 'S':		/* Sync */
		/* sync is followed by ReadyForQuery */

	/* one-packet queries */
	case 'Q':		/* Query */
	case 'F':		/* FunctionCall */

	/* copy end markers */
	case 'c':		/* CopyDone(F/B) */
	case 'f':		/* CopyFail(F/B) */

		/* above packets should be sent ASAP */
		flush = 1;

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

		if (client->pool->admin)
			return admin_handle_client(client, pkt, pkt_type, pkt_len);

		/* aquire server */
		if (!find_server(client))
			return false;

		client->pool->stats.client_bytes += pkt_len;

		/* tag the server as dirty */
		client->link->ready = 0;

		/* forward the packet */
		sbuf_prepare_send(sbuf, &client->link->sbuf, pkt_len, flush);
		break;

	/* client wants to go away */
	default:
		slog_error(client, "unknown pkt from client: %d/0x%x", pkt_type, pkt_type);
		disconnect_client(client, true, "unknown pkt");
		return false;
	case 'X': /* Terminate */
		disconnect_client(client, false, "client close request");
		return false;
	}
	return true;
}

/* callback from SBuf */
bool client_proto(SBuf *sbuf, SBufEvent evtype, MBuf *pkt, void *arg)
{
	bool res = false;
	PgSocket *client = arg;

	Assert(!is_server_socket(client));
	Assert(client->sbuf.sock);
	Assert(client->state != CL_FREE);

	if (client->state == CL_JUSTFREE) {
		/* SBuf should catch the case */
		slog_warning(client, "state=CL_JUSTFREE, should not happen");
		return false;
	}

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
		if (mbuf_avail(pkt) < 5) {
			log_noise("C: got partial header, trying to wait a bit");
			return false;
		}

		client->request_time = get_cached_time();
		switch (client->state) {
		case CL_LOGIN:
			res = handle_client_startup(client, pkt);
			break;
		case CL_ACTIVE:
			if (client->wait_for_welcome)
				res = handle_client_startup(client, pkt);
			else
				res = handle_client_work(client, pkt);
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
	}
	return res;
}

