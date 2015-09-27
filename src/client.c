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

static inline const char *str_skip_ws(const char *p)
{
  while (*p && isspace(*p))
    p++;
  return p;
}

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
	PgUser *user = client->auth_user;
	int auth_type = client->client_auth_type;

	/* disallow empty passwords */
	if (!*passwd || !*user->passwd)
		return false;

	switch (auth_type) {
	case AUTH_PLAIN:
		return strcmp(user->passwd, passwd) == 0;
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

static bool send_client_authreq(PgSocket *client)
{
	uint8_t saltlen = 0;
	int res;
	int auth_type = client->client_auth_type;

	if (auth_type == AUTH_MD5) {
		saltlen = 4;
		get_random_bytes((void*)client->tmp_login_salt, saltlen);
	} else if (auth_type == AUTH_PLAIN) {
		/* nothing to do */
	} else {
		return false;
	}

	SEND_generic(res, client, 'R', "ib", auth_type, client->tmp_login_salt, saltlen);
	if (!res)
		disconnect_client(client, false, "failed to send auth req");
	return res;
}

static void start_auth_request(PgSocket *client, const char *username)
{
	int res;
	PktBuf *buf;

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

	res = 0;
	buf = pktbuf_dynamic(512);
	if (buf) {
		pktbuf_write_ExtQuery(buf, cf_auth_query, 1, username);
		res = pktbuf_send_immediate(buf, client->link);
		pktbuf_free(buf);
		/*
		 * Should do instead:
		 *   res = pktbuf_send_queued(buf, client->link);
		 * but that needs better integration with SBuf.
		 */
	}
	if (!res)
		disconnect_server(client->link, false, "unable to send login query");
}

static bool login_via_cert(PgSocket *client)
{
	struct tls *tls = client->sbuf.tls;
	struct tls_cert *cert;
	struct tls_cert_dname *subj;

	if (!tls) {
		disconnect_client(client, true, "TLS connection required");
		return false;
	}
	if (tls_get_peer_cert(client->sbuf.tls, &cert, NULL) < 0 || !cert) {
		disconnect_client(client, true, "TLS client certificate required");
		return false;
	}

	subj = &cert->subject;
	log_debug("TLS cert login: CN=%s/C=%s/L=%s/ST=%s/O=%s/OU=%s",
		  subj->common_name ? subj->common_name : "(null)",
		  subj->country_name ? subj->country_name : "(null)",
		  subj->locality_name ? subj->locality_name : "(null)",
		  subj->state_or_province_name ? subj->state_or_province_name : "(null)",
		  subj->organization_name ? subj->organization_name : "(null)",
		  subj->organizational_unit_name ? subj->organizational_unit_name : "(null)");
	if (!subj->common_name) {
		disconnect_client(client, true, "Invalid TLS certificate");
		goto fail;
	}
	if (strcmp(subj->common_name, client->auth_user->name) != 0) {
		disconnect_client(client, true, "TLS certificate name mismatch");
		goto fail;
	}
	tls_cert_free(cert);

	/* login successful */
	return finish_client_login(client);
fail:
	tls_cert_free(cert);
	return false;
}

static bool login_as_unix_peer(PgSocket *client)
{
	if (!pga_is_unix(&client->remote_addr))
		goto fail;
	if (!check_unix_peer_name(sbuf_socket(&client->sbuf), client->auth_user->name))
		goto fail;
	return finish_client_login(client);
fail:
	disconnect_client(client, true, "unix socket login rejected");
	return false;
}

static bool finish_set_pool(PgSocket *client, bool takeover)
{
	PgUser *user = client->auth_user;
	bool ok = false;
	int auth;

	/* pool user may be forced */
	if (client->db->forced_user) {
		user = client->db->forced_user;
	}
	client->pool = get_pool(client->db, user);
	if (!client->pool) {
		disconnect_client(client, true, "no memory for pool");
		return false;
	}

	if (cf_log_connections) {
		if (client->sbuf.tls) {
			char infobuf[96] = "";
			tls_get_connection_info(client->sbuf.tls, infobuf, sizeof infobuf);
			slog_info(client, "login attempt: db=%s user=%s tls=%s",
				  client->db->name, client->auth_user->name, infobuf);
		} else {
			slog_info(client, "login attempt: db=%s user=%s tls=no",
				  client->db->name, client->auth_user->name);
		}
	}

	if (!check_fast_fail(client))
		return false;

	if (takeover)
		return true;

	if (client->pool->db->admin) {
		if (!admin_post_login(client))
			return false;
	}

	if (client->own_user)
		return finish_client_login(client);

	auth = cf_auth_type;
	if (auth == AUTH_HBA) {
		auth = hba_eval(parsed_hba, &client->remote_addr, !!client->sbuf.tls,
				client->db->name, client->auth_user->name);
	}

	/* remember method */
	client->client_auth_type = auth;

	switch (auth) {
	case AUTH_ANY:
	case AUTH_TRUST:
		ok = finish_client_login(client);
		break;
	case AUTH_PLAIN:
	case AUTH_MD5:
		ok = send_client_authreq(client);
		break;
	case AUTH_CERT:
		ok = login_via_cert(client);
		break;
	case AUTH_PEER:
		ok = login_as_unix_peer(client);
		break;
	default:
		disconnect_client(client, true, "login rejected");
		ok = false;
	}
	return ok;
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
		} else {
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
			/*
			 * NULL - set an md5 password with an impossible value,
			 * so that nothing will ever match
			 */
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
	case 'N':	/* NoticeResponse */
		break;
	case 'C':	/* CommandComplete */
		break;
	case '1':	/* ParseComplete */
		break;
	case '2':	/* BindComplete */
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
		/*
		 * either sbuf_continue or disconnect_client could disconnect the server
		 * way down in their bowels of other callbacks. so check that, and
		 * return appropriately (similar to reuse_on_release)
		 */
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

static void set_appname(PgSocket *client, const char *app_name)
{
	char buf[400], abuf[300];
	const char *details;

	if (cf_application_name_add_host) {
		/* give app a name */
		if (!app_name)
			app_name = "app";

		/* add details */
		details = pga_details(&client->remote_addr, abuf, sizeof(abuf));
		snprintf(buf, sizeof(buf), "%s - %s", app_name, details);
		app_name = buf;
	}
	if (app_name) {
		slog_debug(client, "using application_name: %s", app_name);
		varcache_set(&client->vars, "application_name", app_name);
	}
}

static bool decide_startup_pool(PgSocket *client, PktHdr *pkt)
{
	const char *username = NULL, *dbname = NULL;
	const char *key, *val;
	bool ok;
	bool appname_found = false;

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
		} else if (strcmp(key, "application_name") == 0) {
			set_appname(client, val);
			appname_found = true;
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

	/* create application_name if requested */
	if (!appname_found)
		set_appname(client, NULL);

	/* check if limit allows, don't limit admin db
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
		} else {
			return false;
		}
	}

	switch (pkt->type) {
	case PKT_SSLREQ:
		slog_noise(client, "C: req SSL");

		if (client->sbuf.tls) {
			disconnect_client(client, false, "SSL req inside SSL");
			return false;
		}
		if (cf_client_tls_sslmode != SSLMODE_DISABLED) {
			slog_noise(client, "P: SSL ack");
			if (!sbuf_answer(&client->sbuf, "S", 1)) {
				disconnect_client(client, false, "failed to ack SSL");
				return false;
			}
			if (!sbuf_tls_accept(&client->sbuf)) {
				disconnect_client(client, false, "failed to accept SSL");
				return false;
			}
			break;
		}

		/* reject SSL attempt */
		slog_noise(client, "P: nak");
		if (!sbuf_answer(&client->sbuf, "N", 1)) {
			disconnect_client(client, false, "failed to nak SSL");
			return false;
		}
		break;
	case PKT_STARTUP_V2:
		disconnect_client(client, true, "Old V2 protocol not supported");
		return false;
	case PKT_STARTUP:
		/* require SSL except on unix socket */
		if (cf_client_tls_sslmode >= SSLMODE_REQUIRE && !client->sbuf.tls && !pga_is_unix(&client->remote_addr)) {
			disconnect_client(client, true, "SSL required");
			return false;
		}

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
		/* too early */
		if (!client->auth_user) {
			disconnect_client(client, true, "client password pkt before startup packet");
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
		} else {
			disconnect_client(client, false, "bad cancel request");
		}
		return false;
	default:
		disconnect_client(client, false, "bad packet");
		return false;
	}
	sbuf_prepare_skip(sbuf, pkt->len);
	client->request_time = get_cached_time();
	return true;
}

static char *scan_for_search_path(struct MBuf *buf, const char type)
{
	size_t token_length      = 0;
	const char * query_str_p = (char *)buf->data + buf->read_pos;
	const char * nul         = memchr(query_str_p, 0, mbuf_avail_for_read(buf));

	if (!nul) {
		log_debug("scan_for_search_path: couldn't find null terminator.");
		return NULL;
	}

	/* A Parse packet's buffer is composed of the following elements:
			<null terminated string: prepared statement name>
			<null terminated string: query string>
			...
	   So, to get to the query string, we need to skip past the "prepared statement name" */
	if (type == 'P') {
		size_t skip_length = (nul - query_str_p) + 1;
		query_str_p += skip_length;

		/* make sure we have a null terminated query string */
		nul = memchr(query_str_p, 0, mbuf_avail_for_read(buf) - skip_length);
		if (!nul) {
			log_debug("scan_for_search_path: "
			          "couldn't find null terminator for query component of Parse packet.");
			return NULL;
		}
	}

#define TOKEN_CHECK(token) \
	do { \
		query_str_p  = str_skip_ws(query_str_p); \
		token_length = strlen(token); \
		if (strncasecmp(token, query_str_p, token_length) == 0) { \
			query_str_p += token_length; \
		} else { \
			return NULL; \
		} \
	} while(0)

	TOKEN_CHECK("SET");
	TOKEN_CHECK("SEARCH_PATH");

	query_str_p = str_skip_ws(query_str_p);

	/* check for '=' or 'TO' */
	if (*query_str_p == '=') {
		query_str_p++;
	} else {
		if (toupper(*query_str_p++) != 'T') return NULL;
		if (toupper(*query_str_p++) != 'O') return NULL;
	}

	/* skip the last bit of whitespace, leading up to the actual search_path */
	return (char *) str_skip_ws(query_str_p);
}

static bool store_client_search_path(PgSocket *client, PktHdr *pkt)
{
	/* 112 is large enough for varcache.c::apply_var to not fail */
	char spath[112];
	char *spath_p = NULL;
	char *end     = NULL;
	size_t length = 0;

	spath_p = scan_for_search_path(&pkt->data, pkt->type);
	if (spath_p) {
		length = strlen(spath_p);
		/* make sure client didn't send an empty search_path */
		if (length == 0 || *spath_p == ';') {
			slog_warning(client, "encountered empty search_path; skipping");
			return false;
		}

		/* find where the search_path ends and semicolon/whitespace begins */
		end = spath_p + length - 1;
		while(end > spath_p && (isspace(*end) || *end == ';'))
			end--;

		/* and now length is the length of the actual search_path,
		   sans trailing semicolon/whitespaces */
		length = (end - spath_p + 1);

		/* make sure our search path is smaller than spath with room for
		   a null terminator */
		if (length >= sizeof(spath) - 1) {
			slog_warning(client, "unable to store search_path; too big (%.*s)", (int) length, spath_p);
			return false;
		}

		/* only copy the calculated length, which takes into account
		   whitespace and semicolons, as defined above */
		strncpy(spath, spath_p, length);
		spath[length] = 0; /* we have to null terminate on our own here */

		slog_noise(client, "storing search path (%s)", spath);
		varcache_set(&client->vars, "search_path", spath);
		return true;
	}

	return false;
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
	case 'S':		/* Sync */
		client->expect_rfq_count++;
		break;
	case 'H':		/* Flush */
		break;

	/* copy end markers */
	case 'c':		/* CopyDone(F/B) */
	case 'f':		/* CopyFail(F/B) */
		break;

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

 	if (pkt->type == 'Q' || pkt->type == 'P') {
		/* search_path caching is superfluous in session pool mode, so don't do it */
		if (cf_consistent_search_path && pool_pool_mode(client->pool) != POOL_SESSION)
			store_client_search_path(client, pkt);
	}

	/* update stats */
	if (!client->query_start) {
		client->pool->stats.request_count++;
		client->query_start = get_cached_time();
	}

	if (client->pool->db->admin)
		return admin_handle_client(client, pkt);

	/* acquire server */
	if (!find_server(client))
		return false;

	client->pool->stats.client_bytes += pkt->len;

	/* tag the server as dirty */
	client->link->ready = false;
	client->link->idle_tx = false;

	/* forward the packet */
	sbuf_prepare_send(sbuf, &client->link->sbuf, pkt->len);

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
		/* Wait until full packet headers is available. */
		if (incomplete_header(data)) {
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
	case SBUF_EV_TLS_READY:
		sbuf_continue(&client->sbuf);
		res = true;
		break;
	}
	return res;
}

