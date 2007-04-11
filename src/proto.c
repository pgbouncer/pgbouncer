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
 * Pieces that need to have detailed info about protocol.
 */

#include "bouncer.h"

/*
 * parse protocol header from MBuf
 */

/* parses pkt header from buffer, returns false if failed */
bool get_header(MBuf *pkt, unsigned *pkt_type_p, unsigned *pkt_len_p)
{
	unsigned type;
	unsigned len;
	unsigned code;

	if (mbuf_avail(pkt) < 5) {
		log_noise("get_header: less then 5 bytes available");
		return false;
	}
	type = mbuf_get_char(pkt);
	if (type != 0) {
		len = mbuf_get_uint32(pkt) + 1;
	} else {
		if (mbuf_get_char(pkt) != 0) {
			log_noise("get_header: unknown special pkt");
			return false;
		}
		/* dont tolerate partial pkt */
		if (mbuf_avail(pkt) < 6) {
			log_noise("get_header: less that 6 bytes for special pkt");
			return false;
		}
		len = mbuf_get_uint16(pkt);
		code = mbuf_get_uint32(pkt);
		if (code == 80877102)
			type = PKT_CANCEL;
		else if (code == 80877103)
			type = PKT_SSLREQ;
		else if ((code >> 16) == 3 && (code & 0xFFFF) < 2)
			type = PKT_STARTUP;
		else {
			log_noise("get_header: unknown special pkt: len=%u code=%u", len, code);
			return false;
		}
	}
	*pkt_type_p = type;
	*pkt_len_p = len;
	return true;
}


/*
 * Send error message packet to client.
 */

bool send_pooler_error(PgSocket *client, bool send_ready, const char *msg)
{
	uint8 tmpbuf[512];
	PktBuf buf;

	if (cf_log_pooler_errors)
		slog_info(client, "Pooler Error: %s", msg);

	pktbuf_static(&buf, tmpbuf, sizeof(tmpbuf));
	pktbuf_write_generic(&buf, 'E', "cscscsc",
			     'S', "ERROR", 'C', "08P01", 'M', msg, 0);
	if (send_ready)
		pktbuf_write_ReadyForQuery(&buf);
	return pktbuf_send_immidiate(&buf, client);
}

/*
 * Parse server error message and log it.
 */
void log_server_error(const char *note, MBuf *pkt)
{
	const char *level = NULL, *msg = NULL, *val;
	int type;
	while (mbuf_avail(pkt)) {
		type = mbuf_get_char(pkt);
		if (type == 0)
			break;
		val = mbuf_get_string(pkt);
		if (!val)
			break;
		if (type == 'S')
			level = val;
		else if (type == 'M')
			msg = val;
	}
	if (!msg || !level)
		log_error("%s: corrupt error message", note);
	else
		log_error("%s: %s: %s", note, level, msg);
}


/*
 * Preparation of welcome message for client connection.
 */

/* add another server parameter packet to cache */
bool add_welcome_parameter(PgSocket *server,
			   unsigned pkt_type, unsigned pkt_len, MBuf *pkt)
{
	PgDatabase *db = server->pool->db;
	PktBuf msg;
	const char *key, *val;

	if (db->welcome_msg_ready)
		return true;

	/* incomplete startup msg from server? */
	if (pkt_len - 5 > mbuf_avail(pkt))
		return false;

	pktbuf_static(&msg, db->welcome_msg + db->welcome_msg_len,
		      sizeof(db->welcome_msg) - db->welcome_msg_len);

	if (db->welcome_msg_len == 0)
		pktbuf_write_AuthenticationOk(&msg);

	key = mbuf_get_string(pkt);
	val = mbuf_get_string(pkt);
	if (!key || !val) {
		log_error("broken ParameterStatus packet");
		return false;
	}
	log_debug("S: param: %s = %s", key, val);
	pktbuf_write_ParameterStatus(&msg, key, val);
	db->welcome_msg_len += pktbuf_written(&msg);

	return true;
}

/* all parameters processed */
void finish_welcome_msg(PgSocket *server)
{
	PgDatabase *db = server->pool->db;
	if (db->welcome_msg_ready)
		return;
	db->welcome_msg_ready = 1;
}

bool welcome_client(PgSocket *client)
{
	int res;
	uint8 buf[1024];
	PktBuf msg;
	PgDatabase *db = client->pool->db;

	log_noise("P: welcome_client");
	if (!db->welcome_msg_ready)
		return false;

	pktbuf_static(&msg, buf, sizeof(buf));
	pktbuf_put_bytes(&msg, db->welcome_msg, db->welcome_msg_len);

	/* give each client its own cancel key */
	get_random_bytes(client->cancel_key, 8);
	pktbuf_write_BackendKeyData(&msg, client->cancel_key);
	pktbuf_write_ReadyForQuery(&msg);

	/* send all together */
	res = pktbuf_send_immidiate(&msg, client);
	if (!res)
		log_warning("unhandled failure to send welcome_msg");

	return true;
}

/*
 * Password authentication for server
 */

/* actual packet send */
static bool send_password(PgSocket *server, const char *enc_psw)
{
	bool res;
	SEND_PasswordMessage(res, server, enc_psw);
	return res;
}

static bool login_clear_psw(PgSocket *server)
{
	log_debug("P: send clear password");
	return send_password(server, server->pool->user->passwd);
}

static bool login_crypt_psw(PgSocket *server, const uint8 *salt)
{
	char saltbuf[3];
	const char *enc;
	PgUser *user = server->pool->user;

	log_debug("P: send crypt password");
	strncpy(saltbuf, (char *)salt, 2);
	enc = pg_crypt(user->passwd, saltbuf);
	return send_password(server, enc);
}


static bool login_md5_psw(PgSocket *server, const uint8 *salt)
{
	char txt[MD5_PASSWD_LEN + 1], *src;
	PgUser *user = server->pool->user;

	log_debug("P: send md5 password");
	if (!isMD5(user->passwd)) {
		pg_md5_encrypt(user->passwd, user->name, strlen(user->name), txt);
		src = txt + 3;
	} else
		src = user->passwd + 3;
	pg_md5_encrypt(src, (char *)salt, 4, txt);

	return send_password(server, txt);
}

/* answer server authentication request */
bool answer_authreq(PgSocket *server,
		    unsigned pkt_type, unsigned pkt_len,
		    MBuf *pkt)
{
	unsigned cmd;
	const uint8 *salt;
	bool res = false;

	if (pkt_len < 5 + 4)
		return false;
	if (mbuf_avail(pkt) < pkt_len - 5)
		return false;

	cmd = mbuf_get_uint32(pkt);
	switch (cmd) {
	case 0:
		log_debug("S: auth ok");
		res = true;
		break;
	case 3:
		log_debug("S: req cleartext password");
		res = login_clear_psw(server);
		break;
	case 4:
		if (pkt_len < 5 + 4 + 2)
			return false;
		log_debug("S: req crypt psw");
		salt = mbuf_get_bytes(pkt, 2);
		res = login_crypt_psw(server, salt);
		break;
	case 5:
		if (pkt_len < 5 + 4 + 4)
			return false;
		log_debug("S: req md5-crypted psw");
		salt = mbuf_get_bytes(pkt, 4);
		res = login_md5_psw(server, salt);
		break;
	case 2: /* kerberos */
	case 6: /* scm something */
		log_error("unsupported auth method: %d", cmd);
		res = false;
		break;
	default:
		log_error("unknown auth method: %d", cmd);
		res = false;
		break;
	}
	return res;
}

bool send_startup_packet(PgSocket *server)
{
	PgDatabase *db = server->pool->db;
	const char *username = server->pool->user->name;
	PktBuf pkt;
	uint8 buf[512];

	pktbuf_static(&pkt, buf, sizeof(buf));
	pktbuf_write_StartupMessage(&pkt, username,
				    db->startup_params,
				    db->startup_params_len);
	return pktbuf_send_immidiate(&pkt, server);
}

int scan_text_result(MBuf *pkt, const char *tupdesc, ...)
{
	char *val = NULL;
	int len;
	unsigned ncol, i;
	va_list ap;

	ncol = mbuf_get_uint16(pkt);
	if (ncol != strlen(tupdesc))
		fatal("different number of cols");

	va_start(ap, tupdesc);
	for (i = 0; i < ncol; i++) {
		len = mbuf_get_uint32(pkt);
		if (len < 0)
			val = NULL;
		else
			val = (char *)mbuf_get_bytes(pkt, len);

		if (tupdesc[i] == 'i') {
			int *dst_p = va_arg(ap, int *);
			*dst_p = atoi(val);
		} else if (tupdesc[i] == 'q') {
			uint64 *dst_p = va_arg(ap, uint64 *);
			*dst_p = atoll(val);
		} else if (tupdesc[i] == 's') {
			char **dst_p = va_arg(ap, char **);
			*dst_p = val;
		} else
			fatal("bad tupdesc: %s", tupdesc);
	}
	va_end(ap);

	if (mbuf_avail(pkt))
		fatal("scan_text_result: unparsed data");

	return ncol;
}

