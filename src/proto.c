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

/*
 * parse protocol header from struct MBuf
 */

/* parses pkt header from buffer, returns false if failed */
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
		log_noise("get_header: less then 5 bytes available");
		return false;
	}
	if (!mbuf_get_byte(&hdr, &type8))
		return false;
	type = type8;
	if (type != 0) {
		/* wire length does not include type byte */
		if (!mbuf_get_uint32be(&hdr, &len))
			return false;
		len++;
		got = NEW_HEADER_LEN;
	} else {
		if (!mbuf_get_byte(&hdr, &type8))
			return false;
		if (type8 != 0) {
			log_noise("get_header: unknown special pkt");
			return false;
		}
		/* dont tolerate partial pkt */
		if (mbuf_avail_for_read(&hdr) < OLD_HEADER_LEN - 2) {
			log_noise("get_header: less than 8 bytes for special pkt");
			return false;
		}
		if (!mbuf_get_uint16be(&hdr, &len16))
			return false;
		len = len16;
		if (!mbuf_get_uint32be(&hdr, &code))
			return false;
		if (code == PKT_CANCEL)
			type = PKT_CANCEL;
		else if (code == PKT_SSLREQ)
			type = PKT_SSLREQ;
		else if ((code >> 16) == 3 && (code & 0xFFFF) < 2)
			type = PKT_STARTUP;
		else if (code == PKT_STARTUP_V2)
			type = PKT_STARTUP_V2;
		else {
			log_noise("get_header: unknown special pkt: len=%u code=%u", len, code);
			return false;
		}
		got = OLD_HEADER_LEN;
	}

	/* don't believe nonsense */
	if (len < got || len >= 0x80000000)
		return false;

	/* store pkt info */
	pkt->type = type;
	pkt->len = len;

	/* fill pkt with only data for this packet */
	if (len > mbuf_avail_for_read(data))
		avail = mbuf_avail_for_read(data);
	else
		avail = len;
	if (!mbuf_slice(data, avail, &pkt->data))
		return false;

	/* tag header as read */
	return mbuf_get_bytes(&pkt->data, got, &ptr);
}


/*
 * Send error message packet to client.
 */

bool send_pooler_error(PgSocket *client, bool send_ready, const char *msg)
{
	uint8_t tmpbuf[512];
	PktBuf buf;

	if (cf_log_pooler_errors)
		slog_warning(client, "Pooler Error: %s", msg);

	pktbuf_static(&buf, tmpbuf, sizeof(tmpbuf));
	pktbuf_write_generic(&buf, 'E', "cscscsc",
			     'S', "ERROR", 'C', "08P01", 'M', msg, 0);
	if (send_ready)
		pktbuf_write_ReadyForQuery(&buf);
	return pktbuf_send_immediate(&buf, client);
}

/*
 * Parse server error message and log it.
 */
void parse_server_error(PktHdr *pkt, const char **level_p, const char **msg_p)
{
	const char *level = NULL, *msg = NULL, *val;
	uint8_t type;
	while (mbuf_avail_for_read(&pkt->data)) {
		if (!mbuf_get_byte(&pkt->data, &type))
			break;
		if (type == 0)
			break;
		if (!mbuf_get_string(&pkt->data, &val))
			break;
		if (type == 'S')
			level = val;
		else if (type == 'M')
			msg = val;
	}
	*level_p = level;
	*msg_p = msg;
}

void log_server_error(const char *note, PktHdr *pkt)
{
	const char *level = NULL, *msg = NULL;

	parse_server_error(pkt, &level, &msg);

	if (!msg || !level)
		log_error("%s: partial error message, cannot log", note);
	else
		log_error("%s: %s: %s", note, level, msg);
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
	pool->welcome_msg_ready = 1;
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

static PgUser *get_srv_psw(PgSocket *server)
{
	PgDatabase *db = server->pool->db;
	PgUser *user = server->pool->user;

	/* if forced user without password, use userlist psw */
	if (!user->passwd[0] && db->forced_user) {
		PgUser *u2 = find_user(user->name);
		if (u2)
			return u2;
	}
	return user;
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
	PgUser *user = get_srv_psw(server);
	slog_debug(server, "P: send clear password");
	return send_password(server, user->passwd);
}

static bool login_crypt_psw(PgSocket *server, const uint8_t *salt)
{
	char saltbuf[3];
	const char *enc;
	PgUser *user = get_srv_psw(server);

	slog_debug(server, "P: send crypt password");
	memcpy(saltbuf, salt, 2);
	saltbuf[2] = 0;
	enc = crypt(user->passwd, saltbuf);
	if (!enc) {
		slog_warning(server, "crypt failed");
		return false;
	}
	return send_password(server, enc);
}

static bool login_md5_psw(PgSocket *server, const uint8_t *salt)
{
	char txt[MD5_PASSWD_LEN + 1], *src;
	PgUser *user = get_srv_psw(server);

	slog_debug(server, "P: send md5 password");
	if (!isMD5(user->passwd)) {
		pg_md5_encrypt(user->passwd, user->name, strlen(user->name), txt);
		src = txt + 3;
	} else
		src = user->passwd + 3;
	pg_md5_encrypt(src, (char *)salt, 4, txt);

	return send_password(server, txt);
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
	case 0:
		slog_debug(server, "S: auth ok");
		res = true;
		break;
	case 3:
		slog_debug(server, "S: req cleartext password");
		res = login_clear_psw(server);
		break;
	case 4:
		slog_debug(server, "S: req crypt psw");
		if (!mbuf_get_bytes(&pkt->data, 2, &salt))
			return false;
		res = login_crypt_psw(server, salt);
		break;
	case 5:
		slog_debug(server, "S: req md5-crypted psw");
		if (!mbuf_get_bytes(&pkt->data, 4, &salt))
			return false;
		res = login_md5_psw(server, salt);
		break;
	case 2: /* kerberos */
	case 6: /* deprecated usage of SCM_RIGHTS */
		slog_error(server, "unsupported auth method: %d", cmd);
		res = false;
		break;
	default:
		slog_error(server, "unknown auth method: %d", cmd);
		res = false;
		break;
	}
	return res;
}

bool send_startup_packet(PgSocket *server)
{
	PgDatabase *db = server->pool->db;
	const char *username = server->pool->user->name;
	PktBuf *pkt;

	pkt = pktbuf_temp();
	pktbuf_write_StartupMessage(pkt, username,
				    db->startup_params->buf,
				    db->startup_params->write_pos);
	return pktbuf_send_immediate(pkt, server);
}

int scan_text_result(struct MBuf *pkt, const char *tupdesc, ...)
{
	const char *val = NULL;
	uint32_t len;
	uint16_t ncol;
	unsigned i, asked;
	va_list ap;
	int *int_p;
	uint64_t *long_p;
	const char **str_p;

	asked = strlen(tupdesc);
	if (!mbuf_get_uint16be(pkt, &ncol))
		return -1;

	va_start(ap, tupdesc);
	for (i = 0; i < asked; i++) {
		if (i < ncol) {
			if (!mbuf_get_uint32be(pkt, &len))
				return -1;
			if ((int32_t)len < 0) {
				val = NULL;
			} else {
				if (!mbuf_get_chars(pkt, len, &val))
					return -1;
			}

			/* hack to zero-terminate the result */
			if (val) {
				char *xval = (char *)val - 1;
				memmove(xval, val, len);
				xval[len] = 0;
				val = xval;
			}
		} else
			/* tuple was shorter than requested */
			val = NULL;

		switch (tupdesc[i]) {
		case 'i':
			int_p = va_arg(ap, int *);
			*int_p = val ? atoi(val) : 0;
			break;
		case 'q':
			long_p = va_arg(ap, uint64_t *);
			*long_p = val ? atoll(val) : 0;
			break;
		case 's':
			str_p = va_arg(ap, const char **);
			*str_p = val;
			break;
		default:
			fatal("bad tupdesc: %s", tupdesc);
		}
	}
	va_end(ap);

	return ncol;
}

