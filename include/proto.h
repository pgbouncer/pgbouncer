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
 * parsed packet header, plus whatever data is
 * available in SBuf for this packet.
 *
 * if (pkt->len == mbuf_avail(&pkt->data))
 * 	packet is fully in buffer
 *
 * get_header() points pkt->data.pos after header.
 * to packet body.
 */
struct PktHdr {
	unsigned type;
	unsigned len;
	MBuf data;
};

bool get_header(MBuf *data, PktHdr *pkt) _MUSTCHECK;

bool send_pooler_error(PgSocket *client, bool send_ready, const char *msg)  /*_MUSTCHECK*/;
void log_server_error(const char *note, PktHdr *pkt);
void parse_server_error(PktHdr *pkt, const char **level_p, const char **msg_p);

void add_welcome_parameter(PgPool *pool, const char *key, const char *val);
void finish_welcome_msg(PgSocket *server);
bool welcome_client(PgSocket *client) _MUSTCHECK;

bool answer_authreq(PgSocket *server, PktHdr *pkt) _MUSTCHECK;

bool send_startup_packet(PgSocket *server) _MUSTCHECK;

int scan_text_result(MBuf *pkt, const char *tupdesc, ...) _MUSTCHECK;

/* is packet completely in our buffer */
static inline bool incomplete_pkt(const PktHdr *pkt)
{
	return mbuf_size(&pkt->data) != pkt->len;
}

/* one char desc */
static inline char pkt_desc(const PktHdr *pkt)
{
	return pkt->type > 256 ? '!' : pkt->type;
}

