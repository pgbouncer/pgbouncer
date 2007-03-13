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

bool get_header(MBuf *pkt, unsigned *pkt_type_p, unsigned *pkt_len_p);

bool send_pooler_error(PgSocket *client, bool send_ready, const char *msg);
void log_server_error(const char *note, MBuf *pkt);

bool add_welcome_parameter(PgSocket *server, unsigned pkt_type, unsigned pkt_len, MBuf *pkt);
void finish_welcome_msg(PgSocket *server);
bool welcome_client(PgSocket *client);

bool answer_authreq(PgSocket *server, unsigned pkt_type, unsigned pkt_len, MBuf *pkt);

bool send_startup_packet(PgSocket *server);

int scan_text_result(MBuf *pkt, const char *tupdesc, ...);

