/* $OpenBSD$ */
/*
 * Copyright (c) 2014 Jeremie Courreges-Anglas <jca@openbsd.org>
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
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

#ifndef HEADER_TLS_INTERNAL_H
#define HEADER_TLS_INTERNAL_H

#include <openssl/ssl.h>

#include <usual/socket.h>

#define _PATH_SSL_CA_FILE USUAL_TLS_CA_FILE

union tls_addr {
	struct in_addr ip4;
	struct in6_addr ip6;
};

struct tls_error {
	char *msg;
	int num;
};

struct tls_keypair {
	struct tls_keypair *next;

	const char *cert_file;
	char *cert_mem;
	size_t cert_len;
	const char *key_file;
	char *key_mem;
	size_t key_len;
};

struct tls_alpn_config {
	const unsigned char *protocols;
	size_t protocols_len;
};

struct tls_config {
	struct tls_error error;

	const char *ca_file;
	const char *ca_path;
	char *ca_mem;
	size_t ca_len;
	const char *ciphers;	/* For TLS v1.2 or older */
	const char *cipher_suites;	/* For TLS v1.3 */
	int ciphers_server;
	int dheparams;
	int ecdhecurve;
	struct tls_keypair *keypair;
	const char *ocsp_file;
	char *ocsp_mem;
	size_t ocsp_len;
	uint32_t protocols;
	int verify_cert;
	int verify_client;
	int verify_depth;
	int verify_name;
	int verify_time;
	struct tls_alpn_config *alpn_config;
};

struct tls_conninfo {
	char *issuer;
	char *subject;
	char *hash;
	char *serial;
	char *fingerprint;
	char *version;
	char *cipher;
	time_t notbefore;
	time_t notafter;
};

#define TLS_CLIENT              (1 << 0)
#define TLS_SERVER              (1 << 1)
#define TLS_SERVER_CONN         (1 << 2)
#define TLS_OCSP_CLIENT         (1 << 3)

#define TLS_EOF_NO_CLOSE_NOTIFY (1 << 0)
#define TLS_HANDSHAKE_COMPLETE  (1 << 1)
#define TLS_DO_ABORT            (1 << 8)

struct tls_ocsp_query;
struct tls_ocsp_info;

struct tls {
	struct tls_config *config;
	struct tls_error error;

	uint32_t flags;
	uint32_t state;

	char *servername;
	int socket;

	SSL *ssl_conn;
	SSL_CTX *ssl_ctx;
	X509 *ssl_peer_cert;
	struct tls_conninfo *conninfo;

	int used_dh_bits;
	int used_ecdh_nid;

	const char *ocsp_result;
	struct tls_ocsp_info *ocsp_info;

	struct tls_ocsp_query *ocsp_query;
};

struct tls_ocsp_info {
	int response_status;
	int cert_status;
	int crl_reason;
	time_t this_update;
	time_t next_update;
	time_t revocation_time;
};

struct tls *tls_new(void);
struct tls *tls_server_conn(struct tls *ctx);

int tls_check_name(struct tls *ctx, X509 *cert, const char *servername);
int tls_configure_keypair(struct tls *ctx, SSL_CTX *ssl_ctx,
			  struct tls_keypair *keypair, int required);
int tls_configure_server(struct tls *ctx);
int tls_configure_ssl(struct tls *ctx);
int tls_configure_ssl_verify(struct tls *ctx, int verify);
int tls_handshake_client(struct tls *ctx);
int tls_handshake_server(struct tls *ctx);
int tls_host_port(const char *hostport, char **host, char **port);

int tls_error_set(struct tls_error *error, const char *fmt, ...)
_PRINTF(2, 3)
__attribute__((__nonnull__ (2)));
int tls_error_setx(struct tls_error *error, const char *fmt, ...)
_PRINTF(2, 3)
__attribute__((__nonnull__ (2)));
int tls_config_set_error(struct tls_config *cfg, const char *fmt, ...)
_PRINTF(2, 3)
__attribute__((__nonnull__ (2)));
int tls_config_set_errorx(struct tls_config *cfg, const char *fmt, ...)
_PRINTF(2, 3)
__attribute__((__nonnull__ (2)));
int tls_set_error(struct tls *ctx, const char *fmt, ...)
_PRINTF(2, 3)
__attribute__((__nonnull__ (2)));
int tls_set_errorx(struct tls *ctx, const char *fmt, ...)
_PRINTF(2, 3)
__attribute__((__nonnull__ (2)));
int tls_set_error_libssl(struct tls *ctx, const char *fmt, ...)
_PRINTF(2, 3)
__attribute__((__nonnull__ (2)));

int tls_ssl_error(struct tls *ctx, SSL *ssl_conn, int ssl_ret,
		  const char *prefix);

int tls_get_conninfo(struct tls *ctx);
void tls_free_conninfo(struct tls_conninfo *conninfo);

int tls_ocsp_verify_callback(SSL *ssl, void *arg);
int tls_ocsp_stapling_callback(SSL *ssl, void *arg);
void tls_ocsp_client_free(struct tls *ctx);
void tls_ocsp_info_free(struct tls_ocsp_info *info);

int tls_asn1_parse_time(struct tls *ctx, const ASN1_TIME *asn1time, time_t *dst);

int asn1_time_parse(const char *, size_t, struct tm *, int);

struct tls_keypair * tls_keypair_new(void);
int tls_keypair_set_cert_file(struct tls_keypair *keypair, const char *cert_file);
bool tls_keypair_list_equal(struct tls_keypair *tkp1, struct tls_keypair *tkp2);

struct tls_alpn_config * tls_alpn_config_new(void);
void tls_alpn_config_set_protocols(struct tls_config *config,
				   const unsigned char *protocols,
				   size_t len);

#endif /* HEADER_TLS_INTERNAL_H */
