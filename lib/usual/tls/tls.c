/* $OpenBSD$ */
/*
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

#include "tls_compat.h"

#ifdef USUAL_LIBSSL_FOR_TLS

#include <limits.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/dh.h>

#include "tls_internal.h"

static struct tls_config *tls_config_default;

static int tls_initialised = 0;

int tls_init(void)
{
	if (tls_initialised)
		return (0);

#ifdef USE_LIBSSL_OLD
	SSL_load_error_strings();
	SSL_library_init();

	if (BIO_sock_init() != 1)
		return (-1);
#endif

	if ((tls_config_default = tls_config_new()) == NULL)
		return (-1);

	tls_initialised = 1;

	return (0);
}

void tls_deinit(void)
{
	if (tls_initialised) {
		tls_compat_cleanup();

		tls_config_free(tls_config_default);
		tls_config_default = NULL;

#ifdef USE_LIBSSL_OLD
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		BIO_sock_cleanup();
		ERR_clear_error();
		ERR_remove_thread_state(NULL);
		ERR_free_strings();
#else
		OPENSSL_cleanup();
#endif

		tls_initialised = 0;
	}
}

const char *tls_error(struct tls *ctx)
{
	return ctx->error.msg;
}

_PRINTF(3, 0)
static int tls_error_vset(struct tls_error *error, int errnum, const char *fmt, va_list ap)
{
	char *errmsg = NULL;
	int rv = -1;

	free(error->msg);
	error->msg = NULL;
	error->num = errnum;

	if (vasprintf(&errmsg, fmt, ap) == -1) {
		errmsg = NULL;
		goto err;
	}

	if (errnum == -1) {
		error->msg = errmsg;
		return (0);
	}

	if (asprintf(&error->msg, "%s: %s", errmsg, strerror(errnum)) == -1) {
		error->msg = NULL;
		goto err;
	}
	rv = 0;

err:
	free(errmsg);

	return (rv);
}

int tls_error_set(struct tls_error *error, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int tls_error_setx(struct tls_error *error, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

int tls_config_set_error(struct tls_config *config, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(&config->error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int tls_config_set_errorx(struct tls_config *config, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(&config->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

int tls_set_error(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int tls_set_errorx(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

int tls_set_error_libssl(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int rv;
	const char *msg = NULL;
	char *old;
	int err;

	err = ERR_peek_error();
	if (err != 0)
		msg = ERR_reason_error_string(err);

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, -1, fmt, ap);
	va_end(ap);
	if (rv != 0 || msg == NULL)
		return rv;

	old = ctx->error.msg;
	ctx->error.msg = NULL;
	if (asprintf(&ctx->error.msg, "%s: %s", old, msg) == -1) {
		ctx->error.msg = old;
	} else {
		free(old);
	}
	return 0;
}

struct tls *tls_new(void)
{
	struct tls *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	ctx->config = tls_config_default;

	tls_reset(ctx);

	return (ctx);
}

int tls_configure(struct tls *ctx, struct tls_config *config)
{
	if (config == NULL)
		config = tls_config_default;

	ctx->config = config;

	if ((ctx->flags & TLS_SERVER) != 0)
		return (tls_configure_server(ctx));

	return (0);
}

int tls_configure_keypair(struct tls *ctx, SSL_CTX *ssl_ctx,
			  struct tls_keypair *keypair, int required)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	BIO *bio = NULL;

	if (!required &&
	    keypair->cert_mem == NULL &&
	    keypair->key_mem == NULL &&
	    keypair->cert_file == NULL &&
	    keypair->key_file == NULL)
		return(0);

	if (keypair->cert_mem != NULL) {
		if (keypair->cert_len > INT_MAX) {
			tls_set_errorx(ctx, "certificate too long");
			goto err;
		}

		if (SSL_CTX_use_certificate_chain_mem(ssl_ctx,
						      keypair->cert_mem, keypair->cert_len) != 1) {
			tls_set_errorx(ctx, "failed to load certificate");
			goto err;
		}
		cert = NULL;
	}
	if (keypair->key_mem != NULL) {
		if (keypair->key_len > INT_MAX) {
			tls_set_errorx(ctx, "key too long");
			goto err;
		}

		if ((bio = BIO_new_mem_buf(keypair->key_mem,
					   keypair->key_len)) == NULL) {
			tls_set_errorx(ctx, "failed to create buffer");
			goto err;
		}
		if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL,
						    NULL)) == NULL) {
			tls_set_errorx(ctx, "failed to read private key");
			goto err;
		}
		if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
			tls_set_errorx(ctx, "failed to load private key");
			goto err;
		}
		BIO_free(bio);
		bio = NULL;
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	if (keypair->cert_file != NULL) {
		if (SSL_CTX_use_certificate_chain_file(ssl_ctx,
						       keypair->cert_file) != 1) {
			const char *errstr = "unknown error";
			unsigned long err;

			if ((err = ERR_peek_error()) != 0)
				errstr = ERR_reason_error_string(err);
			tls_set_errorx(ctx, "failed to load certificate file \"%s\": %s",
				       keypair->cert_file, errstr);
			goto err;
		}
	}
	if (keypair->key_file != NULL) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx,
						keypair->key_file, SSL_FILETYPE_PEM) != 1) {
			const char *errstr = "unknown error";
			unsigned long err;

			if ((err = ERR_peek_error()) != 0)
				errstr = ERR_reason_error_string(err);
			tls_set_errorx(ctx, "failed to load private key file \"%s\": %s",
				       keypair->key_file, errstr);
			goto err;
		}
	}

	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		tls_set_errorx(ctx, "private/public key mismatch");
		goto err;
	}

	return (0);

err:
	EVP_PKEY_free(pkey);
	X509_free(cert);
	BIO_free(bio);

	return (1);
}

static void tls_info_callback(const SSL *ssl, int where, int rc)
{
	struct tls *ctx = SSL_get_app_data(ssl);

#ifdef USE_LIBSSL_INTERNALS
	if (!(ctx->state & TLS_HANDSHAKE_COMPLETE) && ssl->s3) {
		/* steal info about used DH key */
		if (ssl->s3->tmp.dh && !ctx->used_dh_bits) {
			ctx->used_dh_bits = DH_size(ssl->s3->tmp.dh) * 8;
		} else if (ssl->s3->tmp.ecdh && !ctx->used_ecdh_nid) {
			ctx->used_ecdh_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ssl->s3->tmp.ecdh));
		}
	}
#endif

	/*
	 * Detect renegotation on established connection.  With
	 * TLSv1.3 this is no longer applicable, and the code below
	 * would erroneously abort with OpenSSL 1.1.1 and 1.1.1a if
	 * using TLSv1.3, so skip it altogether in that case.
	 */
	if (SSL_version(ssl) < TLS1_3_VERSION) {
		if (where & SSL_CB_HANDSHAKE_START) {
			if (ctx->state & TLS_HANDSHAKE_COMPLETE)
				ctx->state |= TLS_DO_ABORT;
		}
	}
}

static int tls_do_abort(struct tls *ctx)
{
	int ssl_ret, rv;

	ssl_ret = SSL_shutdown(ctx->ssl_conn);
	if (ssl_ret < 0) {
		rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "shutdown");
		if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
			return (rv);
	}

	tls_set_errorx(ctx, "unexpected handshake, closing connection");
	return -1;
}

#ifndef USE_LIBSSL_OLD
static int get_min_ssl_version(uint32_t protocols)
{
	if (protocols & TLS_PROTOCOL_TLSv1_0)
		return TLS1_VERSION;
	if (protocols & TLS_PROTOCOL_TLSv1_1)
		return TLS1_1_VERSION;
	if (protocols & TLS_PROTOCOL_TLSv1_2)
		return TLS1_2_VERSION;
	if (protocols & TLS_PROTOCOL_TLSv1_3)
		return TLS1_3_VERSION;
	return TLS1_VERSION;
}

static int get_max_ssl_version(uint32_t protocols)
{
	if (protocols & TLS_PROTOCOL_TLSv1_3)
		return TLS1_3_VERSION;
	if (protocols & TLS_PROTOCOL_TLSv1_2)
		return TLS1_2_VERSION;
	if (protocols & TLS_PROTOCOL_TLSv1_1)
		return TLS1_1_VERSION;
	if (protocols & TLS_PROTOCOL_TLSv1_0)
		return TLS1_VERSION;
	return TLS1_3_VERSION;
}
#endif

int tls_configure_ssl(struct tls *ctx)
{
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_3);

#ifndef USE_LIBSSL_OLD
	SSL_CTX_set_min_proto_version(ctx->ssl_ctx, get_min_ssl_version(ctx->config->protocols));
	SSL_CTX_set_max_proto_version(ctx->ssl_ctx, get_max_ssl_version(ctx->config->protocols));
#endif

	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_0) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_1) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_2) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_3) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_3);

	/*
	 * obsolete outdated keywords, turn them to default.
	 * For default, don't call SSL_CTX_set_cipher_list()
	 * so we inherit openssl's default, which can also
	 * include a system-wide policy, such as on rhel/fedora
	 * https://docs.fedoraproject.org/en-US/packaging-guidelines/CryptoPolicies/
	 */
	if (ctx->config->ciphers != NULL) {
		if (strcasecmp(ctx->config->ciphers, "default") != 0 &&
		    strcasecmp(ctx->config->ciphers, "secure") != 0 &&
		    strcasecmp(ctx->config->ciphers, "normal") != 0 &&
		    strcasecmp(ctx->config->ciphers, "fast") != 0) {
			if (SSL_CTX_set_cipher_list(ctx->ssl_ctx,
						    ctx->config->ciphers) != 1) {
				tls_set_errorx(ctx, "failed to set ciphers");
				goto err;
			}
		}
	}
	SSL_CTX_set_info_callback(ctx->ssl_ctx, tls_info_callback);

#ifdef X509_V_FLAG_NO_CHECK_TIME
	if (ctx->config->verify_time == 0) {
		X509_VERIFY_PARAM *vfp = SSL_CTX_get0_param(ctx->ssl_ctx);
		X509_VERIFY_PARAM_set_flags(vfp, X509_V_FLAG_NO_CHECK_TIME);
	}
#endif

	return (0);

err:
	return (-1);
}

int tls_configure_ssl_verify(struct tls *ctx, int verify)
{
	SSL_CTX_set_verify(ctx->ssl_ctx, verify, NULL);

	if (ctx->config->ca_mem != NULL) {
		/* XXX do this in set. */
		if (ctx->config->ca_len > INT_MAX) {
			tls_set_errorx(ctx, "ca too long");
			goto err;
		}
		if (SSL_CTX_load_verify_mem(ctx->ssl_ctx,
					    ctx->config->ca_mem, ctx->config->ca_len) != 1) {
			tls_set_errorx(ctx, "ssl verify memory setup failure");
			goto err;
		}
	} else if (SSL_CTX_load_verify_locations(ctx->ssl_ctx,
						 ctx->config->ca_file, ctx->config->ca_path) != 1) {
		const char *errstr = "unknown error";
		unsigned long err;

		if ((err = ERR_peek_error()) != 0)
			errstr = ERR_reason_error_string(err);
		tls_set_errorx(ctx, "failed to load CA: %s", errstr);
		goto err;
	}
	if (ctx->config->verify_depth >= 0) {
		SSL_CTX_set_verify_depth(ctx->ssl_ctx,
					 ctx->config->verify_depth);
	}

	return (0);

err:
	return (-1);
}

void usual_tls_free(struct tls *ctx)
{
	if (ctx == NULL)
		return;
	tls_reset(ctx);
	free(ctx);
}

void tls_reset(struct tls *ctx)
{
	SSL_CTX_free(ctx->ssl_ctx);
	SSL_free(ctx->ssl_conn);
	X509_free(ctx->ssl_peer_cert);

	ctx->ssl_conn = NULL;
	ctx->ssl_ctx = NULL;
	ctx->ssl_peer_cert = NULL;

	ctx->socket = -1;
	ctx->state = 0;

	free(ctx->servername);
	ctx->servername = NULL;

	free(ctx->error.msg);
	ctx->error.msg = NULL;
	ctx->error.num = -1;

	tls_free_conninfo(ctx->conninfo);
	free(ctx->conninfo);
	ctx->conninfo = NULL;

	ctx->used_dh_bits = 0;
	ctx->used_ecdh_nid = 0;

	tls_ocsp_info_free(ctx->ocsp_info);
	ctx->ocsp_info = NULL;
	ctx->ocsp_result = NULL;

	if (ctx->flags & TLS_OCSP_CLIENT)
		tls_ocsp_client_free(ctx);
}

int tls_ssl_error(struct tls *ctx, SSL *ssl_conn, int ssl_ret, const char *prefix)
{
	const char *errstr = "unknown error";
	unsigned long err;
	int ssl_err;

	ssl_err = SSL_get_error(ssl_conn, ssl_ret);
	switch (ssl_err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return (0);

	case SSL_ERROR_WANT_READ:
		return (TLS_WANT_POLLIN);

	case SSL_ERROR_WANT_WRITE:
		return (TLS_WANT_POLLOUT);

	case SSL_ERROR_SYSCALL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		} else if (ssl_ret == 0) {
			if ((ctx->state & TLS_HANDSHAKE_COMPLETE) != 0) {
				ctx->state |= TLS_EOF_NO_CLOSE_NOTIFY;
				return (0);
			}
			errstr = "unexpected EOF";
		} else if (ssl_ret == -1) {
			errstr = strerror(errno);
		}
		tls_set_errorx(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_SSL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		}
		tls_set_errorx(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
	default:
		tls_set_errorx(ctx, "%s failed (%i)", prefix, ssl_err);
		return (-1);
	}
}

int tls_handshake(struct tls *ctx)
{
	int rv = -1;

	if ((ctx->flags & (TLS_CLIENT | TLS_SERVER_CONN)) == 0) {
		tls_set_errorx(ctx, "invalid operation for context");
		goto out;
	}

	if (ctx->conninfo == NULL &&
	    (ctx->conninfo = calloc(1, sizeof(*ctx->conninfo))) == NULL)
		goto out;

	if ((ctx->flags & TLS_CLIENT) != 0)
		rv = tls_handshake_client(ctx);
	else if ((ctx->flags & TLS_SERVER_CONN) != 0)
		rv = tls_handshake_server(ctx);

	if (rv == 0) {
		ctx->ssl_peer_cert = SSL_get_peer_certificate(ctx->ssl_conn);
		if (tls_get_conninfo(ctx) == -1)
			rv = -1;
	}
out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

ssize_t tls_read(struct tls *ctx, void *buf, size_t buflen)
{
	ssize_t rv = -1;
	int ssl_ret;

	if (ctx->state & TLS_DO_ABORT) {
		rv = tls_do_abort(ctx);
		goto out;
	}

	if ((ctx->state & TLS_HANDSHAKE_COMPLETE) == 0) {
		if ((rv = tls_handshake(ctx)) != 0)
			goto out;
	}

	if (buflen > INT_MAX) {
		tls_set_errorx(ctx, "buflen too long");
		goto out;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_read(ctx->ssl_conn, buf, buflen)) > 0) {
		rv = (ssize_t)ssl_ret;
		goto out;
	}
	rv = (ssize_t)tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "read");

out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

ssize_t tls_write(struct tls *ctx, const void *buf, size_t buflen)
{
	ssize_t rv = -1;
	int ssl_ret;

	if (ctx->state & TLS_DO_ABORT) {
		rv = tls_do_abort(ctx);
		goto out;
	}

	if ((ctx->state & TLS_HANDSHAKE_COMPLETE) == 0) {
		if ((rv = tls_handshake(ctx)) != 0)
			goto out;
	}

	if (buflen > INT_MAX) {
		tls_set_errorx(ctx, "buflen too long");
		goto out;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_write(ctx->ssl_conn, buf, buflen)) > 0) {
		rv = (ssize_t)ssl_ret;
		goto out;
	}
	rv = (ssize_t)tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "write");

out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

int tls_close(struct tls *ctx)
{
	int ssl_ret;
	int rv = 0;

	if ((ctx->flags & (TLS_CLIENT | TLS_SERVER_CONN)) == 0) {
		tls_set_errorx(ctx, "invalid operation for context");
		rv = -1;
		goto out;
	}

	if (ctx->ssl_conn != NULL) {
		ERR_clear_error();
		ssl_ret = SSL_shutdown(ctx->ssl_conn);
		if (ssl_ret < 0) {
			rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret,
					   "shutdown");
			if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
				goto out;
		}
	}

	if (ctx->socket != -1) {
		if (shutdown(ctx->socket, SHUT_RDWR) != 0) {
			if (rv == 0 &&
			    errno != ENOTCONN && errno != ECONNRESET) {
				tls_set_error(ctx, "shutdown");
				rv = -1;
			}
		}
		if (close(ctx->socket) != 0) {
			if (rv == 0) {
				tls_set_error(ctx, "close");
				rv = -1;
			}
		}
		ctx->socket = -1;
	}

	if ((ctx->state & TLS_EOF_NO_CLOSE_NOTIFY) != 0) {
		tls_set_errorx(ctx, "EOF without close notify");
		rv = -1;
	}

out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

static bool tls_mem_equal(char *mem1, char *mem2, size_t len1, size_t len2)
{
	if (len1 != len2)
		return false;
	if (mem1 && mem2 && memcmp(mem1, mem2, len1) != 0)
		return false;
	return true;
}

static bool tls_keypair_equal(struct tls_keypair *tkp1, struct tls_keypair *tkp2)
{
	if (!strcmpeq(tkp1->cert_file, tkp2->cert_file))
		return false;
	if (!tls_mem_equal(tkp1->cert_mem, tkp2->cert_mem, tkp1->cert_len, tkp2->cert_len))
		return false;
	if (!strcmpeq(tkp1->key_file, tkp2->key_file))
		return false;
	if (!tls_mem_equal(tkp1->key_mem, tkp2->key_mem, tkp1->key_len, tkp2->key_len))
		return false;
	return true;
}

bool tls_keypair_list_equal(struct tls_keypair *tkp1, struct tls_keypair *tkp2)
{
	for (; tkp1 != NULL && tkp2 != NULL; tkp1 = tkp1->next, tkp2 = tkp2->next) {
		if (!tls_keypair_equal(tkp1, tkp2))
			return false;
	}

	return tkp1 == NULL && tkp2 == NULL;
}

bool tls_config_equal(struct tls_config *tc1, struct tls_config *tc2)
{
	if (!strcmpeq(tc1->ca_file, tc2->ca_file))
		return false;
	if (!strcmpeq(tc1->ca_path, tc2->ca_path))
		return false;
	if (!tls_mem_equal(tc1->ca_mem, tc2->ca_mem, tc1->ca_len, tc2->ca_len))
		return false;
	if (!strcmpeq(tc1->ciphers, tc2->ciphers))
		return false;
	if (tc1->ciphers_server != tc2->ciphers_server)
		return false;
	if (tc1->dheparams != tc2->dheparams)
		return false;
	if (tc1->ecdhecurve != tc2->ecdhecurve)
		return false;
	if (!tls_keypair_list_equal(tc1->keypair, tc2->keypair))
		return false;
	if (!strcmpeq(tc1->ocsp_file, tc2->ocsp_file))
		return false;
	if (!tls_mem_equal(tc1->ocsp_mem, tc2->ocsp_mem, tc1->ocsp_len, tc2->ocsp_len))
		return false;
	if (tc1->protocols != tc2->protocols)
		return false;
	if (tc1->verify_cert != tc2->verify_cert)
		return false;
	if (tc1->verify_client != tc2->verify_client)
		return false;
	if (tc1->verify_depth != tc2->verify_depth)
		return false;
	if (tc1->verify_name != tc2->verify_name)
		return false;
	if (tc1->verify_time != tc2->verify_time)
		return false;
	return true;
}

#endif /* USUAL_LIBSSL_FOR_TLS */
