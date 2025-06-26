/*
 * Copyright (c) 2015 Marko Kreen <markokr@gmail.com>
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

#include <openssl/err.h>

#include "tls_internal.h"

#ifndef OPENSSL_NO_OCSP

#include <openssl/ocsp.h>

#define MAXAGE_SEC (14*24*60*60)
#define JITTER_SEC (60)

#define USE_NONCE 0

#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10002000
#define BUGGY_VERIFY
#endif

/*
 * State for request.
 */

struct tls_ocsp_query {
	/* responder location */
	char *ocsp_url;

	/* request blob */
	uint8_t *request_data;
	size_t request_size;

	/* network state */
	BIO *bio;
	SSL_CTX *ssl_ctx;
	OCSP_REQ_CTX *http_req;

	/* cert data, this struct does not own these */
	X509 *main_cert;
	STACK_OF(X509) *extra_certs;
	SSL_CTX *cert_ssl_ctx;
};

/*
 * Extract OCSP response info.
 */

static int tls_ocsp_fill_info(struct tls *ctx,
			      int response_status, int cert_status, int crl_reason,
			      ASN1_GENERALIZEDTIME *revtime,
			      ASN1_GENERALIZEDTIME *thisupd,
			      ASN1_GENERALIZEDTIME *nextupd)
{
	struct tls_ocsp_info *info;
	int res;

	info = calloc(1, sizeof(struct tls_ocsp_info));
	if (!info) {
		tls_set_error(ctx, "calloc");
		return -1;
	}
	info->response_status = response_status;
	info->cert_status = cert_status;
	info->crl_reason = crl_reason;

	res = tls_asn1_parse_time(ctx, revtime, &info->revocation_time);
	if (res == 0)
		res = tls_asn1_parse_time(ctx, thisupd, &info->this_update);
	if (res == 0)
		res = tls_asn1_parse_time(ctx, nextupd, &info->next_update);

	if (res == 0) {
		ctx->ocsp_info = info;
	} else {
		tls_ocsp_info_free(info);
	}
	return res;
}

static void tls_ocsp_fill_result(struct tls *ctx, int res)
{
	struct tls_ocsp_info *info = ctx->ocsp_info;
	if (res < 0) {
		ctx->ocsp_result = "error";
	} else if (info->response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		ctx->ocsp_result = OCSP_response_status_str(info->response_status);
	} else if (info->cert_status != V_OCSP_CERTSTATUS_REVOKED) {
		ctx->ocsp_result = OCSP_cert_status_str(info->cert_status);
	} else {
		ctx->ocsp_result = OCSP_crl_reason_str(info->crl_reason);
	}
}

void tls_ocsp_info_free(struct tls_ocsp_info *info)
{
	free(info);
}

int tls_get_ocsp_info(struct tls *ctx, int *response_status, int *cert_status,
		      int *crl_reason, time_t *this_update,
		      time_t *next_update, time_t *revoction_time,
		      const char **result_text)
{
	static const struct tls_ocsp_info no_ocsp = { -1, -1, -1, 0, 0, 0 };
	const struct tls_ocsp_info *info = ctx->ocsp_info;
	const char *ocsp_result = ctx->ocsp_result;
	int ret = 0;

	if (!info) {
		info = &no_ocsp;
		ret = -1;
	}

	if (!ocsp_result) {
		ret = TLS_NO_OCSP;
		ocsp_result = "no-ocsp";
	}

	if (response_status)
		*response_status = info->response_status;
	if (cert_status)
		*cert_status = info->cert_status;
	if (crl_reason)
		*crl_reason = info->crl_reason;
	if (this_update)
		*this_update = info->this_update;
	if (next_update)
		*next_update = info->next_update;
	if (revoction_time)
		*revoction_time = info->revocation_time;
	if (result_text)
		*result_text = ocsp_result;

	return ret;
}

/*
 * Verify stapled response
 */

static OCSP_CERTID *tls_ocsp_get_certid(X509 *main_cert, STACK_OF(X509) *extra_certs, SSL_CTX *ssl_ctx)
{
	X509_NAME *issuer_name;
	X509 *issuer;
	X509_STORE_CTX *storectx = NULL;
	X509_OBJECT *tmpobj;
	OCSP_CERTID *cid = NULL;
	X509_STORE *store;
	int ok;

	issuer_name = X509_get_issuer_name(main_cert);
	if (!issuer_name)
		return NULL;

	if (extra_certs) {
		issuer = X509_find_by_subject(extra_certs, issuer_name);
		if (issuer)
			return OCSP_cert_to_id(NULL, main_cert, issuer);
	}

	store = SSL_CTX_get_cert_store(ssl_ctx);
	if (!store)
		goto error;
	storectx = X509_STORE_CTX_new();
	if (!storectx)
		goto error;
	ok = X509_STORE_CTX_init(storectx, store, main_cert, extra_certs);
	if (ok != 1)
		goto error;

	tmpobj = X509_STORE_CTX_get_obj_by_subject(storectx, X509_LU_X509, issuer_name);
	if (!tmpobj)
		goto error;
	cid = OCSP_cert_to_id(NULL, main_cert, X509_OBJECT_get0_X509(tmpobj));
	X509_OBJECT_free(tmpobj);
	X509_STORE_CTX_free(storectx);
	return cid;
error:
	if (storectx) {
		X509_STORE_CTX_free(storectx);
	}
	return NULL;
}

static int tls_ocsp_verify_response(struct tls *ctx, X509 *main_cert, STACK_OF(X509) *extra_certs,
				    SSL_CTX *ssl_ctx, OCSP_RESPONSE *resp)
{
	OCSP_BASICRESP *br = NULL;
	STACK_OF(X509) *ocsp_chain = NULL;
	ASN1_GENERALIZEDTIME *revtime = NULL, *thisupd = NULL, *nextupd = NULL;
	OCSP_CERTID *cid = NULL;
	STACK_OF(X509) *combined = NULL;
	int response_status = 0, cert_status = 0, crl_reason = 0;
	int ssl_res, ret = -1;
	unsigned long flags;
#ifdef BUGGY_VERIFY
	STACK_OF(X509) *tmpchain = NULL;
#endif

	br = OCSP_response_get1_basic(resp);
	if (!br) {
		tls_set_errorx(ctx, "ocsp error: cannot load");
		goto error;
	}

#ifdef BUGGY_VERIFY
	/*
	 * There may be OCSP-subCA in OCSP response that chains to subCA
	 * in main TLS headers.  Need to present both chains to verify.
	 *
	 * OCSP_basic_verify() bugs:
	 * - Does not use br->certs when building chain.
	 * - Does not use main_certs when validating br->certs.
	 */
	if (br->certs && extra_certs) {
		int i;

		combined = sk_X509_new_null();
		if (!combined) {
			tls_set_errorx(ctx, "ocsp error: cannot merge");
			goto error;
		}
		for (i = 0; i < sk_X509_num(br->certs); i++) {
			ssl_res = sk_X509_push(combined, sk_X509_value(br->certs, i));
			if (ssl_res == 0) {
				tls_set_errorx(ctx, "ocsp error: cannot merge");
				goto error;
			}
		}
		for (i = 0; i < sk_X509_num(extra_certs); i++) {
			ssl_res = sk_X509_push(combined, sk_X509_value(extra_certs, i));
			if (ssl_res == 0) {
				tls_set_errorx(ctx, "ocsp error: cannot merge");
				goto error;
			}
		}

		/* OCSP_TRUSTOTHER would skip br->certs checks */
		flags = 0;
		flags = OCSP_TRUSTOTHER;
		ocsp_chain = combined;

		/* Bug: does not use main_certs when validating br->certs */
		if ((flags & OCSP_TRUSTOTHER) == 0) {
			tmpchain = br->certs;
			br->certs = combined;
		}
	} else if (br->certs && !extra_certs) {
		/* can this happen? */
		flags = 0;
		ocsp_chain = br->certs;
	} else
#endif
	{
		/*
		 * Skip validation of 'extra_certs' as this should be done
		 * already as part of main handshake.
		 */
		flags = OCSP_TRUSTOTHER;
		ocsp_chain = extra_certs;
	}

	/* now verify */
	ssl_res = OCSP_basic_verify(br, ocsp_chain, SSL_CTX_get_cert_store(ssl_ctx), flags);

#ifdef BUGGY_VERIFY
	/* replace back */
	if (tmpchain) {
		br->certs = tmpchain;
		tmpchain = NULL;
	}
#endif

	if (ssl_res != 1) {
		tls_set_error_libssl(ctx, "ocsp verify failed");
		goto error;
	}

	/* signature OK, look inside */
	response_status = OCSP_response_status(resp);
	if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		tls_set_errorx(ctx, "ocsp verify failed: unsuccessful response - %s",
			       OCSP_response_status_str(response_status));
		goto error;
	}

	cid = tls_ocsp_get_certid(main_cert, extra_certs, ssl_ctx);
	if (!cid) {
		tls_set_errorx(ctx, "ocsp verify failed: no issuer cert");
		goto error;
	}

	ssl_res = OCSP_resp_find_status(br, cid, &cert_status, &crl_reason, &revtime, &thisupd, &nextupd);
	if (ssl_res != 1) {
		tls_set_errorx(ctx, "ocsp verify failed: no result for cert");
		goto error;
	}

	ssl_res = OCSP_check_validity(thisupd, nextupd, JITTER_SEC, MAXAGE_SEC);
	if (ssl_res != 1) {
		tls_set_errorx(ctx, "ocsp verify failed: bad age");
		goto error;
	}

	ssl_res = tls_ocsp_fill_info(ctx, response_status, cert_status, crl_reason, revtime, thisupd, nextupd);
	if (ssl_res != 0)
		goto error;

	/* finally can look at status */
	if (cert_status != V_OCSP_CERTSTATUS_GOOD && cert_status != V_OCSP_CERTSTATUS_UNKNOWN) {
		tls_set_errorx(ctx, "ocsp verify failed: revoked cert - %s",
			       OCSP_crl_reason_str(crl_reason));
		goto error;
	}

	ret = 0;

error:
	sk_X509_free(combined);
	OCSP_CERTID_free(cid);
	OCSP_BASICRESP_free(br);
	return ret;
}

/*
 * Same callback on client-side has different error proto:
 * 1=OK, 0=bad, -1=internal error
 */

int tls_ocsp_verify_callback(SSL *ssl, void *arg)
{
	OCSP_RESPONSE *resp = NULL;
	STACK_OF(X509) *extra_certs = NULL;
	X509 *peer = NULL;
	const unsigned char *raw = NULL;
	int size, res = -1;
	struct tls *ctx;

	ctx = SSL_get_app_data(ssl);
	if (!ctx)
		return -1;

	size = SSL_get_tlsext_status_ocsp_resp(ssl, &raw);
	if (size <= 0)
		return 1;

	peer = SSL_get_peer_certificate(ssl);
	if (!peer) {
		tls_set_errorx(ctx, "ocsp verify failed: no peer cert");
		goto error;
	}

	resp = d2i_OCSP_RESPONSE(NULL, &raw, size);
	if (!resp) {
		tls_set_errorx(ctx, "ocsp verify failed: parse failed");
		goto error;
	}

	extra_certs = SSL_get_peer_cert_chain(ssl);
	res = tls_ocsp_verify_response(ctx, peer, extra_certs, ctx->ssl_ctx, resp);
error:
	tls_ocsp_fill_result(ctx, res);
	OCSP_RESPONSE_free(resp);
	X509_free(peer);
	return (res == 0) ? 1 : 0;
}

/*
 * Staple OCSP response to server handshake.
 */

int tls_ocsp_stapling_callback(SSL *ssl, void *arg)
{
	struct tls *ctx;
	char *mem, *fmem = NULL;
	uint8_t *xmem;
	size_t len;
	int ret = SSL_TLSEXT_ERR_ALERT_FATAL;

	ctx = SSL_get_app_data(ssl);
	if (!ctx)
		return SSL_TLSEXT_ERR_NOACK;

	if (ctx->config->ocsp_file) {
		fmem = mem = (char *)tls_load_file(ctx->config->ocsp_file, &len, NULL);
		if (!mem)
			goto err;
	} else {
		mem = ctx->config->ocsp_mem;
		len = ctx->config->ocsp_len;
		if (!mem)
			return SSL_TLSEXT_ERR_NOACK;
	}
	xmem = OPENSSL_malloc(len);
	if (xmem) {
		memcpy(xmem, mem, len);
		if (SSL_set_tlsext_status_ocsp_resp(ctx->ssl_conn, xmem, len) != 1) {
			OPENSSL_free(xmem);
			goto err;
		}
		ret = SSL_TLSEXT_ERR_OK;
	}
err:
	free(fmem);
	return ret;
}

/*
 * Query OCSP responder over HTTP(S).
 */

void tls_ocsp_client_free(struct tls *ctx)
{
	struct tls_ocsp_query *q;
	if (!ctx)
		return;
	q = ctx->ocsp_query;
	if (q) {
		if (q->http_req)
			OCSP_REQ_CTX_free(q->http_req);
		BIO_free_all(q->bio);
		SSL_CTX_free(q->ssl_ctx);

		free(q->ocsp_url);
		free(q->request_data);
		free(q);

		ctx->ocsp_query = NULL;
	}
}

static struct tls *tls_ocsp_client_new(void)
{
	struct tls *ctx;

	ctx = tls_new();
	if (!ctx)
		return NULL;
	ctx->flags = TLS_OCSP_CLIENT;

	ctx->ocsp_query = calloc(1, sizeof(struct tls_ocsp_query));
	if (!ctx->ocsp_query) {
		usual_tls_free(ctx);
		return NULL;
	}
	return ctx;
}

static int tls_build_ocsp_request(struct tls *ctx)
{
	struct tls_ocsp_query *q;
	int ok, ret = -1;
	OCSP_REQUEST *req = NULL;
	OCSP_CERTID *cid = NULL;
	OCSP_ONEREQ *onereq = NULL;
	BIO *mem = NULL;
	void *data;

	q = ctx->ocsp_query;

	cid = tls_ocsp_get_certid(q->main_cert, q->extra_certs, q->cert_ssl_ctx);
	if (!cid) {
		tls_set_errorx(ctx, "Cannot create cert-id");
		goto failed;
	}

	req = OCSP_REQUEST_new();
	if (!req) {
		tls_set_error_libssl(ctx, "Cannot create request");
		goto failed;
	}

	onereq = OCSP_request_add0_id(req, cid);
	if (!onereq) {
		tls_set_error_libssl(ctx, "Cannot add cert-id to request");
		goto failed;
	}
	cid = NULL;

	/*
	 * Now render it.
	 */

	mem = BIO_new(BIO_s_mem());
	if (!mem) {
		tls_set_errorx(ctx, "BIO_new");
		goto failed;
	}

	ok = i2d_OCSP_REQUEST_bio(mem, req);
	if (!ok) {
		tls_set_error_libssl(ctx, "i2d_OCSP_RESPONSE_bio");
		goto failed;
	}
	q->request_size = BIO_get_mem_data(mem, &data);
	q->request_data = malloc(q->request_size);
	if (!q->request_data) {
		tls_set_error(ctx, "Failed to allocate request data");
		goto failed;
	}
	memcpy(q->request_data, data, q->request_size);

	req = NULL;
	ret = 0;
failed:
	OCSP_CERTID_free(cid);
	OCSP_REQUEST_free(req);
	BIO_free(mem);
	return ret;
}

static int tls_ocsp_setup(struct tls **ocsp_ctx_p, struct tls_config *config, struct tls *target)
{
	struct tls *ctx;
	struct tls_ocsp_query *q;
	int ret = -1;
	STACK_OF(OPENSSL_STRING) *ocsp_urls;

	ctx = tls_ocsp_client_new();
	if (!ctx)
		return -1;

	*ocsp_ctx_p = ctx;
	q = ctx->ocsp_query;

	if (config) {
		/* create ctx->ssl_ctx */
		ctx->flags = TLS_SERVER;
		ret = tls_configure(ctx, config);
		ctx->flags = TLS_OCSP_CLIENT;
		if (ret != 0)
			return ret;

		q->main_cert = SSL_get_certificate(ctx->ssl_conn);
		q->cert_ssl_ctx = ctx->ssl_ctx;
		SSL_CTX_get_extra_chain_certs(ctx->ssl_ctx, &q->extra_certs);
	} else {
		/* steal state from target struct */
		q->main_cert = SSL_get_peer_certificate(target->ssl_conn);
		q->extra_certs = SSL_get_peer_cert_chain(target->ssl_conn);
		q->cert_ssl_ctx = target->ssl_ctx;
		X509_free(q->main_cert);/* unref */
	}

	if (!q->main_cert) {
		tls_set_errorx(ctx, "No cert");
		return -1;
	}

	ocsp_urls = X509_get1_ocsp(q->main_cert);
	if (!ocsp_urls)
		return TLS_NO_OCSP;
	q->ocsp_url = strdup(sk_OPENSSL_STRING_value(ocsp_urls, 0));
	if (!q->ocsp_url) {
		tls_set_errorx(ctx, "Cannot copy URL");
		goto failed;
	}

	ret = tls_build_ocsp_request(ctx);
	if (ret != 0)
		goto failed;

	*ocsp_ctx_p = ctx;

failed:
	X509_email_free(ocsp_urls);
	return ret;
}

static int tls_ocsp_process_response_parsed(struct tls *ctx, struct tls_config *config, OCSP_RESPONSE *resp)
{
	struct tls_ocsp_query *q = ctx->ocsp_query;
	BIO *mem = NULL;
	size_t len;
	unsigned char *data;
	int ret = -1, ok, res;

	res = tls_ocsp_verify_response(ctx, q->main_cert, q->extra_certs, q->cert_ssl_ctx, resp);
	if (res < 0)
		goto failed;

	/* Update blob in config */
	if (config) {
		mem = BIO_new(BIO_s_mem());
		if (!mem) {
			tls_set_error_libssl(ctx, "BIO_new");
			goto failed;
		}
		ok = i2d_OCSP_RESPONSE_bio(mem, resp);
		if (!ok) {
			tls_set_error_libssl(ctx, "i2d_OCSP_RESPONSE_bio");
			goto failed;
		}
		len = BIO_get_mem_data(mem, &data);
		res = tls_config_set_ocsp_stapling_mem(config, data, len);
		if (res < 0)
			goto failed;
	}
	ret = 0;
failed:
	BIO_free(mem);
	tls_ocsp_fill_result(ctx, ret);
	return ret;
}

static int tls_ocsp_create_request(struct tls **ocsp_ctx_p,
				   struct tls_config *config, struct tls *target,
				   char **ocsp_url,
				   void **request_blob, size_t *request_size)
{
	int res;
	struct tls_ocsp_query *q;

	res = tls_ocsp_setup(ocsp_ctx_p, config, target);
	if (res != 0)
		return res;
	q = (*ocsp_ctx_p)->ocsp_query;

	*ocsp_url = q->ocsp_url;
	*request_blob = q->request_data;
	*request_size = q->request_size;

	return 0;
}

/*
 * Public API for request blobs.
 */

int tls_ocsp_check_peer_request(struct tls **ocsp_ctx_p, struct tls *target,
				char **ocsp_url, void **request_blob, size_t *request_size)
{
	return tls_ocsp_create_request(ocsp_ctx_p, NULL, target,
				       ocsp_url, request_blob, request_size);
}

int tls_ocsp_refresh_stapling_request(struct tls **ocsp_ctx_p,
				      struct tls_config *config,
				      char **ocsp_url, void **request_blob, size_t *request_size)
{
	return tls_ocsp_create_request(ocsp_ctx_p, config, NULL,
				       ocsp_url, request_blob, request_size);
}

int tls_ocsp_process_response(struct tls *ctx, const void *response_blob, size_t size)
{
	int ret;
	OCSP_RESPONSE *resp;
	const unsigned char *raw = response_blob;

	resp = d2i_OCSP_RESPONSE(NULL, &raw, size);
	if (!resp) {
		ctx->ocsp_result = "parse-failed";
		tls_set_error_libssl(ctx, "parse failed");
		return -1;
	}
	ret = tls_ocsp_process_response_parsed(ctx, ctx->config, resp);
	OCSP_RESPONSE_free(resp);
	return ret;
}

/*
 * Network processing
 */

static int tls_ocsp_build_http_req(struct tls *ctx)
{
	struct tls_ocsp_query *q = ctx->ocsp_query;
	int ok;
	OCSP_REQUEST *req;
	OCSP_REQ_CTX *sreq;
	const unsigned char *data;
	int ret = -1, https = 0;
	char *host = NULL, *port = NULL, *path = NULL;

	ok = OCSP_parse_url(q->ocsp_url, &host, &port, &path, &https);
	if (ok != 1) {
		tls_set_error_libssl(ctx, "Cannot parse URL");
		goto failed;
	}

	sreq = OCSP_sendreq_new(q->bio, path, NULL, -1);
	if (!sreq) {
		tls_set_error_libssl(ctx, "OCSP HTTP request setup failed");
		goto failed;
	}
	q->http_req = sreq;

	ok = OCSP_REQ_CTX_add1_header(sreq, "Host", host);

	/* add payload after headers */
	if (ok) {
		data = q->request_data;
		req = d2i_OCSP_REQUEST(NULL, &data, q->request_size);
		if (req)
			ok = OCSP_REQ_CTX_set1_req(sreq, req);
		else
			ok = false;
		OCSP_REQUEST_free(req);
	}

	if (ok)
		ret = 0;
failed:
	free(host);
	free(port);
	free(path);
	return ret;
}

static int tls_ocsp_connection_setup(struct tls *ctx)
{
	SSL *ssl = NULL;
	int ret = -1, ok, https = 0;
	struct tls_ocsp_query *q = ctx->ocsp_query;
	union { struct in_addr ip4; struct in6_addr ip6; } addrbuf;
	char *host = NULL, *port = NULL, *path = NULL;

	ok = OCSP_parse_url(q->ocsp_url, &host, &port, &path, &https);
	if (ok != 1) {
		tls_set_error_libssl(ctx, "Cannot parse URL");
		goto failed;
	}

	if (https) {
		q->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
		if (!q->ssl_ctx) {
			tls_set_error_libssl(ctx, "Cannot init SSL");
			goto failed;
		}

		SSL_CTX_set_options(q->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
		SSL_CTX_clear_options(q->ssl_ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3);
		SSL_CTX_set_mode(q->ssl_ctx, SSL_MODE_AUTO_RETRY);

		q->bio = BIO_new_ssl_connect(q->ssl_ctx);
		if (q->bio) {
			if (inet_pton(AF_INET, host, &addrbuf) != 1 &&
			    inet_pton(AF_INET6, host, &addrbuf) != 1) {
				if (!BIO_get_ssl(q->bio, &ssl)) {
					tls_set_errorx(ctx, "cannot get ssl struct");
					goto failed;
				}
				if (SSL_set_tlsext_host_name(ssl, host) == 0) {
					tls_set_errorx(ctx, "server name indication failure");
					goto failed;
				}
			}
		}
	} else {
		q->bio = BIO_new(BIO_s_connect());
	}

	if (!q->bio) {
		tls_set_error_libssl(ctx, "Cannot connect");
		goto failed;
	}

	BIO_set_conn_hostname(q->bio, host);
	BIO_set_conn_port(q->bio, port);
	BIO_set_nbio(q->bio, 1);
	ret = 0;
failed:
	free(host);
	free(port);
	free(path);
	return ret;
}

static int tls_ocsp_evloop(struct tls *ctx, int *fd_p, struct tls_config *config)
{
	struct tls_ocsp_query *q = ctx->ocsp_query;
	OCSP_RESPONSE *ocsp_resp = NULL;
	int ret, ok;

	if (q->http_req == NULL) {
		ok = BIO_do_connect(q->bio);
		if (ok != 1 && !BIO_should_retry(q->bio)) {
			tls_set_error_libssl(ctx, "Connection failure");
			goto error;
		}

		*fd_p = BIO_get_fd(q->bio, NULL);
		if (*fd_p < 0) {
			tls_set_error_libssl(ctx, "Cannot get FD");
			goto error;
		}

		if (ok != 1)
			return TLS_WANT_POLLOUT;

		ret = tls_ocsp_build_http_req(ctx);
		if (ret != 0)
			goto error;
	}

	ok = OCSP_sendreq_nbio(&ocsp_resp, q->http_req);
	if (ok == 1) {
		ret = tls_ocsp_process_response_parsed(ctx, config, ocsp_resp);
		return ret;
	} else if (ok == 0) {
		tls_set_error_libssl(ctx, "OCSP request failed");
		goto error;
	} else if (BIO_should_read(q->bio)) {
		return TLS_WANT_POLLIN;
	} else if (BIO_should_write(q->bio)) {
		return TLS_WANT_POLLOUT;
	}

	tls_set_error_libssl(ctx, "Unexpected request error");
error:
	tls_ocsp_fill_result(ctx, -1);
	return -1;
}

static int tls_ocsp_do_poll(struct tls *ctx, int errcode, int fd)
{
	struct pollfd pfd;
	int res;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;

	if (errcode == TLS_WANT_POLLIN) {
		pfd.events = POLLIN;
	} else if (errcode == TLS_WANT_POLLOUT) {
		pfd.events = POLLOUT;
	} else {
		tls_set_error(ctx, "bad code to poll");
		return -1;
	}
	res = poll(&pfd, 1, -1);
	if (res == 1) {
		return 0;
	} else if (res == 0) {
		tls_set_errorx(ctx, "poll timed out");
		return -1;
	}
	tls_set_error(ctx, "poll error");
	return -1;
}

static int tls_ocsp_query_async(struct tls **ocsp_ctx_p, int *fd_p, struct tls_config *config, struct tls *target)
{
	struct tls *ctx = *ocsp_ctx_p;
	int ret;

	if (!ctx) {
		ret = tls_ocsp_setup(&ctx, config, target);
		if (ret != 0)
			goto failed;
		ret = tls_ocsp_connection_setup(ctx);
		if (ret != 0)
			goto failed;
		*ocsp_ctx_p = ctx;
	}
	return tls_ocsp_evloop(ctx, fd_p, config);
failed:
	usual_tls_free(ctx);
	return -1;
}

static int tls_ocsp_common_query(struct tls **ocsp_ctx_p, int *fd_p, struct tls_config *config, struct tls *target)
{
	struct tls *ctx = NULL;
	int ret, fd = -1;

	/* async path */
	if (fd_p)
		return tls_ocsp_query_async(ocsp_ctx_p, fd_p, config, target);

	/* sync path */
	while (1) {
		ret = tls_ocsp_query_async(&ctx, &fd, config, target);
		if (ret != TLS_WANT_POLLIN && ret != TLS_WANT_POLLOUT)
			break;
		ret = tls_ocsp_do_poll(ctx, ret, fd);
		if (ret != 0)
			break;
	}
	*ocsp_ctx_p = ctx;
	return ret;
}

/*
 * Public API.
 */

int tls_ocsp_check_peer(struct tls **ocsp_ctx_p, int *async_fd_p, struct tls *target)
{
	return tls_ocsp_common_query(ocsp_ctx_p, async_fd_p, NULL, target);
}

int tls_ocsp_refresh_stapling(struct tls **ocsp_ctx_p, int *async_fd_p, struct tls_config *config)
{
	return tls_ocsp_common_query(ocsp_ctx_p, async_fd_p, config, NULL);
}

#else /* No OCSP */

void tls_ocsp_info_free(struct tls_ocsp_info *info)
{
}
void tls_ocsp_client_free(struct tls *ctx)
{
}

int tls_get_ocsp_info(struct tls *ctx, int *response_status, int *cert_status,
		      int *crl_reason, time_t *this_update,
		      time_t *next_update, time_t *revoction_time,
		      const char **result_text)
{
	if (response_status) *response_status = -1;
	if (cert_status) *cert_status = -1;
	if (crl_reason) *crl_reason = -1;
	if (result_text) *result_text = "OCSP not supported";
	if (this_update) *this_update = 0;
	if (next_update) *next_update = 0;
	if (revoction_time) *revoction_time = 0;
	return TLS_NO_OCSP;
}

int tls_ocsp_check_peer(struct tls **ocsp_ctx_p, int *async_fd_p, struct tls *target)
{
	*ocsp_ctx_p = NULL;
	return TLS_NO_OCSP;
}

int tls_ocsp_refresh_stapling(struct tls **ocsp_ctx_p, int *async_fd_p, struct tls_config *config)
{
	*ocsp_ctx_p = NULL;
	return TLS_NO_OCSP;
}

#endif /* OPENSSL_NO_OCSP */
#endif /* USUAL_LIBSSL_FOR_TLS */
