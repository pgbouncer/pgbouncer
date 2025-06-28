
#ifndef _USUAL_TLS_COMPAT_H_
#define _USUAL_TLS_COMPAT_H_

#include <usual/tls/tls.h>

#ifdef USUAL_LIBSSL_FOR_TLS

#include <usual/string.h>
#include <usual/socket.h>
#include <usual/netdb.h>
#include <usual/time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* OpenSSL 1.1+ has hidden struct fields */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

/*
 * USE_LIBSSL_OLD - old openssl 1.0 api
 * USE_LIBSSL_INTERNALS - can access old openssl 1.0 structs
 * otherwise - new openssl 1.1 api
 */

/* libressl has old api but unstable structs */
#define USE_LIBSSL_OLD

#ifndef LIBRESSL_VERSION_NUMBER
#define USE_LIBSSL_INTERNALS
#endif

#define NID_kx_ecdhe (-90)
#define NID_kx_dhe (-91)
#define SSL_CIPHER_get_kx_nid(ciph) (0)
#define X509_get_key_usage(x509) ((x509)->ex_kusage)
#define X509_get_extended_key_usage(x509) ((x509)->ex_xkusage)
#define SSL_CTX_get0_param(ssl_ctx) ((ssl_ctx)->param)
#define ASN1_STRING_get0_data(x) ((const unsigned char *)ASN1_STRING_data(x))
#define X509_OBJECT_get0_X509(x) ((x)->data.x509)

#ifndef OPENSSL_VERSION
#define OPENSSL_VERSION SSLEAY_VERSION
#define OpenSSL_version(x) SSLeay_version(x)
#endif

static inline X509_OBJECT *X509_OBJECT_new(void)
{
	X509_OBJECT *obj = OPENSSL_malloc(sizeof(*obj));
	if (obj) {
		memset(obj, 0, sizeof(*obj));
	} else {
		X509err(X509_F_GET_CERT_BY_SUBJECT, ERR_R_MALLOC_FAILURE);
	}
	return obj;
}

static inline void X509_OBJECT_free(X509_OBJECT *obj)
{
	if (obj) {
		if (obj->type == X509_LU_X509) {
			X509_free(obj->data.x509);
		} else if (obj->type == X509_LU_CRL) {
			X509_CRL_free(obj->data.crl);
		}
		OPENSSL_free(obj);
	}
}

static inline X509_OBJECT *X509_STORE_CTX_get_obj_by_subject(X509_STORE_CTX *ctx, int lookup, X509_NAME *name)
{
	X509_OBJECT *obj = X509_OBJECT_new();
	if (obj) {
		if (X509_STORE_get_by_subject(ctx, lookup, name, obj)) {
			return obj;
		}
		X509_OBJECT_free(obj);
	}
	return NULL;
}

/*
 * We need these specific functions for OpenSSL 3.0.0 because the
 * generic function no longer works.  But the new ones only exist in
 * 1.1.0, so in older versions we still use the older one.
 */
#define EVP_PKEY_get0_DH(pkey) EVP_PKEY_get0(pkey)
#define EVP_PKEY_get0_EC_KEY(pkey) EVP_PKEY_get0(pkey)

#endif /* OpenSSL <1.1 */

/* ecdh_auto is broken - ignores main EC key */
#undef SSL_CTX_set_ecdh_auto

/* dh_auto seems fine, but use ours to get DH info */
#undef SSL_CTX_set_dh_auto

#ifndef SSL_CTX_set_dh_auto
long SSL_CTX_set_dh_auto(SSL_CTX *ctx, int onoff);
#endif

#ifndef SSL_CTX_set_ecdh_auto
long SSL_CTX_set_ecdh_auto(SSL_CTX *ctx, int onoff);
#endif

#ifndef HAVE_SSL_CTX_USE_CERTIFICATE_CHAIN_MEM
int SSL_CTX_use_certificate_chain_mem(SSL_CTX *ctx, void *buf, int len);
#endif

#ifndef HAVE_SSL_CTX_LOAD_VERIFY_MEM
int SSL_CTX_load_verify_mem(SSL_CTX *ctx, void *buf, int len);
#endif

/* BoringSSL has no OCSP support */
#ifdef OPENSSL_IS_BORINGSSL
#define SSL_CTX_set_tlsext_status_cb(a, b) (1)
#define SSL_set_tlsext_status_type(a, b) (1)
#endif

/* AWS-LC does not currently have OCSP support */
#if defined(OPENSSL_IS_AWSLC) && defined(OPENSSL_NO_OCSP)
#define SSL_CTX_set_tlsext_status_cb(a, b) (1)
#define SSL_set_tlsext_status_type(a, b) (1)
#endif

void tls_compat_cleanup(void);

#ifndef SSL_OP_NO_TLSv1_3
#define SSL_OP_NO_TLSv1_3 0
#endif

#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION 0x0304
#endif

#endif /* USUAL_LIBSSL_FOR_TLS */

#endif /* _USUAL_TLS_COMPAT_H_ */
