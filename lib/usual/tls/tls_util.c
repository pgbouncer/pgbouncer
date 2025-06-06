/* $OpenBSD$ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
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

#include <openssl/dh.h>
#include <openssl/evp.h>

#include <sys/stat.h>

#include "tls_internal.h"

const char *
tls_backend_version(void)
{
	return OpenSSL_version(OPENSSL_VERSION);
}

/*
 * Extract the host and port from a colon separated value. For a literal IPv6
 * address the address must be contained with square braces. If a host and
 * port are successfully extracted, the function will return 0 and the
 * caller is responsible for freeing the host and port. If no port is found
 * then the function will return 1, with both host and port being NULL.
 * On memory allocation failure -1 will be returned.
 */
int
tls_host_port(const char *hostport, char **host, char **port)
{
	char *h, *p, *s;
	int rv = 1;

	*host = NULL;
	*port = NULL;

	if ((s = strdup(hostport)) == NULL)
		goto fail;

	h = p = s;

	/* See if this is an IPv6 literal with square braces. */
	if (p[0] == '[') {
		h++;
		if ((p = strchr(s, ']')) == NULL)
			goto done;
		*p++ = '\0';
	}

	/* Find the port seperator. */
	if ((p = strchr(p, ':')) == NULL)
		goto done;

	/* If there is another separator then we have issues. */
	if (strchr(p + 1, ':') != NULL)
		goto done;

	*p++ = '\0';

	if (asprintf(host, "%s", h) == -1)
		goto fail;
	if (asprintf(port, "%s", p) == -1)
		goto fail;

	rv = 0;
	goto done;

 fail:
	free(*host);
	*host = NULL;
	free(*port);
	*port = NULL;
	rv = -1;

 done:
	free(s);

	return (rv);
}

static int
tls_password_cb(char *buf, int size, int rwflag, void *u)
{
	size_t	len;
	if (u == NULL) {
		memset(buf, 0, size);
		return (0);
	}
	if ((len = strlcpy(buf, u, size)) >= (size_t)size)
		return (0);
	return (len);
}

uint8_t *
tls_load_file(const char *name, size_t *len, char *password)
{
	FILE *fp;
	EVP_PKEY *key = NULL;
	BIO *bio = NULL;
	uint8_t *buf = NULL;
	char *data;
	struct stat st;
	size_t size;
	int fd = -1;

	*len = 0;

	if ((fd = open(name, O_RDONLY)) == -1)
		return (NULL);

	/* Just load the file into memory without decryption */
	if (password == NULL) {
		if (fstat(fd, &st) != 0)
			goto fail;
		size = (size_t)st.st_size;
		if ((buf = calloc(1, size + 1)) == NULL)
			goto fail;
		if (read(fd, buf, size) != (ssize_t)size)
			goto fail;
		close(fd);
		goto done;
	}

	/* Or read the (possibly) encrypted key from file */
	if ((fp = fdopen(fd, "r")) == NULL)
		goto fail;
	fd = -1;

	key = PEM_read_PrivateKey(fp, NULL, tls_password_cb, password);
	fclose(fp);
	if (key == NULL)
		goto fail;

	/* Write unencrypted key to memory buffer */
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		goto fail;
	if (!PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL))
		goto fail;
	if ((size = BIO_get_mem_data(bio, &data)) <= 0)
		goto fail;
	if ((buf = calloc(1, size)) == NULL)
		goto fail;
	memcpy(buf, data, size);

	BIO_free_all(bio);
	EVP_PKEY_free(key);

 done:
	*len = size;
	return (buf);

 fail:
	free(buf);
	if (fd != -1)
		close(fd);
	if (bio != NULL)
		BIO_free_all(bio);
	if (key != NULL)
		EVP_PKEY_free(key);

	return (NULL);
}

ssize_t
tls_get_connection_info(struct tls *ctx, char *buf, size_t buflen)
{
	SSL *conn = ctx->ssl_conn;
	const char *ocsp_pfx = "", *ocsp_info = "";
	const char *proto = "-", *cipher = "-";
	char dh[64];
	int used_dh_bits = ctx->used_dh_bits, used_ecdh_nid = ctx->used_ecdh_nid;
	const SSL_CIPHER *ciph_obj = NULL;

	dh[0] = 0;

	if (conn != NULL) {
		proto = SSL_get_version(conn);
		cipher = SSL_get_cipher(conn);
		ciph_obj = SSL_get_current_cipher(conn);

#ifdef SSL_get_server_tmp_key
		if (ctx->flags & TLS_CLIENT) {
			EVP_PKEY *pk = NULL;
			int ok = SSL_get_server_tmp_key(conn, &pk);
			if (ok) {
				int pk_type = EVP_PKEY_id(pk);
				if (pk_type == EVP_PKEY_DH) {
					const DH *dh = EVP_PKEY_get0_DH(pk);
					used_dh_bits = DH_size(dh) * 8;
				} else if (pk_type == EVP_PKEY_EC) {
					const EC_KEY *ecdh = EVP_PKEY_get0_EC_KEY(pk);
					const EC_GROUP *eg = EC_KEY_get0_group(ecdh);
					used_ecdh_nid = EC_GROUP_get_curve_name(eg);
				}
				EVP_PKEY_free(pk);
			}
		} else
#endif
		if (ciph_obj && !used_ecdh_nid && !used_dh_bits) {
#ifdef SSL_get_shared_curve
			int kx = SSL_CIPHER_get_kx_nid(ciph_obj);
			if (kx == NID_kx_ecdhe) {
				used_ecdh_nid = SSL_get_shared_curve(conn, 0);
			} else if (kx == NID_kx_dhe) {
				snprintf(dh, sizeof dh, "/DH=?");
			}
#endif
		}
	}

	if (used_dh_bits) {
		snprintf(dh, sizeof dh, "/DH=%d", used_dh_bits);
	} else if (used_ecdh_nid) {
		snprintf(dh, sizeof dh, "/ECDH=%s", OBJ_nid2sn(used_ecdh_nid));
	}

	if (ctx->ocsp_result) {
		ocsp_info = ctx->ocsp_result;
		ocsp_pfx = "/OCSP=";
	}

	return snprintf(buf, buflen, "%s/%s%s%s%s", proto, cipher, dh, ocsp_pfx, ocsp_info);
}

#endif /* USUAL_LIBSSL_FOR_TLS */
