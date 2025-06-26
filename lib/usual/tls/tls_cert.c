/* $OpenBSD$ */
/*
 * Copyright (c) 2014 Jeremie Courreges-Anglas <jca@openbsd.org>
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

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "tls_internal.h"

#define TLS_CERT_INTERNAL_FUNCS
#include "tls_cert.h"

/*
 * Load cert data from X509 cert.
 */

/* Upper bounds */
#define UB_COMMON_NAME                          255
#define UB_COUNTRY_NAME                         255
#define UB_STATE_NAME                           255
#define UB_LOCALITY_NAME                        255
#define UB_STREET_ADDRESS                       255
#define UB_ORGANIZATION_NAME                    255
#define UB_ORGANIZATIONAL_UNIT_NAME             255

#define UB_GNAME_DNS                            255
#define UB_GNAME_EMAIL                          255
#define UB_GNAME_URI                            255

/* Convert ASN1_INTEGER to decimal string string */
static int tls_parse_bigint(struct tls *ctx, const ASN1_INTEGER *asn1int, const char **dst_p)
{
	long small;
	BIGNUM *big;
	char *tmp, buf[64];

	*dst_p = NULL;
	small = ASN1_INTEGER_get(asn1int);
	if (small < 0) {
		big = ASN1_INTEGER_to_BN(asn1int, NULL);
		if (big) {
			tmp = BN_bn2dec(big);
			if (tmp)
				*dst_p = strdup(tmp);
			OPENSSL_free(tmp);
		}
		BN_free(big);
	} else {
		snprintf(buf, sizeof buf, "%lu", small);
		*dst_p = strdup(buf);
	}
	if (*dst_p)
		return 0;

	tls_set_errorx(ctx, "cannot parse serial");
	return -1;
}

/*
 * Decode all string types used in RFC5280.
 *
 * OpenSSL used (before Jun 1 2014 commit) to pick between PrintableString,
 * T61String, BMPString and UTF8String, depending on data.  This code
 * tries to match that.
 *
 * Disallow any ancient ASN.1 escape sequences.
 */

static int check_invalid_bytes(struct tls *ctx, const unsigned char *data, unsigned int len,
			       int ascii_only, const char *desc)
{
	unsigned int i, c;

	/* data is utf8 string, check for crap */
	for (i = 0; i < len; i++) {
		c = data[i];

		if (ascii_only && (c & 0x80) != 0) {
			tls_set_errorx(ctx, "invalid %s: contains non-ascii in ascii string", desc);
			goto failed;
		} else if (c < 0x20) {
			/* ascii control chars, including NUL */
			if (c != '\t' && c != '\n' && c != '\r') {
				tls_set_errorx(ctx, "invalid %s: contains C0 control char", desc);
				goto failed;
			}
		} else if (c == 0xC2 && (i + 1) < len) {
			/* C1 control chars in UTF-8: \xc2\x80 - \xc2\x9f */
			c = data[i + 1];
			if (c >= 0x80 && c <= 0x9F) {
				tls_set_errorx(ctx, "invalid %s: contains C1 control char", desc);
				goto failed;
			}
		} else if (c == 0x7F) {
			tls_set_errorx(ctx, "invalid %s: contains DEL char", desc);
			goto failed;
		}
	}
	return 0;
failed:
	return -1;
}

static int tls_parse_asn1string(struct tls *ctx, ASN1_STRING *a1str, const char **dst_p, int minchars, int maxchars, const char *desc)
{
	int format, len, ret = -1;
	const unsigned char *data;
	ASN1_STRING *a1utf = NULL;
	int ascii_only = 0;
	char *cstr = NULL;
	int mbres, mbconvert = -1;

	*dst_p = NULL;

	format = ASN1_STRING_type(a1str);
	data = ASN1_STRING_get0_data(a1str);
	len = ASN1_STRING_length(a1str);
	if (len < minchars) {
		tls_set_errorx(ctx, "invalid %s: string too short", desc);
		goto failed;
	}

	switch (format) {
	case V_ASN1_NUMERICSTRING:
	case V_ASN1_VISIBLESTRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_IA5STRING:
		/* Ascii */
		if (len > maxchars) {
			tls_set_errorx(ctx, "invalid %s: string too long", desc);
			goto failed;
		}
		ascii_only = 1;
		break;
	case V_ASN1_T61STRING:
		/* Latin1 */
		mbconvert = MBSTRING_ASC;
		break;
	case V_ASN1_BMPSTRING:
		/* UCS-2 big-endian */
		mbconvert = MBSTRING_BMP;
		break;
	case V_ASN1_UNIVERSALSTRING:
		/* UCS-4 big-endian */
		mbconvert = MBSTRING_UNIV;
		break;
	case V_ASN1_UTF8STRING:
		/*
		 * UTF-8 - could be used directly if OpenSSL has already
		 * validated the data.  ATM be safe and validate here.
		 */
		mbconvert = MBSTRING_UTF8;
		break;
	default:
		tls_set_errorx(ctx, "invalid %s: unexpected string type", desc);
		goto failed;
	}

	/* Convert to UTF-8 */
	if (mbconvert != -1) {
		mbres = ASN1_mbstring_ncopy(&a1utf, data, len, mbconvert, B_ASN1_UTF8STRING, minchars, maxchars);
		if (mbres < 0) {
			tls_set_error_libssl(ctx, "invalid %s", desc);
			goto failed;
		}
		if (mbres != V_ASN1_UTF8STRING) {
			tls_set_errorx(ctx, "multibyte conversion failed: expected UTF8 result");
			goto failed;
		}
		data = ASN1_STRING_get0_data(a1utf);
		len = ASN1_STRING_length(a1utf);
	}

	/* must not allow \0 */
	if (memchr(data, 0, len) != NULL) {
		tls_set_errorx(ctx, "invalid %s: contains NUL", desc);
		goto failed;
	}

	/* no escape codes please */
	if (check_invalid_bytes(ctx, data, len, ascii_only, desc) < 0)
		goto failed;

	/* copy to new string */
	cstr = malloc(len + 1);
	if (!cstr) {
		tls_set_error(ctx, "malloc");
		goto failed;
	}
	memcpy(cstr, data, len);
	cstr[len] = 0;
	*dst_p = cstr;
	ret = len;
failed:
	ASN1_STRING_free(a1utf);
	return ret;
}

static int tls_cert_get_dname_string(struct tls *ctx, X509_NAME *name, int nid, const char **str_p, int minchars, int maxchars, const char *desc)
{
	int loc, len;
	X509_NAME_ENTRY *ne;
	ASN1_STRING *a1str;

	*str_p = NULL;

	loc = X509_NAME_get_index_by_NID(name, nid, -1);
	if (loc < 0)
		return 0;
	ne = X509_NAME_get_entry(name, loc);
	if (!ne)
		return 0;
	a1str = X509_NAME_ENTRY_get_data(ne);
	if (!a1str)
		return 0;
	len = tls_parse_asn1string(ctx, a1str, str_p, minchars, maxchars, desc);
	if (len < 0)
		return -1;
	return 0;
}

static int tls_load_alt_ia5string(struct tls *ctx, ASN1_IA5STRING *ia5str, struct tls_cert *cert, int slot_type, int minchars, int maxchars, const char *desc)
{
	struct tls_cert_general_name *slot;
	const char *data;
	int len;

	slot = &cert->subject_alt_names[cert->subject_alt_name_count];

	len = tls_parse_asn1string(ctx, ia5str, &data, minchars, maxchars, desc);
	if (len < 0)
		return 0;

	/*
	 * Per RFC 5280 section 4.2.1.6:
	 * " " is a legal domain name, but that
	 * dNSName must be rejected.
	 */
	if (len == 1 && data[0] == ' ') {
		tls_set_errorx(ctx, "invalid %s: single space", desc);
		return -1;
	}

	slot->name_value = data;
	slot->name_type = slot_type;

	cert->subject_alt_name_count++;
	return 0;
}

static int tls_load_alt_ipaddr(struct tls *ctx, ASN1_OCTET_STRING *bin, struct tls_cert *cert)
{
	struct tls_cert_general_name *slot;
	const void *data;
	int len;

	slot = &cert->subject_alt_names[cert->subject_alt_name_count];
	len = ASN1_STRING_length(bin);
	data = ASN1_STRING_get0_data(bin);
	if (len < 0) {
		tls_set_errorx(ctx, "negative length for ipaddress");
		return -1;
	}

	/*
	 * Per RFC 5280 section 4.2.1.6:
	 * IPv4 must use 4 octets and IPv6 must use 16 octets.
	 */
	if (len == 4) {
		slot->name_type = TLS_CERT_GNAME_IPv4;
	} else if (len == 16) {
		slot->name_type = TLS_CERT_GNAME_IPv6;
	} else {
		tls_set_errorx(ctx, "invalid length for ipaddress");
		return -1;
	}

	slot->name_value = malloc(len);
	if (slot->name_value == NULL) {
		tls_set_error(ctx, "malloc");
		return -1;
	}

	memcpy((void *)slot->name_value, data, len);
	cert->subject_alt_name_count++;
	return 0;
}

/* See RFC 5280 section 4.2.1.6 for SubjectAltName details. */
static int tls_cert_get_altnames(struct tls *ctx, struct tls_cert *cert, X509 *x509_cert)
{
	STACK_OF(GENERAL_NAME) *altname_stack = NULL;
	GENERAL_NAME *altname;
	int count, i;
	int rv = -1;

	altname_stack = X509_get_ext_d2i(x509_cert, NID_subject_alt_name, NULL, NULL);
	if (altname_stack == NULL)
		return 0;

	count = sk_GENERAL_NAME_num(altname_stack);
	if (count == 0) {
		rv = 0;
		goto out;
	}

	cert->subject_alt_names = calloc(count, sizeof(struct tls_cert_general_name));
	if (cert->subject_alt_names == NULL) {
		tls_set_error(ctx, "calloc");
		goto out;
	}

	for (i = 0; i < count; i++) {
		altname = sk_GENERAL_NAME_value(altname_stack, i);

		if (altname->type == GEN_DNS) {
			rv = tls_load_alt_ia5string(ctx, altname->d.dNSName, cert, TLS_CERT_GNAME_DNS, 1, UB_GNAME_DNS, "dns");
		} else if (altname->type == GEN_EMAIL) {
			rv = tls_load_alt_ia5string(ctx, altname->d.rfc822Name, cert, TLS_CERT_GNAME_EMAIL, 1, UB_GNAME_EMAIL, "email");
		} else if (altname->type == GEN_URI) {
			rv = tls_load_alt_ia5string(ctx, altname->d.uniformResourceIdentifier, cert, TLS_CERT_GNAME_URI, 1, UB_GNAME_URI, "uri");
		} else if (altname->type == GEN_IPADD) {
			rv = tls_load_alt_ipaddr(ctx, altname->d.iPAddress, cert);
		} else {
			/* ignore unknown types */
			rv = 0;
		}
		if (rv < 0)
			goto out;
	}
	rv = 0;
out:
	sk_GENERAL_NAME_pop_free(altname_stack, GENERAL_NAME_free);
	return rv;
}

static int tls_get_dname(struct tls *ctx, X509_NAME *name, struct tls_cert_dname *dname)
{
	int ret;
	ret = tls_cert_get_dname_string(ctx, name, NID_commonName, &dname->common_name,
					0, UB_COMMON_NAME, "commonName");
	if (ret == 0) {
		ret = tls_cert_get_dname_string(ctx, name, NID_countryName, &dname->country_name,
						0, UB_COUNTRY_NAME, "countryName");
	}
	if (ret == 0) {
		ret = tls_cert_get_dname_string(ctx, name, NID_stateOrProvinceName, &dname->state_or_province_name,
						0, UB_STATE_NAME, "stateName");
	}
	if (ret == 0) {
		ret = tls_cert_get_dname_string(ctx, name, NID_localityName, &dname->locality_name,
						0, UB_LOCALITY_NAME, "localityName");
	}
	if (ret == 0) {
		ret = tls_cert_get_dname_string(ctx, name, NID_streetAddress, &dname->street_address,
						0, UB_STREET_ADDRESS, "streetAddress");
	}
	if (ret == 0) {
		ret = tls_cert_get_dname_string(ctx, name, NID_organizationName, &dname->organization_name,
						0, UB_ORGANIZATION_NAME, "organizationName");
	}
	if (ret == 0) {
		ret = tls_cert_get_dname_string(ctx, name, NID_organizationalUnitName, &dname->organizational_unit_name,
						0, UB_ORGANIZATIONAL_UNIT_NAME, "organizationalUnitName");
	}
	return ret;
}

static int tls_get_basic_constraints(struct tls *ctx, struct tls_cert *cert, X509 *x509)
{
	BASIC_CONSTRAINTS *bc;
	int crit;
	int ret = -1;

	bc = X509_get_ext_d2i(x509, NID_basic_constraints, &crit, NULL);
	if (!bc)
		return 0;

	cert->ext_set |= TLS_EXT_BASIC;
	if (crit)
		cert->ext_crit |= TLS_EXT_BASIC;

	cert->basic_constraints_ca = bc->ca ? 1 : 0;
	if (bc->pathlen) {
		cert->basic_constraints_pathlen = ASN1_INTEGER_get(bc->pathlen);
		if (cert->basic_constraints_pathlen < 0) {
			tls_set_error(ctx, "BasicConstraints has invalid pathlen");
			goto failed;
		}
	} else {
		cert->basic_constraints_pathlen = -1;
	}
	ret = 0;
failed:
	BASIC_CONSTRAINTS_free(bc);
	return ret;
}

static uint32_t map_bits(const uint32_t map[][2], uint32_t input)
{
	uint32_t i, out = 0;
	for (i = 0; map[i][0]; i++) {
		if (map[i][0] & input)
			out |= map[i][1];
	}
	return out;
}

static int tls_get_key_usage(struct tls *ctx, struct tls_cert *cert, X509 *x509)
{
	static const uint32_t ku_map[][2] = {
		{KU_DIGITAL_SIGNATURE, KU_DIGITAL_SIGNATURE},
		{KU_NON_REPUDIATION, KU_NON_REPUDIATION},
		{KU_KEY_ENCIPHERMENT, KU_KEY_ENCIPHERMENT},
		{KU_DATA_ENCIPHERMENT, KU_DATA_ENCIPHERMENT},
		{KU_KEY_AGREEMENT, KU_KEY_AGREEMENT},
		{KU_KEY_CERT_SIGN, KU_KEY_CERT_SIGN},
		{KU_CRL_SIGN, KU_CRL_SIGN},
		{KU_ENCIPHER_ONLY, KU_ENCIPHER_ONLY},
		{KU_DECIPHER_ONLY, KU_DECIPHER_ONLY},
		{0, 0},
	};
	ASN1_BIT_STRING *ku;
	int crit;

	ku = X509_get_ext_d2i(x509, NID_key_usage, &crit, NULL);
	if (!ku)
		return 0;

	cert->ext_set |= TLS_EXT_KEY_USAGE;
	if (crit)
		cert->ext_crit |= TLS_EXT_KEY_USAGE;
	ASN1_BIT_STRING_free(ku);

	cert->key_usage_flags = map_bits(ku_map, X509_get_key_usage(x509));
	return 0;
}

static int tls_get_ext_key_usage(struct tls *ctx, struct tls_cert *cert, X509 *x509)
{
	static const uint32_t xku_map[][2] = {
		{XKU_SSL_SERVER, TLS_XKU_SSL_SERVER},
		{XKU_SSL_CLIENT, TLS_XKU_SSL_CLIENT},
		{XKU_SMIME, TLS_XKU_SMIME},
		{XKU_CODE_SIGN, TLS_XKU_CODE_SIGN},
		{XKU_SGC, TLS_XKU_SGC},
		{XKU_OCSP_SIGN, TLS_XKU_OCSP_SIGN},
		{XKU_TIMESTAMP, TLS_XKU_TIMESTAMP},
		{XKU_DVCS, TLS_XKU_DVCS},
		{0, 0},
	};
	EXTENDED_KEY_USAGE *xku;
	int crit;

	xku = X509_get_ext_d2i(x509, NID_ext_key_usage, &crit, NULL);
	if (!xku)
		return 0;
	sk_ASN1_OBJECT_pop_free(xku, ASN1_OBJECT_free);

	cert->ext_set |= TLS_EXT_EXTENDED_KEY_USAGE;
	if (crit)
		cert->ext_crit |= TLS_EXT_EXTENDED_KEY_USAGE;

	cert->extended_key_usage_flags = map_bits(xku_map, X509_get_extended_key_usage(x509));
	return 0;
}

static int tls_load_extensions(struct tls *ctx, struct tls_cert *cert, X509 *x509)
{
	int ret;

	/*
	 * Force libssl to fill extension fields under X509 struct.
	 * Then libtls does not need to parse raw data.
	 */
	X509_check_ca(x509);

	ret = tls_get_basic_constraints(ctx, cert, x509);
	if (ret == 0)
		ret = tls_get_key_usage(ctx, cert, x509);
	if (ret == 0)
		ret = tls_get_ext_key_usage(ctx, cert, x509);
	if (ret == 0)
		ret = tls_cert_get_altnames(ctx, cert, x509);
	return ret;
}

static void *tls_calc_fingerprint(struct tls *ctx, X509 *x509, const char *algo, size_t *outlen)
{
	const EVP_MD *md;
	void *res;
	int ret;
	unsigned int tmplen, mdlen;

	if (outlen)
		*outlen = 0;

	if (strcasecmp(algo, "sha1") == 0) {
		md = EVP_sha1();
	} else if (strcasecmp(algo, "sha256") == 0) {
		md = EVP_sha256();
	} else {
		tls_set_errorx(ctx, "invalid fingerprint algorithm");
		return NULL;
	}

	mdlen = EVP_MD_size(md);
	res = malloc(mdlen);
	if (!res) {
		tls_set_error(ctx, "malloc");
		return NULL;
	}

	ret = X509_digest(x509, md, res, &tmplen);
	if (ret != 1 || tmplen != mdlen) {
		free(res);
		tls_set_errorx(ctx, "X509_digest failed");
		return NULL;
	}

	if (outlen)
		*outlen = mdlen;

	return res;
}

static void check_verify_error(struct tls *ctx, struct tls_cert *cert)
{
	long vres = SSL_get_verify_result(ctx->ssl_conn);
	if (vres == X509_V_OK) {
		cert->successful_verify = 1;
	} else {
		cert->successful_verify = 0;
	}
}

int tls_parse_cert(struct tls *ctx, struct tls_cert **cert_p, const char *fingerprint_algo, X509 *x509)
{
	struct tls_cert *cert = NULL;
	X509_NAME *subject, *issuer;
	int ret = -1;
	long version;

	*cert_p = NULL;

	version = X509_get_version(x509);
	if (version < 0) {
		tls_set_errorx(ctx, "invalid version");
		return -1;
	}

	subject = X509_get_subject_name(x509);
	if (!subject) {
		tls_set_errorx(ctx, "cert does not have subject");
		return -1;
	}

	issuer = X509_get_issuer_name(x509);
	if (!issuer) {
		tls_set_errorx(ctx, "cert does not have issuer");
		return -1;
	}

	cert = calloc(1, sizeof(*cert));
	if (!cert) {
		tls_set_error(ctx, "calloc");
		goto failed;
	}
	cert->version = version;

	if (fingerprint_algo) {
		cert->fingerprint = tls_calc_fingerprint(ctx, x509, fingerprint_algo, &cert->fingerprint_size);
		if (!cert->fingerprint)
			goto failed;
	}

	ret = tls_get_dname(ctx, subject, &cert->subject);
	if (ret == 0)
		ret = tls_get_dname(ctx, issuer, &cert->issuer);
	if (ret == 0)
		ret = tls_asn1_parse_time(ctx, X509_get_notBefore(x509), &cert->not_before);
	if (ret == 0)
		ret = tls_asn1_parse_time(ctx, X509_get_notAfter(x509), &cert->not_after);
	if (ret == 0)
		ret = tls_parse_bigint(ctx, X509_get_serialNumber(x509), &cert->serial);
	if (ret == 0)
		ret = tls_load_extensions(ctx, cert, x509);
	if (ret == 0) {
		*cert_p = cert;
		return 0;
	}
failed:
	tls_cert_free(cert);
	return ret;
}

int tls_get_peer_cert(struct tls *ctx, struct tls_cert **cert_p, const char *fingerprint_algo)
{
	X509 *peer = ctx->ssl_peer_cert;
	int res;

	*cert_p = NULL;

	if (!peer) {
		tls_set_errorx(ctx, "peer does not have cert");
		return TLS_NO_CERT;
	}

	ERR_clear_error();
	res = tls_parse_cert(ctx, cert_p, fingerprint_algo, peer);
	if (res == 0)
		check_verify_error(ctx, *cert_p);
	ERR_clear_error();
	return res;
}

static void tls_cert_free_dname(struct tls_cert_dname *dname)
{
	free((void *)dname->common_name);
	free((void *)dname->country_name);
	free((void *)dname->state_or_province_name);
	free((void *)dname->locality_name);
	free((void *)dname->street_address);
	free((void *)dname->organization_name);
	free((void *)dname->organizational_unit_name);
}

void tls_cert_free(struct tls_cert *cert)
{
	int i;
	if (!cert)
		return;

	tls_cert_free_dname(&cert->issuer);
	tls_cert_free_dname(&cert->subject);

	if (cert->subject_alt_name_count) {
		for (i = 0; i < cert->subject_alt_name_count; i++)
			free((void *)cert->subject_alt_names[i].name_value);
	}
	free(cert->subject_alt_names);

	free((void *)cert->serial);
	free((void *)cert->fingerprint);
	free(cert);
}

#endif /* USUAL_LIBSSL_FOR_TLS */
