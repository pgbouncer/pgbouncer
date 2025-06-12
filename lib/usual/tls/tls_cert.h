#ifndef _USUAL_TLS_TLS_CERT_H_
#define _USUAL_TLS_TLS_CERT_H_

#define TLS_CERT_GNAME_DNS	1
#define TLS_CERT_GNAME_IPv4	2
#define TLS_CERT_GNAME_IPv6	3
#define TLS_CERT_GNAME_EMAIL	4
#define TLS_CERT_GNAME_URI	5

#define TLS_KU_DIGITAL_SIGNATURE	(1 << 0)
#define TLS_KU_NON_REPUDIATION		(1 << 1)
#define TLS_KU_KEY_ENCIPHERMENT		(1 << 2)
#define TLS_KU_DATA_ENCIPHERMENT	(1 << 3)
#define TLS_KU_KEY_AGREEMENT		(1 << 4)
#define TLS_KU_KEY_CERT_SIGN		(1 << 5)
#define TLS_KU_CRL_SIGN			(1 << 6)
#define TLS_KU_ENCIPHER_ONLY		(1 << 7)
#define TLS_KU_DECIPHER_ONLY		(1 << 8)

#define TLS_XKU_SSL_SERVER		(1 << 0)
#define TLS_XKU_SSL_CLIENT		(1 << 1)
#define TLS_XKU_SMIME			(1 << 2)
#define TLS_XKU_CODE_SIGN		(1 << 3)
#define TLS_XKU_OCSP_SIGN		(1 << 4)
#define TLS_XKU_SGC			(1 << 5)
#define TLS_XKU_TIMESTAMP		(1 << 6)
#define TLS_XKU_DVCS			(1 << 7)

#define TLS_EXT_BASIC			(1 << 0)
#define TLS_EXT_KEY_USAGE		(1 << 1)
#define TLS_EXT_EXTENDED_KEY_USAGE	(1 << 2)
#define TLS_EXT_SUBJECT_ALT_NAME	(1 << 3)

/*
 * GeneralName
 */
struct tls_cert_general_name {
	const void *name_value;
	int name_type;
};

/*
 * DistinguishedName
 */
struct tls_cert_dname {
	const char *common_name;
	const char *country_name;
	const char *state_or_province_name;
	const char *locality_name;
	const char *street_address;
	const char *organization_name;
	const char *organizational_unit_name;
};

struct tls_cert {
	/* Version number from cert: 0:v1, 1:v2, 2:v3 */
	int version;

	/* did it pass verify?  useful when noverifycert is on. */
	int successful_verify;

	/* DistringuishedName for subject */
	struct tls_cert_dname subject;

	/* DistringuishedName for issuer */
	struct tls_cert_dname issuer;

	/* decimal number */
	const char *serial;

	/* Validity times */
	time_t not_before;
	time_t not_after;

	uint32_t ext_set;
	uint32_t ext_crit;

	/* BasicConstraints extension */
	int basic_constraints_ca;
	int basic_constraints_pathlen;

	/* KeyUsage extension */
	uint32_t key_usage_flags;

	/* ExtendedKeyUsage extension */
	uint32_t extended_key_usage_flags;

	/* SubjectAltName extension */
	struct tls_cert_general_name *subject_alt_names;
	int subject_alt_name_count;

	/* Fingerprint as raw hash */
	const unsigned char *fingerprint;
	size_t fingerprint_size;
};

int tls_get_peer_cert(struct tls *ctx, struct tls_cert **cert_p, const char *fingerprint_algo);
void tls_cert_free(struct tls_cert *cert);

#ifdef TLS_CERT_INTERNAL_FUNCS
int tls_parse_cert(struct tls *ctx, struct tls_cert **cert_p,
		   const char *fingerprint_algo, X509 *x509);
#endif

#endif
