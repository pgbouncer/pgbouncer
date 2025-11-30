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
 * SCRAM support
 */

#include "bouncer.h"
#include "scram.h"
#include "common/postgres_compat.h"
#include "common/base64.h"
#include "common/saslprep.h"
#include "common/scram-common.h"
#include "common/hmac.h"


static bool calculate_client_proof(PgSocket *server,
				   const PgCredentials *credentials,
				   const char *client_final_message_without_proof,
				   uint8_t *result);


/*
 * free SCRAM state info after auth is done
 */
void free_scram_state(ScramState *state)
{
	free(state->client_nonce);
	free(state->client_first_message_bare);
	free(state->client_final_message_without_proof);
	free(state->server_nonce);
	free(state->server_first_message);
	free(state->SaltedPassword);
	free(state->salt);
	free(state->encoded_salt);
	memset(state, 0, sizeof(*state));
}

static bool is_scram_printable(char *p)
{
	/*------
	 * Printable characters, as defined by SCRAM spec: (RFC 5802)
	 *
	 *  printable       = %x21-2B / %x2D-7E
	 *                    ;; Printable ASCII except ",".
	 *                    ;; Note that any "printable" is also
	 *                    ;; a valid "value".
	 *------
	 */
	for (; *p; p++)
		if (*p < 0x21 || *p > 0x7E || *p == 0x2C /* comma */)
			return false;

	return true;
}

static char *sanitize_char(char c)
{
	static char buf[5];

	if (c >= 0x21 && c <= 0x7E)
		snprintf(buf, sizeof(buf), "'%c'", c);
	else
		snprintf(buf, sizeof(buf), "0x%02x", (unsigned char) c);
	return buf;
}

/*
 * Read value for an attribute part of a SCRAM message.
 */
static char *read_attr_value(PgSocket *sk, char **input, char attr)
{
	char *begin = *input;
	char *end;

	if (*begin != attr) {
		slog_error(sk, "malformed SCRAM message (attribute \"%c\" expected)",
			   attr);
		return NULL;
	}
	begin++;

	if (*begin != '=') {
		slog_error(sk, "malformed SCRAM message (expected \"=\" after attribute \"%c\")",
			   attr);
		return NULL;
	}
	begin++;

	end = begin;
	while (*end && *end != ',')
		end++;

	if (*end) {
		*end = '\0';
		*input = end + 1;
	} else {
		*input = end;
	}

	return begin;
}

/*
 * Read the next attribute and value in a SCRAM exchange message.
 *
 * Returns NULL if there is no attribute.
 */
static char *read_any_attr(PgSocket *sk, char **input, char *attr_p)
{
	char *begin = *input;
	char *end;
	char attr = *begin;

	if (!((attr >= 'A' && attr <= 'Z') ||
	      (attr >= 'a' && attr <= 'z'))) {
		slog_error(sk, "malformed SCRAM message (attribute expected, but found invalid character \"%s\")",
			   sanitize_char(attr));
		return NULL;
	}
	if (attr_p)
		*attr_p = attr;
	begin++;

	if (*begin != '=') {
		slog_error(sk, "malformed SCRAM message (expected character \"=\" after attribute \"%c\")",
			   attr);
		return NULL;
	}
	begin++;

	end = begin;
	while (*end && *end != ',')
		end++;

	if (*end) {
		*end = '\0';
		*input = end + 1;
	} else {
		*input = end;
	}

	return begin;
}

/*
 * Parse and validate format of given SCRAM secret.
 *
 * Returns true if the SCRAM secret has been parsed, and false otherwise.
 */
static bool parse_scram_secret(const char *secret, int *iterations, char **salt,
			       uint8_t *stored_key, uint8_t *server_key)
{
	char *s;
	char *p;
	char *scheme_str;
	char *salt_str;
	char *iterations_str;
	char *storedkey_str;
	char *serverkey_str;
	int decoded_len;
	uint8_t *decoded_salt_buf;
	uint8_t *decoded_stored_buf = NULL;
	uint8_t *decoded_server_buf = NULL;

	/*
	 * The secret is of form:
	 *
	 * SCRAM-SHA-256$<iterations>:<salt>$<storedkey>:<serverkey>
	 */
	s = strdup(secret);
	if (!s)
		goto invalid_secret;
	if ((scheme_str = strtok(s, "$")) == NULL)
		goto invalid_secret;
	if ((iterations_str = strtok(NULL, ":")) == NULL)
		goto invalid_secret;
	if ((salt_str = strtok(NULL, "$")) == NULL)
		goto invalid_secret;
	if ((storedkey_str = strtok(NULL, ":")) == NULL)
		goto invalid_secret;
	if ((serverkey_str = strtok(NULL, "")) == NULL)
		goto invalid_secret;

	/* Parse the fields */
	if (strcmp(scheme_str, "SCRAM-SHA-256") != 0)
		goto invalid_secret;

	errno = 0;
	*iterations = strtol(iterations_str, &p, 10);
	if (*p || errno != 0)
		goto invalid_secret;

	/*
	 * Verify that the salt is in Base64-encoded format, by decoding it,
	 * although we return the encoded version to the caller.
	 */
	decoded_len = pg_b64_dec_len(strlen(salt_str));
	decoded_salt_buf = malloc(decoded_len);
	if (!decoded_salt_buf)
		goto invalid_secret;
	decoded_len = pg_b64_decode(salt_str, strlen(salt_str), decoded_salt_buf, decoded_len);
	free(decoded_salt_buf);
	if (decoded_len < 0)
		goto invalid_secret;
	*salt = strdup(salt_str);
	if (!*salt)
		goto invalid_secret;

	/*
	 * Decode StoredKey and ServerKey.
	 */
	decoded_len = pg_b64_dec_len(strlen(storedkey_str));
	decoded_stored_buf = malloc(decoded_len);
	if (!decoded_stored_buf)
		goto invalid_secret;
	decoded_len = pg_b64_decode(storedkey_str, strlen(storedkey_str), decoded_stored_buf, decoded_len);
	if (decoded_len != SCRAM_SHA_256_KEY_LEN)
		goto invalid_secret;
	memcpy(stored_key, decoded_stored_buf, SCRAM_SHA_256_KEY_LEN);

	decoded_len = pg_b64_dec_len(strlen(serverkey_str));
	decoded_server_buf = malloc(decoded_len);
	if (!decoded_server_buf)
		goto invalid_secret;

	decoded_len = pg_b64_decode(serverkey_str, strlen(serverkey_str),
				    decoded_server_buf, decoded_len);
	if (decoded_len != SCRAM_SHA_256_KEY_LEN)
		goto invalid_secret;
	memcpy(server_key, decoded_server_buf, SCRAM_SHA_256_KEY_LEN);

	free(decoded_stored_buf);
	free(decoded_server_buf);
	free(s);
	return true;

invalid_secret:
	free(decoded_stored_buf);
	free(decoded_server_buf);
	free(s);
	free(*salt);
	*salt = NULL;
	return false;
}

#define MD5_PASSWD_CHARSET "0123456789abcdef"

/*
 * What kind of a password type is 'shadow_pass'?
 */
PasswordType get_password_type(const char *shadow_pass)
{
	char *encoded_salt = NULL;
	int iterations;
	uint8_t stored_key[SCRAM_SHA_256_KEY_LEN];
	uint8_t server_key[SCRAM_SHA_256_KEY_LEN];

	if (strncmp(shadow_pass, "md5", 3) == 0 &&
	    strlen(shadow_pass) == MD5_PASSWD_LEN &&
	    strspn(shadow_pass + 3, MD5_PASSWD_CHARSET) == MD5_PASSWD_LEN - 3)
		return PASSWORD_TYPE_MD5;
	if (parse_scram_secret(shadow_pass, &iterations, &encoded_salt,
			       stored_key, server_key)) {
		free(encoded_salt);
		return PASSWORD_TYPE_SCRAM_SHA_256;
	}
	free(encoded_salt);
	return PASSWORD_TYPE_PLAINTEXT;
}

/*
 * Functions for communicating as a client with the server
 */

char *build_client_first_message(ScramState *state)
{
	uint8_t raw_nonce[SCRAM_RAW_NONCE_LEN + 1];
	int encoded_len;
	size_t len;
	char *result = NULL;

	state->hash_type = PG_SHA256;
	state->key_length = SCRAM_SHA_256_KEY_LEN;

	get_random_bytes(raw_nonce, SCRAM_RAW_NONCE_LEN);

	encoded_len = pg_b64_enc_len(SCRAM_RAW_NONCE_LEN);
	state->client_nonce = malloc(encoded_len + 1);
	if (state->client_nonce == NULL)
		goto failed;
	encoded_len = pg_b64_encode(raw_nonce, SCRAM_RAW_NONCE_LEN, state->client_nonce, encoded_len);
	if (encoded_len < 0)
		goto failed;
	state->client_nonce[encoded_len] = '\0';

	len = 8 + strlen(state->client_nonce) + 1;
	result = malloc(len);
	if (result == NULL)
		goto failed;
	snprintf(result, len, "n,,n=,r=%s", state->client_nonce);

	state->client_first_message_bare = strdup(result + 3);
	if (state->client_first_message_bare == NULL)
		goto failed;

	return result;

failed:
	free(result);
	free(state->client_nonce);
	free(state->client_first_message_bare);
	return NULL;
}

char *build_client_final_message(PgSocket *server,
				 const PgCredentials *credentials)
{
	ScramState *state = &server->scram_state;
	char buf[512];
	size_t len;
	uint8_t client_proof[SCRAM_SHA_256_KEY_LEN];
	int enclen;

	snprintf(buf, sizeof(buf), "c=biws,r=%s", state->server_nonce);

	state->client_final_message_without_proof = strdup(buf);
	if (state->client_final_message_without_proof == NULL)
		goto failed;

	if (!calculate_client_proof(server, credentials, buf,
				    client_proof))
		goto failed;

	len = strlcat(buf, ",p=", sizeof(buf));
	enclen = pg_b64_enc_len(sizeof(client_proof));
	enclen = pg_b64_encode(client_proof,
			       SCRAM_SHA_256_KEY_LEN,
			       buf + len, enclen);
	if (enclen < 0)
		goto failed;
	len += enclen;
	buf[len] = '\0';

	return strdup(buf);
failed:
	return NULL;
}

bool read_server_first_message(PgSocket *server, char *input)
{
	ScramState *state = &server->scram_state;
	char *server_nonce;
	char *encoded_salt;
	int decoded_salt_len;
	char *iterations_str;
	char *endptr;
	int iterations;

	state->server_first_message = strdup(input);
	if (state->server_first_message == NULL)
		return false;

	server_nonce = read_attr_value(server, &input, 'r');
	if (server_nonce == NULL)
		return false;

	if (strlen(server_nonce) < strlen(state->client_nonce) ||
	    memcmp(server_nonce, state->client_nonce, strlen(state->client_nonce)) != 0) {
		slog_error(server, "invalid SCRAM response (nonce mismatch)");
		return false;
	}

	state->server_nonce = strdup(server_nonce);
	if (state->server_nonce == NULL)
		return false;

	encoded_salt = read_attr_value(server, &input, 's');
	if (encoded_salt == NULL)
		return false;

	decoded_salt_len = pg_b64_dec_len(strlen(encoded_salt));
	state->salt = malloc(decoded_salt_len);
	if (state->salt == NULL)
		return false;
	state->saltlen = pg_b64_decode(encoded_salt,
				       strlen(encoded_salt),
				       state->salt, decoded_salt_len);
	if (state->saltlen < 0) {
		slog_error(server, "malformed SCRAM message (invalid salt)");
		return false;
	}

	iterations_str = read_attr_value(server, &input, 'i');
	if (iterations_str == NULL)
		return false;

	iterations = strtol(iterations_str, &endptr, 10);
	if (*endptr != '\0' || iterations < 1) {
		slog_error(server, "malformed SCRAM message (invalid iteration count)");
		return false;
	}
	state->iterations = iterations;

	if (*input != '\0') {
		slog_error(server, "malformed SCRAM message (garbage at end of server-first-message)");
		return false;
	}

	return true;
}

bool read_server_final_message(PgSocket *server, char *input, char *ServerSignature)
{
	char *encoded_server_signature;
	uint8_t *decoded_server_signature = NULL;
	int server_signature_len;

	if (*input == 'e') {
		char *errmsg = read_attr_value(server, &input, 'e');
		slog_error(server, "error received from server in SCRAM exchange: %s",
			   errmsg);
		goto failed;
	}

	encoded_server_signature = read_attr_value(server, &input, 'v');
	if (encoded_server_signature == NULL)
		goto failed;

	if (*input != '\0')
		slog_error(server, "malformed SCRAM message (garbage at end of server-final-message)");

	server_signature_len = pg_b64_dec_len(strlen(encoded_server_signature));
	decoded_server_signature = malloc(server_signature_len);
	if (!decoded_server_signature)
		goto failed;

	server_signature_len = pg_b64_decode(encoded_server_signature,
					     strlen(encoded_server_signature),
					     decoded_server_signature,
					     server_signature_len);
	if (server_signature_len != SCRAM_SHA_256_KEY_LEN) {
		slog_error(server, "malformed SCRAM message (malformed server signature)");
		goto failed;
	}
	memcpy(ServerSignature, decoded_server_signature, SCRAM_SHA_256_KEY_LEN);

	free(decoded_server_signature);
	return true;
failed:
	free(decoded_server_signature);
	return false;
}

static bool calculate_client_proof(PgSocket *server,
				   const PgCredentials *credentials,
				   const char *client_final_message_without_proof,
				   uint8_t *result)
{
	ScramState *state = &server->scram_state;
	pg_saslprep_rc rc;
	char *prep_password = NULL;
	uint8 StoredKey[SCRAM_MAX_KEY_LEN];
	uint8 ClientKey[SCRAM_MAX_KEY_LEN];
	uint8 ClientSignature[SCRAM_MAX_KEY_LEN];
	int i;
	pg_hmac_ctx *ctx;
	const char *errstr = NULL;

	ctx = pg_hmac_create(state->hash_type);
	if (ctx == NULL) {
		slog_error(server, "HMAC context creation failed: %s", pg_hmac_error(NULL));
		goto failed;
	}

	if (credentials->use_scram_keys) {
		memcpy(ClientKey, credentials->scram_ClientKey, SCRAM_SHA_256_KEY_LEN);
	} else
	{
		rc = pg_saslprep(credentials->passwd, &prep_password);
		if (rc == SASLPREP_OOM)
			goto failed;
		if (rc != SASLPREP_SUCCESS) {
			prep_password = strdup(credentials->passwd);
			if (!prep_password)
				goto failed;
		}
		state->SaltedPassword = malloc(SCRAM_SHA_256_KEY_LEN);
		if (state->SaltedPassword == NULL)
			goto failed;
		/*
		 * Calculate SaltedPassword, and store it in 'state' so that we can
		 * reuse it later in verify_server_signature.
		 */
		if (scram_SaltedPassword(prep_password, state->hash_type,
					 state->key_length, state->salt, state->saltlen,
					 state->iterations, state->SaltedPassword,
					 &errstr) < 0 ||
		    scram_ClientKey(state->SaltedPassword, state->hash_type,
				    state->key_length, ClientKey, &errstr) < 0) {
			slog_error(server, "SCRAM key derivation failed: %s", errstr);
			goto failed;
		}
	}

	if (scram_H(ClientKey, state->hash_type, state->key_length, StoredKey, &errstr) < 0) {
		slog_error(server, "SCRAM hash computation failed: %s", errstr);
		goto failed;
	}

	if (pg_hmac_init(ctx, StoredKey, state->key_length) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *) state->client_first_message_bare,
			   strlen(state->client_first_message_bare)) < 0 ||
	    pg_hmac_update(ctx, (uint8 *) ",", 1) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *) state->server_first_message,
			   strlen(state->server_first_message)) < 0 ||
	    pg_hmac_update(ctx, (uint8 *) ",", 1) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *) client_final_message_without_proof,
			   strlen(client_final_message_without_proof)) < 0 ||
	    pg_hmac_final(ctx, ClientSignature, state->key_length) < 0) {
		slog_error(server, "HMAC computation failed: %s", pg_hmac_error(ctx));
		goto failed;
	}

	for (i = 0; i < state->key_length; i++)
		result[i] = ClientKey[i] ^ ClientSignature[i];

	free(prep_password);
	pg_hmac_free(ctx);
	return true;
failed:
	free(prep_password);
	pg_hmac_free(ctx);
	return false;
}

bool verify_server_signature(PgSocket *server, const PgCredentials *credentials, const char *ServerSignature, bool *match)
{
	ScramState *state = &server->scram_state;
	uint8 expected_ServerSignature[SCRAM_MAX_KEY_LEN];
	uint8 ServerKey[SCRAM_MAX_KEY_LEN];
	pg_hmac_ctx *ctx;
	const char *errstr = NULL;


	ctx = pg_hmac_create(state->hash_type);
	if (ctx == NULL) {
		slog_error(server, "HMAC context creation failed: %s", pg_hmac_error(NULL));
		return false;
	}

	if (credentials->use_scram_keys) {
		memcpy(ServerKey, credentials->scram_ServerKey, SCRAM_SHA_256_KEY_LEN);
	} else
	{
		if (scram_ServerKey(state->SaltedPassword, state->hash_type,
				    state->key_length, ServerKey, &errstr) < 0) {
			slog_error(server, "SCRAM server key derivation failed: %s", errstr);
			pg_hmac_free(ctx);
			return false;
		}
	}

	/* calculate ServerSignature */
	if (pg_hmac_init(ctx, ServerKey, state->key_length) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *) state->client_first_message_bare,
			   strlen(state->client_first_message_bare)) < 0 ||
	    pg_hmac_update(ctx, (uint8 *) ",", 1) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *) state->server_first_message,
			   strlen(state->server_first_message)) < 0 ||
	    pg_hmac_update(ctx, (uint8 *) ",", 1) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *) state->client_final_message_without_proof,
			   strlen(state->client_final_message_without_proof)) < 0 ||
	    pg_hmac_final(ctx, expected_ServerSignature,
			  state->key_length) < 0) {
		slog_error(server, "HMAC server signature computation failed: %s", pg_hmac_error(ctx));
		pg_hmac_free(ctx);
		return false;
	}

	pg_hmac_free(ctx);

	/* signature processed, so now check after it */
	if (memcmp(expected_ServerSignature, ServerSignature,
		   state->key_length) != 0)
		*match = false;
	else
		*match = true;

	return true;
}


/*
 * Functions for communicating as a server to the client
 */

bool read_client_first_message(PgSocket *client, char *input)
{
	ScramState *state = &client->scram_state;
	char *client_first_message_bare = NULL;
	char *client_nonce = NULL;
	char *client_nonce_copy = NULL;

	state->cbind_flag = *input;
	switch (*input) {
	case 'n':
		/* Client does not support channel binding */
		input++;
		break;
	case 'y':
		/* Client supports channel binding, but we're not doing it today */
		input++;
		break;
	case 'p':
		/* Client requires channel binding.  We don't support it. */
		slog_error(client, "client requires SCRAM channel binding, but it is not supported");
		goto failed;
	default:
		slog_error(client, "malformed SCRAM message (unexpected channel-binding flag \"%s\")",
			   sanitize_char(*input));
		goto failed;
	}

	if (*input != ',') {
		slog_error(client, "malformed SCRAM message (comma expected, but found character \"%s\")",
			   sanitize_char(*input));
		goto failed;
	}
	input++;

	if (*input == 'a') {
		slog_error(client, "client uses authorization identity, but it is not supported");
		goto failed;
	}
	if (*input != ',') {
		slog_error(client, "malformed SCRAM message (unexpected attribute \"%s\" in client-first-message)",
			   sanitize_char(*input));
		goto failed;
	}
	input++;

	client_first_message_bare = strdup(input);
	if (client_first_message_bare == NULL)
		goto failed;

	if (*input == 'm') {
		slog_error(client, "client requires an unsupported SCRAM extension");
		goto failed;
	}

	/* read and ignore user name */
	read_attr_value(client, &input, 'n');

	client_nonce = read_attr_value(client, &input, 'r');
	if (client_nonce == NULL)
		goto failed;
	if (!is_scram_printable(client_nonce)) {
		slog_error(client, "non-printable characters in SCRAM nonce");
		goto failed;
	}
	client_nonce_copy = strdup(client_nonce);
	if (client_nonce_copy == NULL)
		goto failed;

	/*
	 * There can be any number of optional extensions after this.  We don't
	 * support any extensions, so ignore them.
	 */
	while (*input != '\0') {
		if (!read_any_attr(client, &input, NULL))
			goto failed;
	}

	state->client_first_message_bare = client_first_message_bare;
	state->client_nonce = client_nonce_copy;
	return true;
failed:
	free(client_first_message_bare);
	free(client_nonce_copy);
	return false;
}

bool read_client_final_message(PgSocket *client, const uint8_t *raw_input, char *input,
			       const char **client_final_nonce_p,
			       char **proof_p)
{
	ScramState *state = &client->scram_state;
	const char *input_start = input;
	char attr;
	char *channel_binding;
	char *client_final_nonce;
	char *proof_start;
	char *value;
	char *encoded_proof;
	uint8_t *proof = NULL;
	int prooflen;

	/*
	 * Read channel-binding.  We don't support channel binding, so
	 * it's expected to always be "biws", which is "n,,",
	 * base64-encoded, or "eSws", which is "y,,".  We also have to
	 * check whether the flag is the same one that the client
	 * originally sent.
	 */
	channel_binding = read_attr_value(client, &input, 'c');
	if (channel_binding == NULL)
		goto failed;
	if (!(strcmp(channel_binding, "biws") == 0 && state->cbind_flag == 'n') &&
	    !(strcmp(channel_binding, "eSws") == 0 && state->cbind_flag == 'y')) {
		slog_error(client, "unexpected SCRAM channel-binding attribute in client-final-message");
		goto failed;
	}

	client_final_nonce = read_attr_value(client, &input, 'r');

	/* ignore optional extensions */
	do {
		proof_start = input - 1;
		value = read_any_attr(client, &input, &attr);
	} while (value && attr != 'p');

	if (!value) {
		slog_error(client, "could not read proof");
		goto failed;
	}

	encoded_proof = value;

	prooflen = pg_b64_dec_len(strlen(encoded_proof));
	proof = malloc(prooflen);
	if (proof == NULL) {
		slog_error(client, "could not decode proof");
		goto failed;
	}
	prooflen = pg_b64_decode(encoded_proof,
				 strlen(encoded_proof),
				 proof, prooflen);
	if (prooflen != SCRAM_SHA_256_KEY_LEN) {
		slog_error(client, "malformed SCRAM message (malformed proof in client-final-message)");
		goto failed;
	}

	if (*input != '\0') {
		slog_error(client, "malformed SCRAM message (garbage at the end of client-final-message)");
		goto failed;
	}

	state->client_final_message_without_proof = malloc(proof_start - input_start + 1);
	if (!state->client_final_message_without_proof)
		goto failed;
	memcpy(state->client_final_message_without_proof, raw_input, proof_start - input_start);
	state->client_final_message_without_proof[proof_start - input_start] = '\0';

	*client_final_nonce_p = client_final_nonce;
	*proof_p = (char *)proof;
	return true;
failed:
	free(proof);
	return false;
}

/*
 * For doing SCRAM with a password stored in plain text, build a SCRAM
 * secret on the fly.
 */
static bool build_adhoc_scram_secret(const char *plain_password, ScramState *state)
{
	const char *password;
	char *prep_password;
	pg_saslprep_rc rc;
	uint8_t saltbuf[SCRAM_DEFAULT_SALT_LEN];
	int encoded_len;
	uint8_t salted_password[SCRAM_SHA_256_KEY_LEN];
	const char *errstr = NULL;

	rc = pg_saslprep(plain_password, &prep_password);
	if (rc == SASLPREP_OOM)
		goto failed;
	else if (rc == SASLPREP_SUCCESS)
		password = prep_password;
	else
		password = plain_password;

	get_random_bytes(saltbuf, sizeof(saltbuf));

	state->adhoc = true;

	state->iterations = cf_scram_iterations;

	encoded_len = pg_b64_enc_len(sizeof(saltbuf));
	state->encoded_salt = malloc(encoded_len + 1);
	if (!state->encoded_salt)
		goto failed;
	encoded_len = pg_b64_encode(saltbuf, sizeof(saltbuf), state->encoded_salt, encoded_len);
	if (encoded_len < 0)
		goto failed;
	state->encoded_salt[encoded_len] = '\0';

	/* Calculate StoredKey and ServerKey */
	scram_SaltedPassword(password, state->hash_type, state->key_length, saltbuf, sizeof(saltbuf),
			     state->iterations,
			     salted_password, &errstr);
	scram_ClientKey(salted_password, state->hash_type, state->key_length, state->StoredKey, &errstr);
	scram_H(state->StoredKey, state->hash_type, state->key_length, state->StoredKey, &errstr);
	scram_ServerKey(salted_password, state->hash_type, state->key_length, state->ServerKey, &errstr);

	free(prep_password);
	return true;
failed:
	free(prep_password);
	return false;
}

/*
 * Deterministically generate salt for mock authentication, using a
 * SHA256 hash based on the username and an instance-level secret key.
 * Target buffer needs to be of size SCRAM_DEFAULT_SALT_LEN.
 */
static bool scram_mock_salt(const char *username, uint8_t *saltbuf)
{
	static uint8_t mock_auth_nonce[32];
	static bool mock_auth_nonce_initialized = false;
	pg_cryptohash_ctx *ctx;
	uint8_t sha_digest[PG_SHA256_DIGEST_LENGTH];

	/*
	 * Generating salt using a SHA256 hash works as long as the
	 * required salt length is not larger than the SHA256 digest
	 * length.
	 */
	static_assert(PG_SHA256_DIGEST_LENGTH >= SCRAM_DEFAULT_SALT_LEN,
		      "salt length greater than SHA256 digest length");

	if (!mock_auth_nonce_initialized) {
		get_random_bytes(mock_auth_nonce, sizeof(mock_auth_nonce));
		mock_auth_nonce_initialized = true;
	}

	ctx = pg_cryptohash_create(PG_SHA256);
	if (!ctx) {
		log_error("could not create cryptohash context");
		return false;
	}

	if (pg_cryptohash_init(ctx) < 0 ||
	    pg_cryptohash_update(ctx, (uint8_t *) username, strlen(username)) < 0 ||
	    pg_cryptohash_update(ctx, mock_auth_nonce, sizeof(mock_auth_nonce)) < 0 ||
	    pg_cryptohash_final(ctx, sha_digest, sizeof(sha_digest)) < 0) {
		log_error("could not generate mock salt: %s", pg_cryptohash_error(ctx));
		pg_cryptohash_free(ctx);
		return false;
	}

	pg_cryptohash_free(ctx);
	memcpy(saltbuf, sha_digest, SCRAM_DEFAULT_SALT_LEN);
	return true;
}

static bool build_mock_scram_secret(const char *username, ScramState *state)
{
	uint8_t saltbuf[SCRAM_DEFAULT_SALT_LEN];
	int encoded_len;

	state->iterations = cf_scram_iterations;

	if (!scram_mock_salt(username, saltbuf))
		goto failed;
	encoded_len = pg_b64_enc_len(sizeof(saltbuf));
	state->encoded_salt = malloc(encoded_len + 1);
	if (!state->encoded_salt)
		goto failed;
	encoded_len = pg_b64_encode(saltbuf, sizeof(saltbuf), state->encoded_salt, encoded_len);
	if (encoded_len < 0)
		goto failed;
	state->encoded_salt[encoded_len] = '\0';

	return true;
failed:
	return false;
}

char *build_server_first_message(ScramState *state, PgCredentials *user, const char *stored_secret)
{
	uint8_t raw_nonce[SCRAM_RAW_NONCE_LEN + 1];
	int encoded_len;
	size_t len;
	char *result;

	state->hash_type = PG_SHA256;
	state->key_length = SCRAM_SHA_256_KEY_LEN;

	if (!stored_secret) {
		if (!build_mock_scram_secret(user->name, state))
			goto failed;
	} else {
		if (user->adhoc_scram_secrets_cached) {
			state->iterations = user->scram_Iiterations;
			state->encoded_salt = strdup(user->scram_SaltKey);
			memcpy(state->StoredKey, user->scram_StoredKey, sizeof(user->scram_StoredKey));
			memcpy(state->ServerKey, user->scram_ServerKey, sizeof(user->scram_ServerKey));
		} else {
			switch (get_password_type(stored_secret)) {
			case PASSWORD_TYPE_SCRAM_SHA_256:
				if (!parse_scram_secret(stored_secret,
							&state->iterations,
							&state->encoded_salt,
							state->StoredKey,
							state->ServerKey))
					goto failed;
				break;
			case PASSWORD_TYPE_PLAINTEXT:
				if (!build_adhoc_scram_secret(stored_secret, state))
					goto failed;
				break;
			default:
				/* shouldn't get here */
				goto failed;
			}

			if (!user->dynamic_passwd) {
				user->scram_Iiterations = state->iterations;
				user->scram_SaltKey = strdup(state->encoded_salt);
				memcpy(user->scram_StoredKey, state->StoredKey, sizeof(state->StoredKey));
				memcpy(user->scram_ServerKey, state->ServerKey, sizeof(state->ServerKey));
				user->adhoc_scram_secrets_cached = true;
			}
		}
	}

	get_random_bytes(raw_nonce, SCRAM_RAW_NONCE_LEN);
	encoded_len = pg_b64_enc_len(SCRAM_RAW_NONCE_LEN);
	state->server_nonce = malloc(encoded_len + 1);
	if (state->server_nonce == NULL)
		goto failed;
	encoded_len = pg_b64_encode(raw_nonce, SCRAM_RAW_NONCE_LEN, state->server_nonce, encoded_len);
	if (encoded_len < 0)
		goto failed;
	state->server_nonce[encoded_len] = '\0';

	len = (2
	       + strlen(state->client_nonce)
	       + strlen(state->server_nonce)
	       + 3
	       + strlen(state->encoded_salt)
	       + 3 + 10 + 1);
	result = malloc(len);
	if (!result)
		goto failed;
	snprintf(result, len,
		 "r=%s%s,s=%s,i=%u",
		 state->client_nonce,
		 state->server_nonce,
		 state->encoded_salt,
		 state->iterations);

	state->server_first_message = result;

	return result;
failed:
	free(state->server_nonce);
	free(state->server_first_message);
	return NULL;
}

static char *compute_server_signature(PgSocket *client, ScramState *state)
{
	uint8_t ServerSignature[SCRAM_SHA_256_KEY_LEN];
	char *server_signature_base64;
	int siglen;
	pg_hmac_ctx *ctx;

	ctx = pg_hmac_create(state->hash_type);
	if (ctx == NULL) {
		slog_error(client, "HMAC context creation failed: %s", pg_hmac_error(NULL));
		return NULL;
	}

	/* calculate ServerSignature */
	if (pg_hmac_init(ctx, state->ServerKey, state->key_length) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *)state->client_first_message_bare,
			   strlen(state->client_first_message_bare)) < 0 ||
	    pg_hmac_update(ctx, (uint8 *)",", 1) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *)state->server_first_message,
			   strlen(state->server_first_message)) < 0 ||
	    pg_hmac_update(ctx, (uint8 *)",", 1) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *)state->client_final_message_without_proof,
			   strlen(state->client_final_message_without_proof)) < 0 ||
	    pg_hmac_final(ctx, ServerSignature, state->key_length) < 0) {
		slog_error(client, "HMAC operation failed: %s", pg_hmac_error(ctx));
		pg_hmac_free(ctx);
		return NULL;
	}

	siglen = pg_b64_enc_len(SCRAM_SHA_256_KEY_LEN);
	server_signature_base64 = malloc(siglen + 1);
	if (!server_signature_base64) {
		pg_hmac_free(ctx);
		return NULL;
	}
	siglen = pg_b64_encode(ServerSignature,
			       SCRAM_SHA_256_KEY_LEN, server_signature_base64, siglen);
	if (siglen < 0) {
		free(server_signature_base64);
		pg_hmac_free(ctx);
		return NULL;
	}
	server_signature_base64[siglen] = '\0';

	pg_hmac_free(ctx);
	return server_signature_base64;
}

char *build_server_final_message(PgSocket *client)
{
	ScramState *state = &client->scram_state;
	char *server_signature = NULL;
	size_t len;
	char *result;

	server_signature = compute_server_signature(client, state);
	if (!server_signature)
		goto failed;

	len = 2 + strlen(server_signature) + 1;

	/*
	 * Avoid compiler warning at snprintf() below because len
	 * could in theory overflow snprintf() result.  If this
	 * happened in practice, it would surely be some crazy
	 * corruption, so treat it as an error.
	 */
	if (len >= INT_MAX)
		goto failed;

	result = malloc(len);
	if (!result)
		goto failed;
	snprintf(result, len, "v=%s", server_signature);

	free(server_signature);
	return result;
failed:
	free(server_signature);
	return NULL;
}

bool verify_final_nonce(const ScramState *state, const char *client_final_nonce)
{
	size_t client_nonce_len = strlen(state->client_nonce);
	size_t server_nonce_len = strlen(state->server_nonce);
	size_t final_nonce_len = strlen(client_final_nonce);

	if (final_nonce_len != client_nonce_len + server_nonce_len)
		return false;
	if (memcmp(client_final_nonce, state->client_nonce, client_nonce_len) != 0)
		return false;
	if (memcmp(client_final_nonce + client_nonce_len, state->server_nonce, server_nonce_len) != 0)
		return false;

	return true;
}

bool verify_client_proof(PgSocket *client, const char *ClientProof)
{
	ScramState *state = &client->scram_state;
	uint8_t ClientSignature[SCRAM_SHA_256_KEY_LEN];
	uint8_t client_StoredKey[SCRAM_SHA_256_KEY_LEN];
	pg_hmac_ctx *ctx;
	int i;
	const char *errstr = NULL;

	ctx = pg_hmac_create(state->hash_type);
	if (ctx == NULL) {
		slog_error(client, "HMAC context creation failed: %s", pg_hmac_error(NULL));
		return false;
	}

	/* calculate ClientSignature */
	if (pg_hmac_init(ctx, state->StoredKey, state->key_length) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *)state->client_first_message_bare,
			   strlen(state->client_first_message_bare)) < 0 ||
	    pg_hmac_update(ctx, (uint8 *)",", 1) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *)state->server_first_message,
			   strlen(state->server_first_message)) < 0 ||
	    pg_hmac_update(ctx, (uint8 *)",", 1) < 0 ||
	    pg_hmac_update(ctx,
			   (uint8 *)state->client_final_message_without_proof,
			   strlen(state->client_final_message_without_proof)) < 0 ||
	    pg_hmac_final(ctx, ClientSignature, state->key_length) < 0) {
		slog_error(client, "HMAC operation failed: %s", pg_hmac_error(ctx));
		pg_hmac_free(ctx);
		return false;
	}

	/* Extract the ClientKey that the client calculated from the proof */
	for (i = 0; i < state->key_length; i++)
		state->ClientKey[i] = ClientProof[i] ^ ClientSignature[i];

	/* Hash it one more time, and compare with StoredKey */
	if (scram_H(state->ClientKey, state->hash_type, state->key_length, client_StoredKey, &errstr) < 0) {
		pg_hmac_free(ctx);
		return false;
	}

	if (memcmp(client_StoredKey, state->StoredKey, state->key_length) != 0) {
		pg_hmac_free(ctx);
		return false;
	}

	pg_hmac_free(ctx);
	return true;
}

/*
 * Verify a plaintext password against a SCRAM secret.  This is used when
 * performing plaintext password authentication for a user that has a SCRAM
 * secret stored in pg_authid.
 */
bool scram_verify_plain_password(PgSocket *client,
				 const char *username, const char *password,
				 const char *secret)
{
	char *encoded_salt = NULL;
	uint8_t *salt = NULL;
	int saltlen;
	int iterations;
	uint8_t salted_password[SCRAM_SHA_256_KEY_LEN];
	uint8_t stored_key[SCRAM_SHA_256_KEY_LEN];
	uint8_t server_key[SCRAM_SHA_256_KEY_LEN];
	uint8_t computed_key[SCRAM_SHA_256_KEY_LEN];
	char *prep_password = NULL;
	pg_saslprep_rc rc;
	bool result = false;
	const char *errstr = NULL;

	if (!parse_scram_secret(secret, &iterations, &encoded_salt,
				stored_key, server_key)) {
		/* The password looked like a SCRAM secret, but could not be parsed. */
		slog_warning(client, "invalid SCRAM secret for user \"%s\"", username);
		goto failed;
	}

	saltlen = pg_b64_dec_len(strlen(encoded_salt));
	salt = malloc(saltlen);
	if (!salt)
		goto failed;
	saltlen = pg_b64_decode(encoded_salt, strlen(encoded_salt), salt, saltlen);
	if (saltlen < 0) {
		slog_warning(client, "invalid SCRAM secret for user \"%s\"", username);
		goto failed;
	}

	/* Normalize the password */
	rc = pg_saslprep(password, &prep_password);
	if (rc == SASLPREP_SUCCESS)
		password = prep_password;

	/* Compute Server Key based on the user-supplied plaintext password */
	scram_SaltedPassword(password, PG_SHA256, SCRAM_SHA_256_KEY_LEN, salt, saltlen, iterations, salted_password, &errstr);
	scram_ServerKey(salted_password, PG_SHA256, SCRAM_SHA_256_KEY_LEN, computed_key, &errstr);

	/*
	 * Compare the secret's Server Key with the one computed from the
	 * user-supplied password.
	 */
	result = memcmp(computed_key, server_key, SCRAM_SHA_256_KEY_LEN) == 0;

failed:
	free(encoded_salt);
	free(salt);
	free(prep_password);
	return result;
}
