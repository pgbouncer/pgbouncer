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

#include <usual/crypto/sha256.h>

void free_scram_state(ScramState *scram_state);

typedef enum PasswordType {
	PASSWORD_TYPE_PLAINTEXT = 0,
	PASSWORD_TYPE_MD5,
	PASSWORD_TYPE_SCRAM_SHA_256
} PasswordType;

PasswordType get_password_type(const char *shadow_pass);

/*
 * Functions for communicating as a client with the server
 */

char *build_client_first_message(ScramState *scram_state);
char *build_client_final_message(ScramState *scram_state,
				 const PgCredentials *credentials,
				 const char *server_nonce,
				 const char *salt,
				 int saltlen,
				 int iterations);

bool read_server_first_message(PgSocket *server, char *input,
			       char **server_nonce_p, char **salt_p, int *saltlen_p, int *iterations_p);
bool read_server_final_message(PgSocket *server, char *input, char *ServerSignature);

bool verify_server_signature(ScramState *scram_state, const PgCredentials *credentials, const char *ServerSignature);


/*
 * Functions for communicating as a server to the client
 */

bool read_client_first_message(PgSocket *client, char *input,
			       char *cbind_flag_p,
			       char **client_first_message_bare_p,
			       char **client_nonce_p);

bool read_client_final_message(PgSocket *client, const uint8_t *raw_input, char *input,
			       const char **client_final_nonce_p,
			       char **proof_p);

char *build_server_first_message(ScramState *scram_state,
				 PgCredentials *user, const char *stored_secret);

char *build_server_final_message(ScramState *scram_state);

bool verify_final_nonce(const ScramState *scram_state, const char *client_final_nonce);

bool verify_client_proof(ScramState *state, const char *ClientProof);

bool scram_verify_plain_password(PgSocket *client,
				 const char *username, const char *password,
				 const char *secret);
