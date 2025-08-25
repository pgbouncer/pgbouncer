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


extern int cf_scram_iterations;

void free_scram_state(ScramState *state);

typedef enum PasswordType {
	PASSWORD_TYPE_PLAINTEXT = 0,
	PASSWORD_TYPE_MD5,
	PASSWORD_TYPE_SCRAM_SHA_256
} PasswordType;

PasswordType get_password_type(const char *shadow_pass);

/*
 * Functions for communicating as a client with the server
 */

char *build_client_first_message(ScramState *state);
char *build_client_final_message(PgSocket *server,
				 const PgCredentials *credentials);

bool read_server_first_message(PgSocket *server, char *input);
bool read_server_final_message(PgSocket *server, char *input, char *ServerSignature);

bool verify_server_signature(PgSocket *server, const PgCredentials *credentials, const char *ServerSignature, bool *match);


/*
 * Functions for communicating as a server to the client
 */

bool read_client_first_message(PgSocket *client, char *input);

bool read_client_final_message(PgSocket *client, const uint8_t *raw_input, char *input,
			       const char **client_final_nonce_p,
			       char **proof_p);

char *build_server_first_message(ScramState *state,
				 PgCredentials *user, const char *stored_secret);

char *build_server_final_message(PgSocket *client);

bool verify_final_nonce(const ScramState *state, const char *client_final_nonce);

bool verify_client_proof(PgSocket *client, const char *ClientProof);

bool scram_verify_plain_password(PgSocket *client,
				 const char *username, const char *password,
				 const char *secret);
