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
 * GSSAPI (Kerberos) authentication support.
 *
 * Architecture overview
 * ---------------------
 *
 * Client-side (pgbouncer as GSSAPI acceptor):
 *   A connecting PostgreSQL client presents a Kerberos ticket.  pgbouncer
 *   acts as the GSSAPI acceptor: it acquires server credentials from its
 *   keytab, drives gss_accept_sec_context() to completion, then maps the
 *   authenticated principal to a local username via gss_localname().  The
 *   mapped name must exactly match the username the client supplied in the
 *   startup packet.
 *
 * Server-side (pgbouncer as GSSAPI initiator):
 *   When a PostgreSQL backend requests GSSAPI authentication pgbouncer
 *   calls gss_init_sec_context() targeting the backend's "postgres@<host>"
 *   host-based service name.  The pool service account authenticates as
 *   itself.  No client credentials are forwarded; GSS_C_DELEG_FLAG is
 *   never requested.
 *
 * Username mapping
 * ----------------
 * We use gss_localname(), which delegates to the auth_to_local rules in
 * krb5.conf.  This is the correct, site-policy-respecting approach.  We
 * deliberately do not implement ad-hoc realm stripping.
 *
 * Credential store
 * ----------------
 * Acceptor: gss_acquire_cred_from() with an explicit credential store
 * pointing to auth_gssapi_keytab.  MIT Kerberos reads keys directly from
 * disk to validate client service tickets.
 *
 * Initiator: by default, gss_acquire_cred_from() is called with a NULL
 * credential store, so MIT Kerberos uses the process's existing credential
 * cache (KCM, FILE:, or whatever default_ccache_name specifies).  This is
 * the standard behaviour for any Kerberos client with a live TGT.  If
 * auth_gssapi_client_keytab is set, that keytab is used instead as an
 * override for environments without automatic credential management.
 */

#include "bouncer.h"
#include "gssapi_auth.h"

#ifdef HAVE_GSSAPI

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

/*
 * Initialise the GSSAPI subsystem.  Called once at startup.
 */
void gssapi_auth_init(void)
{
}

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

/*
 * Log both the GSS-layer and mechanism-layer messages for a GSSAPI error.
 * 'op' is a short string identifying the failing operation for log context.
 */
static void log_gss_error(PgSocket *sk, OM_uint32 major, OM_uint32 minor, const char *op)
{
	OM_uint32 msg_major, msg_minor;
	gss_buffer_desc status;
	OM_uint32 msg_ctx;

	msg_ctx = 0;
	do {
		msg_major = gss_display_status(&msg_minor, major, GSS_C_GSS_CODE,
					       GSS_C_NO_OID, &msg_ctx, &status);
		if (!GSS_ERROR(msg_major) && status.length > 0) {
			slog_error(sk, "GSSAPI %s: %.*s",
				   op, (int)status.length, (char *)status.value);
			gss_release_buffer(&msg_minor, &status);
		}
	} while (!GSS_ERROR(msg_major) && msg_ctx != 0);

	msg_ctx = 0;
	do {
		msg_major = gss_display_status(&msg_minor, minor, GSS_C_MECH_CODE,
					       GSS_C_NO_OID, &msg_ctx, &status);
		if (!GSS_ERROR(msg_major) && status.length > 0) {
			slog_error(sk, "GSSAPI %s (mechanism): %.*s",
				   op, (int)status.length, (char *)status.value);
			gss_release_buffer(&msg_minor, &status);
		}
	} while (!GSS_ERROR(msg_major) && msg_ctx != 0);
}

/*
 * Build and send an AuthenticationRequest message to the client containing
 * a GSSAPI token.  req_type is AUTH_REQ_GSS (7) or AUTH_REQ_GSS_CONT (8).
 * token/token_len may be NULL/0 for the initial AUTH_REQ_GSS message.
 */
static bool send_auth_token_to_client(PgSocket *client, int req_type,
				      const void *token, size_t token_len)
{
	PktBuf *pkt;
	bool res;

	pkt = pktbuf_dynamic((int)(token_len + 16));
	if (!pkt) {
		slog_error(client, "GSSAPI: out of memory for authentication packet");
		return false;
	}
	pktbuf_start_packet(pkt, PqMsg_AuthenticationRequest);
	pktbuf_put_uint32(pkt, (uint32_t)req_type);
	if (token && token_len > 0)
		pktbuf_put_bytes(pkt, token, (int)token_len);
	pktbuf_finish_packet(pkt);
	res = pktbuf_send_immediate(pkt, client);
	pktbuf_free(pkt);
	return res;
}

/*
 * Send a raw binary GSSAPI token to the backend as a GSSResponse ('p').
 * The entire message body is the token; there is no SASL framing.
 */
static bool send_gss_response_to_server(PgSocket *server, const void *token, size_t token_len)
{
	PktBuf *pkt;
	bool res;

	pkt = pktbuf_dynamic((int)(token_len + 8));
	if (!pkt) {
		slog_error(server, "GSSAPI: out of memory for GSSResponse packet");
		return false;
	}
	pktbuf_start_packet(pkt, PqMsg_PasswordMessage);
	pktbuf_put_bytes(pkt, token, (int)token_len);
	pktbuf_finish_packet(pkt);
	res = pktbuf_send_immediate(pkt, server);
	pktbuf_free(pkt);
	return res;
}

/* --------------------------------------------------------------------------
 * Client-side (acceptor): verifying a client's Kerberos ticket
 * -------------------------------------------------------------------------- */

/*
 * Release all client-side GSSAPI state.  Safe to call multiple times.
 */
void gssapi_accept_cleanup(PgSocket *client)
{
	OM_uint32 minor;

	if (client->gss_state.context != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor, &client->gss_state.context,
				       GSS_C_NO_BUFFER);
		client->gss_state.context = GSS_C_NO_CONTEXT;
	}
	if (client->gss_state.creds != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&minor, &client->gss_state.creds);
		client->gss_state.creds = GSS_C_NO_CREDENTIAL;
	}
}

/*
 * Map an authenticated GSSAPI principal to a local username and verify it
 * matches what the client claimed in the startup packet.
 *
 * Uses gss_localname(), which applies auth_to_local rules from krb5.conf.
 * This is the authoritative mapping function; no ad-hoc realm stripping.
 *
 * Logs the authenticated principal regardless of match outcome for auditing.
 */
static bool gssapi_map_and_verify_username(PgSocket *client, gss_name_t client_name,
					   gss_OID mech_type)
{
	OM_uint32 major, minor;
	gss_buffer_desc display = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc localname = GSS_C_EMPTY_BUFFER;
	const char *claimed = client->login_user_credentials->name;
	bool matched = false;

	major = gss_display_name(&minor, client_name, &display, NULL);
	if (!GSS_ERROR(major)) {
		if (cf_log_connections) {
			slog_info(client, "GSSAPI: authenticated principal: %.*s",
				  (int)display.length, (char *)display.value);
		}
		gss_release_buffer(&minor, &display);
	}

	major = gss_localname(&minor, client_name, mech_type, &localname);
	if (GSS_ERROR(major)) {
		log_gss_error(client, major, minor, "gss_localname");
		slog_error(client, "GSSAPI: principal mapping failed for "
			   "claimed user \"%s\"", claimed);
		return false;
	}

	/*
	 * Exact match required.  Case folding and other transformations are
	 * the responsibility of auth_to_local rules in krb5.conf, not of this
	 * code.
	 */
	matched = (localname.length == strlen(claimed) &&
		   memcmp(localname.value, claimed, localname.length) == 0);

	if (!matched) {
		slog_error(client, "GSSAPI: local name \"%.*s\" does not match "
			   "claimed username \"%s\"",
			   (int)localname.length, (char *)localname.value,
			   claimed);
	} else {
		slog_debug(client, "GSSAPI: principal mapped to local user \"%s\"",
			   claimed);
	}

	gss_release_buffer(&minor, &localname);
	return matched;
}

/*
 * Initiate GSSAPI authentication with a connecting client.
 *
 * Acquires server credentials from the configured keytab (any principal in
 * the keytab is accepted; the actual principal is determined by what the
 * client requests), then sends AuthenticationGSS (AUTH_REQ_GSS = 7) to
 * prompt the client to begin the exchange.
 */
bool gssapi_accept_send_request(PgSocket *client)
{
	OM_uint32 major, minor;
	gss_key_value_element_desc keytab_el;
	gss_key_value_set_desc keytab_store;
	const gss_key_value_set_desc *store_ptr = NULL;
	bool res;

	if (cf_auth_gssapi_keytab && *cf_auth_gssapi_keytab) {
		keytab_el.key = "keytab";
		keytab_el.value = cf_auth_gssapi_keytab;
		keytab_store.count = 1;
		keytab_store.elements = &keytab_el;
		store_ptr = &keytab_store;
	}

	/*
	 * GSS_C_NO_NAME: accept any principal we can validate with the keytab.
	 * The GSSAPI library chooses the matching key based on the service
	 * ticket the client sends.
	 */
	major = gss_acquire_cred_from(&minor,
				      GSS_C_NO_NAME,
				      GSS_C_INDEFINITE,
				      GSS_C_NO_OID_SET,
				      GSS_C_ACCEPT,
				      store_ptr,
				      &client->gss_state.creds,
				      NULL,
				      NULL);
	if (GSS_ERROR(major)) {
		log_gss_error(client, major, minor, "gss_acquire_cred_from (accept)");
		slog_error(client, "GSSAPI: failed to acquire server credentials%s%s",
			   store_ptr ? " from keytab " : "",
			   store_ptr ? cf_auth_gssapi_keytab : "");
		disconnect_client(client, true, "GSSAPI credential acquisition failed");
		return false;
	}

	client->gss_state.context = GSS_C_NO_CONTEXT;

	/* Send AUTH_REQ_GSS (7) with no token; client sends the first token. */
	res = send_auth_token_to_client(client, AUTH_REQ_GSS, NULL, 0);
	if (!res) {
		slog_error(client, "GSSAPI: failed to send authentication request");
		gssapi_accept_cleanup(client);
	}
	return res;
}

/*
 * Process a GSSAPI token received from a client (a 'p' / GSSResponse packet).
 *
 * Calls gss_accept_sec_context() and handles all outcomes:
 *   - GSS_S_CONTINUE_NEEDED: sends AUTH_REQ_GSS_CONT with the output token
 *     and returns true, leaving the connection active for the next round.
 *   - Context established: maps the principal via gss_localname(), verifies
 *     it against the claimed username, and calls finish_client_login().
 *   - Error: disconnects the client and returns false.
 */
bool gssapi_accept_continue(PgSocket *client, const uint8_t *token, unsigned token_len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
	gss_name_t client_name = GSS_C_NO_NAME;
	gss_OID mech_type = GSS_C_NO_OID;
	bool ok;
	bool sent_ap_rep = false;

	if (token_len > GSSAPI_MAX_TOKEN_SIZE) {
		slog_error(client, "GSSAPI: token too large (%u bytes, limit %d)",
			   token_len, GSSAPI_MAX_TOKEN_SIZE);
		disconnect_client(client, true, "GSSAPI token too large");
		return false;
	}

	input_token.value = (void *)token;
	input_token.length = token_len;

	/*
	 * delegated_cred is passed as NULL: we never accept delegated
	 * credentials.  The pool connects to postgres under its own identity.
	 */
	major = gss_accept_sec_context(&minor,
				       &client->gss_state.context,
				       client->gss_state.creds,
				       &input_token,
				       GSS_C_NO_CHANNEL_BINDINGS,
				       &client_name,
				       &mech_type,
				       &output_token,
				       NULL,	/* ret_flags - not inspected */
				       NULL,	/* time_rec */
				       NULL);	/* delegated_cred - never */

	if (GSS_ERROR(major)) {
		log_gss_error(client, major, minor, "gss_accept_sec_context");
		if (output_token.length > 0)
			gss_release_buffer(&minor, &output_token);
		if (client_name != GSS_C_NO_NAME)
			gss_release_name(&minor, &client_name);
		gssapi_accept_cleanup(client);
		disconnect_client(client, true, "GSSAPI authentication failed");
		return false;
	}

	/*
	 * Whether or not the exchange is complete, send any output token the
	 * library produced (e.g. the AP-REP for mutual authentication).
	 */
	if (output_token.length > 0) {
		bool send_ok = send_auth_token_to_client(client, AUTH_REQ_GSS_CONT,
							 output_token.value,
							 output_token.length);
		gss_release_buffer(&minor, &output_token);
		if (!send_ok) {
			slog_error(client, "GSSAPI: failed to send token to client");
			if (client_name != GSS_C_NO_NAME)
				gss_release_name(&minor, &client_name);
			gssapi_accept_cleanup(client);
			disconnect_client(client, false, "GSSAPI: send failed");
			return false;
		}
		sent_ap_rep = true;
	}

	if (major & GSS_S_CONTINUE_NEEDED) {
		/*
		 * Exchange is not yet complete.  The client will send another
		 * token; the sbuf will deliver it to gssapi_accept_continue()
		 * again on the next event.
		 */
		if (client_name != GSS_C_NO_NAME)
			gss_release_name(&minor, &client_name);
		return true;
	}

	/* Context fully established.  Map the principal and finish login. */
	ok = gssapi_map_and_verify_username(client, client_name, mech_type);
	if (client_name != GSS_C_NO_NAME)
		gss_release_name(&minor, &client_name);

	gssapi_accept_cleanup(client);

	if (!ok) {
		disconnect_client(client, true,
				  "GSSAPI authentication failed: principal mapping error");
		return false;
	}

	/*
	 * When GSS_C_MUTUAL_FLAG is negotiated, gss_accept_sec_context()
	 * produces an AP-REP output token (sent above as AUTH_REQ_GSS_CONT).
	 * The client feeds that token to gss_init_sec_context(); RFC 2744
	 * permits the mechanism to emit a final token together with
	 * GSS_S_COMPLETE, and when it does libpq forwards it as one more
	 * GSSResponse ('p') even though our context is already established.
	 * Standard single-realm MIT Kerberos returns an empty final token
	 * (no trailing packet), but this is mechanism-dependent, so record
	 * that we sent an AP-REP and let handle_client_work() absorb the
	 * extra packet if it arrives rather than rejecting it as unknown.
	 */
	client->gss_state.sent_ap_rep = sent_ap_rep;

	return finish_client_login(client);
}

/* --------------------------------------------------------------------------
 * Server-side (initiator): connecting to a PostgreSQL backend via Kerberos
 * -------------------------------------------------------------------------- */

/*
 * Release all server-side GSSAPI state.  Safe to call multiple times.
 */
void gssapi_initiate_cleanup(PgSocket *server)
{
	OM_uint32 minor;

	if (server->gss_state.context != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor, &server->gss_state.context,
				       GSS_C_NO_BUFFER);
		server->gss_state.context = GSS_C_NO_CONTEXT;
	}
	if (server->gss_state.creds != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&minor, &server->gss_state.creds);
		server->gss_state.creds = GSS_C_NO_CREDENTIAL;
	}
	if (server->gss_state.target_name != GSS_C_NO_NAME) {
		gss_release_name(&minor, &server->gss_state.target_name);
		server->gss_state.target_name = GSS_C_NO_NAME;
	}
}

/*
 * Construct the GSSAPI target name for the PostgreSQL service.
 *
 * Uses GSS_C_NT_HOSTBASED_SERVICE with name "postgres@<host>".  The GSSAPI
 * library canonicalises the hostname and appends the default realm, yielding
 * the SPN postgres/<canonical-host>@REALM that must exist in the KDC.
 */
static bool build_target_name(PgSocket *server, gss_name_t *target_name_out)
{
	OM_uint32 major, minor;
	gss_buffer_desc name_buf;
	const char *host;
	char *svc_name;
	size_t svc_len;

	/*
	 * Use the host actually connected to, not db->host, which may be a
	 * comma-separated list when load balancing over multiple hosts.  This is
	 * the same field the TLS path uses for its peer name (sbuf_tls_connect).
	 */
	host = server->host;
	if (!host || !*host) {
		slog_error(server, "GSSAPI: backend database has no hostname configured; "
			   "GSSAPI requires a resolvable hostname to construct the "
			   "service principal");
		return false;
	}

	/*
	 * The service name defaults to "postgres", matching PostgreSQL's
	 * default krbsrvname.  If the backend uses a non-default krbsrvname
	 * (set in postgresql.conf), configure auth_gssapi_service_name to
	 * match.
	 */
	{
		const char *svcname = (cf_auth_gssapi_service_name && *cf_auth_gssapi_service_name)
				      ? cf_auth_gssapi_service_name : "postgres";
		svc_len = strlen(svcname) + 1 + strlen(host) + 1;	/* "svcname@host\0" */
		svc_name = malloc(svc_len);
		if (!svc_name) {
			slog_error(server, "GSSAPI: out of memory constructing service name");
			return false;
		}
		snprintf(svc_name, svc_len, "%s@%s", svcname, host);
	}

	name_buf.value = svc_name;
	name_buf.length = strlen(svc_name);

	major = gss_import_name(&minor, &name_buf,
				GSS_C_NT_HOSTBASED_SERVICE, target_name_out);
	free(svc_name);

	if (GSS_ERROR(major)) {
		log_gss_error(server, major, minor, "gss_import_name");
		return false;
	}
	return true;
}

/*
 * Begin GSSAPI authentication to a PostgreSQL backend.
 * Called when the backend sends AuthenticationGSSAPI (AUTH_REQ_GSS = 7).
 *
 * Acquires initiator credentials, then sends the first GSSAPI token to the
 * backend.
 *
 * Credential acquisition follows standard Kerberos client behaviour:
 *   - By default (auth_gssapi_client_keytab unset), store_ptr is NULL and
 *     gss_acquire_cred_from() uses the default credential cache (KCM, FILE:,
 *     etc.).  This is the correct mode when the pgbouncer process already has
 *     a TGT, obtained through any standard mechanism (KCM, kinitd, sssd).
 *   - If auth_gssapi_client_keytab is set, MIT Kerberos acquires credentials
 *     directly from the keytab without requiring a pre-existing ccache.  This
 *     is an override for environments without automatic credential management.
 *
 * Only GSS_C_MUTUAL_FLAG is requested.  GSS_C_DELEG_FLAG and
 * GSS_C_DELEG_POLICY_FLAG are deliberately absent: the pool connects under
 * its own service-account identity and does not forward any user credential.
 */
bool gssapi_initiate_begin(PgSocket *server)
{
	OM_uint32 major, minor;
	gss_key_value_element_desc keytab_el;
	gss_key_value_set_desc keytab_store;
	const gss_key_value_set_desc *store_ptr = NULL;
	gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

	if (!build_target_name(server, &server->gss_state.target_name)) {
		kill_pool_logins(server->pool, NULL,
				 "server login failed: GSSAPI service name error");
		return false;
	}

	if (cf_auth_gssapi_client_keytab && *cf_auth_gssapi_client_keytab) {
		/*
		 * Explicit keytab override: acquire credentials directly from
		 * the keytab without a pre-existing ccache.  Only used when
		 * auth_gssapi_client_keytab is configured.
		 *
		 * Note: do NOT fall back to auth_gssapi_keytab here.  That file
		 * holds the host-based service SPN used to accept client tickets
		 * (postgres/<pgbouncer-host>@REALM), which is the wrong identity
		 * for the initiator role.
		 */
		keytab_el.key = "client_keytab";
		keytab_el.value = cf_auth_gssapi_client_keytab;
		keytab_store.count = 1;
		keytab_store.elements = &keytab_el;
		store_ptr = &keytab_store;
	}
	/* else store_ptr remains NULL: gss_acquire_cred_from() uses the
	 * default credential cache (KCM:%{euid}, FILE:, etc.). */

	major = gss_acquire_cred_from(&minor,
				      GSS_C_NO_NAME,
				      GSS_C_INDEFINITE,
				      GSS_C_NO_OID_SET,
				      GSS_C_INITIATE,
				      store_ptr,
				      &server->gss_state.creds,
				      NULL,
				      NULL);
	if (GSS_ERROR(major)) {
		log_gss_error(server, major, minor, "gss_acquire_cred_from (initiate)");
		slog_error(server, "GSSAPI: failed to acquire initiator credentials from %s",
			   store_ptr ? cf_auth_gssapi_client_keytab : "default credential cache");
		gssapi_initiate_cleanup(server);
		kill_pool_logins(server->pool, NULL,
				 "server login failed: GSSAPI credential acquisition failed");
		return false;
	}

	server->gss_state.context = GSS_C_NO_CONTEXT;

	major = gss_init_sec_context(&minor,
				     server->gss_state.creds,
				     &server->gss_state.context,
				     server->gss_state.target_name,
				     GSS_C_NO_OID,	/* default mechanism (Kerberos) */
				     GSS_C_MUTUAL_FLAG,	/* mutual auth; NO delegation */
				     GSS_C_INDEFINITE,
				     GSS_C_NO_CHANNEL_BINDINGS,
				     GSS_C_NO_BUFFER,	/* no input on first call */
				     NULL,
				     &output_token,
				     NULL,
				     NULL);

	if (GSS_ERROR(major)) {
		log_gss_error(server, major, minor, "gss_init_sec_context (initial)");
		if (output_token.length > 0)
			gss_release_buffer(&minor, &output_token);
		gssapi_initiate_cleanup(server);
		kill_pool_logins(server->pool, NULL,
				 "server login failed: GSSAPI context initialization failed");
		return false;
	}

	if (output_token.length == 0) {
		slog_error(server, "GSSAPI: gss_init_sec_context produced no token "
			   "on first call; this is unexpected for Kerberos");
		gssapi_initiate_cleanup(server);
		kill_pool_logins(server->pool, NULL,
				 "server login failed: GSSAPI produced no initial token");
		return false;
	}

	slog_debug(server, "GSSAPI: sending initial token to backend (%zu bytes)",
		   output_token.length);

	if (!send_gss_response_to_server(server, output_token.value,
					 output_token.length)) {
		slog_error(server, "GSSAPI: failed to send initial token to backend");
		gss_release_buffer(&minor, &output_token);
		gssapi_initiate_cleanup(server);
		return false;
	}
	gss_release_buffer(&minor, &output_token);

	/* Unlikely for Kerberos, but handle single-round completion. */
	if (!(major & GSS_S_CONTINUE_NEEDED)) {
		slog_debug(server, "GSSAPI: context established in one round");
		gssapi_initiate_cleanup(server);
	}

	return true;
}

/*
 * Continue GSSAPI authentication to a PostgreSQL backend.
 * Called when the backend sends AuthenticationGSSContinue (AUTH_REQ_GSS_CONT = 8).
 */
bool gssapi_initiate_continue(PgSocket *server, const uint8_t *token, unsigned token_len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

	if (server->gss_state.context == GSS_C_NO_CONTEXT) {
		slog_error(server, "GSSAPI: received AUTH_REQ_GSS_CONT but context "
			   "is not in progress; protocol error");
		kill_pool_logins(server->pool, NULL,
				 "server login failed: unexpected GSSAPI continuation");
		return false;
	}

	if (token_len > GSSAPI_MAX_TOKEN_SIZE) {
		slog_error(server, "GSSAPI: backend token too large (%u bytes, limit %d)",
			   token_len, GSSAPI_MAX_TOKEN_SIZE);
		gssapi_initiate_cleanup(server);
		kill_pool_logins(server->pool, NULL,
				 "server login failed: GSSAPI token too large");
		return false;
	}

	input_token.value = (void *)token;
	input_token.length = token_len;

	major = gss_init_sec_context(&minor,
				     server->gss_state.creds,
				     &server->gss_state.context,
				     server->gss_state.target_name,
				     GSS_C_NO_OID,
				     GSS_C_MUTUAL_FLAG,	/* consistent; no delegation */
				     GSS_C_INDEFINITE,
				     GSS_C_NO_CHANNEL_BINDINGS,
				     &input_token,
				     NULL,
				     &output_token,
				     NULL,
				     NULL);

	if (GSS_ERROR(major)) {
		log_gss_error(server, major, minor, "gss_init_sec_context (continuation)");
		if (output_token.length > 0)
			gss_release_buffer(&minor, &output_token);
		gssapi_initiate_cleanup(server);
		kill_pool_logins(server->pool, NULL,
				 "server login failed: GSSAPI context establishment failed");
		return false;
	}

	if (output_token.length > 0) {
		slog_debug(server, "GSSAPI: sending continuation token to backend "
			   "(%zu bytes)", output_token.length);
		if (!send_gss_response_to_server(server, output_token.value,
						 output_token.length)) {
			slog_error(server, "GSSAPI: failed to send continuation token");
			gss_release_buffer(&minor, &output_token);
			gssapi_initiate_cleanup(server);
			return false;
		}
		gss_release_buffer(&minor, &output_token);
	}

	if (!(major & GSS_S_CONTINUE_NEEDED)) {
		slog_debug(server, "GSSAPI: context established with backend");
		gssapi_initiate_cleanup(server);
	}

	return true;
}

/* --------------------------------------------------------------------------
 * GSSAPI encryption: wrap/unwrap for the sbuf I/O layer
 * --------------------------------------------------------------------------
 *
 * These functions mirror be_gssapi_read() / be_gssapi_write() from the
 * postgres source (be-secure-gssapi.c).  The framing is:
 *   [uint32 wrapped_length (network byte order)] [gss_wrap() output]
 *
 * gss_unwrap() requires the complete wrapped token; partial input is
 * accumulated in gss_enc.recv_buf across calls.
 */

/*
 * Decrypt data from the GSS-encrypted stream.
 * Returns bytes of plaintext delivered, or -1 with errno set.
 */
ssize_t gssenc_recv(PgSocket *sk, void *buf, size_t len)
{
	struct GssEncState *enc = &sk->gss_enc;
	OM_uint32 major, minor;
	gss_buffer_desc input, output = GSS_C_EMPTY_BUFFER;
	int conf_state;
	int bytes_returned = 0;
	ssize_t ret;
	int raw_sock = sk->sbuf.sock;

	while ((size_t)bytes_returned < len) {
		int avail;

		/* return any buffered decrypted data */
		if (enc->result_next < enc->result_len) {
			avail = enc->result_len - enc->result_next;
			if (avail > (int)(len - bytes_returned))
				avail = (int)(len - bytes_returned);
			memcpy((char *)buf + bytes_returned,
			       enc->result_buf + enc->result_next, avail);
			enc->result_next += avail;
			bytes_returned += avail;
			break;
		}

		enc->result_len = enc->result_next = 0;
		if (bytes_returned > 0)
			break;

		/* read 4-byte length header */
		if (enc->recv_len < (int)sizeof(uint32_t)) {
			ret = recv(raw_sock,
				   enc->recv_buf + enc->recv_len,
				   sizeof(uint32_t) - enc->recv_len, 0);
			if (ret <= 0) {
				if (ret == 0) {
					errno = ECONNRESET;
					return -1;
				}
				if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
					errno = EAGAIN;
					return bytes_returned > 0 ? bytes_returned : -1;
				}
				return -1;
			}
			enc->recv_len += ret;
			if (enc->recv_len < (int)sizeof(uint32_t)) {
				errno = EAGAIN;
				return -1;
			}
		}

		/* decode and validate length */
		{
			uint32_t pktlen;
			memcpy(&pktlen, enc->recv_buf, sizeof(uint32_t));
			pktlen = ntohl(pktlen);
			if (pktlen > PQ_GSS_MAX_PACKET_SIZE - sizeof(uint32_t)) {
				slog_error(sk, "GSSAPI: encrypted packet too large (%u bytes)",
					   pktlen);
				errno = ECONNRESET;
				return -1;
			}
			enc->pkt_expected = (int)pktlen;
		}

		/* read encrypted payload */
		{
			int need = enc->pkt_expected - (enc->recv_len - (int)sizeof(uint32_t));
			if (need > 0) {
				ret = recv(raw_sock,
					   enc->recv_buf + enc->recv_len,
					   need, 0);
				if (ret <= 0) {
					if (ret == 0) {
						errno = ECONNRESET;
						return -1;
					}
					if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
						errno = EAGAIN;
						return bytes_returned > 0 ? bytes_returned : -1;
					}
					return -1;
				}
				enc->recv_len += ret;
				if (enc->recv_len - (int)sizeof(uint32_t) < enc->pkt_expected) {
					errno = EAGAIN;
					return -1;
				}
			}
		}

		/* decrypt the complete packet */
		input.value = enc->recv_buf + sizeof(uint32_t);
		input.length = enc->pkt_expected;

		major = gss_unwrap(&minor, enc->ctx, &input, &output,
				   &conf_state, NULL);
		if (GSS_ERROR(major)) {
			log_gss_error(sk, major, minor, "gss_unwrap");
			if (output.length > 0)
				gss_release_buffer(&minor, &output);
			errno = ECONNRESET;
			return -1;
		}
		if (conf_state == 0) {
			slog_error(sk, "GSSAPI: incoming message did not use confidentiality");
			gss_release_buffer(&minor, &output);
			errno = ECONNRESET;
			return -1;
		}

		memcpy(enc->result_buf, output.value, output.length);
		enc->result_len = output.length;
		enc->result_next = 0;
		enc->recv_len = 0;
		gss_release_buffer(&minor, &output);
	}

	return bytes_returned;
}

/*
 * Encrypt and send data over the GSS-encrypted stream.
 * Returns bytes of plaintext consumed, or -1 with errno set.
 */
ssize_t gssenc_send(PgSocket *sk, const void *buf, size_t len)
{
	struct GssEncState *enc = &sk->gss_enc;
	OM_uint32 major, minor;
	gss_buffer_desc input, output = GSS_C_EMPTY_BUFFER;
	int conf_state;
	int bytes_encrypted = enc->send_consumed;
	int bytes_to_encrypt = (int)len - bytes_encrypted;
	ssize_t ret;
	int raw_sock = sk->sbuf.sock;

	if ((int)len < enc->send_consumed) {
		slog_error(sk, "GSSAPI: send retry with fewer bytes than consumed");
		errno = EINVAL;
		return -1;
	}

	while (bytes_to_encrypt > 0 || enc->send_len > 0) {
		/* flush any pending encrypted data */
		while (enc->send_next < enc->send_len) {
			ret = send(raw_sock,
				   enc->send_buf + enc->send_next,
				   enc->send_len - enc->send_next, 0);
			if (ret <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
					enc->send_consumed = bytes_encrypted;
					errno = EAGAIN;
					return -1;
				}
				return -1;
			}
			enc->send_next += ret;
		}
		enc->send_len = enc->send_next = 0;

		if (bytes_to_encrypt <= 0)
			break;

		/* chunk plaintext and encrypt */
		input.length = bytes_to_encrypt;
		if (input.length > enc->max_pkt_size)
			input.length = enc->max_pkt_size;
		input.value = (char *)buf + bytes_encrypted;

		major = gss_wrap(&minor, enc->ctx, 1, GSS_C_QOP_DEFAULT,
				 &input, &conf_state, &output);
		if (GSS_ERROR(major)) {
			log_gss_error(sk, major, minor, "gss_wrap");
			if (output.length > 0)
				gss_release_buffer(&minor, &output);
			errno = ECONNRESET;
			return -1;
		}
		if (conf_state == 0) {
			slog_error(sk, "GSSAPI: outgoing message would not use confidentiality");
			gss_release_buffer(&minor, &output);
			errno = ECONNRESET;
			return -1;
		}
		if (output.length > PQ_GSS_MAX_PACKET_SIZE - sizeof(uint32_t)) {
			slog_error(sk, "GSSAPI: wrapped output too large (%zu bytes)",
				   output.length);
			gss_release_buffer(&minor, &output);
			errno = ECONNRESET;
			return -1;
		}

		/* frame: [uint32 length][encrypted payload] */
		{
			uint32_t netlen = htonl((uint32_t)output.length);
			memcpy(enc->send_buf, &netlen, sizeof(uint32_t));
			enc->send_len = sizeof(uint32_t);
			memcpy(enc->send_buf + enc->send_len, output.value, output.length);
			enc->send_len += output.length;
			enc->send_next = 0;
		}

		bytes_encrypted += input.length;
		bytes_to_encrypt -= input.length;
		gss_release_buffer(&minor, &output);
	}

	enc->send_consumed = 0;
	return bytes_encrypted;
}

/*
 * Allocate GSS encryption buffers for the handshake phase.
 * send/recv/result are allocated at the given size; hs_buf is
 * always allocated at PQ_GSS_AUTH_BUFFER_SIZE.
 */
static bool gssenc_alloc_buffers(struct GssEncState *enc, int size)
{
	free(enc->send_buf);
	free(enc->recv_buf);
	free(enc->result_buf);
	enc->send_buf = malloc(size);
	enc->recv_buf = malloc(size);
	enc->result_buf = malloc(size);
	if (!enc->send_buf || !enc->recv_buf || !enc->result_buf) {
		free(enc->send_buf);
		free(enc->recv_buf);
		free(enc->result_buf);
		enc->send_buf = enc->recv_buf = enc->result_buf = NULL;
		return false;
	}
	enc->send_len = enc->send_next = enc->send_consumed = 0;
	enc->recv_len = 0;
	enc->result_len = enc->result_next = 0;
	enc->pkt_expected = 0;
	enc->hs_want = GSSENC_HS_READ;
	enc->hs_complete_pending = false;

	free(enc->hs_buf);
	enc->hs_buf = malloc(PQ_GSS_AUTH_BUFFER_SIZE);
	if (!enc->hs_buf) {
		free(enc->send_buf);
		free(enc->recv_buf);
		free(enc->result_buf);
		enc->send_buf = enc->recv_buf = enc->result_buf = NULL;
		return false;
	}
	enc->hs_len = 0;
	return true;
}

/*
 * Resize send/recv/result buffers for the data phase
 * (PQ_GSS_MAX_PACKET_SIZE).  Called at handshake completion after
 * hs_buf has been freed.
 */
static bool gssenc_realloc_data_buffers(struct GssEncState *enc)
{
	free(enc->send_buf);
	free(enc->recv_buf);
	free(enc->result_buf);
	enc->send_buf = malloc(PQ_GSS_MAX_PACKET_SIZE);
	enc->recv_buf = malloc(PQ_GSS_MAX_PACKET_SIZE);
	enc->result_buf = malloc(PQ_GSS_MAX_PACKET_SIZE);
	if (!enc->send_buf || !enc->recv_buf || !enc->result_buf) {
		free(enc->send_buf);
		free(enc->recv_buf);
		free(enc->result_buf);
		enc->send_buf = enc->recv_buf = enc->result_buf = NULL;
		return false;
	}
	enc->send_len = enc->send_next = enc->send_consumed = 0;
	enc->recv_len = 0;
	enc->result_len = enc->result_next = 0;
	enc->pkt_expected = 0;
	return true;
}

/*
 * Release all GSS encryption state.
 */
void gssenc_cleanup(PgSocket *sk)
{
	struct GssEncState *enc = &sk->gss_enc;
	OM_uint32 minor;

	if (enc->ctx != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor, &enc->ctx, GSS_C_NO_BUFFER);
		enc->ctx = GSS_C_NO_CONTEXT;
	}
	if (enc->creds != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&minor, &enc->creds);
		enc->creds = GSS_C_NO_CREDENTIAL;
	}
	if (enc->target_name != GSS_C_NO_NAME) {
		gss_release_name(&minor, &enc->target_name);
		enc->target_name = GSS_C_NO_NAME;
	}
	free(enc->send_buf);
	free(enc->recv_buf);
	free(enc->result_buf);
	free(enc->hs_buf);
	enc->send_buf = enc->recv_buf = enc->result_buf = enc->hs_buf = NULL;
	enc->active = false;
}

/*
 * Start accepting a GSS-encrypted connection from a client.
 * Allocates buffers and acquires acceptor credentials.
 */
bool gssenc_accept_start(PgSocket *client)
{
	OM_uint32 major, minor;
	gss_key_value_element_desc keytab_el;
	gss_key_value_set_desc keytab_store;
	const gss_key_value_set_desc *store_ptr = NULL;
	struct GssEncState *enc = &client->gss_enc;

	if (!gssenc_alloc_buffers(enc, PQ_GSS_AUTH_BUFFER_SIZE))
		return false;
	enc->ctx = GSS_C_NO_CONTEXT;
	enc->active = false;

	/* acquire acceptor credentials from keytab */
	if (cf_auth_gssapi_keytab && *cf_auth_gssapi_keytab) {
		keytab_el.key = "keytab";
		keytab_el.value = cf_auth_gssapi_keytab;
		keytab_store.count = 1;
		keytab_store.elements = &keytab_el;
		store_ptr = &keytab_store;
	}

	major = gss_acquire_cred_from(&minor, GSS_C_NO_NAME,
				      GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
				      GSS_C_ACCEPT, store_ptr,
				      &enc->creds, NULL, NULL);
	if (GSS_ERROR(major)) {
		log_gss_error(client, major, minor, "gss_acquire_cred_from (enc accept)");
		gssenc_cleanup(client);
		return false;
	}

	return true;
}

/*
 * Frame [uint32 length][token] into send_buf for a non-blocking flush.
 * During the handshake send_buf is PQ_GSS_AUTH_BUFFER_SIZE bytes, matching the
 * maximum token size accepted on read, so any legitimate token fits.
 */
static bool gssenc_hs_queue(PgSocket *sk, gss_buffer_desc *tok)
{
	struct GssEncState *enc = &sk->gss_enc;
	uint32_t netlen;

	if (tok->length > PQ_GSS_AUTH_BUFFER_SIZE - sizeof(uint32_t)) {
		slog_error(sk, "GSSAPI enc: output token too large (%zu bytes)", tok->length);
		return false;
	}
	netlen = htonl((uint32_t)tok->length);
	memcpy(enc->send_buf, &netlen, sizeof(uint32_t));
	memcpy(enc->send_buf + sizeof(uint32_t), tok->value, tok->length);
	enc->send_len = (int)(sizeof(uint32_t) + tok->length);
	enc->send_next = 0;
	return true;
}

/*
 * Flush a queued handshake token, non-blocking.
 * Returns 1 when fully sent, 0 when the socket would block (caller must re-arm
 * EV_WRITE and resume later), -1 on a fatal error.
 */
static int gssenc_hs_flush(PgSocket *sk)
{
	struct GssEncState *enc = &sk->gss_enc;
	int raw_sock = sk->sbuf.sock;
	ssize_t ret;

	while (enc->send_next < enc->send_len) {
		ret = send(raw_sock, enc->send_buf + enc->send_next,
			   enc->send_len - enc->send_next, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		}
		enc->send_next += ret;
	}
	enc->send_len = enc->send_next = 0;
	return 1;
}

/*
 * The context is established and its final token has been fully sent: free the
 * handshake buffer, size the data buffers, and switch the socket to the
 * encrypted data phase.  Shared by the acceptor and initiator.
 */
static bool gssenc_hs_transition(PgSocket *sk, const char *role)
{
	struct GssEncState *enc = &sk->gss_enc;
	OM_uint32 major, minor;

	free(enc->hs_buf);
	enc->hs_buf = NULL;

	if (!gssenc_realloc_data_buffers(enc))
		return false;

	major = gss_wrap_size_limit(&minor, enc->ctx, 1, GSS_C_QOP_DEFAULT,
				    PQ_GSS_MAX_PACKET_SIZE - sizeof(uint32_t),
				    &enc->max_pkt_size);
	if (GSS_ERROR(major)) {
		log_gss_error(sk, major, minor, "gss_wrap_size_limit");
		return false;
	}

	enc->active = true;
	if (cf_log_connections)
		slog_info(sk, "GSSAPI: encrypted channel established (%s)", role);
	return true;
}

/*
 * Accumulate one framed [uint32 length][token] handshake message into hs_buf
 * across event-driven reads.  Returns 1 when a whole token is available (input
 * then points into hs_buf), 0 when more data is needed (wait for EV_READ), or
 * -1 on error.
 */
static int gssenc_hs_read_token(PgSocket *sk, gss_buffer_desc *input)
{
	struct GssEncState *enc = &sk->gss_enc;
	int raw_sock = sk->sbuf.sock;
	ssize_t ret;

	while (enc->hs_len < (int)sizeof(uint32_t)) {
		ret = recv(raw_sock, enc->hs_buf + enc->hs_len,
			   sizeof(uint32_t) - enc->hs_len, 0);
		if (ret <= 0) {
			if (ret == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
				slog_error(sk, "GSSAPI enc: handshake read failed");
				return -1;
			}
			return 0;
		}
		enc->hs_len += ret;
	}

	if (enc->pkt_expected == 0) {
		uint32_t pktlen;
		memcpy(&pktlen, enc->hs_buf, sizeof(uint32_t));
		pktlen = ntohl(pktlen);
		if (pktlen > PQ_GSS_AUTH_BUFFER_SIZE - sizeof(uint32_t)) {
			slog_error(sk, "GSSAPI enc: handshake token too large (%u)", pktlen);
			return -1;
		}
		enc->pkt_expected = (int)pktlen;
	}

	{
		int need = enc->pkt_expected - (enc->hs_len - (int)sizeof(uint32_t));
		while (need > 0) {
			ret = recv(raw_sock, enc->hs_buf + enc->hs_len, need, 0);
			if (ret <= 0) {
				if (ret == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
					slog_error(sk, "GSSAPI enc: handshake read failed");
					return -1;
				}
				return 0;
			}
			enc->hs_len += ret;
			need -= ret;
		}
	}

	input->value = enc->hs_buf + sizeof(uint32_t);
	input->length = enc->pkt_expected;
	return 1;
}

/*
 * Process one round of the GSS encryption handshake for the acceptor.
 * Returns true if more data is expected or handshake is complete.
 * Returns false on error.
 *
 * Event-driven: each call either consumes the peer's next token (EV_READ) or
 * resumes flushing our own output token (EV_WRITE).  gss_enc.hs_want tells the
 * sbuf layer which event to wait on next.
 */
bool gssenc_accept_handshake(PgSocket *client)
{
	struct GssEncState *enc = &client->gss_enc;
	OM_uint32 major, minor;
	gss_buffer_desc input, output = GSS_C_EMPTY_BUFFER;
	int fr;

	/* Resume flushing a token that was only partially sent on a prior call. */
	if (enc->send_len > 0) {
		fr = gssenc_hs_flush(client);
		if (fr < 0) {
			slog_error(client, "GSSAPI enc: handshake write failed");
			return false;
		}
		if (fr == 0) {
			enc->hs_want = GSSENC_HS_WRITE;
			return true;
		}
		if (enc->hs_complete_pending)
			return gssenc_hs_transition(client, "acceptor");
		enc->hs_want = GSSENC_HS_READ;
		return true;
	}

	/* Read the client's next token. */
	enc->hs_want = GSSENC_HS_READ;
	fr = gssenc_hs_read_token(client, &input);
	if (fr < 0)
		return false;
	if (fr == 0)
		return true;	/* need more data */

	major = gss_accept_sec_context(&minor, &enc->ctx, enc->creds,
				       &input, GSS_C_NO_CHANNEL_BINDINGS,
				       NULL, NULL, &output, NULL, NULL, NULL);

	enc->hs_len = 0;
	enc->pkt_expected = 0;

	if (GSS_ERROR(major)) {
		log_gss_error(client, major, minor, "gss_accept_sec_context (enc)");
		if (output.length > 0)
			gss_release_buffer(&minor, &output);
		return false;
	}

	enc->hs_complete_pending = !(major & GSS_S_CONTINUE_NEEDED);

	if (output.length > 0) {
		bool queued = gssenc_hs_queue(client, &output);
		gss_release_buffer(&minor, &output);
		if (!queued)
			return false;
		fr = gssenc_hs_flush(client);
		if (fr < 0) {
			slog_error(client, "GSSAPI enc: handshake write failed");
			return false;
		}
		if (fr == 0) {
			enc->hs_want = GSSENC_HS_WRITE;
			return true;
		}
	}

	if (enc->hs_complete_pending)
		return gssenc_hs_transition(client, "acceptor");

	enc->hs_want = GSSENC_HS_READ;
	return true;
}

/*
 * Start a GSS-encrypted connection to a backend server.
 */
bool gssenc_have_initiator_cred(PgSocket *server)
{
	OM_uint32 major, minor;
	gss_key_value_element_desc keytab_el;
	gss_key_value_set_desc keytab_store;
	const gss_key_value_set_desc *store_ptr = NULL;
	gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;

	if (cf_auth_gssapi_client_keytab && *cf_auth_gssapi_client_keytab) {
		keytab_el.key = "client_keytab";
		keytab_el.value = cf_auth_gssapi_client_keytab;
		keytab_store.count = 1;
		keytab_store.elements = &keytab_el;
		store_ptr = &keytab_store;
	}

	major = gss_acquire_cred_from(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
				      GSS_C_NO_OID_SET, GSS_C_INITIATE,
				      store_ptr, &creds, NULL, NULL);
	if (GSS_ERROR(major))
		return false;

	gss_release_cred(&minor, &creds);
	return true;
}

bool gssenc_connect_start(PgSocket *server)
{
	struct GssEncState *enc = &server->gss_enc;
	OM_uint32 major, minor;
	gss_key_value_element_desc keytab_el;
	gss_key_value_set_desc keytab_store;
	const gss_key_value_set_desc *store_ptr = NULL;
	gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
	bool queued;
	int fr;

	if (!gssenc_alloc_buffers(enc, PQ_GSS_AUTH_BUFFER_SIZE))
		return false;
	enc->ctx = GSS_C_NO_CONTEXT;
	enc->active = false;

	/* acquire initiator credentials */
	if (cf_auth_gssapi_client_keytab && *cf_auth_gssapi_client_keytab) {
		keytab_el.key = "client_keytab";
		keytab_el.value = cf_auth_gssapi_client_keytab;
		keytab_store.count = 1;
		keytab_store.elements = &keytab_el;
		store_ptr = &keytab_store;
	}

	major = gss_acquire_cred_from(&minor, GSS_C_NO_NAME,
				      GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
				      GSS_C_INITIATE, store_ptr,
				      &enc->creds, NULL, NULL);
	if (GSS_ERROR(major)) {
		log_gss_error(server, major, minor, "gss_acquire_cred_from (enc initiate)");
		gssenc_cleanup(server);
		return false;
	}

	if (!build_target_name(server, &enc->target_name)) {
		gssenc_cleanup(server);
		return false;
	}

	/* first gss_init_sec_context call */
	{
		OM_uint32 gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG |
				      GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG |
				      GSS_C_INTEG_FLAG;

		major = gss_init_sec_context(&minor, enc->creds, &enc->ctx,
					     enc->target_name, GSS_C_NO_OID,
					     gss_flags, GSS_C_INDEFINITE,
					     GSS_C_NO_CHANNEL_BINDINGS,
					     GSS_C_NO_BUFFER, NULL,
					     &output, NULL, NULL);
	}

	if (GSS_ERROR(major)) {
		log_gss_error(server, major, minor, "gss_init_sec_context (enc initial)");
		if (output.length > 0)
			gss_release_buffer(&minor, &output);
		gssenc_cleanup(server);
		return false;
	}

	if (output.length == 0) {
		slog_error(server, "GSSAPI enc: gss_init_sec_context produced no token "
			   "on first call; this is unexpected for Kerberos");
		gssenc_cleanup(server);
		return false;
	}

	/*
	 * Queue the first token and flush it non-blocking.  A partial write leaves
	 * the remainder buffered and asks the sbuf layer to re-arm EV_WRITE; the
	 * first token never completes the context, so hs_complete_pending stays false.
	 */
	queued = gssenc_hs_queue(server, &output);
	gss_release_buffer(&minor, &output);
	if (!queued) {
		gssenc_cleanup(server);
		return false;
	}
	enc->hs_complete_pending = false;
	fr = gssenc_hs_flush(server);
	if (fr < 0) {
		gssenc_cleanup(server);
		return false;
	}
	enc->hs_want = (fr == 0) ? GSSENC_HS_WRITE : GSSENC_HS_READ;
	return true;
}

/*
 * Continue the GSS encryption handshake for the initiator.
 */
bool gssenc_connect_handshake(PgSocket *server)
{
	struct GssEncState *enc = &server->gss_enc;
	OM_uint32 major, minor;
	gss_buffer_desc input, output = GSS_C_EMPTY_BUFFER;
	OM_uint32 gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG |
			      GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG |
			      GSS_C_INTEG_FLAG;
	int fr;

	/* Resume flushing a token that was only partially sent on a prior call. */
	if (enc->send_len > 0) {
		fr = gssenc_hs_flush(server);
		if (fr < 0)
			return false;
		if (fr == 0) {
			enc->hs_want = GSSENC_HS_WRITE;
			return true;
		}
		if (enc->hs_complete_pending)
			return gssenc_hs_transition(server, "initiator");
		enc->hs_want = GSSENC_HS_READ;
		return true;
	}

	/* Read the backend's next token. */
	enc->hs_want = GSSENC_HS_READ;
	fr = gssenc_hs_read_token(server, &input);
	if (fr < 0)
		return false;
	if (fr == 0)
		return true;	/* need more data */

	major = gss_init_sec_context(&minor, enc->creds, &enc->ctx,
				     enc->target_name, GSS_C_NO_OID,
				     gss_flags, GSS_C_INDEFINITE,
				     GSS_C_NO_CHANNEL_BINDINGS,
				     &input, NULL, &output, NULL, NULL);

	enc->hs_len = 0;
	enc->pkt_expected = 0;

	if (GSS_ERROR(major)) {
		log_gss_error(server, major, minor, "gss_init_sec_context (enc continue)");
		if (output.length > 0)
			gss_release_buffer(&minor, &output);
		return false;
	}

	enc->hs_complete_pending = !(major & GSS_S_CONTINUE_NEEDED);

	if (output.length > 0) {
		bool queued = gssenc_hs_queue(server, &output);
		gss_release_buffer(&minor, &output);
		if (!queued)
			return false;
		fr = gssenc_hs_flush(server);
		if (fr < 0)
			return false;
		if (fr == 0) {
			enc->hs_want = GSSENC_HS_WRITE;
			return true;
		}
	}

	if (enc->hs_complete_pending)
		return gssenc_hs_transition(server, "initiator");

	enc->hs_want = GSSENC_HS_READ;
	return true;
}

/*
 * Extract the client principal from a GSS encryption context and verify
 * it against the claimed username.  Used when GSS encryption is active
 * to skip the separate AUTH_REQ_GSS exchange.
 */
bool gssenc_extract_and_verify_identity(PgSocket *client)
{
	struct GssEncState *enc = &client->gss_enc;
	OM_uint32 major, minor;
	gss_name_t client_name = GSS_C_NO_NAME;
	gss_OID mech_type = GSS_C_NO_OID;

	major = gss_inquire_context(&minor, enc->ctx, &client_name,
				    NULL, NULL, &mech_type, NULL, NULL, NULL);
	if (GSS_ERROR(major)) {
		log_gss_error(client, major, minor, "gss_inquire_context");
		return false;
	}

	{
		bool ok = gssapi_map_and_verify_username(client, client_name,
							 mech_type);
		gss_release_name(&minor, &client_name);
		if (!ok) {
			disconnect_client(client, true,
					  "GSSAPI enc: principal mapping error");
			return false;
		}
	}

	return finish_client_login(client);
}

#else /* !HAVE_GSSAPI */

void gssapi_auth_init(void)
{
}

bool gssapi_accept_send_request(PgSocket *client)
{
	disconnect_client(client, true,
			  "GSSAPI authentication is not supported in this build");
	return false;
}

bool gssapi_accept_continue(PgSocket *client, const uint8_t *token, unsigned token_len)
{
	(void)token;
	(void)token_len;
	disconnect_client(client, true,
			  "GSSAPI authentication is not supported in this build");
	return false;
}

void gssapi_accept_cleanup(PgSocket *client)
{
}

bool gssapi_initiate_begin(PgSocket *server)
{
	slog_error(server, "GSSAPI is not supported in this build");
	kill_pool_logins(server->pool, NULL,
			 "server login failed: GSSAPI not supported in this build");
	return false;
}

bool gssapi_initiate_continue(PgSocket *server, const uint8_t *token, unsigned token_len)
{
	(void)token;
	(void)token_len;
	kill_pool_logins(server->pool, NULL,
			 "server login failed: GSSAPI not supported in this build");
	return false;
}

void gssapi_initiate_cleanup(PgSocket *server)
{
}

ssize_t gssenc_recv(PgSocket *sk, void *buf, size_t len)
{
	(void)sk; (void)buf; (void)len;
	errno = ECONNRESET;
	return -1;
}

ssize_t gssenc_send(PgSocket *sk, const void *buf, size_t len)
{
	(void)sk; (void)buf; (void)len;
	errno = ECONNRESET;
	return -1;
}

bool gssenc_accept_start(PgSocket *client)
{
	disconnect_client(client, true, "GSSAPI encryption not supported in this build");
	return false;
}

bool gssenc_accept_handshake(PgSocket *client)
{
	(void)client;
	return false;
}

bool gssenc_have_initiator_cred(PgSocket *server)
{
	(void)server;
	return false;
}

bool gssenc_connect_start(PgSocket *server)
{
	(void)server;
	return false;
}

bool gssenc_connect_handshake(PgSocket *server)
{
	(void)server;
	return false;
}

void gssenc_cleanup(PgSocket *sk)
{
	(void)sk;
}

bool gssenc_extract_and_verify_identity(PgSocket *client)
{
	disconnect_client(client, true, "GSSAPI encryption not supported in this build");
	return false;
}

#endif /* HAVE_GSSAPI */
