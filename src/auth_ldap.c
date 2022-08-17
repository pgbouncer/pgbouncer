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
 * LDAP authentication support. (Use the same thread model of pam)
 */

#include "bouncer.h"

#ifdef HAVE_LDAP

#include <pthread.h>
#include <ldap.h>

/* The request is waiting in the queue or being authenticated */
#define LDAP_STATUS_IN_PROGRESS  1
/* The request was successfully authenticated */
#define LDAP_STATUS_SUCCESS      2
/* The request failed authentication */
#define LDAP_STATUS_FAILED       3

/*
 * How many microseconds to sleep between calls to ldap_poll in
 * ldap_auth_begin when the queue is full.
 * Default is 100 milliseconds.
 */
#define LDAP_QUEUE_WAIT_SLEEP_MCS    (100*1000)
#define LDAP_LONG_LENGTH 256

struct ldap_auth_request {
	/* The socket we check authentication for */
	PgSocket *client;

	/* CHECKME: The socket can be closed and reused while the request is waiting
	 * in the queue. Thus we need something to check the socket validity, and
	 * combination of its state and connect_time seems to be the good one.
	 */
	usec_t connect_time;

	/* Same as in client->remote_addr.
	 * We want to minimize synchronization between the authentication thread and
	 * the rest of pgbouncer, so the username and remote_addr are explicitly stored here.
	 */
	PgAddr remote_addr;

	/* The request status, one of the LDAP_STATUS_* constants */
	int status;

	/* The username (same as in client->login_user->name).
	 * See the comment for remote_addr.
	 */
	char username[MAX_USERNAME];

	/* password we should check for validity together with the socket's username */
	char password[MAX_PASSWORD];

	char ldap_parameters[MAX_LDAP_CONFIG];
	int param_pos;
	/* ldap specific parameters */
	bool ldaptls;
	char *ldapscheme;
	char *ldapserver;
	char *ldapbinddn;
	char *ldapsearchattribute;
	char *ldapsearchfilter;
	char *ldapbasedn;
	char *ldapbindpasswd;
	char *ldapprefix;
	char *ldapsuffix;
	int ldapport;
	int ldapscope;
};


/*
 * All incoming requests are kept in a queue which is implemented using a ring buffer.
 * Such structure allows to avoid memory reallocation thus minimizing amount of
 * synchronization to be done between threads.
 *
 * ldap_first_taken_slot points to the first element in the queue;
 * ldap_first_free_slot points to the next slot after the last element in the queue.
 *
 * if ldap_first_taken_slot == ldap_first_free_slot then the queue is considered empty;
 *
 */
volatile int ldap_first_taken_slot;
volatile int ldap_first_free_slot;
struct ldap_auth_request ldap_auth_queue[LDAP_REQUEST_QUEUE_SIZE];

pthread_t ldap_worker_thread;

/*
 * Mutex serializes access to the queue's tail when we add new requests or
 * check that we reach the end of the queue in the worker thread.
 *
 * Head and tail are modified only in the main thread. In theory, being sure that they
 * are properly aligned we can access them directly without any risk for data races.
 * Practically, it is better to secure them anyway to increase overall stability and
 * provide faster notification of new requests via the condition variable.
 */
pthread_mutex_t ldap_queue_tail_mutex;
pthread_cond_t ldap_data_available;

/* Forward declarations */
static void *ldap_auth_worker(void *arg);

static bool is_valid_socket(const struct ldap_auth_request *request);

static void ldap_auth_finish(struct ldap_auth_request *request);

static bool checkldapauth(struct ldap_auth_request *request);

/*
 * Initialize LDAP subsystem.
 */
void auth_ldap_init(void)
{
	int rc;

	ldap_first_taken_slot = 0;
	ldap_first_free_slot = 0;

	rc = pthread_mutex_init(&ldap_queue_tail_mutex, NULL);
	if (rc != 0) {
		die("failed to initialize a mutex: %s", strerror(errno));
	}

	rc = pthread_cond_init(&ldap_data_available, NULL);
	if (rc != 0) {
		die("failed to initialize a condition variable: %s", strerror(errno));
	}

	rc = pthread_create(&ldap_worker_thread, NULL, &ldap_auth_worker, NULL);
	if (rc != 0) {
		die("failed to create the authentication thread: %s", strerror(errno));
	}
}

#define reset_ptr(ptr, name) ptr->name = NULL
#define ldap_parameter_dup(ptr, name, src_str) \
do {                                           \
    (ptr)->name = (ptr)->ldap_parameters + (ptr)->param_pos; \
    safe_strcpy((ptr)->name, src_str, sizeof((ptr)->ldap_parameters) - (ptr)->param_pos); \
    (ptr)->param_pos += strlen(src_str) + 1;      \
    if ((ptr)->param_pos >= MAX_LDAP_CONFIG) {    \
        log_warning("The parameters are longer than MAX_LDAP_CONFIG:%d", MAX_LDAP_CONFIG); \
        return false; \
    } \
} while(0)

static void free_ldap_parameters(struct ldap_auth_request *request)
{
	memset(request->ldap_parameters, 0, MAX_LDAP_CONFIG);
	request->param_pos = 0;
	reset_ptr(request, ldapserver);
	reset_ptr(request, ldapbinddn);
	reset_ptr(request, ldapsearchattribute);
	reset_ptr(request, ldapbasedn);
	reset_ptr(request, ldapbindpasswd);
	reset_ptr(request, ldapprefix);
	reset_ptr(request, ldapsuffix);

	request->ldaptls = false;
	request->ldapport = 0;
	request->ldapscope = 0;
}

static bool is_valid_parameter(struct ldap_auth_request *request)
{
	/*
	 * LDAP can operate in two modes: either with a direct bind, using
	 * ldapprefix and ldapsuffix, or using a search+bind, using
	 * ldapbasedn, ldapbinddn, ldapbindpasswd and ldapsearchattribute.
	 * Disallow mixing these parameters.
	 */
	if (request->ldapprefix || request->ldapsuffix) {
		if (request->ldapbasedn ||
			request->ldapbinddn ||
			request->ldapbindpasswd ||
			request->ldapsearchattribute ||
			request->ldapsearchfilter ) {
			log_warning("cannot use ldapbasedn, ldapbinddn, ldapbindpasswd, "
						"ldapsearchattribute, ldapsearchfilter, or ldapurl together with ldapprefix");
			return false;
		}
	} else if (!request->ldapbasedn) {
		log_warning(
				"authentication method \"ldap\" requires argument \"ldapbasedn\", \"ldapprefix\", or \"ldapsuffix\" to be set");
		return false;
	}
	/*
	 * When using search+bind, you can either use a simple attribute
	 * (defaulting to "uid") or a fully custom search filter.  You can't
	 * do both.
	 */
	if (request->ldapsearchattribute && request->ldapsearchfilter)
	{
		log_warning("cannot use ldapsearchattribute together with ldapsearchfilter");
		return false;
	}

	return true;
}

static bool parse_ldapurl(struct ldap_auth_request *request, char *val)
{
	LDAPURLDesc *urldata;
	int rc = ldap_url_parse(val, &urldata);
	if (rc != LDAP_SUCCESS) {
		log_warning("could not parse LDAP URL \"%s\": %s", val, ldap_err2string(rc));
		return false;
	}

	if (strcmp(urldata->lud_scheme, "ldap") != 0 &&
		strcmp(urldata->lud_scheme, "ldaps") != 0) {
		log_warning("unsupported LDAP URL scheme: %s", urldata->lud_scheme);
		ldap_free_urldesc(urldata);
		return false;
	}
	if (urldata->lud_scheme)
		ldap_parameter_dup(request, ldapscheme, urldata->lud_scheme);

	if (urldata->lud_host)
		ldap_parameter_dup(request, ldapserver, urldata->lud_host);
	request->ldapport = urldata->lud_port;
	if (urldata->lud_dn)
		ldap_parameter_dup(request, ldapbasedn, urldata->lud_dn);
	if (urldata->lud_attrs)
		ldap_parameter_dup(request, ldapsearchattribute, urldata->lud_attrs[0]); /* only use first one */
	request->ldapscope = urldata->lud_scope;
	if (urldata->lud_filter)
		ldap_parameter_dup(request, ldapsearchfilter, urldata->lud_filter);
	ldap_free_urldesc(urldata);
	return true;
}

static bool get_key_value(char **p, char **key, char **value)
{
	char *start, *name, *val;

	start = *p;
	while (*start && isspace(*start)) ++start; /* skip space */

	name = start;
	while (*start && *start != '=') start++;
	if (!*start) return false; /* Only key, stop scan */
	*start++ = 0;

	val = start;
	if (*start == '"') {
		val = ++start;
		while (*start && *start != '"') ++start;
		if (!*start) return false; /* incomplete value */
		*start++ = 0;
	} else {
		if (*start == ' ') return false; /* Not key=value format */
		while (*start && *start != ' ') start++;
		if (*start == ' ') {
			*start++ = 0;
		}
	}

	*p = start;
	*key = name;
	*value = val;
	return true;
}

static bool ldap_initialize_parameters(struct ldap_auth_request *request, char *parameter)
{
	char *key, *value;
	char *p = parameter;

	request->ldapscope = LDAP_SCOPE_SUBTREE;
	while (get_key_value(&p, &key, &value)) {
		if (strcmp(key, "ldaptls") == 0) {
			if (strcmp(value, "1") == 0)
				request->ldaptls = true;
			else
				request->ldaptls = false;
		} else if (strcmp(key, "ldapscheme") == 0) {
			if (strcmp(value, "ldap") != 0 && strcmp(value, "ldaps") != 0) {
				log_warning("invalid ldapscheme value: \"%s\"", value);
				return false;
			}
			ldap_parameter_dup(request, ldapscheme, value);
		} else if (strcmp(key, "ldapport") == 0) {
			request->ldapport = atoi(value);
			if (request->ldapport == 0) {
				log_warning("invalid LDAP port number: \"%s\"", value);
				return false;
			}
		} else if (strcmp(key, "ldapserver") == 0) {
			ldap_parameter_dup(request, ldapserver, value);
		} else if (strcmp(key, "ldapbinddn") == 0) {
			ldap_parameter_dup(request, ldapbinddn, value);
		} else if (strcmp(key, "ldapsearchattribute") == 0) {
			ldap_parameter_dup(request, ldapsearchattribute, value);
		} else if (strcmp(key, "ldapsearchfilter") == 0) {
			ldap_parameter_dup(request, ldapsearchfilter, value);
		} else if (strcmp(key, "ldapbasedn") == 0) {
			ldap_parameter_dup(request, ldapbasedn, value);
		} else if (strcmp(key, "ldapbindpasswd") == 0) {
			ldap_parameter_dup(request, ldapbindpasswd, value);
		} else if (strcmp(key, "ldapprefix") == 0) {
			ldap_parameter_dup(request, ldapprefix, value);
		} else if (strcmp(key, "ldapsuffix") == 0) {
			ldap_parameter_dup(request, ldapsuffix, value);
		} else if (strcmp(key, "ldapurl") == 0) {
			if (!parse_ldapurl(request, value))
				return false;
		} else {
			log_warning("invalid LDAP key parameter: \"%s\"", key);
			return false;
		}
	}

	return is_valid_parameter(request);
}

/*
 * Initiate the authentication request using LDAP. The request result will be
 * available during next calls to ldap_poll(). The function might block if the
 * request queue is full until there are free slots available.
 * The function is called only from the main thread.
 */
void ldap_auth_begin(PgSocket *client, const char *passwd)
{
	int next_free_slot = (ldap_first_free_slot + 1) % LDAP_REQUEST_QUEUE_SIZE;
	struct ldap_auth_request *request;

	slog_debug(
			client,
			"ldap_auth_begin(): ldap_first_taken_slot=%d, ldap_first_free_slot=%d",
			ldap_first_taken_slot, ldap_first_free_slot);

	client->wait_for_auth = true;

	/* Check that we have free slots in the queue, and if no
	 * then block until one is available.
	 */
	if (next_free_slot == ldap_first_taken_slot)
		slog_debug(client, "LDAP queue is full, waiting");

	while (next_free_slot == ldap_first_taken_slot) {
		if (ldap_poll() == 0) {
			/* Sleep a bit between consequent queue checks to avoid consuming too much CPU */
			usleep(LDAP_QUEUE_WAIT_SLEEP_MCS);
		}
	}

	pthread_mutex_lock(&ldap_queue_tail_mutex);

	request = &ldap_auth_queue[ldap_first_free_slot];

	request->client = client;
	request->connect_time = client->connect_time;
	request->status = LDAP_STATUS_IN_PROGRESS;
	memcpy(&request->remote_addr, &client->remote_addr, sizeof(client->remote_addr));
	safe_strcpy(request->username, client->login_user->name, MAX_USERNAME);
	safe_strcpy(request->password, passwd, MAX_PASSWORD);
	/* Reset value of ldap parameters */
	free_ldap_parameters(request);

	ldap_first_free_slot = next_free_slot;

	pthread_cond_signal(&ldap_data_available);
	pthread_mutex_unlock(&ldap_queue_tail_mutex);
}

/*
 * Checks for completed auth requests, returns amount of requests handled.
 * The function is called only from the main thread.
 */
int ldap_poll(void)
{
	struct ldap_auth_request *request;
	int count = 0;

	while (ldap_first_taken_slot != ldap_first_free_slot) {
		request = &ldap_auth_queue[ldap_first_taken_slot];

		if (request->status == LDAP_STATUS_IN_PROGRESS) {
			/* When still-in-progress slot is found there is no need to continue
			 * the loop since all further requests will be in progress too.
			 */
			break;
		}

		if (is_valid_socket(request)) {
			ldap_auth_finish(request);
		}

		count++;
		ldap_first_taken_slot = (ldap_first_taken_slot + 1) % LDAP_REQUEST_QUEUE_SIZE;
	}

	return count;
}


/*
 * The authentication thread function.
 * Performs scanning the queue for new requests and calling LDAP for them.
 */
static void *ldap_auth_worker(void *arg)
{
	int current_slot = ldap_first_taken_slot;
	struct ldap_auth_request *request;

	while (true) {

		/* Wait for new data in the queue */
		pthread_mutex_lock(&ldap_queue_tail_mutex);

		while (current_slot == ldap_first_free_slot) {
			pthread_cond_wait(&ldap_data_available, &ldap_queue_tail_mutex);
		}

		pthread_mutex_unlock(&ldap_queue_tail_mutex);

		log_debug("ldap_auth_worker(): processing slot %d", current_slot);

		/* We have at least one request in the queue */
		request = &ldap_auth_queue[current_slot];
		current_slot = (current_slot + 1) % LDAP_REQUEST_QUEUE_SIZE;

		/* If the socket is already in the wrong state or reused then ignore it.
		 * This check is not safe and should not be trusted (the socket state
		 * might change exactly after it), but it helps to quickly filter out invalid
		 * sockets and thus save some time.
		 */
		if (!is_valid_socket(request)) {
			log_debug("ldap_auth_worker(): invalid socket in slot %d", current_slot);
			request->status = LDAP_STATUS_FAILED;
			continue;
		}

		if (checkldapauth(request)) {
			request->status = LDAP_STATUS_SUCCESS;
		} else {
			request->status = LDAP_STATUS_FAILED;
		}

		log_debug("ldap_auth_worker(): authentication completed, status=%d", request->status);
	}

	return NULL;
}

/*
 * Checks that the socket is still valid to be processed.
 * By validity we mean that it is still waiting in the login phase
 * and was not reused for other connections.
 */
static bool is_valid_socket(const struct ldap_auth_request *request)
{
	if (request->client->state != CL_LOGIN || request->client->connect_time != request->connect_time)
		return false;
	return true;
}

/*
 * Finishes the handshake after successful or unsuccessful authentication.
 * The function is only called from the main thread.
 */
static void ldap_auth_finish(struct ldap_auth_request *request)
{
	PgSocket *client = request->client;
	bool authenticated = (request->status == LDAP_STATUS_SUCCESS);

	if (authenticated) {
		safe_strcpy(client->login_user->passwd, request->password, sizeof(client->login_user->passwd));
		sbuf_continue(&client->sbuf);
	} else {
		disconnect_client(client, true, "LDAP authentication failed");
	}
}

/*
 * Initialize a connection to the LDAP server, including setting up
 * TLS if requested.
 */
static bool
InitializeLDAPConnection(struct ldap_auth_request *request, LDAP **ldap)
{
	int ldapversion = LDAP_VERSION3;
	int r;
	struct timeval ts;

	if (strncmp(request->ldapserver, "ldaps://", 8) == 0 ||
		strncmp(request->ldapserver, "ldap://", 7) == 0) {
		if ((r = ldap_initialize(ldap, request->ldapserver)) != LDAP_SUCCESS) {
			log_warning("could not initialize LDAP: code: %d, msg: %s",
						r, ldap_err2string(r));
			*ldap = NULL;
			return false;
		}
	} else {
		*ldap = ldap_init(request->ldapserver, request->ldapport);
	}

	if (!*ldap) {
		log_warning("could not initialize LDAP: %m");
		return false;
	}

	if ((r = ldap_set_option(*ldap, LDAP_OPT_PROTOCOL_VERSION, &ldapversion)) != LDAP_SUCCESS) {
		ldap_unbind(*ldap);
		log_warning("could not set LDAP protocol version: %s", ldap_err2string(r));
		return false;
	}

	ts.tv_sec = 10;
	ts.tv_usec = 0;
	if ((r = ldap_set_option(*ldap, LDAP_OPT_NETWORK_TIMEOUT, &ts)) != LDAP_SUCCESS) {
		ldap_unbind(*ldap);
		log_warning("could not set LDAP timeout: %s", ldap_err2string(r));
		return false;
	}

	if (request->ldaptls) {
		if ((r = ldap_start_tls_s(*ldap, NULL, NULL)) != LDAP_SUCCESS) {
			ldap_unbind(*ldap);
			log_warning("could not start LDAP TLS session: %s, server: %s, port: %d",
						ldap_err2string(r), request->ldapserver, request->ldapport);
			return false;
		}
	}

	return true;
}
/* Placeholders recognized by formatsearchfilter.  For now just one. */
#define LPH_USERNAME "$username"
#define LPH_USERNAME_LEN strlen(LPH_USERNAME)
/*
 * Return a newly allocated C string copied from "pattern" with all
 * occurrences of the placeholder "$username" replaced with "user_name".
 */
static void
formatsearchfilter(char *filter, int length, const char *pattern, const char *user_name)
{
	int cur_len = 0;
	while ((*pattern != '\0') && (cur_len < length))
	{
		if (strncmp(pattern, LPH_USERNAME, LPH_USERNAME_LEN) == 0)
		{
			cur_len += snprintf(filter + cur_len, length - cur_len, "%s", user_name);
			pattern += LPH_USERNAME_LEN;
		}
		else {
			filter[cur_len++] = *pattern++;
		}
	}
	if (cur_len >= length)
		cur_len = length - 1;
	filter[cur_len] = '\0';
}
/*
 * Perform LDAP authentication
 */
static bool
checkldapauth(struct ldap_auth_request *request)
{
	LDAP *ldap;
	int r;
	char fulluser[LDAP_LONG_LENGTH];

	if (!ldap_initialize_parameters(request, request->client->ldap_parameters)) {
		return false;
	}
	if ((!request->ldapserver || request->ldapserver[0] == '\0') &&
		(!request->ldapbasedn || request->ldapbasedn[0] == '\0')) {
		log_warning("LDAP server not specified, and no ldapbasedn");
		return false;
	}

	if (request->ldapport == 0)
	{
		if (request->ldapscheme != NULL &&
			strcmp(request->ldapscheme, "ldaps") == 0)
			request->ldapport = LDAPS_PORT;
		else
			request->ldapport = LDAP_PORT;
	}

	if (request->password[0] == '\0') {
		return false;
	}

	if (InitializeLDAPConnection(request, &ldap) == false) {
		return false;
	}

	if (request->ldapbasedn) {
		/*
		 * First perform an LDAP search to find the DN for the user we are
		 * trying to log in as.
		 */
		char filter[LDAP_LONG_LENGTH];
		LDAPMessage *search_message;
		LDAPMessage *entry;
		char *attributes[2];
		char *dn;
		char *c;
		int count;

		/*
		 * Disallow any characters that we would otherwise need to escape,
		 * since they aren't really reasonable in a username anyway. Allowing
		 * them would make it possible to inject any kind of custom filters in
		 * the LDAP filter.
		 */
		for (c = request->username; *c; c++) {
			if (*c == '*' ||
				*c == '(' ||
				*c == ')' ||
				*c == '\\' ||
				*c == '/') {
				log_warning("invalid character in user name for LDAP authentication");
				return false;
			}
		}

		/*
		 * Bind with a pre-defined username/password (if available) for
		 * searching. If none is specified, this turns into an anonymous bind.
		 */
		r = ldap_simple_bind_s(ldap,
							   request->ldapbinddn ? request->ldapbinddn : "",
							   request->ldapbindpasswd ? request->ldapbindpasswd : "");
		if (r != LDAP_SUCCESS) {
			log_warning("could not perform initial LDAP bind for ldapbinddn \"%s\" on server \"%s\": %s",
						request->ldapbinddn ? request->ldapbinddn : "",
						request->ldapserver, ldap_err2string(r));
			ldap_unbind(ldap);
			return false;
		}

		/* Fetch just one attribute, else *all* attributes are returned */
		if (request->ldapsearchfilter)
			formatsearchfilter(filter, LDAP_LONG_LENGTH, request->ldapsearchfilter, request->username);
		else {
			attributes[0] = request->ldapsearchattribute ? request->ldapsearchattribute : "uid";
			attributes[1] = NULL;
			snprintf(filter, LDAP_LONG_LENGTH, "(%s=%s)",
					 attributes[0],
					 request->username);
		}

		r = ldap_search_s(ldap,
						  request->ldapbasedn,
						  request->ldapscope,
						  filter,
						  attributes,
						  0,
						  &search_message);

		if (r != LDAP_SUCCESS) {
			log_warning("could not search LDAP for filter \"%s\" on server \"%s\": %s",
						filter, request->ldapserver, ldap_err2string(r));
			ldap_unbind(ldap);
			return false;
		}

		count = ldap_count_entries(ldap, search_message);
		if (count != 1) {
			if (count == 0) {
				log_warning("LDAP user \"%s\" does not exist", request->username);
				log_warning("LDAP search for filter \"%s\" on server \"%s\" returned no entries.",
							filter, request->ldapserver);
			} else {
				log_warning("LDAP user \"%s\" is not unique", request->username);
				log_warning("LDAP search for filter \"%s\" on server \"%s\" returned %d entries.",
							filter, request->ldapserver, count);
			}
			ldap_unbind(ldap);
			ldap_msgfree(search_message);
			return false;
		}

		entry = ldap_first_entry(ldap, search_message);
		dn = ldap_get_dn(ldap, entry);
		if (dn == NULL) {
			int error;

			(void) ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &error);
			log_warning("could not get dn for the first entry matching \"%s\" on server \"%s\": %s",
						filter, request->ldapserver, ldap_err2string(error));
			ldap_unbind(ldap);
			ldap_msgfree(search_message);
			return false;
		}
		snprintf(fulluser, LDAP_LONG_LENGTH, "%s", dn);

		ldap_memfree(dn);
		ldap_msgfree(search_message);

		/* Unbind and disconnect from the LDAP server */
		r = ldap_unbind_s(ldap);
		if (r != LDAP_SUCCESS) {
			int error;

			(void) ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &error);
			log_warning("could not unbind after searching for user \"%s\" on server \"%s\": %s",
						fulluser, request->ldapserver, ldap_err2string(error));
			return false;
		}

		/*
		 * Need to re-initialize the LDAP connection, so that we can bind to
		 * it with a different username.
		 */
		if (InitializeLDAPConnection(request, &ldap) == false) {
			/* Error message already sent */
			return false;
		}
	} else
		snprintf(fulluser, LDAP_LONG_LENGTH, "%s%s%s",
				 request->ldapprefix ? request->ldapprefix : "",
				 request->username,
				 request->ldapsuffix ? request->ldapsuffix : "");

	r = ldap_simple_bind_s(ldap, fulluser, request->password);
	ldap_unbind(ldap);

	if (r != LDAP_SUCCESS) {
		log_warning("LDAP login failed for user %s on server %s: %s",
					fulluser, request->ldapserver, ldap_err2string(r));
		return false;
	}

	return true;
}

#else /* !HAVE_LDAP */

/* If LDAP is not supported then this dummy functions is used which always rejects passwords */

void auth_ldap_init(void)
{
	/* do nothing */
}

void ldap_auth_begin(PgSocket *client, const char *passwd)
{
	die("LDAP authentication is not supported");
}

int ldap_poll(void)
{
	/* do nothing */
	return 0;
}

#endif
