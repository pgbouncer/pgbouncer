
#include "bouncer.h"
#ifdef HAVE_GSS

#include <pthread.h>

/* The request is waiting in the queue or being authenticated */
#define GSS_STATUS_IN_PROGRESS  1
/* The request was successfully authenticated */
#define GSS_STATUS_SUCCESS      2
/* The request failed authentication */
#define GSS_STATUS_FAILED       3

/*
 * How many microseconds to sleep between calls to gss_poll in
 * gss_auth_begin when the queue is full.
 * Default is 100 milliseconds.
 */
#define GSS_QUEUE_WAIT_SLEEP_MCS        (100*1000)

struct gss_auth_request {
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

	/* The request status, one of the GSS_STATUS_* constants */
	int status;
	/* Protect status from main thread reading and worker thread writing at the same time */
	pthread_mutex_t mutex;

	uint8_t *token;
	uint32_t token_length;

	enum {
		GSS_INITIAL,
		GSS_CONTINUE,
		GSS_DONE
	} gss_state;

	/* The username (same as in client->login_user_credentials->name).
	 * See the comment for remote_addr.
	 *
	 */
	gss_name_t gss_name;	/* GSSAPI client name */
	char gss_parameters[MAX_GSS_CONFIG];
	int param_pos;
	char username[MAX_USERNAME];
	gss_ctx_id_t context;
	bool include_realm;
	char *krb_realm;
	OM_uint32 flags;
};

/*
 * All incoming requests are kept in a queue which is implemented using a ring buffer.
 * Such structure allows to avoid memory reallocation thus minimizing amount of
 * synchronization to be done between threads.
 *
 * gss_first_taken_slot points to the first element in the queue;
 * gss_first_free_slot points to the next slot after the last element in the queue.
 *
 * if gss_first_taken_slot == gss_first_free_slot then the queue is considered empty;
 *
 */
volatile int gss_first_taken_slot;
volatile int gss_first_free_slot;

pthread_t gss_worker_thread;

/*
 * Mutex serializes access to the queue's tail when we add new requests or
 * check that we reach the end of the queue in the worker thread.
 *
 * Head and tail are modified only in the main thread. In theory, being sure that they
 * are properly aligned we can access them directly without any risk for data races.
 * Practically, it is better to secure them anyway to increase overall stability and
 * provide faster notification of new requests via the condition variable.
 */
pthread_mutex_t gss_queue_tail_mutex;
pthread_cond_t gss_data_available;
struct gss_auth_request gss_auth_queue[GSS_REQUEST_QUEUE_SIZE];

/* Forward declarations */
static bool is_valid_socket(const struct gss_auth_request *request);
static void * gss_auth_worker(void *arg);
static void gss_auth_finish(struct gss_auth_request *request, int status);
static bool gss_recvauth(struct gss_auth_request *request);
static bool gss_checkauth(struct gss_auth_request *request);
static bool get_key_value(char **p, char **key, char **value);
static int get_request_status(struct gss_auth_request *request);
static void set_request_status(struct gss_auth_request *request, int status);

#define reset_ptr(ptr, name) ptr->name = NULL
#define gss_parameter_dup(ptr, name, src_str) \
	do {                                           \
		(ptr)->name = (ptr)->gss_parameters + (ptr)->param_pos; \
		safe_strcpy((ptr)->name, src_str, sizeof((ptr)->gss_parameters) - (ptr)->param_pos); \
		(ptr)->param_pos += strlen(src_str) + 1;      \
		if ((ptr)->param_pos >= MAX_GSS_CONFIG) {    \
			log_warning("The parameters are longer than MAX_GSS_CONFIG:%d", MAX_GSS_CONFIG); \
			return false; \
		} \
	} while (0)


static void free_gss_parameters(struct gss_auth_request *request)
{
	memset(request->gss_parameters, 0, MAX_GSS_CONFIG);
	request->param_pos = 0;
	reset_ptr(request, krb_realm);

	request->include_realm = 0;
}
static bool get_key_value(char **p, char **key, char **value)
{
	char *start, *name, *val;
	char *name_copy = NULL;
	char *val_copy = NULL;

	start = *p;
	while (*start && isspace(*start))
		++start;/* skip space */
	if (*start == ',')
		++start;/* skip ',' */
	while (*start && isspace(*start))
		++start;/* skip space */

	/* Parse key */
	if (*start == '"') {
		start++;
		name = start;
		name_copy = start;
		while (*start) {
			if (*start == '"' && *(start + 1) == '"') {
				*name_copy++ = '"';
				start += 2;
			} else if (*start == '"') {
				*name_copy = '\0';
				start++;
				break;
			} else {
				*name_copy++ = *start++;
			}
		}
		if ((!*start) || (*start != '='))
			return false;	/* Only key, stop scan */
	} else {
		name = start;
		name_copy = start;
		while ((*start) && (*start != '=')) {
			*name_copy++ = *start++;
		}
		if ((!*start) || (*start != '='))
			return false;	/* Only key, stop scan */
		*name_copy = '\0';
	}

	start++;// skip '='
	if (isspace(*start)) {
		/* Not allow insert space after '=' */
		return false;
	}

	/* Parse value */
	if (*start == '"') {
		start++;
		val = start;
		val_copy = start;
		while (*start) {
			if (*start == '"' && *(start + 1) == '"') {
				*val_copy++ = '"';
				start += 2;
			} else if (*start == '"') {
				*val_copy++ = '\0';
				start++;
				break;
			} else {
				*val_copy++ = *start++;
			}
		}
	} else {
		val = start;
		val_copy = start;
		while (*start && !(isspace(*start) || *start == ',')) {
			*val_copy++ = *start++;
		}
		if (*val_copy != '\0') {
			*val_copy = '\0';
			start++;
		}
	}
	if (*name == '\0' || *val == '\0') {
		return false;	/* No key or no value */
	}

	*p = start;
	*key = name;
	*value = val;
	return true;
}

static void ignore_space_from_end(char *parameter)
{
	int length = strlen(parameter);
	while (length > 0 && isspace(parameter[length - 1])) {
		parameter[length - 1] = '\0';
		length--;
	}
	return;
}

static bool initialize_gss_parameters(struct gss_auth_request *request, char *parameter)
{
	char *key, *value;
	char *p = parameter;

	/* There maybe \n at the end of parameter */
	ignore_space_from_end(parameter);
	request->include_realm = true;
	while (get_key_value(&p, &key, &value)) {
		if (strcmp(key, "include_realm") == 0) {
			if (strcmp(value, "0") == 0)
				request->include_realm = false;
		} else if (strcmp(key, "krb_realm") == 0) {
			gss_parameter_dup(request, krb_realm, value);
		} else {
			log_warning("invalid GSS key parameter: \"%s\"", key);
			return false;
		}
	}

	return true;
}

/*
 * Initialize GSS subsystem.
 */
void gss_init(void)
{
	int rc;

	gss_first_taken_slot = 0;
	gss_first_free_slot = 0;

	rc = pthread_mutex_init(&gss_queue_tail_mutex, NULL);
	if (rc != 0) {
		die("failed to initialize a mutex: %s", strerror(errno));
	}

	rc = pthread_cond_init(&gss_data_available, NULL);
	if (rc != 0) {
		die("failed to initialize a condition variable: %s", strerror(errno));
	}

	rc = pthread_create(&gss_worker_thread, NULL, &gss_auth_worker, NULL);
	if (rc != 0) {
		die("failed to create the authentication thread: %s", strerror(errno));
	}
}

/*
 * Initiate the authentication request using GSS. The request result will be
 * available during next calls to gss_poll(). The function might block if the
 * request queue is full until there are free slots available.
 * The function is called only from the main thread.
 */
void gss_auth_begin(PgSocket *client, uint8_t *token, uint32_t token_length)
{
	int next_free_slot = (gss_first_free_slot + 1) % GSS_REQUEST_QUEUE_SIZE;
	struct gss_auth_request *request;

	slog_debug(
		client,
		"gss_auth_begin(): gss_first_taken_slot=%d, gss_first_free_slot=%d",
		gss_first_taken_slot, gss_first_free_slot);

	client->wait_for_auth = true;

	/* Check that we have free slots in the queue, and if no
	 * then block until one is available.
	 */
	if (next_free_slot == gss_first_taken_slot)
		slog_warning(client, "GSS queue is full, waiting");

	while (next_free_slot == gss_first_taken_slot) {
		if (gss_poll() == 0) {
			/* Sleep a bit between consequent queue checks to avoid consuming too much CPU */
			usleep(GSS_QUEUE_WAIT_SLEEP_MCS);
		}
	}

	pthread_mutex_lock(&gss_queue_tail_mutex);

	request = &gss_auth_queue[gss_first_free_slot];

	request->token = token;
	request->token_length = token_length;

	request->client = client;
	request->connect_time = client->connect_time;
	request->status = GSS_STATUS_IN_PROGRESS;	/* This is protected by gss_queue_tail_mutex */
	memcpy(&request->remote_addr, &client->remote_addr, sizeof(client->remote_addr));
	safe_strcpy(request->username, client->login_user_credentials->name, MAX_USERNAME);

	free_gss_parameters(request);

	gss_first_free_slot = next_free_slot;

	pthread_cond_signal(&gss_data_available);
	pthread_mutex_unlock(&gss_queue_tail_mutex);
}

static int get_request_status(struct gss_auth_request *request)
{
	int rc = 0;

	pthread_mutex_lock(&request->mutex);
	rc = request->status;
	pthread_mutex_unlock(&request->mutex);
	return rc;
}

static void set_request_status(struct gss_auth_request *request, int status)
{
	pthread_mutex_lock(&request->mutex);
	request->status = status;
	pthread_mutex_unlock(&request->mutex);
}

/*
 * Checks for completed auth requests, returns amount of requests handled.
 * The function is called only from the main thread.
 */
int gss_poll(void)
{
	struct gss_auth_request *request;
	int count = 0;
	int status = 0;

	while (gss_first_taken_slot != gss_first_free_slot) {
		request = &gss_auth_queue[gss_first_taken_slot];

		status = get_request_status(request);
		if (status == GSS_STATUS_IN_PROGRESS) {
			/* When still-in-progress slot is found there is no need to continue
			 * the loop since all further requests will be in progress too.
			 */
			break;
		}

		if (is_valid_socket(request)) {
			gss_auth_finish(request, status);
		}

		count++;
		gss_first_taken_slot = (gss_first_taken_slot + 1) % GSS_REQUEST_QUEUE_SIZE;
	}

	return count;
}

/*
 * The authentication thread function.
 * Performs scanning the queue for new requests and calling GSS for them.
 */
static void * gss_auth_worker(void *arg)
{
	int current_slot = gss_first_taken_slot;
	struct gss_auth_request *request;
	int request_status = 0;

	while (true) {
		/* Wait for new data in the queue */
		pthread_mutex_lock(&gss_queue_tail_mutex);

		while (current_slot == gss_first_free_slot) {
			pthread_cond_wait(&gss_data_available, &gss_queue_tail_mutex);
		}

		pthread_mutex_unlock(&gss_queue_tail_mutex);

		log_debug("gss_auth_worker(): processing slot %d", current_slot);

		/* We have at least one request in the queue */
		request = &gss_auth_queue[current_slot];
		current_slot = (current_slot + 1) % GSS_REQUEST_QUEUE_SIZE;

		if (gss_recvauth(request)) {
			request_status = GSS_STATUS_SUCCESS;
		} else {
			request_status = GSS_STATUS_FAILED;
		}
		set_request_status(request, request_status);

		log_debug("gss_auth_worker(): authentication completed, status=%d", request_status);
	}

	return NULL;
}


static bool gss_recvauth(struct gss_auth_request *request)
{
	gss_buffer_desc send_tok;
	OM_uint32 maj_stat,
		  min_stat,
		  lmin_s;
	gss_buffer_desc gbuf;
	gss_cred_id_t server_credentials, delegated_creds;

	if (!initialize_gss_parameters(request, request->client->gss_parameters)) {
		return false;
	}

	if (!cf_auth_krb_server_keyfile) {
		log_debug("No cf_auth_krb_server_keyfile specified in config");
		return false;
	}
	setenv("KRB5_KTNAME", cf_auth_krb_server_keyfile, 1);
	if (GSS_INITIAL == request->gss_state) {
		request->context = GSS_C_NO_CONTEXT;
	}

	gbuf.length = request->token_length;
	gbuf.value = request->token;

	log_debug("Received GSSAPI token.");
	server_credentials = GSS_C_NO_CREDENTIAL;
	delegated_creds = GSS_C_NO_CREDENTIAL;

	/* Accept the context. */
	maj_stat = gss_accept_sec_context(&min_stat,
					  &request->context,
					  server_credentials,
					  &gbuf,
					  GSS_C_NO_CHANNEL_BINDINGS,
					  &request->gss_name,
					  NULL,
					  &send_tok,
					  &request->flags,
					  NULL,
					  cf_auth_gss_accept_delegation ? &delegated_creds : NULL);

	log_debug("gss_accept_sec_context major: %u, "
		  "minor: %u, outlen: %u, outflags: %x",
		  maj_stat, min_stat,
		  (unsigned int) send_tok.length, request->flags);

	/* Send back token to the client, if expected to do so. */
	if (send_tok.length != 0) {
		PktBuf _buf;
		uint8_t _data[512];

		log_debug("sending GSS response token of length %u", (unsigned int) send_tok.length);

		/* Construct a custom response with the token */
		pktbuf_static(&_buf, _data, sizeof(_data));
		pktbuf_put_char(&_buf, 'R');
		pktbuf_put_uint32(&_buf, send_tok.length + 4 + 4);
		pktbuf_put_uint32(&_buf, AUTH_REQ_GSS_CONT);
		pktbuf_put_bytes(&_buf, send_tok.value, send_tok.length);

		if (!pktbuf_send_immediate(&_buf, request->client)) {
			gss_release_buffer(&lmin_s, &send_tok);
			log_debug("Failed to send gss token to client");
			return false;
		}
		gss_release_buffer(&lmin_s, &send_tok);
	}

	if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
		gss_delete_sec_context(&lmin_s, &request->context, GSS_C_NO_BUFFER);
		log_debug("accepting GSS security context failed major: %u, minor: %u",
			  maj_stat, min_stat);
		return false;
	}

	if (maj_stat == GSS_S_CONTINUE_NEEDED) {
		request->gss_state = GSS_CONTINUE;
		log_debug("GSS continue needed");
	}

	if (server_credentials != GSS_C_NO_CREDENTIAL) {
		/*
		 * Release service principal credentials
		 */
		gss_release_cred(&min_stat, &server_credentials);
	}

	return gss_checkauth(request);
}

static bool gss_checkauth(struct gss_auth_request *request)
{
	int ret;
	OM_uint32 maj_stat,
		  min_stat,
		  lmin_s;
	gss_buffer_desc gbuf;
	char *princ;

	maj_stat = gss_display_name(&min_stat, request->gss_name, &gbuf, NULL);

	if (maj_stat != GSS_S_COMPLETE) {
		log_warning("retrieving GSS user name failed major: %u, minor: %u", maj_stat, min_stat);
		return false;
	}

	princ = malloc(gbuf.length + 1);
	memcpy(princ, gbuf.value, gbuf.length);
	gss_release_buffer(&lmin_s, &gbuf);

	if (strchr(princ, '@')) {
		char *cp = strchr(princ, '@');

		if (!request->include_realm)
			*cp = '\0';
		cp++;

		if (request->krb_realm != NULL && strlen(request->krb_realm)) {
			if (cf_auth_krb_caseins_users) {
				ret = strcasecmp(cp, request->krb_realm);
			} else {
				ret = strcmp(cp, request->krb_realm);
			}

			if (ret) {
				log_warning("GSSAPI realm (%s) and configured realm (%s) don't match", cp, request->krb_realm);
				free(princ);
				return false;
			}
		}
	}
	if (cf_auth_krb_caseins_users == 0) {
		ret = strcmp(princ, request->username);
	} else {
		ret = strcasecmp(princ, request->username);
	}
	if (ret) {
		log_warning("provided user name (%s) and authenticated user name (%s) do not match", request->username, princ);
		free(princ);
		return false;
	}
	free(princ);
	return true;
}

/*
 * Checks that the socket is still valid to be processed.
 * By validity we mean that it is still waiting in the login phase
 * and was not reused for other connections.
 */
static bool is_valid_socket(const struct gss_auth_request *request)
{
	if (request->client->state != CL_LOGIN || request->client->connect_time != request->connect_time)
		return false;
	return true;
}

/*
 * Finishes the handshake after successful or unsuccessful authentication.
 * The function is only called from the main thread.
 */
static void gss_auth_finish(struct gss_auth_request *request, int status)
{
	PgSocket *client = request->client;
	bool authenticated = (status == GSS_STATUS_SUCCESS);

	if (authenticated) {
		sbuf_continue(&client->sbuf);
	} else {
		disconnect_client(client, true, "GSS authentication failed");
	}
}

#else /* !HAVE_GSS */

/* If GSS is not supported then this dummy functions is used which always rejects passwords */

void gss_init(void)
{
	/* do nothing */
}

void gss_auth_begin(PgSocket *client, uint8_t *token, uint32_t token_length)
{
	die("GSS authentication is not supported");
}

int gss_poll(void)
{
	/* do nothing */
	return 0;
}

#endif
