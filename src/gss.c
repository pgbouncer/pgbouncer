
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

	uint8_t *token;
	uint32_t token_length;

	/* The username (same as in client->login_user_credentials->name).
	 * See the comment for remote_addr.
	 *
	 */
	// TODO Probably dont need
	char username[MAX_USERNAME];
	gss_ctx_id_t *context;
	OM_uint32 *flags;
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
static void gss_auth_finish(struct gss_auth_request *request);
static bool gss_check_passwd(struct gss_auth_request *request);

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
		slog_debug(client, "GSS queue is full, waiting");

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
	request->status = GSS_STATUS_IN_PROGRESS;
	memcpy(&request->remote_addr, &client->remote_addr, sizeof(client->remote_addr));
	safe_strcpy(request->username, client->login_user_credentials->name, MAX_USERNAME);
// safe_strcpy(request->password, passwd, MAX_PASSWORD);
	request->context = &client->gss.ctx;
	request->flags = &client->gss.flags;
	gss_first_free_slot = next_free_slot;

	pthread_mutex_unlock(&gss_queue_tail_mutex);
	pthread_cond_signal(&gss_data_available);
}

/*
 * Checks for completed auth requests, returns amount of requests handled.
 * The function is called only from the main thread.
 */
int gss_poll(void)
{
	struct gss_auth_request *request;
	int count = 0;

	while (gss_first_taken_slot != gss_first_free_slot) {
		request = &gss_auth_queue[gss_first_taken_slot];

		if (request->status == GSS_STATUS_IN_PROGRESS) {
			/* When still-in-progress slot is found there is no need to continue
			 * the loop since all further requests will be in progress too.
			 */
			break;
		}

		if (is_valid_socket(request)) {
			gss_auth_finish(request);
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

		/* If the socket is already in the wrong state or reused then ignore it.
		 * This check is not safe and should not be trusted (the socket state
		 * might change exactly after it), but it helps to quickly filter out invalid
		 * sockets and thus save some time.
		 */
		if (!is_valid_socket(request)) {
			log_debug("gss_auth_worker(): invalid socket in slot %d", current_slot);
			request->status = GSS_STATUS_FAILED;
			continue;
		}

		if (gss_check_passwd(request)) {
			request->status = GSS_STATUS_SUCCESS;
		} else {
			request->status = GSS_STATUS_FAILED;
		}

		log_debug("gss_auth_worker(): authentication completed, status=%d", request->status);
	}

	return NULL;
}


// TODO Change name, this function does not actually check password
static bool gss_check_passwd(struct gss_auth_request *request)
{
	gss_buffer_desc send_tok;
	gss_name_t user_name;
	OM_uint32 maj_stat, min_stat, acc_sec_min_stat, lmin_s;
	gss_buffer_desc gbuf;
	gss_cred_id_t server_credentials;
	char *princ;

	if (!cf_krb_server_keyfile) {
		log_debug("No cf_krb_server_keyfile specified in config");
		return false;
	}
	setenv("KRB5_KTNAME", cf_krb_server_keyfile, 1);
	if (GSS_INITIAL == request->client->gss.state) {
		*(request->context) = GSS_C_NO_CONTEXT;
	}

	gbuf.length = request->token_length;
	gbuf.value = request->token;

	log_debug("Received GSSAPI token.");
	server_credentials = GSS_C_NO_CREDENTIAL;
	/* Accept the context. */
	maj_stat = gss_accept_sec_context(&acc_sec_min_stat,
					  request->context,
					  server_credentials,
					  &gbuf,
					  GSS_C_NO_CHANNEL_BINDINGS,
					  &user_name,
					  NULL,
					  &send_tok,
					  request->flags,
					  NULL,
					  NULL);

	log_debug("Evaluation of GSSAPI token");

	log_debug("gss_accept_sec_context major: %u, "
		  "minor: %u, outlen: %u, outflags: %x",
		  maj_stat, min_stat,
		  (unsigned int) send_tok.length, *request->flags);

	if (GSS_S_COMPLETE != maj_stat) {
		return false;
	}

	/* Send back token to the client, if expected to do so. */
	if (0 != send_tok.length) {
		PktBuf _buf;
		int res;
		uint8_t _data[512];

		log_debug("Acknowledged and returing token to client");

		/* Construct a custom response with the token */
		pktbuf_static(&_buf, _data, sizeof(_data));
		pktbuf_put_char(&_buf, 'R');
		pktbuf_put_uint32(&_buf, send_tok.length + 4 + 4);
		pktbuf_put_uint32(&_buf, 8);
		pktbuf_put_bytes(&_buf, send_tok.value, send_tok.length);

		if (false == (res = pktbuf_send_immediate(&_buf, request->client))) {
			return false;
		}
	}

	if ((GSS_S_COMPLETE != maj_stat) && (GSS_S_CONTINUE_NEEDED != maj_stat)) {
		log_debug("No content");
		gss_delete_sec_context(&min_stat, request->context, GSS_C_NO_BUFFER);
		return false;
	}

	if (GSS_S_CONTINUE_NEEDED == maj_stat) {
		request->client->gss.state = GSS_CONTINUE;
		log_debug("Will run GSSAPI continuation in another pass later");
	} else {
		request->client->gss.state = GSS_DONE;

		if (*request->flags & GSS_C_DELEG_FLAG)
			log_debug("context flag: GSS_C_DELEG_FLAG");
		if (*request->flags & GSS_C_MUTUAL_FLAG)
			log_debug("context flag: GSS_C_MUTUAL_FLAG");
		if (*request->flags & GSS_C_REPLAY_FLAG)
			log_debug("context flag: GSS_C_REPLAY_FLAG");
		if (*request->flags & GSS_C_SEQUENCE_FLAG)
			log_debug("context flag: GSS_C_SEQUENCE_FLAG");
		if (*request->flags & GSS_C_CONF_FLAG)
			log_debug("context flag: GSS_C_CONF_FLAG");
		if (*request->flags & GSS_C_INTEG_FLAG) {
			log_debug("context flag: GSS_C_INTEG_FLAG");
		} else {
			log_debug("No delegated credentials.");	/* Just for the info */
		}
	}


	maj_stat = gss_display_name(&min_stat, user_name, &gbuf, NULL);

	if (maj_stat != GSS_S_COMPLETE) {
		log_warning("gss_release_name_failed");	/* Just for the info */
		return false;
	}

	princ = valloc(gbuf.length + 1);
	memcpy(princ, gbuf.value, gbuf.length);
	princ[gbuf.length] = '\0';
	gss_release_buffer(&lmin_s, &gbuf);
	log_debug("princ %s", princ);

	if (GSS_S_COMPLETE != gss_release_name(&min_stat, &user_name)) {
		log_warning("gss_release_name_failed");	/* Just for the info */
		return false;
	}

	if (strchr(princ, '@')) {
		char *cp = strchr(princ, '@');
		*cp = '\0';
		cp++;
	}
	if (strcmp(princ, request->username) != 0) {
		log_warning("gss_name_mismatch");	/* Just for the info */
		return false;
	}
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
static void gss_auth_finish(struct gss_auth_request *request)
{
	PgSocket *client = request->client;
	bool authenticated = (request->status == GSS_STATUS_SUCCESS);

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
