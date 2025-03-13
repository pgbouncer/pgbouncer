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
 * PAM authentication support.
 */

#include "bouncer.h"

#ifdef HAVE_PAM

#include <pthread.h>
#include <security/pam_appl.h>

/* The request is waiting in the queue or being authenticated */
#define PAM_STATUS_IN_PROGRESS  1
/* The request was successfully authenticated */
#define PAM_STATUS_SUCCESS      2
/* The request failed authentication */
#define PAM_STATUS_FAILED       3

/*
 * How many microseconds to sleep between calls to pam_poll in
 * pam_auth_begin when the queue is full.
 * Default is 100 milliseconds.
 */
#define PAM_QUEUE_WAIT_SLEEP_MCS        (100*1000)


struct pam_auth_request {
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

	/* The request status, one of the PAM_STATUS_* constants */
	int status;
	/* Protect status from main thread reading and worker thread writing at the same time */
	pthread_mutex_t mutex;

	/* The username (same as in client->login_user_credentials->name).
	 * See the comment for remote_addr.
	 */
	char username[MAX_USERNAME];

	/* password we should check for validity together with the socket's username */
	char password[MAX_PASSWORD];
};


/*
 * All incoming requests are kept in a queue which is implemented using a ring buffer.
 * Such structure allows to avoid memory reallocation thus minimizing amount of
 * synchronization to be done between threads.
 *
 * pam_first_taken_slot points to the first element in the queue;
 * pam_first_free_slot points to the next slot after the last element in the queue.
 *
 * if pam_first_taken_slot == pam_first_free_slot then the queue is considered empty;
 *
 */
volatile int pam_first_taken_slot;
volatile int pam_first_free_slot;
struct pam_auth_request pam_auth_queue[PAM_REQUEST_QUEUE_SIZE];

pthread_t pam_worker_thread;

/*
 * Mutex serializes access to the queue's tail when we add new requests or
 * check that we reach the end of the queue in the worker thread.
 *
 * Head and tail are modified only in the main thread. In theory, being sure that they
 * are properly aligned we can access them directly without any risk for data races.
 * Practically, it is better to secure them anyway to increase overall stability and
 * provide faster notification of new requests via the condition variable.
 */
pthread_mutex_t pam_queue_tail_mutex;
pthread_cond_t pam_data_available;

/* Forward declarations */
static void * pam_auth_worker(void *arg);
static bool is_valid_socket(const struct pam_auth_request *request);
static void pam_auth_finish(struct pam_auth_request *request);
static bool pam_check_passwd(struct pam_auth_request *request);
static int get_request_status(struct pam_auth_request *request);
static void set_request_status(struct pam_auth_request *request, int status);

/*
 * Initialize PAM subsystem.
 */
void pam_init(void)
{
	int rc;

	pam_first_taken_slot = 0;
	pam_first_free_slot = 0;

	rc = pthread_mutex_init(&pam_queue_tail_mutex, NULL);
	if (rc != 0) {
		die("failed to initialize a mutex: %s", strerror(errno));
	}

	rc = pthread_cond_init(&pam_data_available, NULL);
	if (rc != 0) {
		die("failed to initialize a condition variable: %s", strerror(errno));
	}

	rc = pthread_create(&pam_worker_thread, NULL, &pam_auth_worker, NULL);
	if (rc != 0) {
		die("failed to create the authentication thread: %s", strerror(errno));
	}
}

/*
 * Initiate the authentication request using PAM. The request result will be
 * available during next calls to pam_poll(). The function might block if the
 * request queue is full until there are free slots available.
 * The function is called only from the main thread.
 */
void pam_auth_begin(PgSocket *client, const char *passwd)
{
	int next_free_slot = (pam_first_free_slot + 1) % PAM_REQUEST_QUEUE_SIZE;
	struct pam_auth_request *request;

	slog_debug(
		client,
		"pam_auth_begin(): pam_first_taken_slot=%d, pam_first_free_slot=%d",
		pam_first_taken_slot, pam_first_free_slot);

	client->wait_for_auth = true;

	/* Check that we have free slots in the queue, and if no
	 * then block until one is available.
	 */
	if (next_free_slot == pam_first_taken_slot)
		slog_debug(client, "PAM queue is full, waiting");

	while (next_free_slot == pam_first_taken_slot) {
		if (pam_poll() == 0) {
			/* Sleep a bit between consequent queue checks to avoid consuming too much CPU */
			usleep(PAM_QUEUE_WAIT_SLEEP_MCS);
		}
	}

	pthread_mutex_lock(&pam_queue_tail_mutex);

	request = &pam_auth_queue[pam_first_free_slot];

	request->client = client;
	request->connect_time = client->connect_time;
	request->status = PAM_STATUS_IN_PROGRESS;	/* This is protected by pam_queue_tail_mutex */
	memcpy(&request->remote_addr, &client->remote_addr, sizeof(client->remote_addr));
	safe_strcpy(request->username, client->login_user_credentials->name, MAX_USERNAME);
	safe_strcpy(request->password, passwd, MAX_PASSWORD);

	pam_first_free_slot = next_free_slot;

	pthread_cond_signal(&pam_data_available);
	pthread_mutex_unlock(&pam_queue_tail_mutex);
}


static int get_request_status(struct pam_auth_request *request)
{
	int rc = 0;

	pthread_mutex_lock(&request->mutex);
	rc = request->status;
	pthread_mutex_unlock(&request->mutex);
	return rc;
}

static void set_request_status(struct pam_auth_request *request, int status)
{
	pthread_mutex_lock(&request->mutex);
	request->status = status;
	pthread_mutex_unlock(&request->mutex);
}

/*
 * Checks for completed auth requests, returns amount of requests handled.
 * The function is called only from the main thread.
 */
int pam_poll(void)
{
	struct pam_auth_request *request;
	int count = 0;
	int status = 0;

	while (pam_first_taken_slot != pam_first_free_slot) {
		request = &pam_auth_queue[pam_first_taken_slot];

		status = get_request_status(request);
		if (status == PAM_STATUS_IN_PROGRESS) {
			/* When still-in-progress slot is found there is no need to continue
			 * the loop since all further requests will be in progress too.
			 */
			break;
		}

		if (is_valid_socket(request)) {
			pam_auth_finish(request);
		}

		count++;
		pam_first_taken_slot = (pam_first_taken_slot + 1) % PAM_REQUEST_QUEUE_SIZE;
	}

	return count;
}


/*
 * The authentication thread function.
 * Performs scanning the queue for new requests and calling PAM for them.
 */
static void * pam_auth_worker(void *arg)
{
	int current_slot = pam_first_taken_slot;
	struct pam_auth_request *request;
	int request_status = 0;

	while (true) {
		/* Wait for new data in the queue */
		pthread_mutex_lock(&pam_queue_tail_mutex);

		while (current_slot == pam_first_free_slot) {
			pthread_cond_wait(&pam_data_available, &pam_queue_tail_mutex);
		}

		pthread_mutex_unlock(&pam_queue_tail_mutex);

		log_debug("pam_auth_worker(): processing slot %d", current_slot);

		/* We have at least one request in the queue */
		request = &pam_auth_queue[current_slot];
		current_slot = (current_slot + 1) % PAM_REQUEST_QUEUE_SIZE;

		if (pam_check_passwd(request)) {
			request_status = PAM_STATUS_SUCCESS;
		} else {
			request_status = PAM_STATUS_FAILED;
		}
		set_request_status(request, request_status);

		log_debug("pam_auth_worker(): authentication completed, status=%d", request->status);
	}

	return NULL;
}

/*
 * Checks that the socket is still valid to be processed.
 * By validity we mean that it is still waiting in the login phase
 * and was not reused for other connections.
 */
static bool is_valid_socket(const struct pam_auth_request *request)
{
	if (request->client->state != CL_LOGIN || request->client->connect_time != request->connect_time)
		return false;
	return true;
}

/*
 * Finishes the handshake after successful or unsuccessful authentication.
 * The function is only called from the main thread.
 */
static void pam_auth_finish(struct pam_auth_request *request)
{
	PgSocket *client = request->client;
	bool authenticated = (request->status == PAM_STATUS_SUCCESS);

	if (authenticated) {
		safe_strcpy(client->login_user_credentials->passwd, request->password, sizeof(client->login_user_credentials->passwd));
		sbuf_continue(&client->sbuf);
	} else {
		disconnect_client(client, true, "PAM authentication failed");
	}
}

static int pam_conversation(int msgc,
			    const struct pam_message **msgv,
			    struct pam_response **rspv,
			    void *authdata)
{
	struct pam_auth_request *request = (struct pam_auth_request *)authdata;
	int i, rc;

	if (msgc < 1 || msgv == NULL || request == NULL) {
		log_debug(
			"pam_conversation(): wrong input, msgc=%d, msgv=%p, authdata=%p",
			msgc, msgv, authdata);
		return PAM_CONV_ERR;
	}

	/* Allocate and fill with zeroes an array of responses.
	 * By filling with zeroes we automatically set resp_retcode to
	 * zero and simplify freeing resp on errors.
	 */
	*rspv = malloc(msgc * sizeof(struct pam_response));
	if (*rspv == NULL) {
		log_warning("pam_conversation(): not enough memory for responses");
		return PAM_CONV_ERR;
	}

	memset(*rspv, 0, msgc * sizeof(struct pam_response));

	rc = PAM_SUCCESS;

	for (i = 0; i < msgc; i++) {
		if (rc != PAM_SUCCESS)
			break;

		switch (msgv[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			(*rspv)[i].resp = strdup(request->password);
			if ((*rspv)[i].resp == NULL) {
				log_warning("pam_conversation(): not enough memory for password");
				rc = PAM_CONV_ERR;
			}
			break;

		case PAM_ERROR_MSG:
			log_warning(
				"pam_conversation(): PAM error: %s",
				msgv[i]->msg);
			break;

		default:
			log_debug(
				"pam_conversation(): unhandled message, msg_style=%d",
				msgv[i]->msg_style);
			break;
		}
	}

	if (rc != PAM_SUCCESS) {
		for (i = 0; i < msgc; i++)
			free((*rspv)[i].resp);
		free(*rspv);
	}

	return rc;
}


static bool pam_check_passwd(struct pam_auth_request *request)
{
	pam_handle_t *hpam;
	char raddr[PGADDR_BUF];
	int rc;

	struct pam_conv pam_conv = {
		.conv = pam_conversation,
		.appdata_ptr = request
	};

	rc = pam_start(PGBOUNCER_PAM_SERVICE, request->username, &pam_conv, &hpam);
	if (rc != PAM_SUCCESS) {
		log_warning("pam_start() failed: %s", pam_strerror(NULL, rc));
		return false;
	}

	/* Set rhost too in case if some PAM modules want to take it into account (and for logging too) */
	pga_ntop(&request->remote_addr, raddr, sizeof(raddr));
	rc = pam_set_item(hpam, PAM_RHOST, raddr);
	if (rc != PAM_SUCCESS) {
		log_warning("pam_set_item(): can't set PAM_RHOST to '%s'", raddr);
		pam_end(hpam, rc);
		return false;
	}

	/* Here the authentication is performed */
	rc = pam_authenticate(hpam, PAM_SILENT);
	if (rc != PAM_SUCCESS) {
		log_warning("pam_authenticate() failed: %s", pam_strerror(hpam, rc));
		pam_end(hpam, rc);
		return false;
	}

	/* And here we check that the account is not expired, verifies access hours, etc */
	rc = pam_acct_mgmt(hpam, PAM_SILENT);
	if (rc != PAM_SUCCESS) {
		log_warning("pam_acct_mgmt() failed: %s", pam_strerror(hpam, rc));
		pam_end(hpam, rc);
		return false;
	}

	rc = pam_end(hpam, rc);
	if (rc != PAM_SUCCESS) {
		log_warning("pam_end() failed: %s", pam_strerror(hpam, rc));
	}

	return true;
}

#else /* !HAVE_PAM */

/* If PAM is not supported then this dummy functions is used which always rejects passwords */

void pam_init(void)
{
	/* do nothing */
}

void pam_auth_begin(PgSocket *client, const char *passwd)
{
	die("PAM authentication is not supported");
}

int pam_poll(void)
{
	/* do nothing */
	return 0;
}

#endif
