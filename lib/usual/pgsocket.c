/*
 * Async Postgres connection.
 *
 * Copyright (c) 2009  Marko Kreen
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

#include <usual/pgsocket.h>

#include <usual/logging.h>
#include <usual/time.h>
#include <usual/string.h>

#include <event.h>

#define MAX_QRY_ARGS 32

/* PgSocket.wait_type */
enum WType {
	W_NONE = 0,
	W_SOCK,
	W_TIME
};

typedef void (*libev_cb)(int sock, short flags, void *arg);

struct PgSocket {
	/* libevent state */
	struct event ev;

	/* track wait state */
	enum WType wait_type;

	/* EV_READ / EV_WRITE */
	uint8_t wait_event;

	/* should connect after sleep */
	bool reconnect;

	/* current connection */
	PGconn *con;

	/* user handler */
	pgs_handler_f handler_func;
	void *handler_arg;

	/* saved connect string */
	char *connstr;

	/* custom base or NULL */
	struct event_base *base;

	/* temp place for resultset */
	PGresult *last_result;

	usec_t connect_time;
	usec_t lifetime;
};

/* report event to user callback */
static void send_event(struct PgSocket *db, enum PgEvent ev)
{
	db->handler_func(db, db->handler_arg, ev, NULL);
}

/* wait socket event from libevent */
static void wait_event(struct PgSocket *db, short ev, libev_cb fn)
{
	Assert(!db->wait_type);

	event_set(&db->ev, PQsocket(db->con), ev, fn, db);
	if (db->base)
		event_base_set(db->base, &db->ev);
	if (event_add(&db->ev, NULL) < 0)
		die("event_add failed: %s", strerror(errno));

	db->wait_type = W_SOCK;
	db->wait_event = ev;
}

/* wait timeout from libevent */
static void timeout_cb(evutil_socket_t sock, short flags, void *arg)
{
	struct PgSocket *db = arg;

	db->wait_type = W_NONE;

	if (db->reconnect) {
		db->reconnect = false;
		pgs_connect(db);
	} else {
		send_event(db, PGS_TIMEOUT);
	}
}

/* some error happened */
static void conn_error(struct PgSocket *db, enum PgEvent ev, const char *desc)
{
	log_error("connection error: %s", desc);
	log_error("libpq: %s", PQerrorMessage(db->con));
	send_event(db, ev);
}

/* report previously stored result */
static void report_last_result(struct PgSocket *db)
{
	PGresult *res = db->last_result;
	if (!res)
		return;
	db->last_result = NULL;

	switch (PQresultStatus(res)) {
	default:
		log_error("%s: %s", PQdb(db->con), PQresultErrorMessage(res));
	/* fallthrough */
	case PGRES_COMMAND_OK:
	case PGRES_TUPLES_OK:
	case PGRES_COPY_OUT:
	case PGRES_COPY_IN:
		db->handler_func(db, db->handler_arg, PGS_RESULT_OK, res);
	}
	PQclear(res);
}

/*
 * Called when select() told that conn is avail for reading.
 *
 * It should call postgres handlers and then change state if needed.
 *
 * Because the callback may want to close the connection when processing
 * last resultset, the PGresult handover is delayed one step.
 */
static void result_cb(evutil_socket_t sock, short flags, void *arg)
{
	struct PgSocket *db = arg;
	PGresult *res;

	db->wait_type = W_NONE;

	if (!PQconsumeInput(db->con)) {
		conn_error(db, PGS_RESULT_BAD, "PQconsumeInput");
		return;
	}

	/* loop until PQgetResult returns NULL */
	while (db->con) {
		/* incomplete result? */
		if (PQisBusy(db->con)) {
			wait_event(db, EV_READ, result_cb);
			return;
		}

		/* next result */
		res = PQgetResult(db->con);
		if (!res)
			break;

		report_last_result(db);
		db->last_result = res;
	}

	report_last_result(db);
}

static void flush(struct PgSocket *db);

static void send_cb(evutil_socket_t sock, short flags, void *arg)
{
	struct PgSocket *db = arg;

	db->wait_type = W_NONE;

	flush(db);
}

/* handle connect states */
static void connect_cb(evutil_socket_t sock, short flags, void *arg)
{
	struct PgSocket *db = arg;
	PostgresPollingStatusType poll_res;

	db->wait_type = W_NONE;

	poll_res = PQconnectPoll(db->con);
	switch (poll_res) {
	case PGRES_POLLING_WRITING:
		wait_event(db, EV_WRITE, connect_cb);
		break;
	case PGRES_POLLING_READING:
		wait_event(db, EV_READ, connect_cb);
		break;
	case PGRES_POLLING_OK:
		db->connect_time = get_time_usec();
		send_event(db, PGS_CONNECT_OK);
		break;
	default:
		conn_error(db, PGS_CONNECT_FAILED, "PQconnectPoll");
	}
}

/* send query to server */
static void flush(struct PgSocket *db)
{
	int res = PQflush(db->con);
	if (res > 0) {
		wait_event(db, EV_WRITE, send_cb);
	} else if (res == 0) {
		wait_event(db, EV_READ, result_cb);
	} else {
		conn_error(db, PGS_RESULT_BAD, "PQflush");
	}
}

/* override default notice receiver */
static void custom_notice_receiver(void *arg, const PGresult *res)
{
	/* do nothing */
}

/*
 * Public API
 */

struct PgSocket *pgs_create(const char *connstr, pgs_handler_f fn, void *handler_arg)
{
	struct PgSocket *db;

	db = calloc(1, sizeof(*db));
	if (!db)
		return NULL;

	db->handler_func = fn;
	db->handler_arg = handler_arg;

	db->connstr = strdup(connstr);
	if (!db->connstr) {
		pgs_free(db);
		return NULL;
	}
	return db;
}

void pgs_set_event_base(struct PgSocket *pgs, struct event_base *base)
{
	pgs->base = base;
}

void pgs_set_lifetime(struct PgSocket *pgs, double lifetime)
{
	pgs->lifetime = USEC * lifetime;
}

void pgs_connect(struct PgSocket *db)
{
	if (db->con)
		pgs_disconnect(db);

	db->con = PQconnectStart(db->connstr);
	if (db->con == NULL) {
		conn_error(db, PGS_CONNECT_FAILED, "PQconnectStart");
		return;
	}

	if (PQstatus(db->con) == CONNECTION_BAD) {
		conn_error(db, PGS_CONNECT_FAILED, "PQconnectStart");
		return;
	}

	PQsetNoticeReceiver(db->con, custom_notice_receiver, db);

	wait_event(db, EV_WRITE, connect_cb);
}


void pgs_disconnect(struct PgSocket *db)
{
	if (db->wait_type) {
		event_del(&db->ev);
		db->wait_type = W_NONE;
		db->reconnect = false;
	}
	if (db->con) {
		PQfinish(db->con);
		db->con = NULL;
	}
	if (db->last_result) {
		PQclear(db->last_result);
		db->last_result = NULL;
	}
}

void pgs_free(struct PgSocket *db)
{
	if (db) {
		pgs_disconnect(db);
		free(db->connstr);
		free(db);
	}
}

void pgs_sleep(struct PgSocket *db, double timeout)
{
	struct timeval tv;

	Assert(!db->wait_type);

	if (db->con && db->lifetime) {
		usec_t now = get_time_usec();
		if (db->connect_time + db->lifetime < now) {
			pgs_disconnect(db);
			db->reconnect = true;
		}
	}

	tv.tv_sec = timeout;
	tv.tv_usec = (timeout - tv.tv_sec) * USEC;

	evtimer_set(&db->ev, timeout_cb, db);
	if (db->base)
		event_base_set(db->base, &db->ev);
	if (evtimer_add(&db->ev, &tv) < 0)
		die("evtimer_add failed: %s", strerror(errno));

	db->wait_type = W_TIME;
}

void pgs_reconnect(struct PgSocket *db, double timeout)
{
	pgs_disconnect(db);
	pgs_sleep(db, timeout);
	db->reconnect = true;
}

void pgs_send_query_simple(struct PgSocket *db, const char *q)
{
	int res;

	log_noise("%s", q);
	res = PQsendQuery(db->con, q);
	if (!res) {
		conn_error(db, PGS_RESULT_BAD, "PQsendQuery");
		return;
	}

	flush(db);
}

void pgs_send_query_params(struct PgSocket *db, const char *q, int cnt, ...)
{
	int i;
	va_list ap;
	const char *args[MAX_QRY_ARGS];

	if (cnt < 0 || cnt > MAX_QRY_ARGS) {
		log_warning("bad query arg cnt");
		send_event(db, PGS_RESULT_BAD);
		return;
	}

	va_start(ap, cnt);
	for (i = 0; i < cnt; i++)
		args[i] = va_arg(ap, char *);
	va_end(ap);

	pgs_send_query_params_list(db, q, cnt, args);
}

void pgs_send_query_params_list(struct PgSocket *db, const char *q, int cnt, const char *args[])
{
	int res;

	log_noise("%s", q);
	res = PQsendQueryParams(db->con, q, cnt, NULL, args, NULL, NULL, 0);
	if (!res) {
		conn_error(db, PGS_RESULT_BAD, "PQsendQueryParams");
		return;
	}

	flush(db);
}

int pgs_connection_valid(struct PgSocket *db)
{
	return (db->con != NULL);
}

PGconn *pgs_get_connection(struct PgSocket *db)
{
	return db->con;
}

bool pgs_waiting_for_reply(struct PgSocket *db)
{
	if (!db->con)
		return false;
	if (PQstatus(db->con) != CONNECTION_OK)
		return false;
	return (db->wait_type == W_SOCK) && (db->wait_event == EV_READ);
}
