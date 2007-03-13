/*
 * Things to test:
 * - Conn per query
 * - show tx
 * - long tx
 * - variable-size query
 */

#include <sys/time.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <libpq-fe.h>
#include <event.h>

#define Assert(e) do { if (!(e)) { \
	printf("Assert(%s) failed: %s:%d in %s\n", \
		#e, __FILE__, __LINE__, __FUNCTION__); \
	exit(1); } } while (0)

typedef enum { false=0, true=1 } bool;

#include "list.h"

typedef struct DbConn {
	List		head;
	const char	*connstr;
	struct event	ev;
	//time_t		connect_time;
	//unsigned	query_count;
	PGconn		*con;
	const char	*query;
} DbConn;

static LIST(idle_list);
static LIST(active_list);

static DbConn *new_db(const char *connstr)
{
	DbConn *db = malloc(sizeof(*db));
	memset(db, 0, sizeof(*db));
	list_init(&db->head);
	db->connstr = connstr;
	return db;
}

static void set_idle(DbConn *db)
{
	Assert(item_in_list(&db->head, &active_list));
	list_del(&db->head);
	list_append(&db->head, &idle_list);
}

static void set_active(DbConn *db)
{
	Assert(item_in_list(&db->head, &idle_list));
	list_del(&db->head);
	list_append(&db->head, &active_list);
}

/** some error happened */
static void conn_error(DbConn *db, const char *desc)
{
	if (db->con) {
		printf("libpq error in %s: %s\n",
		       desc, PQerrorMessage(db->con));
		PQfinish(db->con);
		db->con = NULL;
	} else {
		printf("random error\n");
	}
	set_idle(db);
}

/**
 * Connection has a resultset avalable, fetch it.
 *
 * Returns true if there may be more results coming,
 * false if all done.
 */
static bool another_result(DbConn *db)
{
	PGresult *res;

	/* got one */
	res = PQgetResult(db->con);
	if (res == NULL) {
		set_idle(db);
		if (1) {
			PQfinish(db->con);
			db->con = NULL;
		}
		return false;
	}

	switch (PQresultStatus(res)) {
	case PGRES_TUPLES_OK:
		// todo: check result
	case PGRES_COMMAND_OK:
		PQclear(res);
		break;
	default:
		PQclear(res);
		conn_error(db, "weird result");
		return false;
	}
	return true;
}

/**
 * Called when select() told that conn is avail for reading/writing.
 *
 * It should call postgres handlers and then change state if needed.
 */
static void result_cb(int sock, short flags, void *arg)
{
	DbConn *db = arg;
	int res;

	res = PQconsumeInput(db->con);
	if (res == 0) {
		conn_error(db, "PQconsumeInput");
		return;
	}

	/* loop until PQgetResult returns NULL */
	while (1) {
		/* if PQisBusy, then incomplete result */
		if (PQisBusy(db->con)) {
			event_set(&db->ev, PQsocket(db->con), EV_READ, result_cb, db);
			event_add(&db->ev, NULL);
			break;
		}

		/* got one */
		if (!another_result(db))
			break;
	}
}

static void send_cb(int sock, short flags, void *arg)
{
	int res;
	DbConn *db = arg;

	res = PQflush(db->con);
	if (res > 0) {
		event_set(&db->ev, PQsocket(db->con), EV_WRITE, send_cb, db);
		event_add(&db->ev, NULL);
	} else if (res == 0) {
		event_set(&db->ev, PQsocket(db->con), EV_READ, result_cb, db);
		event_add(&db->ev, NULL);
	} else
		conn_error(db, "PQflush");
}

/** send the query to server connection */
static void send_query(DbConn *db)
{
	int res;

	/* send query */
	res = PQsendQueryParams(db->con, db->query, 0,
			NULL,	/* paramTypes */
			NULL,	/* paramValues */
			NULL,	/* paramLengths */
			NULL,	/* paramFormats */
			0);	/* resultformat, 0-text, 1-bin */
	if (!res) {
		conn_error(db, "PQsendQueryParams");
		return;
	}

	/* flush it down */
	res = PQflush(db->con);
	if (res > 0) {
		event_set(&db->ev, PQsocket(db->con), EV_WRITE, send_cb, db);
		event_add(&db->ev, NULL);
	} else if (res == 0) {
		event_set(&db->ev, PQsocket(db->con), EV_READ, result_cb, db);
		event_add(&db->ev, NULL);
	} else
		conn_error(db, "PQflush");
}

static void connect_cb(int sock, short flags, void *arg)
{
	DbConn *db = arg;
	PostgresPollingStatusType poll_res;

	poll_res = PQconnectPoll(db->con);
	switch (poll_res) {
	case PGRES_POLLING_WRITING:
		event_set(&db->ev, PQsocket(db->con), EV_WRITE, connect_cb, db);
		event_add(&db->ev, NULL);
		break;
	case PGRES_POLLING_READING:
		event_set(&db->ev, PQsocket(db->con), EV_READ, connect_cb, db);
		event_add(&db->ev, NULL);
		break;
	case PGRES_POLLING_OK:
		send_query(db);
		break;
	case PGRES_POLLING_ACTIVE:
	case PGRES_POLLING_FAILED:
		conn_error(db, "PQconnectPoll");
	}
}

static void launch_connect(DbConn *db)
{
	/* launch new connection */
	db->con = PQconnectStart(db->connstr);
	if (db->con == NULL) {
		conn_error(db, "PQconnectStart: no mem");
		return;
	}

	if (PQstatus(db->con) == CONNECTION_BAD) {
		conn_error(db, "PQconnectStart");
		return;
	}

	event_set(&db->ev, PQsocket(db->con), EV_WRITE, connect_cb, db);
	event_add(&db->ev, NULL);
}

static void handle_idle(DbConn *db)
{
	set_active(db);
	if (db->con)
		send_query(db);
	else
		launch_connect(db);
}

int main(void)
{
	int i;
	DbConn *db;
	List *item, *tmp;

	for (i = 0; i < 10; i++) {
		db = new_db("dbname=marko port=6000 host=/tmp");
		db->query = "select 1";
		list_append(&db->head, &idle_list);
	}

	event_init();

	while (1) {
		event_loop(EVLOOP_ONCE);
		list_for_each_safe(item, &idle_list, tmp) {
			db = container_of(item, DbConn, head);
			handle_idle(db);
		}
	}
	return 0;
}


