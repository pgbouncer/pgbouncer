/*
 * Things to test:
 * - Conn per query
 * - show tx
 * - long tx
 * - variable-size query
 */

#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <libpq-fe.h>
#include <event.h>

static void log_error(const char *, ...);
static void log_debug(const char *, ...);
static void fatal(const char *fmt, ...);

typedef uint64_t usec_t;
#define USEC 1000000ULL
static usec_t get_time_usec(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (usec_t)tv.tv_sec * USEC + tv.tv_usec;
}

typedef void (*libev_cb_f)(int sock, short flags, void *arg);

#define Assert(e) do { if (!(e)) { \
	log_error("Assert(%s) failed: %s:%d in %s", \
		  #e, __FILE__, __LINE__, __FUNCTION__); \
	exit(1); } } while (0)

typedef enum { false=0, true=1 } bool;

#define LIST_DEBUG

#include "list.h"

static STATLIST(idle_list);
static STATLIST(active_list);

#define QT_SIMPLE  1
#define QT_BIGDATA 2
#define QT_SLEEP   4
static unsigned QueryTypes = 0;

static uint64_t LoginFailedCount = 0;
static uint64_t SqlErrorCount = 0;
static uint64_t QueryCount = 0;

typedef struct DbConn {
	List		head;
	const char	*connstr;
	struct event	ev;
	PGconn		*con;
	bool		logged_in;

	//time_t		connect_time;
	//unsigned	query_count;
	//const char	*query;
} DbConn;

static char *bulk_data;
static int bulk_data_max = 16*1024;  /* power of 2 */
static int verbose = 0;

/* fill mem with random junk */
static void init_bulk_data(void)
{
	int i;
	bulk_data = malloc(bulk_data_max + 1);
	for (i = 0; i < bulk_data_max; i++) {
		bulk_data[i] = 'a' + (i % 26);
	}
	bulk_data[i] = 0;
}

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
	Assert(item_in_list(&db->head, &active_list.head));
	statlist_remove(&db->head, &active_list);
	statlist_append(&db->head, &idle_list);
	log_debug("%p: set_idle", db);
}

static void set_active(DbConn *db)
{
	Assert(item_in_list(&db->head, &idle_list.head));
	statlist_remove(&db->head, &idle_list);
	statlist_append(&db->head, &active_list);
	log_debug("%p: set_active", db);
}

static void fatal_perror(const char *err)
{
	log_error("%s: %s", err, strerror(errno));
	exit(1);
}

static void fatal(const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	printf("FATAL: %s\n", buf);
	exit(1);
}

static void log_debug(const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	if (verbose == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	printf("dbg: %s\n", buf);
}

static void log_error(const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	printf("ERR: %s\n", buf);
}

static void wait_event(DbConn *db, short ev, libev_cb_f fn)
{
	event_set(&db->ev, PQsocket(db->con), ev, fn, db);
	if (event_add(&db->ev, NULL) < 0)
		fatal_perror("event_add");
}

static void disconnect(DbConn *db, bool is_err, const char *reason, ...)
{
	char buf[1024];
	va_list ap;
	if (is_err) {
		if (db->logged_in)
			SqlErrorCount++;
		else
			LoginFailedCount++;
	}
	if (db->con) {
		va_start(ap, reason);
		vsnprintf(buf, sizeof(buf), reason, ap);
		va_end(ap);
		log_debug("disconnect because: %s", buf);
		PQfinish(db->con);
		db->con = NULL;
		db->logged_in = 0;
		set_idle(db);
	}
}

/* some error happened */
static void conn_error(DbConn *db, const char *desc)
{
	if (db->con) {
		/* fixme show firt couple errors */
		disconnect(db, true, "%s: %s", desc, PQerrorMessage(db->con));
	} else {
		printf("random error: %s\n", desc);
		exit(1);
	}
}

/*
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
		QueryCount++;
		disconnect(db, false, "query done");
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
			wait_event(db, EV_READ, result_cb);
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
		wait_event(db, EV_WRITE, send_cb);
	} else if (res == 0) {
		wait_event(db, EV_READ, result_cb);
	} else
		conn_error(db, "PQflush");
}

static int send_query_bigdata(DbConn *db)
{
	const char *values[1];
	int lengths[1];
	int fmts[1];
	int arglen;
	char *q = "select $1::text";

	arglen = random() & (bulk_data_max - 1);
	values[0] = bulk_data + bulk_data_max - arglen;
	lengths[0] = arglen;
	fmts[0] = 1;

	return PQsendQueryParams(db->con, q, 1, NULL, values, lengths, fmts, 1);
}

static int send_query_sleep(DbConn *db)
{
	const char *q = "select pg_sleep(0.2)";
	return PQsendQueryParams(db->con, q, 0, NULL, NULL, NULL, NULL, 0);
}

static int send_query_simple(DbConn *db)
{
	const char *q = "select 1";
	return PQsendQueryParams(db->con, q, 0, NULL, NULL, NULL, NULL, 0);
}

/** send the query to server connection */
static void send_query(DbConn *db)
{
	int res;

	/* send query */
	if (QueryTypes & QT_SLEEP) {
		res = send_query_sleep(db);
	} else if (QueryTypes & QT_BIGDATA) {
		res = send_query_bigdata(db);
	} else {
		res = send_query_simple(db);
	}
	if (!res) {
		conn_error(db, "PQsendQueryParams");
		return;
	}

	/* flush it down */
	res = PQflush(db->con);
	if (res > 0) {
		wait_event(db, EV_WRITE, send_cb);
	} else if (res == 0) {
		wait_event(db, EV_READ, result_cb);
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
		wait_event(db, EV_WRITE, connect_cb);
		break;
	case PGRES_POLLING_READING:
		wait_event(db, EV_READ, connect_cb);
		break;
	case PGRES_POLLING_OK:
		log_debug("login ok: fd=%d", PQsocket(db->con));
		db->logged_in = 1;
		send_query(db);
		break;
	default:
		conn_error(db, "PQconnectPoll");
	}
}

static void launch_connect(DbConn *db)
{
	/* launch new connection */
	db->logged_in = 0;
	db->con = PQconnectStart(db->connstr);
	if (db->con == NULL) {
		log_error("PQconnectStart: no mem");
		exit(1);
	}

	if (PQstatus(db->con) == CONNECTION_BAD) {
		conn_error(db, "PQconnectStart");
		return;
	}

	wait_event(db, EV_WRITE, connect_cb);
}

static void handle_idle(DbConn *db)
{
	set_active(db);
	if (db->con)
		send_query(db);
	else
		launch_connect(db);
}

static const char usage_str [] =
"usage: asynctest [-d connstr][-n numconn][-s seed][-t <types>]\n"
"accepted types:\n"
"  B - bigdata\n"
"  S - sleep occasionally\n"
"  1 - simple 'select 1'\n";

static void run_stats(int fd, short ev, void *arg)
{
	static struct event ev_stats;
	struct timeval period = { 2, 0 };

	static usec_t last_time = 0;
	static uint64_t last_query_count = 0;
	static uint64_t last_login_failed_count = 0;
	static uint64_t last_sql_error_count = 0;

	double time_diff, qcount_diff, loginerr_diff, sqlerr_diff;
	usec_t now = get_time_usec();

	time_diff = now - last_time;
	if (last_time && time_diff) {
		qcount_diff = QueryCount - last_query_count;
		loginerr_diff = LoginFailedCount - last_login_failed_count;
		sqlerr_diff = SqlErrorCount - last_sql_error_count;
		if (verbose == 0) {
			printf(">> loginerr,sqlerr,qcount: %6.1f / %6.1f / %6.1f  active/idle: %3d / %3d   \r",
			       USEC * loginerr_diff / time_diff,
			       USEC * sqlerr_diff / time_diff,
			       USEC * qcount_diff / time_diff,
			       statlist_count(&active_list), statlist_count(&idle_list));
			fflush(stdout);
		}
	}

	if (!last_time)
		evtimer_set(&ev_stats, run_stats, NULL);
	if (evtimer_add(&ev_stats, &period) < 0)
		fatal_perror("evtimer_add");

	last_query_count = QueryCount;
	last_login_failed_count = LoginFailedCount;
	last_sql_error_count = SqlErrorCount;
	last_time = now;
}

int main(int argc, char *argv[])
{
	int i, c;
	DbConn *db;
	List *item, *tmp;
	unsigned seed = time(NULL) ^ getpid();
	char *cstr = "dbname=conntest port=6000 host=127.0.0.1";
	int numcon = 50;

	while ((c = getopt(argc, argv, "d:n:s:t:hv")) != EOF) {
		switch (c) {
		default:
		case 'h':
			printf("%s", usage_str);
			return 0;
		case 'd':
			cstr = optarg;
			break;
		case 'n':
			numcon = atoi(optarg);
			break;
		case 's':
			seed = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 't':
			for (i = 0; optarg[i]; i++) {
				switch (optarg[i]) {
				case 'B': QueryTypes = QT_BIGDATA; break;
				case 'S': QueryTypes = QT_SLEEP; break;
				case '1': QueryTypes = QT_SIMPLE; break;
				default: log_error("bad type"); break;
				}
			}
		}
	}

	if (QueryTypes == 0)
		QueryTypes = QT_SIMPLE;

	printf("using seed: %u\n", seed);
	srandom(seed);

	init_bulk_data();

	for (i = 0; i < numcon; i++) {
		db = new_db(cstr);
		statlist_append(&db->head, &idle_list);
	}

#if 0
	if (1)
	for (i = 0; i < 50; i++) {
		db = new_db("dbname=conntest port=7000 host=127.0.0.1 password=kama");
		list_append(&db->head, &idle_list);
	}
#endif
	event_init();

	run_stats(0, 0, NULL);

	printf("running..\n");

	while (1) {
		if (event_loop(EVLOOP_ONCE) < 0)
			log_error("event_loop: %s", strerror(errno));
		statlist_for_each_safe(item, &idle_list, tmp) {
			db = container_of(item, DbConn, head);
			handle_idle(db);
		}
	}
	return 0;
}


