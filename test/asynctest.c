/*
 * Things to test:
 * - Conn per query
 * - show tx
 * - long tx
 * - variable-size query
 */

#ifdef WIN32
#undef strerror
#undef main
#endif

#include <usual/logging.h>
#include <usual/getopt.h>
#include <usual/logging.h>
#include <usual/list.h>
#include <usual/statlist.h>
#include <usual/time.h>
#include <usual/string.h>

#include <event2/event.h>
#include <event2/event_struct.h>
#include <libpq-fe.h>

static char *simple_query = "select 1";

static struct event_base *evbase;

typedef struct DbConn {
	struct List	head;
	const char	*connstr;
	struct event	ev;
	PGconn		*con;
	bool		logged_in;

	/* time_t		connect_time; */
	int	query_count;
	/* const char	*query; */
	int _arglen;
} DbConn;

#define QT_SIMPLE  1
#define QT_BIGDATA 2
#define QT_SLEEP   4
static unsigned QueryTypes = 0;
static uint64_t LoginOkCount = 0;
static uint64_t LoginFailedCount = 0;
static uint64_t SqlErrorCount = 0;
static uint64_t QueryCount = 0;

static char *bulk_data;
static int bulk_data_max = 128*1024;  /* power of 2 */
static int verbose = 0;
static int throttle_connects = 0;
static int throttle_queries = 0;
static int per_conn_queries = 1;

static STATLIST(idle_list);
static STATLIST(active_list);

/*
 * utility functions
 */

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
	statlist_remove(&active_list, &db->head);
	statlist_append(&idle_list, &db->head);
	log_debug("%p: set_idle", db);
}

static void set_active(DbConn *db)
{
	statlist_remove(&idle_list, &db->head);
	statlist_append(&active_list, &db->head);
	log_debug("%p: set_active", db);
}

static void wait_event(DbConn *db, short ev, event_callback_fn fn)
{
	event_assign(&db->ev, evbase, PQsocket(db->con), ev, fn, db);
	if (event_add(&db->ev, NULL) < 0)
		fatal_perror("event_add");
}

_PRINTF(3, 4)
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
		db->logged_in = false;
		set_idle(db);
	}
}

/* some error happened */
static void conn_error(DbConn *db, const char *desc)
{
	static int ecount = 0;
	if (db->con) {
		if (ecount++ < 3)
			printf("\r%s (arglen=%d)\n", PQerrorMessage(db->con), db->_arglen);
		disconnect(db, true, "%s: %s", desc, PQerrorMessage(db->con));
	} else {
		printf("random error: %s\n", desc);
		exit(1);
	}
}

/*
 * Connection has a resultset available, fetch it.
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
		set_idle(db);
		return false;
	}

	switch (PQresultStatus(res)) {
	case PGRES_TUPLES_OK:
		/* TODO: check result */
		if (db->_arglen > 0) {
			int curlen = strlen(PQgetvalue(res, 0, 0));
			if (curlen != db->_arglen) {
				printf("result does not match: sent=%d got=%d\n",
				       db->_arglen, curlen);
			}
		}
		/* fallthrough */
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

/*
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

	arglen = random() % bulk_data_max;
	db->_arglen = arglen;
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
	const char *q = simple_query;
	return PQsendQueryParams(db->con, q, 0, NULL, NULL, NULL, NULL, 0);
}

/* send the query to server connection */
static void send_query(DbConn *db)
{
	int res;

	if (db->query_count >= per_conn_queries) {
		disconnect(db, false, "query count full");
		return;
	}
	db->query_count++;

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
		LoginOkCount++;
		db->logged_in = true;
		send_query(db);
		break;
	default:
		conn_error(db, "PQconnectPoll");
	}
}

static void launch_connect(DbConn *db)
{
	/* launch new connection */
	db->logged_in = false;
	db->query_count = 0;
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

#define ACT_ONCE 10

static void handle_idle(void)
{
	DbConn *db;
	struct List *item, *tmp;
	int allow_connects = 100000;
	int allow_queries = 100000;
	static usec_t startup_time = 0;
	usec_t now = get_cached_time();
	usec_t diff;
	int once;

	if (startup_time == 0)
		startup_time = get_cached_time();

	diff = now - startup_time;
	if (diff < USEC)
		diff = USEC;

	if (throttle_connects > 0) {
		allow_connects = throttle_connects - LoginOkCount * USEC / diff;
		once = throttle_connects / ACT_ONCE;
		if (!once)
			once = 1;
		if (once < allow_connects)
			allow_connects = once;
	}
	if (throttle_queries > 0) {
		allow_queries = throttle_queries - QueryCount * USEC / diff;
		once = throttle_connects / ACT_ONCE;
		if (!once)
			once = 1;
		if (once < allow_connects)
			allow_connects = once;
	}

	statlist_for_each_safe(item, &idle_list, tmp) {
		db = container_of(item, DbConn, head);
		if (db->con && allow_queries > 0) {
			set_active(db);
			send_query(db);
			allow_queries--;
		} else if (allow_connects > 0) {
			set_active(db);
			launch_connect(db);
			allow_connects--;
		}
	}
}

static void run_stats(int fd, short ev, void *arg)
{
	static struct event ev_stats;
	struct timeval period = { 5, 0 };

	static usec_t last_time = 0;
	static uint64_t last_query_count = 0;
	static uint64_t last_login_failed_count = 0;
	static uint64_t last_login_ok_count = 0;
	static uint64_t last_sql_error_count = 0;

	double time_diff, qcount_diff, loginerr_diff, loginok_diff, sqlerr_diff;
	usec_t now = get_cached_time();

	time_diff = now - last_time;
	if (last_time && time_diff) {
		qcount_diff = QueryCount - last_query_count;
		loginerr_diff = LoginFailedCount - last_login_failed_count;
		sqlerr_diff = SqlErrorCount - last_sql_error_count;
		loginok_diff = LoginOkCount - last_login_ok_count;
		if (verbose == 0) {
			printf(">> loginok,loginerr,sqlerr,qcount: %6.1f / %6.1f / %6.1f / %6.1f  active/idle: %3d / %3d   \r",
			       USEC * loginok_diff / time_diff,
			       USEC * loginerr_diff / time_diff,
			       USEC * sqlerr_diff / time_diff,
			       USEC * qcount_diff / time_diff,
			       statlist_count(&active_list), statlist_count(&idle_list));
			fflush(stdout);
		}
	}

	if (!last_time)
		evtimer_assign(&ev_stats, evbase, run_stats, NULL);
	if (evtimer_add(&ev_stats, &period) < 0)
		fatal_perror("evtimer_add");

	last_query_count = QueryCount;
	last_login_failed_count = LoginFailedCount;
	last_sql_error_count = SqlErrorCount;
	last_login_ok_count = LoginOkCount;
	last_time = now;
}

static const char usage_str [] =
"usage: asynctest [-d connstr][-n numconn][-s seed][-t <types>][-C maxconn][-Q maxquery][-q perconnq]\n"
"  -d connstr		libpq connect string\n"
"  -n num		number of connections\n"
"  -s seed		random number seed\n"
"  -t type of queries	query type, see below\n"
"  -C maxcps		max number of connects per sec\n"
"  -Q maxqps		max number of queries per sec\n"
"  -q num		queries per connection (default 1)\n"
"  -S sql		set simple query\n"
"accepted query types:\n"
"  B - bigdata\n"
"  S - sleep occasionally\n"
"  1 - simple 'select 1'\n";

int main(int argc, char *argv[])
{
	int i, c;
	DbConn *db;
	unsigned seed = time(NULL) ^ getpid();
	char *cstr = "";
	int numcon = 50;
#ifdef WIN32
	int wsresult;
	WSADATA wsaData;
#endif

	while ((c = getopt(argc, argv, "S:d:n:s:t:hvC:Q:q:")) != EOF) {
		switch (c) {
		default:
		case 'h':
			printf("%s", usage_str);
			return 0;
		case 'S':
			simple_query = optarg;
			break;
		case 'd':
			cstr = optarg;
			break;
		case 'C':
			throttle_connects = atoi(optarg);
			break;
		case 'Q':
			throttle_queries = atoi(optarg);
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
		case 'q':
			per_conn_queries = atoi(optarg);
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

#ifdef WIN32
        wsresult = WSAStartup(MAKEWORD(2,0),&wsaData);
        if (wsresult != 0)
        {
                fatal("cannot start the network subsystem: -%d", wsresult);
        }
#endif
	if (throttle_connects < 0 || throttle_queries < 0 || numcon < 0)
		fatal("invalid parameter");

	if (QueryTypes == 0)
		QueryTypes = QT_SIMPLE;

	printf("using seed: %u\n", seed);
	srandom(seed);

	init_bulk_data();

	for (i = 0; i < numcon; i++) {
		db = new_db(cstr);
		statlist_append(&idle_list, &db->head);
	}

	evbase = event_base_new();

	run_stats(0, 0, NULL);

	printf("running..\n");

	while (1) {
		handle_idle();
		reset_time_cache();
		if (event_base_loop(evbase, EVLOOP_ONCE) < 0)
			log_error("event_loop: %s", strerror(errno));
	}
	return 0;
}
