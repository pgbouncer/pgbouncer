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
 * Launcer for all the rest.
 */

#include "bouncer.h"

#include <usual/signal.h>
#include <usual/err.h>
#include <usual/cfparser.h>
#include <usual/getopt.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

static const char usage_str[] =
"Usage: %s [OPTION]... config.ini\n"
"  -d, --daemon           Run in background (as a daemon)\n"
"  -R, --restart          Do a online restart\n"
"  -q, --quiet            Run quietly\n"
"  -v, --verbose          Increase verbosity\n"
"  -u, --user=<username>  Assume identity of <username>\n"
"  -V, --version          Show version\n"
"  -h, --help             Show this help screen and exit\n";

static void usage(int err, char *exe)
{
	printf(usage_str, basename(exe));
	exit(err);
}

/* async dns handler */
struct DNSContext *adns;

/*
 * configuration storage
 */

int cf_daemon;
int cf_pause_mode = P_NONE;
int cf_shutdown; /* 1 - wait for queries to finish, 2 - shutdown immediately */
int cf_reboot;
static char *cf_username;
char *cf_config_file;

char *cf_listen_addr;
int cf_listen_port;
int cf_listen_backlog;
char *cf_unix_socket_dir;
int cf_unix_socket_mode;
char *cf_unix_socket_group;

int cf_pool_mode = POOL_SESSION;

/* sbuf config */
int cf_sbuf_len;
int cf_sbuf_loopcnt;
int cf_tcp_socket_buffer;
#if defined(TCP_DEFER_ACCEPT) || defined(SO_ACCEPTFILTER)
int cf_tcp_defer_accept = 1;
#else
int cf_tcp_defer_accept = 0;
#endif
int cf_tcp_keepalive;
int cf_tcp_keepcnt;
int cf_tcp_keepidle;
int cf_tcp_keepintvl;

int cf_auth_type = AUTH_MD5;
char *cf_auth_file;

int cf_max_client_conn;
int cf_default_pool_size;
int cf_min_pool_size;
int cf_res_pool_size;
usec_t cf_res_pool_timeout;
int cf_max_db_connections;

char *cf_server_reset_query;
char *cf_server_check_query;
usec_t cf_server_check_delay;
int cf_server_round_robin;
int cf_disable_pqexec;
usec_t cf_dns_max_ttl;
usec_t cf_dns_nxdomain_ttl;
usec_t cf_dns_zone_check_period;
unsigned int cf_max_packet_size;

char *cf_ignore_startup_params;

char *cf_autodb_connstr; /* here is "" different from NULL */

usec_t cf_autodb_idle_timeout;

usec_t cf_server_lifetime;
usec_t cf_server_idle_timeout;
usec_t cf_server_connect_timeout;
usec_t cf_server_login_retry;
usec_t cf_query_timeout;
usec_t cf_query_wait_timeout;
usec_t cf_client_idle_timeout;
usec_t cf_client_login_timeout;
usec_t cf_idle_transaction_timeout;
usec_t cf_suspend_timeout;

usec_t g_suspend_start;

char *cf_pidfile;
char *cf_jobname;

char *cf_admin_users;
char *cf_stats_users;
int cf_stats_period;

int cf_log_connections;
int cf_log_disconnections;
int cf_log_pooler_errors;

/*
 * config file description
 */

static bool set_defer_accept(struct CfValue *cv, const char *val);
#define DEFER_OPS {set_defer_accept, cf_get_int}

static const struct CfLookup auth_type_map[] = {
	{ "any", AUTH_ANY },
	{ "trust", AUTH_TRUST },
	{ "plain", AUTH_PLAIN },
#ifdef HAVE_CRYPT
	{ "crypt", AUTH_CRYPT },
#endif
	{ "md5", AUTH_MD5 },
	{ NULL }
};

const struct CfLookup pool_mode_map[] = {
	{ "session", POOL_SESSION },
	{ "transaction", POOL_TX },
	{ "statement", POOL_STMT },
	{ NULL }
};

static const struct CfKey bouncer_params [] = {
CF_ABS("job_name", CF_STR, cf_jobname, CF_NO_RELOAD, "pgbouncer"),
#ifdef WIN32
CF_ABS("service_name", CF_STR, cf_jobname, CF_NO_RELOAD, NULL), /* alias for job_name */
#endif
CF_ABS("conffile", CF_STR, cf_config_file, 0, NULL),
CF_ABS("logfile", CF_STR, cf_logfile, 0, ""),
CF_ABS("pidfile", CF_STR, cf_pidfile, CF_NO_RELOAD, ""),
CF_ABS("listen_addr", CF_STR, cf_listen_addr, CF_NO_RELOAD, ""),
CF_ABS("listen_port", CF_INT, cf_listen_port, CF_NO_RELOAD, "6432"),
CF_ABS("listen_backlog", CF_INT, cf_listen_backlog, CF_NO_RELOAD, "128"),
#ifndef WIN32
CF_ABS("unix_socket_dir", CF_STR, cf_unix_socket_dir, CF_NO_RELOAD, "/tmp"),
CF_ABS("unix_socket_mode", CF_INT, cf_unix_socket_mode, CF_NO_RELOAD, "0777"),
CF_ABS("unix_socket_group", CF_STR, cf_unix_socket_group, CF_NO_RELOAD, ""),
#endif
CF_ABS("auth_type", CF_LOOKUP(auth_type_map), cf_auth_type, 0, "md5"),
CF_ABS("auth_file", CF_STR, cf_auth_file, 0, "unconfigured_file"),
CF_ABS("pool_mode", CF_LOOKUP(pool_mode_map), cf_pool_mode, 0, "session"),
CF_ABS("max_client_conn", CF_INT, cf_max_client_conn, 0, "100"),
CF_ABS("default_pool_size", CF_INT, cf_default_pool_size, 0, "20"),
CF_ABS("min_pool_size", CF_INT, cf_min_pool_size, 0, "0"),
CF_ABS("reserve_pool_size", CF_INT, cf_res_pool_size, 0, "0"),
CF_ABS("reserve_pool_timeout", CF_TIME_USEC, cf_res_pool_timeout, 0, "5"),
CF_ABS("max_db_connections", CF_INT, cf_max_db_connections, 0, "0"),
CF_ABS("syslog", CF_INT, cf_syslog, 0, "0"),
CF_ABS("syslog_facility", CF_STR, cf_syslog_facility, 0, "daemon"),
CF_ABS("syslog_ident", CF_STR, cf_syslog_ident, 0, "pgbouncer"),
#ifndef WIN32
CF_ABS("user", CF_STR, cf_username, CF_NO_RELOAD, NULL),
#endif

CF_ABS("autodb_idle_timeout", CF_TIME_USEC, cf_autodb_idle_timeout, 0, "3600"),

CF_ABS("server_reset_query", CF_STR, cf_server_reset_query, 0, "DISCARD ALL"),
CF_ABS("server_check_query", CF_STR, cf_server_check_query, 0, "select 1"),
CF_ABS("server_check_delay", CF_TIME_USEC, cf_server_check_delay, 0, "30"),
CF_ABS("query_timeout", CF_TIME_USEC, cf_query_timeout, 0, "0"),
CF_ABS("query_wait_timeout", CF_TIME_USEC, cf_query_wait_timeout, 0, "0"),
CF_ABS("client_idle_timeout", CF_TIME_USEC, cf_client_idle_timeout, 0, "0"),
CF_ABS("client_login_timeout", CF_TIME_USEC, cf_client_login_timeout, 0, "60"),
CF_ABS("idle_transaction_timeout", CF_TIME_USEC, cf_idle_transaction_timeout, 0, "0"),
CF_ABS("server_lifetime", CF_TIME_USEC, cf_server_lifetime, 0, "3600"),
CF_ABS("server_idle_timeout", CF_TIME_USEC, cf_server_idle_timeout, 0, "600"),
CF_ABS("server_connect_timeout", CF_TIME_USEC, cf_server_connect_timeout, 0, "15"),
CF_ABS("server_login_retry", CF_TIME_USEC, cf_server_login_retry, 0, "15"),
CF_ABS("server_round_robin", CF_INT, cf_server_round_robin, 0, "0"),
CF_ABS("suspend_timeout", CF_TIME_USEC, cf_suspend_timeout, 0, "10"),
CF_ABS("ignore_startup_parameters", CF_STR, cf_ignore_startup_params, 0, ""),
CF_ABS("disable_pqexec", CF_INT, cf_disable_pqexec, CF_NO_RELOAD, "0"),
CF_ABS("dns_max_ttl", CF_TIME_USEC, cf_dns_max_ttl, 0, "15"),
CF_ABS("dns_nxdomain_ttl", CF_TIME_USEC, cf_dns_nxdomain_ttl, 0, "15"),
CF_ABS("dns_zone_check_period", CF_TIME_USEC, cf_dns_zone_check_period, 0, "0"),

CF_ABS("max_packet_size", CF_UINT, cf_max_packet_size, 0, "2147483647"),
CF_ABS("pkt_buf", CF_INT, cf_sbuf_len, CF_NO_RELOAD, "2048"),
CF_ABS("sbuf_loopcnt", CF_INT, cf_sbuf_loopcnt, 0, "5"),
CF_ABS("tcp_defer_accept", DEFER_OPS, cf_tcp_defer_accept, 0, NULL),
CF_ABS("tcp_socket_buffer", CF_INT, cf_tcp_socket_buffer, 0, "0"),
CF_ABS("tcp_keepalive", CF_INT, cf_tcp_keepalive, 0, "1"),
CF_ABS("tcp_keepcnt", CF_INT, cf_tcp_keepcnt, 0, "0"),
CF_ABS("tcp_keepidle", CF_INT, cf_tcp_keepidle, 0, "0"),
CF_ABS("tcp_keepintvl", CF_INT, cf_tcp_keepintvl, 0, "0"),
CF_ABS("verbose", CF_INT, cf_verbose, 0, NULL),
CF_ABS("admin_users", CF_STR, cf_admin_users, 0, ""),
CF_ABS("stats_users", CF_STR, cf_stats_users, 0, ""),
CF_ABS("stats_period", CF_INT, cf_stats_period, 0, "60"),
CF_ABS("log_connections", CF_INT, cf_log_connections, 0, "1"),
CF_ABS("log_disconnections", CF_INT, cf_log_disconnections, 0, "1"),
CF_ABS("log_pooler_errors", CF_INT, cf_log_pooler_errors, 0, "1"),
{NULL}
};

static const struct CfSect config_sects [] = {
	{
		.sect_name = "pgbouncer",
		.key_list = bouncer_params,
	}, {
		.sect_name = "databases",
		.set_key = parse_database,
	}, {
		.sect_name = "users",
		.set_key = parse_user,
	}, {
		.sect_name = NULL,
	}
};

static struct CfContext main_config = { config_sects, };

bool set_config_param(const char *key, const char *val)
{
	return cf_set(&main_config, "pgbouncer", key, val);
}

void config_for_each(void (*param_cb)(void *arg, const char *name, const char *val, bool reloadable),
		     void *arg)
{
	const struct CfKey *k = bouncer_params;
	char buf[256];
	bool reloadable;
	const char *val;
	int ro = CF_NO_RELOAD | CF_READONLY;

	for (; k->key_name; k++) {
		val = cf_get(&main_config, "pgbouncer", k->key_name, buf, sizeof(buf));
		reloadable = (k->flags & ro) == 0;
		param_cb(arg, k->key_name, val, reloadable);
	}
}

static bool set_defer_accept(struct CfValue *cv, const char *val)
{
	int *p = cv->value_p;
	bool ok;
	int oldval = *p;
	ok = cf_set_int(cv, val);
	if (ok && !!oldval != !!*p)
		pooler_tune_accept(*p);
	return ok;
}

static void set_dbs_dead(bool flag)
{
	struct List *item;
	PgDatabase *db;

	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);
		if (db->admin)
			continue;
		if (db->db_auto)
			continue;
		db->db_dead = flag;
	}
}

/* config loading, tries to be tolerant to errors */
void load_config(void)
{
	static bool loaded = false;
	bool ok;

	set_dbs_dead(true);

	/* actual loading */
	ok = cf_load_file(&main_config, cf_config_file);
	if (ok) {
		/* load users if needed */
		if (cf_auth_type >= AUTH_TRUST)
			loader_users_check();
		loaded = true;
	} else if (!loaded) {
		die("Cannot load config file");
	} else {
		log_warning("Config file loading failed");
		/* if ini file missing, dont kill anybody */
		set_dbs_dead(false);
	}

	/* reset pool_size, kill dbs */
	config_postprocess();

	/* reopen logfile */
	if (main_config.loaded)
		reset_logging();
}

/*
 * signal handling.
 *
 * handle_* functions are not actual signal handlers but called from
 * event_loop() so they have no restrictions what they can do.
 */
static struct event ev_sigterm;
static struct event ev_sigint;

static void handle_sigterm(int sock, short flags, void *arg)
{
	log_info("Got SIGTERM, fast exit");
	/* pidfile cleanup happens via atexit() */
	exit(1);
}

static void handle_sigint(int sock, short flags, void *arg)
{
	log_info("Got SIGINT, shutting down");
	if (cf_reboot)
		fatal("Takeover was in progress, going down immediately");
	if (cf_pause_mode == P_SUSPEND)
		fatal("Suspend was in progress, going down immediately");
	cf_pause_mode = P_PAUSE;
	cf_shutdown = 1;
}

#ifndef WIN32

static struct event ev_sigusr1;
static struct event ev_sigusr2;
static struct event ev_sighup;

static void handle_sigusr1(int sock, short flags, void *arg)
{
	if (cf_pause_mode == P_NONE) {
		log_info("Got SIGUSR1, pausing all activity");
		cf_pause_mode = P_PAUSE;
	} else {
		log_info("Got SIGUSR1, but already paused/suspended");
	}
}

static void handle_sigusr2(int sock, short flags, void *arg)
{
	switch (cf_pause_mode) {
	case P_SUSPEND:
		log_info("Got SIGUSR2, continuing from SUSPEND");
		resume_all();
		cf_pause_mode = P_NONE;
		break;
	case P_PAUSE:
		log_info("Got SIGUSR2, continuing from PAUSE");
		cf_pause_mode = P_NONE;
		break;
	case P_NONE:
		log_info("Got SIGUSR1, but not paused/suspended");
	}

	/* avoid surprise later if cf_shutdown stays set */
	if (cf_shutdown) {
		log_info("Canceling shutdown");
		cf_shutdown = 0;
	}
}

static void handle_sighup(int sock, short flags, void *arg)
{
	log_info("Got SIGHUP re-reading config");
	load_config();
}
#endif

static void signal_setup(void)
{
	int err;

#ifndef WIN32
	sigset_t set;

	/* block SIGPIPE */
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	err = sigprocmask(SIG_BLOCK, &set, NULL);
	if (err < 0)
		fatal_perror("sigprocmask");

	/* install handlers */

	signal_set(&ev_sigusr1, SIGUSR1, handle_sigusr1, NULL);
	err = signal_add(&ev_sigusr1, NULL);
	if (err < 0)
		fatal_perror("signal_add");

	signal_set(&ev_sigusr2, SIGUSR2, handle_sigusr2, NULL);
	err = signal_add(&ev_sigusr2, NULL);
	if (err < 0)
		fatal_perror("signal_add");

	signal_set(&ev_sighup, SIGHUP, handle_sighup, NULL);
	err = signal_add(&ev_sighup, NULL);
	if (err < 0)
		fatal_perror("signal_add");
#endif
	signal_set(&ev_sigterm, SIGTERM, handle_sigterm, NULL);
	err = signal_add(&ev_sigterm, NULL);
	if (err < 0)
		fatal_perror("signal_add");

	signal_set(&ev_sigint, SIGINT, handle_sigint, NULL);
	err = signal_add(&ev_sigint, NULL);
	if (err < 0)
		fatal_perror("signal_add");
}

/*
 * daemon mode
 */
static void go_daemon(void)
{
	int pid, fd;

	if (!cf_pidfile[0])
		fatal("daemon needs pidfile configured");

	/* dont log to stdout anymore */
	cf_quiet = 1;

	/* send stdin, stdout, stderr to /dev/null */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		fatal_perror("/dev/null");
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (fd > 2)
		close(fd);

	/* fork new process */
	pid = fork();
	if (pid < 0)
		fatal_perror("fork");
	if (pid > 0)
		_exit(0);

	/* create new session */
	pid = setsid();
	if (pid < 0)
		fatal_perror("setsid");

	/* fork again to avoid being session leader */
	pid = fork();
	if (pid < 0)
		fatal_perror("fork");
	if (pid > 0)
		_exit(0);
}

/*
 * pidfile management.
 */

static void remove_pidfile(void)
{
	if (!cf_pidfile[0])
		return;
	unlink(cf_pidfile);
}

static void check_pidfile(void)
{
	char buf[128 + 1];
	struct stat st;
	pid_t pid = 0;
	int fd, res;

	if (!cf_pidfile[0])
		return;

	/* check if pidfile exists */
	if (stat(cf_pidfile, &st) < 0) {
		if (errno != ENOENT)
			fatal_perror("stat");
		return;
	}

	/* read old pid */
	fd = open(cf_pidfile, O_RDONLY);
	if (fd < 0)
		goto locked_pidfile;
	res = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (res <= 0)
		goto locked_pidfile;

	/* parse pid */
	buf[res] = 0;
	pid = atol(buf);
	if (pid <= 0)
		goto locked_pidfile;

	/* check if running */
	if (kill(pid, 0) >= 0)
		goto locked_pidfile;
	if (errno != ESRCH)
		goto locked_pidfile;

	/* seems the pidfile is not in use */
	log_info("Stale pidfile, removing");
	remove_pidfile();
	return;

locked_pidfile:
	fatal("pidfile exists, another instance running?");
}

static void write_pidfile(void)
{
	char buf[64];
	pid_t pid;
	int res, fd;

	if (!cf_pidfile[0])
		return;

	pid = getpid();
	snprintf(buf, sizeof(buf), "%u\n", (unsigned)pid);

	fd = open(cf_pidfile, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0)
		fatal_perror("%s", cf_pidfile);
	res = safe_write(fd, buf, strlen(buf));
	if (res < 0)
		fatal_perror("%s", cf_pidfile);
	close(fd);

	/* only remove when we have it actually written */
	atexit(remove_pidfile);
}

/* just print out max files, in the future may warn if something is off */
static void check_limits(void)
{
	struct rlimit lim;
	int total_users = statlist_count(&user_list);
	int fd_count;
	int err;
	struct List *item;
	PgDatabase *db;

	log_noise("event: %d, SBuf: %d, PgSocket: %d, IOBuf: %d",
		  (int)sizeof(struct event), (int)sizeof(SBuf),
		  (int)sizeof(PgSocket), (int)IOBUF_SIZE);

	/* load limits */
	err = getrlimit(RLIMIT_NOFILE, &lim);
	if (err < 0) {
		log_error("could not get RLIMIT_NOFILE: %s", strerror(errno));
		return;
	}

	/* calculate theoretical max, +10 is just in case */
	fd_count = cf_max_client_conn + 10;
	statlist_for_each(item, &database_list) {
		db = container_of(item, PgDatabase, head);
		if (db->forced_user)
			fd_count += db->pool_size;
		else
			fd_count += db->pool_size * total_users;
	}

	log_info("File descriptor limit: %d (H:%d), max_client_conn: %d, max fds possible: %d",
		 (int)lim.rlim_cur, (int)lim.rlim_max, cf_max_client_conn, fd_count);
}

static bool check_old_process_unix(void)
{
	struct sockaddr_un sa_un;
	socklen_t len = sizeof(sa_un);
	int domain = AF_UNIX;
	int res, fd;

	if (!cf_unix_socket_dir || !*cf_unix_socket_dir)
		return false;

	memset(&sa_un, 0, len);
	sa_un.sun_family = domain;
	snprintf(sa_un.sun_path, sizeof(sa_un.sun_path),
		 "%s/.s.PGSQL.%d", cf_unix_socket_dir, cf_listen_port);

	fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0)
		fatal_perror("cannot create socket");
	res = safe_connect(fd, (struct sockaddr *)&sa_un, len);
	safe_close(fd);
	if (res < 0)
		return false;
	return true;
}

static void main_loop_once(void)
{
	int err;

	reset_time_cache();

	err = event_loop(EVLOOP_ONCE);
	if (err < 0) {
		if (errno != EINTR)
			log_warning("event_loop failed: %s", strerror(errno));
	}
	per_loop_maint();
	reuse_just_freed_objects();
	rescue_timers();
	per_loop_pooler_maint();

	adns_per_loop(adns);
}

static void takeover_part1(void)
{
	/* use temporary libevent base */
	void *evtmp = event_init();

	if (!cf_unix_socket_dir || !*cf_unix_socket_dir)
		fatal("cannot reboot if unix dir not configured");

	takeover_init();
	while (cf_reboot)
		main_loop_once();
	event_base_free(evtmp);
}

static void dns_setup(void)
{
	if (adns)
		return;
	adns = adns_create_context();
	if (!adns)
		fatal_perror("dns setup failed");
}

/* boot everything */
int main(int argc, char *argv[])
{
	int c;
	bool did_takeover = false;
	char *arg_username = NULL;
	int long_idx;

	static const struct option long_options[] = {
		{"quiet", no_argument, NULL, 'q'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{"daemon", no_argument, NULL, 'd'},
		{"version", no_argument, NULL, 'V'},
		{"reboot", no_argument, NULL, 'R'},
		{"user", required_argument, NULL, 'u'},
		{NULL, 0, NULL, 0}
	};

	setprogname(basename(argv[0]));

	/* parse cmdline */
	while ((c = getopt_long(argc, argv, "qvhdVRu:", long_options, &long_idx)) != -1) {
		switch (c) {
		case 'R':
			cf_reboot = 1;
			break;
		case 'v':
			cf_verbose++;
			break;
		case 'V':
			printf("%s\n", FULLVER);
			return 0;
		case 'd':
			cf_daemon = 1;
			break;
		case 'q':
			cf_quiet = 1;
			break;
		case 'u':
			arg_username = optarg;
			break;
		case 'h':
			usage(0, argv[0]);
		default:
			usage(1, argv[0]);
		}
	}
	if (optind + 1 != argc) {
		fprintf(stderr, "Need config file.  See pgbouncer -h for usage.\n");
		exit(1);
	}
	cf_config_file = xstrdup(argv[optind]);

	init_objects();
	load_config();
	main_config.loaded = true;
	init_caches();
	logging_prefix_cb = log_socket_prefix;

	/* prefer cmdline over config for username */
	if (arg_username) {
		if (cf_username)
			free(cf_username);
		cf_username = xstrdup(arg_username);
	}

	/* switch user is needed */
	if (cf_username && *cf_username)
		change_user(cf_username);

	/* disallow running as root */
	if (getuid() == 0)
		fatal("PgBouncer should not run as root");

	/* need to do that after loading config */
	check_limits();

	admin_setup();

	if (cf_reboot) {
		if (check_old_process_unix()) {
			takeover_part1();
			did_takeover = true;
		} else {
			log_info("old process not found, try to continue normally");
			cf_reboot = 0;
			check_pidfile();
		}
	} else {
		if (check_old_process_unix())
			fatal("unix socket is in use, cannot continue");
		check_pidfile();
	}

	if (cf_daemon)
		go_daemon();

	/* initialize subsystems, order important */
	srandom(time(NULL) ^ getpid());
	if (!event_init())
		fatal("event_init() failed");
	dns_setup();
	signal_setup();
	janitor_setup();
	stats_setup();

	if (did_takeover)
		takeover_finish();
	else
		pooler_setup();

	write_pidfile();

	log_info("process up: %s, libevent %s (%s), adns: %s", PACKAGE_STRING,
		 event_get_version(), event_get_method(), adns_get_backend());

	/* main loop */
	while (cf_shutdown < 2)
		main_loop_once();

	return 0;
}

