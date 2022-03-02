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
 * Launcher for all the rest.
 */

#include "bouncer.h"

#include <usual/signal.h>
#include <usual/err.h>
#include <usual/cfparser.h>
#include <usual/getopt.h>
#include <usual/safeio.h>
#include <usual/slab.h>
#include <usual/socket.h>
#include <usual/string.h>

#ifdef WIN32
#include "win32support.h"
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

static void usage(const char *exe)
{
	printf("%s is a connection pooler for PostgreSQL.\n\n", exe);
	printf("Usage:\n");
	printf("  %s [OPTION]... CONFIG_FILE\n", exe);
	printf("\nOptions:\n");
	printf("  -d, --daemon         run in background (as a daemon)\n");
	printf("  -q, --quiet          run quietly\n");
	printf("  -R, --reboot         do an online reboot\n");
	printf("  -u, --user=USERNAME  assume identity of USERNAME\n");
	printf("  -v, --verbose        increase verbosity\n");
	printf("  -V, --version        show version, then exit\n");
	printf("  -h, --help           show this help, then exit\n");
	printf("\n");
#ifdef WIN32
	printf("Windows service registration:\n");
	printf("  --regservice CONFIG_FILE [-U USERNAME [-P PASSWORD]]\n");
	printf("  --unregservice CONFIG_FILE\n");
	printf("\n");
#endif
	printf("Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
	printf("%s home page: <%s>\n", PACKAGE_NAME, PACKAGE_URL);
	exit(0);
}

/* global libevent handle */
struct event_base *pgb_event_base;

/* async dns handler */
struct DNSContext *adns;

struct HBA *parsed_hba;

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
int cf_so_reuseport;
int cf_tcp_socket_buffer;
int cf_tcp_defer_accept;
#if defined(TCP_DEFER_ACCEPT)
#define DEFAULT_TCP_DEFER_ACCEPT "1"
#else
#define DEFAULT_TCP_DEFER_ACCEPT "0"
#endif
int cf_tcp_keepalive;
int cf_tcp_keepcnt;
int cf_tcp_keepidle;
int cf_tcp_keepintvl;
int cf_tcp_user_timeout;

int cf_auth_type = AUTH_MD5;
char *cf_auth_file;
char *cf_auth_hba_file;
char *cf_auth_user;
char *cf_auth_query;

int cf_max_client_conn;
int cf_default_pool_size;
int cf_min_pool_size;
int cf_res_pool_size;
usec_t cf_res_pool_timeout;
int cf_max_db_connections;
int cf_max_user_connections;

char *cf_server_reset_query;
int cf_server_reset_query_always;
char *cf_server_check_query;
usec_t cf_server_check_delay;
int cf_server_fast_close;
int cf_server_round_robin;
int cf_disable_pqexec;
usec_t cf_dns_max_ttl;
usec_t cf_dns_nxdomain_ttl;
usec_t cf_dns_zone_check_period;
char *cf_resolv_conf;
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
int cf_log_stats;

int cf_log_connections;
int cf_log_disconnections;
int cf_log_pooler_errors;
int cf_application_name_add_host;

int cf_client_tls_sslmode;
char *cf_client_tls_protocols;
char *cf_client_tls_ca_file;
char *cf_client_tls_cert_file;
char *cf_client_tls_key_file;
char *cf_client_tls_ciphers;
char *cf_client_tls_dheparams;
char *cf_client_tls_ecdhecurve;

int cf_server_tls_sslmode;
char *cf_server_tls_protocols;
char *cf_server_tls_ca_file;
char *cf_server_tls_cert_file;
char *cf_server_tls_key_file;
char *cf_server_tls_ciphers;

/*
 * config file description
 */

static bool set_defer_accept(struct CfValue *cv, const char *val);
#define DEFER_OPS {set_defer_accept, cf_get_int}

static const struct CfLookup auth_type_map[] = {
	{ "any", AUTH_ANY },
	{ "trust", AUTH_TRUST },
	{ "plain", AUTH_PLAIN },
	{ "md5", AUTH_MD5 },
	{ "cert", AUTH_CERT },
	{ "hba", AUTH_HBA },
#ifdef HAVE_PAM
	{ "pam", AUTH_PAM },
#endif
	{ "scram-sha-256", AUTH_SCRAM_SHA_256 },
	{ NULL }
};

const struct CfLookup pool_mode_map[] = {
	{ "session", POOL_SESSION },
	{ "transaction", POOL_TX },
	{ "statement", POOL_STMT },
	{ NULL }
};

const struct CfLookup sslmode_map[] = {
	{ "disable", SSLMODE_DISABLED },
	{ "allow", SSLMODE_ALLOW },
	{ "prefer", SSLMODE_PREFER },
	{ "require", SSLMODE_REQUIRE },
	{ "verify-ca", SSLMODE_VERIFY_CA },
	{ "verify-full", SSLMODE_VERIFY_FULL },
	{ NULL }
};

/*
 * Add new parameters in alphabetical order. This order is used by SHOW CONFIG.
 */
static const struct CfKey bouncer_params [] = {
CF_ABS("admin_users", CF_STR, cf_admin_users, 0, ""),
CF_ABS("application_name_add_host", CF_INT, cf_application_name_add_host, 0, "0"),
CF_ABS("auth_file", CF_STR, cf_auth_file, 0, NULL),
CF_ABS("auth_hba_file", CF_STR, cf_auth_hba_file, 0, ""),
CF_ABS("auth_query", CF_STR, cf_auth_query, 0, "SELECT usename, passwd FROM pg_shadow WHERE usename=$1"),
CF_ABS("auth_type", CF_LOOKUP(auth_type_map), cf_auth_type, 0, "md5"),
CF_ABS("auth_user", CF_STR, cf_auth_user, 0, NULL),
CF_ABS("autodb_idle_timeout", CF_TIME_USEC, cf_autodb_idle_timeout, 0, "3600"),
CF_ABS("client_idle_timeout", CF_TIME_USEC, cf_client_idle_timeout, 0, "0"),
CF_ABS("client_login_timeout", CF_TIME_USEC, cf_client_login_timeout, 0, "60"),
CF_ABS("client_tls_ca_file", CF_STR, cf_client_tls_ca_file, 0, ""),
CF_ABS("client_tls_cert_file", CF_STR, cf_client_tls_cert_file, 0, ""),
CF_ABS("client_tls_ciphers", CF_STR, cf_client_tls_ciphers, 0, "fast"),
CF_ABS("client_tls_dheparams", CF_STR, cf_client_tls_dheparams, 0, "auto"),
CF_ABS("client_tls_ecdhcurve", CF_STR, cf_client_tls_ecdhecurve, 0, "auto"),
CF_ABS("client_tls_key_file", CF_STR, cf_client_tls_key_file, 0, ""),
CF_ABS("client_tls_protocols", CF_STR, cf_client_tls_protocols, 0, "secure"),
CF_ABS("client_tls_sslmode", CF_LOOKUP(sslmode_map), cf_client_tls_sslmode, 0, "disable"),
CF_ABS("conffile", CF_STR, cf_config_file, 0, NULL),
CF_ABS("default_pool_size", CF_INT, cf_default_pool_size, 0, "20"),
CF_ABS("disable_pqexec", CF_INT, cf_disable_pqexec, CF_NO_RELOAD, "0"),
CF_ABS("dns_max_ttl", CF_TIME_USEC, cf_dns_max_ttl, 0, "15"),
CF_ABS("dns_nxdomain_ttl", CF_TIME_USEC, cf_dns_nxdomain_ttl, 0, "15"),
CF_ABS("dns_zone_check_period", CF_TIME_USEC, cf_dns_zone_check_period, 0, "0"),
CF_ABS("idle_transaction_timeout", CF_TIME_USEC, cf_idle_transaction_timeout, 0, "0"),
CF_ABS("ignore_startup_parameters", CF_STR, cf_ignore_startup_params, 0, ""),
CF_ABS("job_name", CF_STR, cf_jobname, CF_NO_RELOAD, "pgbouncer"),
CF_ABS("listen_addr", CF_STR, cf_listen_addr, CF_NO_RELOAD, ""),
CF_ABS("listen_backlog", CF_INT, cf_listen_backlog, CF_NO_RELOAD, "128"),
CF_ABS("listen_port", CF_INT, cf_listen_port, CF_NO_RELOAD, "6432"),
CF_ABS("log_connections", CF_INT, cf_log_connections, 0, "1"),
CF_ABS("log_disconnections", CF_INT, cf_log_disconnections, 0, "1"),
CF_ABS("log_pooler_errors", CF_INT, cf_log_pooler_errors, 0, "1"),
CF_ABS("log_stats", CF_INT, cf_log_stats, 0, "1"),
CF_ABS("logfile", CF_STR, cf_logfile, 0, ""),
CF_ABS("max_client_conn", CF_INT, cf_max_client_conn, 0, "100"),
CF_ABS("max_db_connections", CF_INT, cf_max_db_connections, 0, "0"),
CF_ABS("max_packet_size", CF_UINT, cf_max_packet_size, 0, "2147483647"),
CF_ABS("max_user_connections", CF_INT, cf_max_user_connections, 0, "0"),
CF_ABS("min_pool_size", CF_INT, cf_min_pool_size, 0, "0"),
CF_ABS("pidfile", CF_STR, cf_pidfile, CF_NO_RELOAD, ""),
CF_ABS("pkt_buf", CF_INT, cf_sbuf_len, CF_NO_RELOAD, "4096"),
CF_ABS("pool_mode", CF_LOOKUP(pool_mode_map), cf_pool_mode, 0, "session"),
CF_ABS("query_timeout", CF_TIME_USEC, cf_query_timeout, 0, "0"),
CF_ABS("query_wait_timeout", CF_TIME_USEC, cf_query_wait_timeout, 0, "120"),
CF_ABS("reserve_pool_size", CF_INT, cf_res_pool_size, 0, "0"),
CF_ABS("reserve_pool_timeout", CF_TIME_USEC, cf_res_pool_timeout, 0, "5"),
CF_ABS("resolv_conf", CF_STR, cf_resolv_conf, CF_NO_RELOAD, ""),
CF_ABS("sbuf_loopcnt", CF_INT, cf_sbuf_loopcnt, 0, "5"),
CF_ABS("server_check_delay", CF_TIME_USEC, cf_server_check_delay, 0, "30"),
CF_ABS("server_check_query", CF_STR, cf_server_check_query, 0, "select 1"),
CF_ABS("server_connect_timeout", CF_TIME_USEC, cf_server_connect_timeout, 0, "15"),
CF_ABS("server_fast_close", CF_INT, cf_server_fast_close, 0, "0"),
CF_ABS("server_idle_timeout", CF_TIME_USEC, cf_server_idle_timeout, 0, "600"),
CF_ABS("server_lifetime", CF_TIME_USEC, cf_server_lifetime, 0, "3600"),
CF_ABS("server_login_retry", CF_TIME_USEC, cf_server_login_retry, 0, "15"),
CF_ABS("server_reset_query", CF_STR, cf_server_reset_query, 0, "DISCARD ALL"),
CF_ABS("server_reset_query_always", CF_INT, cf_server_reset_query_always, 0, "0"),
CF_ABS("server_round_robin", CF_INT, cf_server_round_robin, 0, "0"),
CF_ABS("server_tls_ca_file", CF_STR, cf_server_tls_ca_file, 0, ""),
CF_ABS("server_tls_cert_file", CF_STR, cf_server_tls_cert_file, 0, ""),
CF_ABS("server_tls_ciphers", CF_STR, cf_server_tls_ciphers, 0, "fast"),
CF_ABS("server_tls_key_file", CF_STR, cf_server_tls_key_file, 0, ""),
CF_ABS("server_tls_protocols", CF_STR, cf_server_tls_protocols, 0, "secure"),
CF_ABS("server_tls_sslmode", CF_LOOKUP(sslmode_map), cf_server_tls_sslmode, 0, "disable"),
#ifdef WIN32
CF_ABS("service_name", CF_STR, cf_jobname, CF_NO_RELOAD, NULL), /* alias for job_name */
#endif
CF_ABS("so_reuseport", CF_INT, cf_so_reuseport, CF_NO_RELOAD, "0"),
CF_ABS("stats_period", CF_INT, cf_stats_period, 0, "60"),
CF_ABS("stats_users", CF_STR, cf_stats_users, 0, ""),
CF_ABS("suspend_timeout", CF_TIME_USEC, cf_suspend_timeout, 0, "10"),
CF_ABS("syslog", CF_INT, cf_syslog, 0, "0"),
CF_ABS("syslog_facility", CF_STR, cf_syslog_facility, 0, "daemon"),
CF_ABS("syslog_ident", CF_STR, cf_syslog_ident, 0, "pgbouncer"),
CF_ABS("tcp_defer_accept", DEFER_OPS, cf_tcp_defer_accept, 0, DEFAULT_TCP_DEFER_ACCEPT),
CF_ABS("tcp_keepalive", CF_INT, cf_tcp_keepalive, 0, "1"),
CF_ABS("tcp_keepcnt", CF_INT, cf_tcp_keepcnt, 0, "0"),
CF_ABS("tcp_keepidle", CF_INT, cf_tcp_keepidle, 0, "0"),
CF_ABS("tcp_keepintvl", CF_INT, cf_tcp_keepintvl, 0, "0"),
CF_ABS("tcp_socket_buffer", CF_INT, cf_tcp_socket_buffer, 0, "0"),
CF_ABS("tcp_user_timeout", CF_INT, cf_tcp_user_timeout, 0, "0"),
CF_ABS("unix_socket_dir", CF_STR, cf_unix_socket_dir, CF_NO_RELOAD, DEFAULT_UNIX_SOCKET_DIR),
#ifndef WIN32
CF_ABS("unix_socket_group", CF_STR, cf_unix_socket_group, CF_NO_RELOAD, ""),
CF_ABS("unix_socket_mode", CF_INT, cf_unix_socket_mode, CF_NO_RELOAD, "0777"),
#endif
#ifndef WIN32
CF_ABS("user", CF_STR, cf_username, CF_NO_RELOAD, NULL),
#endif
CF_ABS("verbose", CF_INT, cf_verbose, 0, NULL),

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

void config_for_each(void (*param_cb)(void *arg, const char *name, const char *val, const char *defval, bool reloadable),
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
		param_cb(arg, k->key_name, val, k->def_value, reloadable);
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

/* Tells if the specified auth type requires data from the auth file. */
static bool requires_auth_file(int auth_type)
{
	/* For PAM authentication auth file is not used */
	if (auth_type == AUTH_PAM)
		return false;
	return auth_type >= AUTH_TRUST;
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
		if (requires_auth_file(cf_auth_type))
			loader_users_check();
		loaded = true;
	} else if (!loaded) {
		die("cannot load config file");
	} else {
		log_warning("config file loading failed");
		/* if ini file missing, don't kill anybody */
		set_dbs_dead(false);
	}

	if (cf_auth_type == AUTH_HBA) {
		struct HBA *hba = hba_load_rules(cf_auth_hba_file);
		if (hba) {
			if (parsed_hba)
				hba_free(parsed_hba);
			parsed_hba = hba;
		}
	}

	/* kill dbs */
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

static void handle_sigterm(evutil_socket_t sock, short flags, void *arg)
{
	log_info("got SIGTERM, fast exit");
	/* pidfile cleanup happens via atexit() */
	exit(1);
}

static void handle_sigint(evutil_socket_t sock, short flags, void *arg)
{
	log_info("got SIGINT, shutting down");
	sd_notify(0, "STOPPING=1");
	if (cf_reboot)
		die("takeover was in progress, going down immediately");
	if (cf_pause_mode == P_SUSPEND)
		die("suspend was in progress, going down immediately");
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
		log_info("got SIGUSR1, pausing all activity");
		cf_pause_mode = P_PAUSE;
	} else {
		log_info("got SIGUSR1, but already paused/suspended");
	}
}

static void handle_sigusr2(int sock, short flags, void *arg)
{
	switch (cf_pause_mode) {
	case P_SUSPEND:
		log_info("got SIGUSR2, continuing from SUSPEND");
		resume_all();
		cf_pause_mode = P_NONE;
		break;
	case P_PAUSE:
		log_info("got SIGUSR2, continuing from PAUSE");
		cf_pause_mode = P_NONE;
		break;
	case P_NONE:
		log_info("got SIGUSR2, but not paused/suspended");
	}

	/* avoid surprise later if cf_shutdown stays set */
	if (cf_shutdown) {
		log_info("canceling shutdown");
		cf_shutdown = 0;
	}
}

static void handle_sighup(int sock, short flags, void *arg)
{
	log_info("got SIGHUP, re-reading config");
	sd_notify(0, "RELOADING=1");
	load_config();
	if (!sbuf_tls_setup())
		log_error("TLS configuration could not be reloaded, keeping old configuration");
	sd_notify(0, "READY=1");
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

	evsignal_assign(&ev_sigusr1, pgb_event_base, SIGUSR1, handle_sigusr1, NULL);
	err = evsignal_add(&ev_sigusr1, NULL);
	if (err < 0)
		fatal_perror("evsignal_add");

	evsignal_assign(&ev_sigusr2, pgb_event_base, SIGUSR2, handle_sigusr2, NULL);
	err = evsignal_add(&ev_sigusr2, NULL);
	if (err < 0)
		fatal_perror("evsignal_add");

	evsignal_assign(&ev_sighup, pgb_event_base, SIGHUP, handle_sighup, NULL);
	err = evsignal_add(&ev_sighup, NULL);
	if (err < 0)
		fatal_perror("evsignal_add");
#endif
	evsignal_assign(&ev_sigterm, pgb_event_base, SIGTERM, handle_sigterm, NULL);
	err = evsignal_add(&ev_sigterm, NULL);
	if (err < 0)
		fatal_perror("evsignal_add");

	evsignal_assign(&ev_sigint, pgb_event_base, SIGINT, handle_sigint, NULL);
	err = evsignal_add(&ev_sigint, NULL);
	if (err < 0)
		fatal_perror("evsignal_add");
}

/*
 * daemon mode
 */
static void go_daemon(void)
{
	int pid, fd;

	if (!cf_pidfile || !cf_pidfile[0])
		die("daemon needs pidfile configured");

	/* don't log to stdout anymore */
	cf_quiet = 1;

	/* send stdin, stdout, stderr to /dev/null */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		die("could not open /dev/null: %s", strerror(errno));
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (fd > 2)
		close(fd);

	/* fork new process */
	pid = fork();
	if (pid < 0)
		die("fork failed: %s", strerror(errno));
	if (pid > 0)
		_exit(0);

	/* create new session */
	pid = setsid();
	if (pid < 0)
		die("setsid failed: %s", strerror(errno));

	/* fork again to avoid being session leader */
	pid = fork();
	if (pid < 0)
		die("fork failed: %s", strerror(errno));
	if (pid > 0)
		_exit(0);
}

/*
 * pidfile management.
 */

static void remove_pidfile(void)
{
	if (cf_pidfile) {
		if (cf_pidfile[0])
			unlink(cf_pidfile);
		free(cf_pidfile);
		cf_pidfile = NULL;
	}
}

static void check_pidfile(void)
{
	char buf[128 + 1];
	pid_t pid = 0;
	int fd, res, err;

	if (!cf_pidfile || !cf_pidfile[0])
		return;

	/* read old pid */
	fd = open(cf_pidfile, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return;
		die("could not open pidfile '%s': %s", cf_pidfile, strerror(errno));
	}
	res = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (res <= 0)
		die("could not read pidfile '%s': %s", cf_pidfile, strerror(errno));

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
	log_info("stale pidfile, removing");
	err = unlink(cf_pidfile);
	if (err != 0)
		die("could not remove stale pidfile: %s", strerror(errno));
	return;

locked_pidfile:
	die("pidfile exists, another instance running?");
}

static void write_pidfile(void)
{
	char buf[64];
	pid_t pid;
	int res, fd;

	if (!cf_pidfile || !cf_pidfile[0])
		return;

	pid = getpid();
	snprintf(buf, sizeof(buf), "%u\n", (unsigned)pid);

	fd = open(cf_pidfile, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0)
		die("could not open pidfile '%s': %s", cf_pidfile, strerror(errno));
	res = safe_write(fd, buf, strlen(buf));
	if (res < 0)
		die("could not write pidfile '%s': %s", cf_pidfile, strerror(errno));
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
			fd_count += (db->pool_size >= 0 ? db->pool_size : cf_default_pool_size);
		else
			fd_count += (db->pool_size >= 0 ? db->pool_size : cf_default_pool_size) * total_users;
	}

	log_info("kernel file descriptor limit: %d (hard: %d); max_client_conn: %d, max expected fd use: %d",
		 (int)lim.rlim_cur, (int)lim.rlim_max, cf_max_client_conn, fd_count);
}

static bool check_old_process_unix(void)
{
	struct sockaddr_un sa_un;
	socklen_t len = sizeof(sa_un);
	int domain = AF_UNIX;
	int res, fd;

	if (!cf_unix_socket_dir || !*cf_unix_socket_dir || sd_listen_fds(0) > 0)
		return false;

	memset(&sa_un, 0, len);
	sa_un.sun_family = domain;
	snprintf(sa_un.sun_path, sizeof(sa_un.sun_path),
		 "%s/.s.PGSQL.%d", cf_unix_socket_dir, cf_listen_port);

	fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0)
		die("could not create socket: %s", strerror(errno));
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

	err = event_base_loop(pgb_event_base, EVLOOP_ONCE);
	if (err < 0) {
		if (errno != EINTR)
			log_warning("event_loop failed: %s", strerror(errno));
	}
	pam_poll();
	per_loop_maint();
	reuse_just_freed_objects();
	rescue_timers();
	per_loop_pooler_maint();

	if (adns)
		adns_per_loop(adns);
}

static void takeover_part1(void)
{
	/* use temporary libevent base */
	struct event_base *evtmp;

	evtmp = pgb_event_base;
	pgb_event_base = event_base_new();

	if (!cf_unix_socket_dir || !*cf_unix_socket_dir)
		die("cannot reboot if unix dir not configured");

	/*
	 * Takeover with abstract Unix socket doesn't work because the
	 * new process can't unlink the socket used by the old process
	 * and put its own in place (see create_unix_socket()).
	 */
	if (cf_unix_socket_dir[0] == '@')
		die("cannot reboot with abstract Unix socket");

	if (sd_listen_fds(0) > 0)
		die("cannot reboot under service manager");

	takeover_init();
	while (cf_reboot)
		main_loop_once();

	event_base_free(pgb_event_base);
	pgb_event_base = evtmp;
}

static void dns_setup(void)
{
	if (adns)
		return;
	adns = adns_create_context();
	if (!adns)
		die("dns setup failed");
}

static void xfree(char **ptr_p)
{
	if (*ptr_p) {
		free(*ptr_p);
		*ptr_p = NULL;
	}
}

_UNUSED
static void cleanup(void)
{
	adns_free_context(adns);
	adns = NULL;

	admin_cleanup();
	objects_cleanup();
	sbuf_cleanup();

	event_base_free(pgb_event_base);

	tls_deinit();
	varcache_deinit();
	pktbuf_cleanup();

	reset_logging();

	xfree(&cf_username);
	xfree(&cf_config_file);
	xfree(&cf_listen_addr);
	xfree(&cf_unix_socket_dir);
	xfree(&cf_unix_socket_group);
	xfree(&cf_auth_file);
	xfree(&cf_auth_hba_file);
	xfree(&cf_auth_query);
	xfree(&cf_auth_user);
	xfree(&cf_server_reset_query);
	xfree(&cf_server_check_query);
	xfree(&cf_ignore_startup_params);
	xfree(&cf_autodb_connstr);
	xfree(&cf_jobname);
	xfree(&cf_admin_users);
	xfree(&cf_stats_users);
	xfree(&cf_client_tls_protocols);
	xfree(&cf_client_tls_ca_file);
	xfree(&cf_client_tls_cert_file);
	xfree(&cf_client_tls_key_file);
	xfree(&cf_client_tls_ciphers);
	xfree(&cf_client_tls_dheparams);
	xfree(&cf_client_tls_ecdhecurve);
	xfree(&cf_server_tls_protocols);
	xfree(&cf_server_tls_ca_file);
	xfree(&cf_server_tls_cert_file);
	xfree(&cf_server_tls_key_file);
	xfree(&cf_server_tls_ciphers);

	xfree((char **)&cf_logfile);
	xfree((char **)&cf_syslog_ident);
	xfree((char **)&cf_syslog_facility);
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
			printf("%s\n", PACKAGE_STRING);
			printf("libevent %s\nadns: %s\ntls: %s\n",
			       event_get_version(),
			       adns_get_backend(),
			       tls_backend_version());
#ifdef USE_SYSTEMD
			printf("systemd: yes\n");
#endif
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
			usage(argv[0]);
			break;
		default:
			fprintf(stderr, "Try \"%s --help\" for more information.\n", argv[0]);
			exit(1);
			break;
		}
	}
	if (optind + 1 != argc) {
		fprintf(stderr, "%s: no configuration file specified\n", argv[0]);
		fprintf(stderr, "Try \"%s --help\" for more information.\n", argv[0]);
		exit(1);
	}
	cf_config_file = xstrdup(argv[optind]);

#ifdef CASSERT
	/*
	 * Clean up all objects at the end, only for testing the
	 * cleanup code, not useful for production.  This must be the
	 * first atexit() call, since other atexit() handlers still
	 * make use of things that will be cleaned up.
	 */
	atexit(cleanup);
#endif

	init_objects();
	load_config();
	main_config.loaded = true;
	init_caches();
	logging_prefix_cb = log_socket_prefix;

	if (!sbuf_tls_setup())
		die("TLS setup failed");

	/* prefer cmdline over config for username */
	if (arg_username) {
		free(cf_username);
		cf_username = xstrdup(arg_username);
	}

	/* switch user is needed */
	if (cf_username && *cf_username)
		change_user(cf_username);

	/* disallow running as root */
	if (getuid() == 0)
		die("PgBouncer should not run as root");

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
			die("unix socket is in use, cannot continue");
		check_pidfile();
	}

	if (cf_daemon)
		go_daemon();

#ifndef USE_SYSTEMD
	if (getenv("NOTIFY_SOCKET"))
		log_warning("apparently running under systemd with notify socket, but systemd support was not built");
#endif

	/* need to do that after loading config; also do after
	 * go_daemon() so that output goes to log file */
	check_limits();

	/* initialize subsystems, order important */
	srandom(time(NULL) ^ getpid());
	if (!(pgb_event_base = event_base_new()))
		die("event_base_new() failed");
	dns_setup();
	signal_setup();
	janitor_setup();
	stats_setup();

	pam_init();

	if (did_takeover) {
		takeover_finish();
	} else {
		pooler_setup();
	}

	write_pidfile();

	log_info("process up: %s, libevent %s (%s), adns: %s, tls: %s", PACKAGE_STRING,
		 event_get_version(), event_base_get_method(pgb_event_base), adns_get_backend(),
		 tls_backend_version());

	sd_notify(0, "READY=1");

	/* main loop */
	while (cf_shutdown < 2)
		main_loop_once();

	return 0;
}
