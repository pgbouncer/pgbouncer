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
 * core structures
 */

#include "system.h"

#include <usual/cfparser.h>
#include <usual/time.h>
#include <usual/list.h>
#include <usual/statlist.h>
#include <usual/string.h>
#include <usual/logging.h>
#include <usual/aatree.h>
#include <usual/hashing/lookup3.h>
#include <usual/slab.h>
#include <usual/socket.h>
#include <usual/safeio.h>
#include <usual/mbuf.h>
#include <usual/strpool.h>

#include <event2/event.h>
#include <event2/event_struct.h>

#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#else
#define SD_LISTEN_FDS_START 3
#define sd_is_socket(fd, f, t, l) (0)
#define sd_listen_fds(ue) (0)
#define sd_listen_fds_with_names(ue, n) (0)
#define sd_notify(ue, s)
#define sd_notifyf(ue, f, ...)
#endif


/* global libevent handle */
extern struct event_base *pgb_event_base;


/* each state corresponds to a list */
enum SocketState {
	CL_FREE,		/* free_client_list */
	CL_JUSTFREE,		/* justfree_client_list */
	CL_LOGIN,		/* login_client_list */
	CL_WAITING,		/* pool->waiting_client_list */
	CL_WAITING_LOGIN,	/*   - but return to CL_LOGIN instead of CL_ACTIVE */
	CL_ACTIVE,		/* pool->active_client_list */
	CL_CANCEL,		/* pool->cancel_req_list */

	SV_FREE,		/* free_server_list */
	SV_JUSTFREE,		/* justfree_server_list */
	SV_LOGIN,		/* pool->new_server_list */
	SV_IDLE,		/* pool->idle_server_list */
	SV_ACTIVE,		/* pool->active_server_list */
	SV_USED,		/* pool->used_server_list */
	SV_TESTED		/* pool->tested_server_list */
};

enum PauseMode {
	P_NONE = 0,		/* active pooling */
	P_PAUSE = 1,		/* wait for client to finish work */
	P_SUSPEND = 2		/* wait for buffers to be empty */
};

enum SSLMode {
	SSLMODE_DISABLED,
	SSLMODE_ALLOW,
	SSLMODE_PREFER,
	SSLMODE_REQUIRE,
	SSLMODE_VERIFY_CA,
	SSLMODE_VERIFY_FULL
};

#define is_server_socket(sk) ((sk)->state >= SV_FREE)


typedef struct PgSocket PgSocket;
typedef struct PgUser PgUser;
typedef struct PgDatabase PgDatabase;
typedef struct PgPool PgPool;
typedef struct PgStats PgStats;
typedef union PgAddr PgAddr;
typedef enum SocketState SocketState;
typedef struct PktHdr PktHdr;
typedef struct ScramState ScramState;

extern int cf_sbuf_len;

#include "util.h"
#include "iobuf.h"
#include "sbuf.h"
#include "pktbuf.h"
#include "varcache.h"
#include "dnslookup.h"

#include "admin.h"
#include "loader.h"
#include "client.h"
#include "server.h"
#include "pooler.h"
#include "proto.h"
#include "objects.h"
#include "stats.h"
#include "takeover.h"
#include "janitor.h"
#include "hba.h"
#include "pam.h"

#ifndef WIN32
#define DEFAULT_UNIX_SOCKET_DIR "/tmp"
#else
#define DEFAULT_UNIX_SOCKET_DIR ""
#endif

/* to avoid allocations will use static buffers */
#define MAX_DBNAME	64
#define MAX_USERNAME	64
/* typical SCRAM-SHA-256 verifier takes at least 133 bytes */
#define MAX_PASSWORD	160

/*
 * AUTH_* symbols are used for both protocol handling and
 * configuration settings (auth_type, hba).  Some are only applicable
 * to one or the other.
 */

/* no-auth modes */
#define AUTH_ANY	-1 /* same as trust but without username check */
#define AUTH_TRUST	AUTH_OK

/* protocol codes in Authentication* 'R' messages from server */
#define AUTH_OK		0
#define AUTH_KRB4	1	/* not supported */
#define AUTH_KRB5	2	/* not supported */
#define AUTH_PLAIN	3
#define AUTH_CRYPT	4	/* not supported */
#define AUTH_MD5	5
#define AUTH_SCM_CREDS	6	/* not supported */
#define AUTH_GSS	7	/* not supported */
#define AUTH_GSS_CONT	8	/* not supported */
#define AUTH_SSPI	9	/* not supported */
#define AUTH_SASL	10
#define AUTH_SASL_CONT	11
#define AUTH_SASL_FIN	12

/* internal codes */
#define AUTH_CERT	107
#define AUTH_PEER	108
#define AUTH_HBA	109
#define AUTH_REJECT	110
#define AUTH_PAM	111
#define AUTH_SCRAM_SHA_256	112

/* type codes for weird pkts */
#define PKT_STARTUP_V2  0x20000
#define PKT_STARTUP     0x30000
#define PKT_CANCEL      80877102
#define PKT_SSLREQ      80877103
#define PKT_GSSENCREQ   80877104

#define POOL_SESSION	0
#define POOL_TX		1
#define POOL_STMT	2
#define POOL_INHERIT	3

#define BACKENDKEY_LEN	8

/* buffer size for startup noise */
#define STARTUP_BUF	1024


/*
 * Remote/local address
 */

/* buffer for pgaddr string conversions (with port) */
#define PGADDR_BUF  (INET6_ADDRSTRLEN + 10)

struct sockaddr_ucreds {
	struct sockaddr_in sin;
	uid_t uid;
	pid_t pid;
};

/*
 * AF_INET,AF_INET6 are stored as-is,
 * AF_UNIX uses sockaddr_in port + uid/pid.
 */
union PgAddr {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_ucreds scred;
};

static inline unsigned int pga_family(const PgAddr *a) { return a->sa.sa_family; }
static inline bool pga_is_unix(const PgAddr *a) { return a->sa.sa_family == AF_UNIX; }

int pga_port(const PgAddr *a);
void pga_set(PgAddr *a, int fam, int port);
void pga_copy(PgAddr *a, const struct sockaddr *sa);
bool pga_pton(PgAddr *a, const char *s, int port);
const char *pga_ntop(const PgAddr *a, char *dst, int dstlen);
const char *pga_str(const PgAddr *a, char *dst, int dstlen);
const char *pga_details(const PgAddr *a, char *dst, int dstlen);
int pga_cmp_addr(const PgAddr *a, const PgAddr *b);

/*
 * Stats, kept per-pool.
 */
struct PgStats {
	uint64_t xact_count;
	uint64_t query_count;
	uint64_t server_bytes;
	uint64_t client_bytes;
	usec_t xact_time;	/* total transaction time in us */
	usec_t query_time;	/* total query time in us */
	usec_t wait_time;	/* total time clients had to wait */
};

/*
 * Contains connections for one db+user pair.
 *
 * Stats:
 *   ->stats is updated online.
 *   for each stats_period:
 *   ->older_stats = ->newer_stats
 *   ->newer_stats = ->stats
 */
struct PgPool {
	struct List head;			/* entry in global pool_list */
	struct List map_head;			/* entry in user->pool_list */

	PgDatabase *db;			/* corresponding database */
	PgUser *user;			/* user logged in as */

	struct StatList active_client_list;	/* waiting events logged in clients */
	struct StatList waiting_client_list;	/* client waits for a server to be available */
	struct StatList cancel_req_list;	/* closed client connections with server key */

	struct StatList active_server_list;	/* servers linked with clients */
	struct StatList idle_server_list;	/* servers ready to be linked with clients */
	struct StatList used_server_list;	/* server just unlinked from clients */
	struct StatList tested_server_list;	/* server in testing process */
	struct StatList new_server_list;	/* servers in login phase */

	PgStats stats;
	PgStats newer_stats;
	PgStats older_stats;

	/* database info to be sent to client */
	struct PktBuf *welcome_msg; /* ServerParams without VarCache ones */

	VarCache orig_vars;		/* default params from server */

	usec_t last_lifetime_disconnect;/* last time when server_lifetime was applied */

	/* if last connect to server failed, there should be delay before next */
	usec_t last_connect_time;
	unsigned last_connect_failed:1;
	unsigned last_login_failed:1;

	unsigned welcome_msg_ready:1;
};

#define pool_connected_server_count(pool) ( \
		statlist_count(&(pool)->active_server_list) + \
		statlist_count(&(pool)->idle_server_list) + \
		statlist_count(&(pool)->tested_server_list) + \
		statlist_count(&(pool)->used_server_list))

#define pool_server_count(pool) ( \
		pool_connected_server_count(pool) + \
		statlist_count(&(pool)->new_server_list))

#define pool_client_count(pool) ( \
		statlist_count(&(pool)->active_client_list) + \
		statlist_count(&(pool)->waiting_client_list))

/*
 * A user in login db.
 *
 * FIXME: remove ->head as ->tree_node should be enough.
 *
 * For databases where remote user is forced, the pool is:
 * first(db->forced_user->pool_list), where pool_list has only one entry.
 *
 * Otherwise, ->pool_list contains multiple pools, for all PgDatabases
 * which user has logged in.
 */
struct PgUser {
	struct List head;		/* used to attach user to list */
	struct List pool_list;		/* list of pools where pool->user == this user */
	struct AANode tree_node;	/* used to attach user to tree */
	char name[MAX_USERNAME];
	char passwd[MAX_PASSWORD];
	uint8_t scram_ClientKey[32];
	uint8_t scram_ServerKey[32];
	bool has_scram_keys;		/* true if the above two are valid */
	int pool_mode;
	int max_user_connections;	/* how much server connections are allowed */
	int connection_count;	/* how much connections are used by user now */
};

/*
 * A database entry from config.
 */
struct PgDatabase {
	struct List head;
	char name[MAX_DBNAME];	/* db name for clients */

	bool db_paused;		/* PAUSE <db>; was issued */
	bool db_wait_close;	/* WAIT_CLOSE was issued for this database */
	bool db_dead;		/* used on RELOAD/SIGHUP to later detect removed dbs */
	bool db_auto;		/* is the database auto-created by autodb_connstr */
	bool db_disabled;	/* is the database accepting new connections? */
	bool admin;		/* internal console db */

	struct PktBuf *startup_params; /* partial StartupMessage (without user) be sent to server */

	PgUser *forced_user;	/* if not NULL, the user/psw is forced */
	PgUser *auth_user;	/* if not NULL, users not in userlist.txt will be looked up on the server */

	char *host;		/* host or unix socket name */
	int port;

	int pool_size;		/* max server connections in one pool */
	int res_pool_size;	/* additional server connections in case of trouble */
	int pool_mode;		/* pool mode for this database */
	int max_db_connections;	/* max server connections between all pools */

	const char *dbname;	/* server-side name, pointer to inside startup_msg */

	/* startup commands to send to server after connect. malloc-ed */
	char *connect_query;

	usec_t inactive_time;	/* when auto-database became inactive (to kill it after timeout) */
	unsigned active_stamp;	/* set if autodb has connections */

	int connection_count;	/* total connections for this database in all pools */

	struct AATree user_tree;	/* users that have been queried on this database */
};


/*
 * A client or server connection.
 *
 * ->state corresponds to various lists the struct can be at.
 */
struct PgSocket {
	struct List head;		/* list header */
	PgSocket *link;		/* the dest of packets */
	PgPool *pool;		/* parent pool, if NULL not yet assigned */

	PgUser *auth_user;	/* presented login, for client it may differ from pool->user */

	int client_auth_type;	/* auth method decided by hba */

	SocketState state:8;	/* this also specifies socket location */

	bool ready:1;		/* server: accepts new query */
	bool idle_tx:1;		/* server: idling in tx */
	bool close_needed:1;	/* server: this socket must be closed ASAP */
	bool setting_vars:1;	/* server: setting client vars */
	bool exec_on_connect:1;	/* server: executing connect_query */
	bool resetting:1;	/* server: executing reset query from auth login; don't release on flush */
	bool copy_mode:1;	/* server: in copy stream, ignores any Sync packets */

	bool wait_for_welcome:1;/* client: no server yet in pool, cannot send welcome msg */
	bool wait_for_user_conn:1;/* client: waiting for auth_conn server connection */
	bool wait_for_user:1;	/* client: waiting for auth_conn query results */
	bool wait_for_auth:1;	/* client: waiting for external auth (PAM) to be completed */

	bool suspended:1;	/* client/server: if the socket is suspended */

	bool admin_user:1;	/* console client: has admin rights */
	bool own_user:1;	/* console client: client with same uid on unix socket */
	bool wait_for_response:1;/* console client: waits for completion of PAUSE/SUSPEND cmd */

	bool wait_sslchar:1;	/* server: waiting for ssl response: S/N */

	int expect_rfq_count;	/* client: count of ReadyForQuery packets client should see */

	usec_t connect_time;	/* when connection was made */
	usec_t request_time;	/* last activity time */
	usec_t query_start;	/* query start moment */
	usec_t xact_start;	/* xact start moment */
	usec_t wait_start;	/* waiting start moment */

	uint8_t cancel_key[BACKENDKEY_LEN]; /* client: generated, server: remote */
	PgAddr remote_addr;	/* ip:port for remote endpoint */
	PgAddr local_addr;	/* ip:port for local endpoint */

	union {
		struct DNSToken *dns_token;	/* ongoing request */
		PgDatabase *db;			/* cache db while doing auth query */
	};

	struct ScramState {
		char *client_nonce;
		char *client_first_message_bare;
		char *client_final_message_without_proof;
		char *server_nonce;
		char *server_first_message;
		uint8_t	*SaltedPassword;
		char cbind_flag;
		bool adhoc;	/* SCRAM data made up from plain-text password */
		int iterations;
		char *salt;	/* base64-encoded */
		uint8_t ClientKey[32];	/* SHA256_DIGEST_LENGTH */
		uint8_t StoredKey[32];
		uint8_t ServerKey[32];
	} scram_state;

	VarCache vars;		/* state of interesting server parameters */

	SBuf sbuf;		/* stream buffer, must be last */
};

#define RAW_IOBUF_SIZE	offsetof(IOBuf, buf)
#define IOBUF_SIZE	(RAW_IOBUF_SIZE + cf_sbuf_len)

/* where to store old fd info during SHOW FDS result processing */
#define tmp_sk_oldfd	request_time
#define tmp_sk_linkfd	query_start
/* takeover_clean_socket() needs to clean those up */

/* where the salt is temporarily stored */
#define tmp_login_salt  cancel_key

/* main.c */
extern int cf_daemon;

extern char *cf_config_file;
extern char *cf_jobname;

extern char *cf_unix_socket_dir;
extern int cf_unix_socket_mode;
extern char *cf_unix_socket_group;
extern char *cf_listen_addr;
extern int cf_listen_port;
extern int cf_listen_backlog;

extern int cf_pool_mode;
extern int cf_max_client_conn;
extern int cf_default_pool_size;
extern int cf_min_pool_size;
extern int cf_res_pool_size;
extern usec_t cf_res_pool_timeout;
extern int cf_max_db_connections;
extern int cf_max_user_connections;

extern char * cf_autodb_connstr;
extern usec_t cf_autodb_idle_timeout;

extern usec_t cf_suspend_timeout;
extern usec_t cf_server_lifetime;
extern usec_t cf_server_idle_timeout;
extern char * cf_server_reset_query;
extern int cf_server_reset_query_always;
extern char * cf_server_check_query;
extern usec_t cf_server_check_delay;
extern int cf_server_fast_close;
extern usec_t cf_server_connect_timeout;
extern usec_t cf_server_login_retry;
extern usec_t cf_query_timeout;
extern usec_t cf_query_wait_timeout;
extern usec_t cf_client_idle_timeout;
extern usec_t cf_client_login_timeout;
extern usec_t cf_idle_transaction_timeout;
extern int cf_server_round_robin;
extern int cf_disable_pqexec;
extern usec_t cf_dns_max_ttl;
extern usec_t cf_dns_nxdomain_ttl;
extern usec_t cf_dns_zone_check_period;
extern char *cf_resolv_conf;

extern int cf_auth_type;
extern char *cf_auth_file;
extern char *cf_auth_query;
extern char *cf_auth_user;
extern char *cf_auth_hba_file;

extern char *cf_pidfile;

extern char *cf_ignore_startup_params;

extern char *cf_admin_users;
extern char *cf_stats_users;
extern int cf_stats_period;
extern int cf_log_stats;

extern int cf_pause_mode;
extern int cf_shutdown;
extern int cf_reboot;

extern unsigned int cf_max_packet_size;

extern int cf_sbuf_loopcnt;
extern int cf_so_reuseport;
extern int cf_tcp_keepalive;
extern int cf_tcp_keepcnt;
extern int cf_tcp_keepidle;
extern int cf_tcp_keepintvl;
extern int cf_tcp_socket_buffer;
extern int cf_tcp_defer_accept;
extern int cf_tcp_user_timeout;

extern int cf_log_connections;
extern int cf_log_disconnections;
extern int cf_log_pooler_errors;
extern int cf_application_name_add_host;

extern int cf_client_tls_sslmode;
extern char *cf_client_tls_protocols;
extern char *cf_client_tls_ca_file;
extern char *cf_client_tls_cert_file;
extern char *cf_client_tls_key_file;
extern char *cf_client_tls_ciphers;
extern char *cf_client_tls_dheparams;
extern char *cf_client_tls_ecdhecurve;

extern int cf_server_tls_sslmode;
extern char *cf_server_tls_protocols;
extern char *cf_server_tls_ca_file;
extern char *cf_server_tls_cert_file;
extern char *cf_server_tls_key_file;
extern char *cf_server_tls_ciphers;

extern const struct CfLookup pool_mode_map[];

extern usec_t g_suspend_start;

extern struct DNSContext *adns;
extern struct HBA *parsed_hba;

static inline PgSocket * _MUSTCHECK
pop_socket(struct StatList *slist)
{
	struct List *item = statlist_pop(slist);
	if (item == NULL)
		return NULL;
	return container_of(item, PgSocket, head);
}

static inline PgSocket *
first_socket(struct StatList *slist)
{
	if (statlist_empty(slist))
		return NULL;
	return container_of(slist->head.next, PgSocket, head);
}

static inline PgSocket *
last_socket(struct StatList *slist)
{
	if (statlist_empty(slist))
		return NULL;
	return container_of(slist->head.prev, PgSocket, head);
}

bool requires_auth_file(int);
void load_config(void);


bool set_config_param(const char *key, const char *val);
void config_for_each(void (*param_cb)(void *arg, const char *name, const char *val, bool reloadable),
		     void *arg);
