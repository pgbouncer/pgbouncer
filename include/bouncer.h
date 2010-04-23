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

#include <event.h>

#ifdef DBGVER
#define FULLVER   PACKAGE_NAME " version " PACKAGE_VERSION " (" DBGVER ")"
#else
#define FULLVER   PACKAGE_NAME " version " PACKAGE_VERSION
#endif

/* each state corresponts to a list */
enum SocketState {
	CL_FREE,		/* free_client_list */
	CL_JUSTFREE,		/* justfree_client_list */
	CL_LOGIN,		/* login_client_list */
	CL_WAITING,		/* pool->waiting_client_list */
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

#define is_server_socket(sk) ((sk)->state >= SV_FREE)


typedef struct PgSocket PgSocket;
typedef struct PgUser PgUser;
typedef struct PgDatabase PgDatabase;
typedef struct PgPool PgPool;
typedef struct PgStats PgStats;
typedef struct PgAddr PgAddr;
typedef enum SocketState SocketState;
typedef struct PktHdr PktHdr;

extern int cf_sbuf_len;

#include "aatree.h"
#include "hash.h"
#include "util.h"
#include "list.h"
#include "mbuf.h"
#include "iobuf.h"
#include "sbuf.h"
#include "pktbuf.h"
#include "varcache.h"
#include "slab.h"

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

/* to avoid allocations will use static buffers */
#define MAX_DBNAME	64
#define MAX_USERNAME	64
#define MAX_PASSWORD	64

/* auth modes, should match PG's */
#define AUTH_ANY	-1 /* same as trust but without username check */
#define AUTH_TRUST	0
#define AUTH_PLAIN	3
#define AUTH_CRYPT	4
#define AUTH_MD5	5
#define AUTH_CREDS	6

/* type codes for weird pkts */
#define PKT_STARTUP_V2  0x20000
#define PKT_STARTUP     0x30000
#define PKT_CANCEL      80877102
#define PKT_SSLREQ      80877103

#define POOL_SESSION	0
#define POOL_TX		1
#define POOL_STMT	2

/* old style V2 header: len:4b code:4b */
#define OLD_HEADER_LEN	8
/* new style V3 packet header len - type:1b, len:4b */ 
#define NEW_HEADER_LEN	5

#define BACKENDKEY_LEN	8

/* buffer size for startup noise */
#define STARTUP_BUF	1024

/*
 * Remote/local address
 */
struct PgAddr {
	struct in_addr ip_addr;
	unsigned short port;
	bool is_unix;
};

/*
 * Stats, kept per-pool.
 */
struct PgStats {
	uint64_t request_count;
	uint64_t server_bytes;
	uint64_t client_bytes;
	usec_t query_time;	/* total req time in us */
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
	List head;			/* entry in global pool_list */
	List map_head;			/* entry in user->pool_list */

	PgDatabase *db;			/* corresponging database */
	PgUser *user;			/* user logged in as */

	StatList active_client_list;	/* waiting events logged in clients */
	StatList waiting_client_list;	/* client waits for a server to be available */
	StatList cancel_req_list;	/* closed client connections with server key */

	StatList active_server_list;	/* servers linked with clients */
	StatList idle_server_list;	/* servers ready to be linked with clients */
	StatList used_server_list;	/* server just unlinked from clients */
	StatList tested_server_list;	/* server in testing process */
	StatList new_server_list;	/* servers in login phase */

	PgStats stats;
	PgStats newer_stats;
	PgStats older_stats;

	/* database info to be sent to client */
	uint8_t welcome_msg[STARTUP_BUF]; /* ServerParams without VarCache ones */
	unsigned welcome_msg_len;

	VarCache orig_vars;		/* default params from server */

	usec_t last_lifetime_disconnect;/* last time when server_lifetime was applied */

	/* if last connect failed, there should be delay before next */
	usec_t last_connect_time;
	unsigned last_connect_failed:1;

	unsigned welcome_msg_ready:1;
};

#define pool_server_count(pool) ( \
		statlist_count(&(pool)->active_server_list) + \
		statlist_count(&(pool)->idle_server_list) + \
		statlist_count(&(pool)->new_server_list) + \
		statlist_count(&(pool)->tested_server_list) + \
		statlist_count(&(pool)->used_server_list))

#define pool_client_count(pool) ( \
		statlist_count(&(pool)->active_client_list) + \
		statlist_count(&(pool)->waiting_client_list))

/*
 * A user in login db.
 *
 * fixme: remove ->head as ->tree_node should be enough.
 *
 * For databases where remote user is forced, the pool is:
 * first(db->forced_user->pool_list), where pool_list has only one entry.
 *
 * Otherwise, ->pool_list contains multiple pools, for all PgDatabases
 * whis user has logged in.
 */
struct PgUser {
	List head;		/* used to attach user to list */
	List pool_list;		/* list of pools where pool->user == this user */
	Node tree_node;		/* used to attach user to tree */
	char name[MAX_USERNAME];
	char passwd[MAX_PASSWORD];
};

/*
 * A database entry from config.
 */
struct PgDatabase {
	List head;
	char name[MAX_DBNAME];	/* db name for clients */

	bool db_paused;		/* PAUSE <db>; was issued */
	bool db_dead;		/* used on RELOAD/SIGHUP to later detect removed dbs */
	bool db_auto;		/* is the database auto-created by autodb_connstr */
	bool admin;		/* internal console db */

	uint8_t startup_params[STARTUP_BUF]; /* partial StartupMessage (without user) be sent to server */
	unsigned startup_params_len;

	PgUser *forced_user;	/* if not NULL, the user/psw is forced */

	PgAddr addr;		/* address prepared for connect() */
	char unix_socket_dir[UNIX_PATH_MAX]; /* custom unix socket dir */

	int pool_size;		/* max server connections in one pool */
	int res_pool_size;	/* additional server connections in case of trouble */

	const char *dbname;	/* server-side name, pointer to inside startup_msg */

	/* startup commands to send to server after connect. malloc-ed */
	const char *connect_query;

	usec_t inactive_time; /* when auto-database became inactive (to kill it after timeout) */
};


/*
 * A client or server connection.
 *
 * ->state corresponds to various lists the struct can be at.
 */
struct PgSocket {
	List head;		/* list header */
	PgSocket *link;		/* the dest of packets */
	PgPool *pool;		/* parent pool, if NULL not yet assigned */

	PgUser *auth_user;	/* presented login, for client it may differ from pool->user */

	SocketState state:8;	/* this also specifies socket location */

	bool ready:1;		/* server: accepts new query */
	bool close_needed:1;	/* server: this socket must be closed ASAP */
	bool setting_vars:1;	/* server: setting client vars */
	bool exec_on_connect:1;	/* server: executing connect_query */

	bool wait_for_welcome:1;/* client: no server yet in pool, cannot send welcome msg */

	bool suspended:1;	/* client/server: if the socket is suspended */

	bool admin_user:1;	/* console client: has admin rights */
	bool own_user:1;	/* console client: client with same uid on unix socket */
	bool wait_for_response:1;/* console client: waits for completion of PAUSE/SUSPEND cmd */

	usec_t connect_time;	/* when connection was made */
	usec_t request_time;	/* last activity time */
	usec_t query_start;	/* query start moment */

	uint8_t cancel_key[BACKENDKEY_LEN]; /* client: generated, server: remote */
	PgAddr remote_addr;	/* ip:port for remote endpoint */
	PgAddr local_addr;	/* ip:port for local endpoint */

	VarCache vars;		/* state of interesting server parameters */

	SBuf sbuf;		/* stream buffer, must be last */
};

#define RAW_IOBUF_SIZE	offsetof(IOBuf, buf)
#define IOBUF_SIZE	(RAW_IOBUF_SIZE + cf_sbuf_len)

/* where to store old fd info during SHOW FDS result processing */
#define tmp_sk_oldfd	request_time
#define tmp_sk_linkfd	query_start
/* takeover_clean_socket() needs to clean those up */

/* where the salt is temporarly stored */
#define tmp_login_salt  cancel_key

/* main.c */
extern int cf_verbose;
extern int cf_daemon;
extern int cf_quiet;

extern char *cf_config_file;
extern char *cf_jobname;
extern int cf_syslog;
extern char *cf_syslog_facility;

extern char *cf_unix_socket_dir;
extern char *cf_listen_addr;
extern int cf_listen_port;
extern int cf_listen_backlog;

extern int cf_pool_mode;
extern int cf_max_client_conn;
extern int cf_default_pool_size;
extern int cf_res_pool_size;
extern usec_t cf_res_pool_timeout;

extern char * cf_autodb_connstr;
extern usec_t cf_autodb_idle_timeout;

extern usec_t cf_suspend_timeout;
extern usec_t cf_server_lifetime;
extern usec_t cf_server_idle_timeout;
extern char * cf_server_reset_query;
extern char * cf_server_check_query;
extern usec_t cf_server_check_delay;
extern usec_t cf_server_connect_timeout;
extern usec_t cf_server_login_retry;
extern usec_t cf_query_timeout;
extern usec_t cf_query_wait_timeout;
extern usec_t cf_client_idle_timeout;
extern usec_t cf_client_login_timeout;
extern int cf_server_round_robin;

extern int cf_auth_type;
extern char *cf_auth_file;

extern char *cf_logfile;
extern char *cf_pidfile;

extern char *cf_ignore_startup_params;

extern char *cf_admin_users;
extern char *cf_stats_users;
extern int cf_stats_period;

extern int cf_pause_mode;
extern int cf_shutdown;
extern int cf_reboot;

extern int cf_sbuf_loopcnt;
extern int cf_tcp_keepalive;
extern int cf_tcp_keepcnt;
extern int cf_tcp_keepidle;
extern int cf_tcp_keepintvl;
extern int cf_tcp_socket_buffer;
extern int cf_tcp_defer_accept;

extern int cf_log_connections;
extern int cf_log_disconnections;
extern int cf_log_pooler_errors;

extern ConfElem bouncer_params[];

extern usec_t g_suspend_start;

static inline PgSocket * _MUSTCHECK
pop_socket(StatList *slist)
{
	List *item = statlist_pop(slist);
	if (item == NULL)
		return NULL;
	return container_of(item, PgSocket, head);
}

static inline PgSocket *
first_socket(StatList *slist)
{
	if (statlist_empty(slist))
		return NULL;
	return container_of(slist->head.next, PgSocket, head);
}

void load_config(bool reload);


