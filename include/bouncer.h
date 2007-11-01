/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007 Marko Kreen, Skype Technologies OÜ
 * 
 * Permission to use, copy, modify, and distribute this software for any
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
	P_NONE = 0,
	P_PAUSE = 1,
	P_SUSPEND = 2
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

#include "aatree.h"
#include "hash.h"
#include "util.h"
#include "list.h"
#include "mbuf.h"
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

struct PgAddr {
	struct in_addr ip_addr;
	unsigned short port;
	unsigned is_unix:1;
};

struct PgStats {
	uint64_t	request_count;
	uint64_t	server_bytes;
	uint64_t	client_bytes;
	usec_t		query_time;	/* total req time in us */
};

/* contains connections for one db/user combo */
struct PgPool {
	List 		head;		/* all pools */
	List		map_head;	/* pools for specific client/db */

	/* pool contains connection into 'db' under 'user' */
	PgDatabase *	db;
	PgUser *	user;

	/* waiting events logged in clients */
	StatList	active_client_list;
	/* client waits for a server to be available */
	StatList	waiting_client_list;
	/* closed client connections with server key */
	StatList	cancel_req_list;

	/* servers linked with clients */
	StatList	active_server_list;
	/* servers ready to be linked with clients */
	StatList	idle_server_list;
	/* server just unlinked from clients */
	StatList	used_server_list;
	/* server in testing process */
	StatList	tested_server_list;
	/* servers in login phase */
	StatList	new_server_list;

	/* stats */
	PgStats		stats;
	PgStats		newer_stats;
	PgStats		older_stats;

	/* database info to be sent to client */
	uint8_t		welcome_msg[256];
	unsigned	welcome_msg_len;

	VarCache	orig_vars;

	/* if last connect failed, there should be delay before next */
	usec_t		last_connect_time;
	unsigned	last_connect_failed:1;
	unsigned	admin:1;
	unsigned	welcome_msg_ready:1;
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

struct PgUser {
	List head;
	List pool_list;
	Node tree_node;
	char name[MAX_USERNAME];
	char passwd[MAX_PASSWORD];
};

struct PgDatabase {
	List			head;
	char			name[MAX_DBNAME];

	unsigned		db_paused:1;

	/* key/val pairs (without user) for startup msg to be sent to server */
	uint8_t			startup_params[256];
	unsigned		startup_params_len;

	/* if not NULL, the user/psw is forced */
	PgUser *		forced_user;

	/* address prepared for connect() */
	PgAddr			addr;
	char			unix_socket_dir[UNIX_PATH_MAX];

	/* max server connections in one pool */
	int			pool_size;

	/* info fields, pointer to inside startup_msg */
	const char *		dbname;
};

struct PgSocket {
	List		head;		/* list header */
	PgSocket *	link;		/* the dest of packets */
	PgPool *	pool;		/* parent pool, if NULL not yet assigned */

	SocketState	state;

	unsigned	wait_for_welcome:1;	/* no server yet in pool */
	unsigned	ready:1;		/* server accepts new query */
	unsigned	admin_user:1;
	unsigned	own_user:1;		/* is console client with same uid */

	/* if the socket is suspended */
	unsigned	suspended:1;

	/* admin conn, waits for completion of PAUSE/SUSPEND cmd */
	unsigned	wait_for_response:1;
	/* this (server) socket must be closed ASAP */
	unsigned	close_needed:1;
	/* setting client vars */
	unsigned	setting_vars:1;

	usec_t		connect_time;	/* when connection was made */
	usec_t		request_time;	/* last activity time */
	usec_t		query_start;	/* query start moment */

	char		salt[4];
	uint8_t		cancel_key[BACKENDKEY_LEN];
	PgUser *	auth_user;
	PgAddr		remote_addr;
	PgAddr		local_addr;

	VarCache	vars;

	SBuf		sbuf;		/* stream buffer, must be last */
};

/* where to store old fd info during SHOW FDS result processing */
#define tmp_sk_oldfd	request_time
#define tmp_sk_linkfd	query_start
/* takeover_clean_socket() needs to clean those up */

/* main.c */
extern int cf_verbose;
extern int cf_daemon;
extern int cf_quiet;

extern char *cf_unix_socket_dir;
extern char *cf_listen_addr;
extern int cf_listen_port;

extern int cf_pool_mode;
extern int cf_max_client_conn;
extern int cf_default_pool_size;

extern usec_t cf_server_lifetime;
extern usec_t cf_server_idle_timeout;
extern char * cf_server_reset_query;
extern char * cf_server_check_query;
extern usec_t cf_server_check_delay;
extern usec_t cf_server_connect_timeout;
extern usec_t cf_server_login_retry;
extern usec_t cf_query_timeout;
extern usec_t cf_client_idle_timeout;
extern usec_t cf_client_login_timeout;
extern int cf_server_round_robin;

extern int cf_auth_type;
extern char *cf_auth_file;

extern char *cf_logfile;
extern char *cf_pidfile;

extern char *cf_admin_users;
extern char *cf_stats_users;
extern int cf_stats_period;

extern int cf_pause_mode;
extern int cf_shutdown;
extern int cf_reboot;

extern int cf_sbuf_len;
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


static inline PgSocket *
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


