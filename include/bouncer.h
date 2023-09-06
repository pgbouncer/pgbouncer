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
#include <usual/aatree.h>
#include <usual/socket.h>

#include <event2/event.h>
#include <event2/event_struct.h>

#include "uthash.h"


#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#else
#define SD_LISTEN_FDS_START 3
#define sd_is_socket(fd, f, t, l) (0)
#define sd_listen_fds(ue) (0)
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
	CL_WAITING_CANCEL,	/* pool->waiting_cancel_req_list */
	CL_ACTIVE_CANCEL,	/* pool->active_cancel_req_list */

	SV_FREE,		/* free_server_list */
	SV_JUSTFREE,		/* justfree_server_list */
	SV_LOGIN,		/* pool->new_server_list */
	SV_BEING_CANCELED,	/* pool->being_canceled_server_list */
	SV_IDLE,		/* pool->idle_server_list */
	SV_ACTIVE,		/* pool->active_server_list */
	SV_ACTIVE_CANCEL,	/* pool->active_cancel_server_list */
	SV_USED,		/* pool->used_server_list */
	SV_TESTED		/* pool->tested_server_list */
};

enum PauseMode {
	P_NONE = 0,		/* active pooling */
	P_PAUSE = 1,		/* wait for client to finish work */
	P_SUSPEND = 2		/* wait for buffers to be empty */
};

enum ShutDownMode {
	SHUTDOWN_NONE = 0,
	/* wait for all servers to become idle before stopping the process */
	SHUTDOWN_WAIT_FOR_SERVERS,
	/* close all connections immediately and stop the process */
	SHUTDOWN_IMMEDIATE,
};

enum SSLMode {
	SSLMODE_DISABLED,
	SSLMODE_ALLOW,
	SSLMODE_PREFER,
	SSLMODE_REQUIRE,
	SSLMODE_VERIFY_CA,
	SSLMODE_VERIFY_FULL
};

enum PacketCallbackFlag {
	CB_NONE = 0,	/* no callback */
	/*
	 * buffer the full packet into client->packet_cb_state.complete_packet
	 * and once that is done transfer to CB_HANDLE_COMPLETE_PACKET, which
	 * calls. This is used to handle prepared statements in transaction
	 * pooling mode.
	 */
	CB_WANT_COMPLETE_PACKET,
	/*
	 * The second stage of CB_WANT_COMPLETE_PACKET. The packet is fully
	 * buffered and can now be processed by client_proto.
	 */
	CB_HANDLE_COMPLETE_PACKET,
};


#define is_server_socket(sk) ((sk)->state >= SV_FREE)


typedef struct PgSocket PgSocket;
typedef struct PgUser PgUser;
typedef struct PgDatabase PgDatabase;
typedef struct PgPool PgPool;
typedef struct PgStats PgStats;
typedef union PgAddr PgAddr;
typedef enum SocketState SocketState;
typedef enum PacketCallbackFlag PacketCallbackFlag;
typedef struct PktHdr PktHdr;
typedef struct PktBuf PktBuf;
typedef struct ScramState ScramState;
typedef struct PgPreparedStatement PgPreparedStatement;
typedef enum ResponseAction ResponseAction;

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
#include "messages.h"
#include "pam.h"
#include "prepared_statement.h"

#ifndef WIN32
#define DEFAULT_UNIX_SOCKET_DIR "/tmp"
#else
#define DEFAULT_UNIX_SOCKET_DIR ""
#endif

/*
 * To avoid allocations, we use static buffers.
 *
 * Note that a trailing zero byte is used in each case, so the actual
 * usable length is one less.
 */

/* matching NAMEDATALEN */
#define MAX_DBNAME      64

/*
 * Ought to match NAMEDATALEN.  Some cloud services use longer user
 * names, so give it some extra room.
 */
#define MAX_USERNAME    128

/*
 * Some cloud services use very long generated passwords, so give it
 * plenty of room.
 */
#define MAX_PASSWORD    2048

/*
 * AUTH_* symbols are used for both protocol handling and
 * configuration settings (auth_type, hba).  Some are only applicable
 * to one or the other.
 */

/* no-auth modes */
#define AUTH_ANY        -1	/* same as trust but without username check */
#define AUTH_TRUST      AUTH_OK

/* protocol codes in Authentication* 'R' messages from server */
#define AUTH_OK         0
#define AUTH_KRB4       1	/* not supported */
#define AUTH_KRB5       2	/* not supported */
#define AUTH_PLAIN      3
#define AUTH_CRYPT      4	/* not supported */
#define AUTH_MD5        5
#define AUTH_SCM_CREDS  6	/* not supported */
#define AUTH_GSS        7	/* not supported */
#define AUTH_GSS_CONT   8	/* not supported */
#define AUTH_SSPI       9	/* not supported */
#define AUTH_SASL       10
#define AUTH_SASL_CONT  11
#define AUTH_SASL_FIN   12

/* internal codes */
#define AUTH_CERT       107
#define AUTH_PEER       108
#define AUTH_HBA        109
#define AUTH_REJECT     110
#define AUTH_PAM        111
#define AUTH_SCRAM_SHA_256      112

/* type codes for weird pkts */
#define PKT_STARTUP_V2  0x20000
#define PKT_STARTUP     0x30000
#define PKT_CANCEL      80877102
#define PKT_SSLREQ      80877103
#define PKT_GSSENCREQ   80877104

#define POOL_SESSION    0
#define POOL_TX         1
#define POOL_STMT       2
#define POOL_INHERIT    3

#define BACKENDKEY_LEN  8

/* buffer size for startup noise */
#define STARTUP_BUF     1024

/*
 * When peering is enabled we always put a 1 in the last two bits of the cancel
 * key when sending it to the client. These bits indicate the TTL and thus
 * allow forwarding the the cancel key 3 times before it is dropped. Triple
 * forwarding seems enough for any reasonable multi layered load balancing
 * setup.
 */
#define CANCELLATION_TTL_MASK 0x03


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

static inline unsigned int pga_family(const PgAddr *a)
{
	return a->sa.sa_family;
}
static inline bool pga_is_unix(const PgAddr *a)
{
	return a->sa.sa_family == AF_UNIX;
}

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

	/* stats for prepared statements */
	uint64_t ps_server_parse_count;
	uint64_t ps_client_parse_count;
	uint64_t ps_bind_count;
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
	PgUser *user;			/* user logged in as, this field is NULL for peer pools */

	/*
	 * Clients that are both logged in and where pgbouncer is actively
	 * listening for messages on the client socket.
	 */
	struct StatList active_client_list;

	/*
	 * Clients that are waiting for a server to be available to which their
	 * query/queries can be sent. These clients were originally in the
	 * active_client_list. But were placed in this list when a query was
	 * received on the client socket when no server connection was available to
	 * handle it.
	 */
	struct StatList waiting_client_list;

	/*
	 * Clients that sent cancel request, to cancel another client its query.
	 * These requests are waiting for a new server connection to be opened,
	 * before the request can be forwarded.
	 */
	struct StatList waiting_cancel_req_list;

	/*
	 * Clients that sent a cancel request, to cancel another client its query.
	 * This request was already forwarded to a server. They are waiting for a
	 * response from the server.
	 */
	struct StatList active_cancel_req_list;

	/*
	 * Server connections that are linked with a client. These clients cannot
	 * be used for other clients until they are back in the idle_server_list,
	 * which is done by calling release_server.
	 */
	struct StatList active_server_list;

	/*
	 * Server connections that are only used to forward a cancel request. These
	 * servers have a cancel request in-flight
	 */
	struct StatList active_cancel_server_list;

	/*
	 * Servers that normally could become idle, to be linked with with a new
	 * server. But active_cancel_server_list still contains servers that have a
	 * cancel request in flight which cancels queries on this server. To avoid
	 * race conditions this server will not be placed in the idle list (and
	 * thus not be reused) until all in-flight cancel requests for it have
	 * completed.
	 */
	struct StatList being_canceled_server_list;

	/*
	 * Servers connections that are ready to be linked with clients. These will
	 * be automatically used whenever a client needs a new connection to the
	 * server.
	 */
	struct StatList idle_server_list;

	/*
	 * Server connections that were just unlinked from their previous client.
	 * Some work is needed to make sure these server connections can be reused
	 * for another client. After all that that work is done the server is
	 * placed into idle_server_list.
	 */
	struct StatList used_server_list;

	/*
	 * Server connections in testing process. This is only applicable when the
	 * server_reset_query option is set in the pgbouncer.ini config. The server
	 * connection is in this state when it needs to run this reset query.
	 */
	struct StatList tested_server_list;

	/*
	 * Servers connections that are in the login phase. This is the initial
	 * state that every server connection is in. Once the whole login process
	 * has completed the server is moved to the idle list.
	 *
	 * A special case is when there are cancel requests waiting to be forwarded
	 * to servers in waiting_cancel_req_list. In that case the server bails out
	 * of the login flow, because a cancel reuest needs to be sent before
	 * logging in.
	 *
	 * NOTE: This list can at most contain a single server due to the way
	 * launch_new_connection spawns them.
	 */
	struct StatList new_server_list;

	PgStats stats;
	PgStats newer_stats;
	PgStats older_stats;

	/* database info to be sent to client */
	struct PktBuf *welcome_msg;	/* ServerParams without VarCache ones */

	VarCache orig_vars;		/* default params from server */

	usec_t last_lifetime_disconnect;/* last time when server_lifetime was applied */

	/* if last connect to server failed, there should be delay before next */
	usec_t last_connect_time;
	bool last_connect_failed : 1;
	bool last_login_failed : 1;

	bool welcome_msg_ready : 1;

	uint16_t rrcounter;		/* round-robin counter */
};

/*
 * pool_connected_server_count returns the number of servers that are fully
 * connected. This is used by the janitor to make the number of connected
 * servers satisfy the pool_size and min_pool_size config values. This
 * explicitly doesn't contain server connections used to send cancellation
 * requests, since those connections are untracked by Postgres and they cannot
 * be reused for purposes other than sending a single cancellation.
 */
#define pool_connected_server_count(pool) ( \
		statlist_count(&(pool)->active_server_list) + \
		statlist_count(&(pool)->being_canceled_server_list) + \
		statlist_count(&(pool)->idle_server_list) + \
		statlist_count(&(pool)->tested_server_list) + \
		statlist_count(&(pool)->used_server_list))

/*
 * pool_server_count returns how many connections to the server are open. This
 * includes connections for cancellations, because we also want to limit those
 * to some extent.
 */
#define pool_server_count(pool) ( \
		pool_connected_server_count(pool) + \
		statlist_count(&(pool)->new_server_list) + \
		statlist_count(&(pool)->active_cancel_server_list))

/*
 * pool_client_count returns the number of clients that have completed the
 * login phase. This doesn't include clients that are sending a cancellation
 * request.
 */
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
	bool mock_auth;			/* not a real user, only for mock auth */
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

	/*
	 * Pgbouncer peer database related settings
	 */
	int peer_id;	/* the peer_id of this peer */
	struct PgPool *pool;		/* the pool of this peer database */

	/*
	 * configuration
	 */
	char *host;		/* host or unix socket name */
	int port;
	int pool_size;		/* max server connections in one pool */
	int min_pool_size;	/* min server connections in one pool */
	int res_pool_size;	/* additional server connections in case of trouble */
	int pool_mode;		/* pool mode for this database */
	int max_db_connections;	/* max server connections between all pools */
	char *connect_query;	/* startup commands to send to server after connect */

	struct PktBuf *startup_params;	/* partial StartupMessage (without user) be sent to server */
	const char *dbname;	/* server-side name, pointer to inside startup_msg */
	char *auth_dbname;	/* if not NULL, auth_query will be run on the specified database */
	PgUser *forced_user;	/* if not NULL, the user/psw is forced */
	PgUser *auth_user;	/* if not NULL, users not in userlist.txt will be looked up on the server */

	/*
	 * run-time state
	 */
	bool db_paused;		/* PAUSE <db>; was issued */
	bool db_wait_close;	/* WAIT_CLOSE was issued for this database */
	bool db_dead;		/* used on RELOAD/SIGHUP to later detect removed dbs */
	bool db_auto;		/* is the database auto-created by autodb_connstr */
	bool db_disabled;	/* is the database accepting new connections? */
	bool admin;		/* internal console db */
	bool fake;		/* not a real database, only for mock auth */
	usec_t inactive_time;	/* when auto-database became inactive (to kill it after timeout) */
	unsigned active_stamp;	/* set if autodb has connections */
	int connection_count;	/* total connections for this database in all pools */

	struct AATree user_tree;	/* users that have been queried on this database */
};

enum ResponseAction {
	/* Forward the response that is received from the server */
	RA_FORWARD,
	/*
	 * drop the response received from the server (the client did not initiate
	 * the request)
	 */
	RA_SKIP,
	/*
	 * Generate a response to this type of request at this spot in the
	 * pipeline. The request from the client was not actually sent to the
	 * server, but the client expects a response to it.
	 */
	RA_FAKE,
};

typedef struct OutstandingRequest {
	struct List node;
	char type;	/* The single character type of the request */
	ResponseAction action;	/* What action to take (see comments on ResponseAction) */
	PgServerPreparedStatement *server_ps; /* The server-side prepared statement, if any */
} OutstandingRequest;

/*
 * A client or server connection.
 *
 * ->state corresponds to various lists the struct can be at.
 */
struct PgSocket {
	struct List head;		/* list header for pool list */
	struct List cancel_head;	/* list header for server->canceling_clients */
	PgSocket *link;		/* the dest of packets */
	PgPool *pool;		/* parent pool, if NULL not yet assigned */

	PgUser *login_user;	/* presented login, for client it may differ from pool->user */

	int client_auth_type;	/* auth method decided by hba */

	/* the queue of requests that we still expect a server response for */
	struct StatList outstanding_requests;

	SocketState state : 8;		/* this also specifies socket location */

	bool ready : 1;			/* server: accepts new query */
	bool idle_tx : 1;		/* server: idling in tx */
	bool close_needed : 1;		/* server: this socket must be closed ASAP */
	bool setting_vars : 1;		/* server: setting client vars */
	bool exec_on_connect : 1;	/* server: executing connect_query */
	bool resetting : 1;		/* server: executing reset query from auth login; don't release on flush */
	bool copy_mode : 1;		/* server: in copy stream, ignores any Sync packets */

	bool wait_for_welcome : 1;	/* client: no server yet in pool, cannot send welcome msg */
	bool wait_for_user_conn : 1;	/* client: waiting for auth_conn server connection */
	bool wait_for_user : 1;		/* client: waiting for auth_conn query results */
	bool wait_for_auth : 1;		/* client: waiting for external auth (PAM) to be completed */

	bool suspended : 1;		/* client/server: if the socket is suspended */

	bool admin_user : 1;		/* console client: has admin rights */
	bool own_user : 1;		/* console client: client with same uid on unix socket */
	bool wait_for_response : 1;	/* console client: waits for completion of PAUSE/SUSPEND cmd */

	bool wait_sslchar : 1;		/* server: waiting for ssl response: S/N */
	/* server: received an ErrorResponse, waiting for ReadyForQuery to clear
	 * the outstanding requests until the next Sync */
	bool query_failed : 1;

	int expect_rfq_count;	/* client: count of ReadyForQuery packets client should see */

	usec_t connect_time;	/* when connection was made */
	usec_t request_time;	/* last activity time */
	usec_t query_start;	/* client: query start moment */
	usec_t xact_start;	/* client: xact start moment */
	usec_t wait_start;	/* client: waiting start moment */

	uint8_t cancel_key[BACKENDKEY_LEN];	/* client: generated, server: remote */
	struct StatList canceling_clients;	/* clients trying to cancel the query on this connection */
	PgSocket *canceled_server;	/* server that is being canceled by this request */

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
		uint8_t *SaltedPassword;
		char cbind_flag;
		bool adhoc;	/* SCRAM data made up from plain-text password */
		int iterations;
		char *salt;	/* base64-encoded */
		uint8_t ClientKey[32];	/* SHA256_DIGEST_LENGTH */
		uint8_t StoredKey[32];
		uint8_t ServerKey[32];
	} scram_state;

	VarCache vars;		/* state of interesting server parameters */

	/* client: prepared statements prepared by this client */
	PgClientPreparedStatement *client_prepared_statements;
	/* server: prepared statements prepared on this server */
	PgServerPreparedStatement *server_prepared_statements;

	/* cb state during SBUF_EV_PKT_CALLBACK processing */
	struct CallbackState {
		/*
		 * Which callback should be executed.
		 * See comments on PacketCallbackFlag for details
		 */
		PacketCallbackFlag flag : 8;
		/*
		 * A temporary buffer into which we load the complete
		 * packet (if desired by the callback).
		 */
		PktHdr pkt;
	} packet_cb_state;


	SBuf sbuf;		/* stream buffer, must be last */
};

#define RAW_IOBUF_SIZE  offsetof(IOBuf, buf)
#define IOBUF_SIZE      (RAW_IOBUF_SIZE + cf_sbuf_len)

/* where to store old fd info during SHOW FDS result processing */
#define tmp_sk_oldfd    request_time
#define tmp_sk_linkfd   query_start
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
extern int cf_peer_id;

extern int cf_pool_mode;
extern int cf_max_client_conn;
extern int cf_default_pool_size;
extern int cf_min_pool_size;
extern int cf_res_pool_size;
extern usec_t cf_res_pool_timeout;
extern int cf_max_db_connections;
extern int cf_max_user_connections;

extern char *cf_autodb_connstr;
extern usec_t cf_autodb_idle_timeout;

extern usec_t cf_suspend_timeout;
extern usec_t cf_server_lifetime;
extern usec_t cf_server_idle_timeout;
extern char *cf_server_reset_query;
extern int cf_server_reset_query_always;
extern char *cf_server_check_query;
extern usec_t cf_server_check_delay;
extern int cf_server_fast_close;
extern usec_t cf_server_connect_timeout;
extern usec_t cf_server_login_retry;
extern usec_t cf_query_timeout;
extern usec_t cf_query_wait_timeout;
extern usec_t cf_cancel_wait_timeout;
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
extern char *cf_auth_dbname;

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

extern int cf_prepared_statement_cache_size;

extern const struct CfLookup pool_mode_map[];

extern usec_t g_suspend_start;

extern struct DNSContext *adns;
extern struct HBA *parsed_hba;

static inline PgSocket * _MUSTCHECK pop_socket(struct StatList *slist)
{
	struct List *item = statlist_pop(slist);
	if (item == NULL)
		return NULL;
	return container_of(item, PgSocket, head);
}

static inline PgSocket *first_socket(struct StatList *slist)
{
	if (statlist_empty(slist))
		return NULL;
	return container_of(slist->head.next, PgSocket, head);
}

static inline PgSocket *last_socket(struct StatList *slist)
{
	if (statlist_empty(slist))
		return NULL;
	return container_of(slist->head.prev, PgSocket, head);
}


/*
 * cstr_skip_ws returns a pointer to the first non whitespace character
 * in the given string.
 */
static inline char *cstr_skip_ws(char *p)
{
	while (*p && *p == ' ')
		p++;
	return p;
}


void load_config(void);


bool set_config_param(const char *key, const char *val);
void config_for_each(void (*param_cb)(void *arg, const char *name, const char *val, const char *defval, bool reloadable),
		     void *arg);
