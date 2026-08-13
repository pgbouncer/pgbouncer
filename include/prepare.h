#include <inttypes.h>

/* The format that our prepared statements are called on the Postgres server */
#define PREPARED_STMT_NAME_FORMAT "PGBOUNCER_%" PRIu64
/* "PGBOUNCER_" + 20 digits for unsigned 64 bit int + \0 */
#define MAX_SERVER_PREPARED_STMT_NAME 31


/* Structure to store text of prepared query */
typedef struct PgPreparedStatement {
	UT_hash_handle hh;
	uint64_t query_id;
	uint32_t use_count;
	size_t query_and_parameters_len;
	uint8_t stmt_name_len;
	char stmt_name[MAX_SERVER_PREPARED_STMT_NAME];
	char query_and_parameters[];	/* varying length */
} PgPreparedStatement;

/* Client session prepared statements */
typedef struct PgClientPreparedStatement {
	UT_hash_handle hh;
	PgPreparedStatement *ps;
	/*
	 * Order in which the client registered this statement, taken from the
	 * client its prepared_statement_seq counter. A DEALLOCATE ALL or
	 * DISCARD ALL only invalidates statements that the client registered
	 * before it sent the reset, so the reset compares against this.
	 */
	uint64_t seq;
	char stmt_name[];	/* varying size */
} PgClientPreparedStatement;

/* Prepared statements in Postgres backends */
typedef struct PgServerPreparedStatement {
	uint64_t query_id;
	UT_hash_handle hh;
	PgPreparedStatement *ps;
	/*
	 * Order in which this statement was prepared on the server, taken from
	 * the server its prepared_statement_seq counter. A reset only removes
	 * what the server had prepared before it ran the reset.
	 */
	uint64_t seq;
} PgServerPreparedStatement;

#define is_prepared_statements_enabled(client_or_server) \
	(connection_pool_mode(client_or_server) != POOL_SESSION && cf_max_prepared_statements != 0)


bool handle_parse_command(PgSocket *client, PktHdr *pkt);
bool handle_bind_command(PgSocket *client, PktHdr *pkt);
bool handle_describe_command(PgSocket *client, PktHdr *pkt);
bool handle_close_statement_command(PgSocket *client, PktHdr *pkt, PgClosePacket *close_packet);

void free_server_prepared_statement(PgServerPreparedStatement *server_ps);
void unregister_prepared_statement(PgSocket *server, uint64_t query_id);
bool add_prepared_statement(PgSocket *server, PgServerPreparedStatement *server_ps) _MUSTCHECK;
void free_client_prepared_statements(PgSocket *client);
void free_client_prepared_statements_upto(PgSocket *client, uint64_t seq);
void free_server_prepared_statements(PgSocket *server);
void free_server_prepared_statements_upto(PgSocket *server, uint64_t seq);
