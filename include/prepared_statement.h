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
	char stmt_name[];	/* varying size */
} PgClientPreparedStatement;

/* Prepared statements in Postgres backends */
typedef struct PgServerPreparedStatement {
	uint64_t query_id;
	UT_hash_handle hh;
	PgPreparedStatement *ps;
} PgServerPreparedStatement;

#define is_prepared_statements_enabled(pool) \
	(pool_pool_mode(pool) != POOL_SESSION && cf_prepared_statement_cache_size != 0)

bool handle_parse_command(PgSocket *client, PktHdr *pkt);
bool handle_bind_command(PgSocket *client, PktHdr *pkt);
bool handle_describe_command(PgSocket *client, PktHdr *pkt);
bool handle_close_statement_command(PgSocket *client, PktHdr *pkt, PgClosePacket *close_packet);

void unregister_prepared_statement(PgSocket *server, PgServerPreparedStatement *ps);
