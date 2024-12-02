/* The parsed contents of a Parse ('P') packet. */
typedef struct PgParsePacket {
	unsigned int len;
	const char *name;
	size_t query_and_parameters_len;
	const char *query_and_parameters;
} PgParsePacket;

/* The parsed contents of a Bind ('B') packet. */
typedef struct PgBindPacket {
	unsigned int len;
	const char *portal;
	const char *name;
} PgBindPacket;

/* The parsed contents of a Describe ('D') packet. */
typedef struct PgDescribePacket {
	char type;
	const char *name;
} PgDescribePacket;

/* The parsed contents of a Close ('C') packet. */
typedef struct PgClosePacket {
	char type;
	const char *name;
} PgClosePacket;

typedef enum PreparedStatementAction {
	PS_IGNORE = 0,	/* not related to prepared statements */
	/*
	 * It's a prepared statement related packet that we need to handle and
	 * we have received enough data to handle it.
	 */
	PS_HANDLE,
	/*
	 * It's a prepared statement related packet that we need to handle and
	 * but it needs to be completely buffered into memory before we can
	 * handle it.
	 */
	PS_HANDLE_FULL_PACKET,
	/*
	 * We could not determine if the packet is related to prepared
	 * statements that we need to handle. If we have not received all data,
	 * then we should wait for more. If we already received all data, then
	 * it's a broken packet.
	 */
	PS_INSPECT_FAILED,
} PreparedStatementAction;

PreparedStatementAction inspect_parse_packet(PgSocket *client, PktHdr *pkt);
PreparedStatementAction inspect_bind_packet(PgSocket *client, PktHdr *pkt);
PreparedStatementAction inspect_describe_or_close_packet(PgSocket *client, PktHdr *pkt);

bool unmarshall_parse_packet(PgSocket *client, PktHdr *pkt, PgParsePacket *parse_packet_p);
bool unmarshall_bind_packet(PgSocket *client, PktHdr *pkt, PgBindPacket *bind_packet_p);
bool unmarshall_describe_packet(PgSocket *client, PktHdr *pkt, PgDescribePacket *describe_packet_p);
bool unmarshall_close_packet(PgSocket *client, PktHdr *pkt, PgClosePacket *close_packet_p);

bool is_close_named_statement_packet(PgClosePacket *close_packet);

PktBuf *create_parse_packet(char *statement, PgPreparedStatement *parse_packet);
PktBuf *create_parse_complete_packet(void);
PktBuf *create_describe_packet(char *statement);
PktBuf *create_close_packet(char *statement);
PktBuf *create_close_complete_packet(void);

void parse_packet_free(PgParsePacket *pkt);
