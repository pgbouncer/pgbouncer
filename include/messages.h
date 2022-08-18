typedef struct PgParsePacket
{
  unsigned int len;
  char *name;
  char *query;
  uint16_t num_parameters;
  uint8_t *parameter_types_bytes;
} PgParsePacket;

typedef struct PgBindPacket
{
  unsigned int len;
  char *portal;
  char *name;
} PgBindPacket;

typedef struct PgDescribePacket
{
  char type;
  char *name;
} PgDescribePacket;

typedef struct PgClosePacket
{
	char type;
  char* name;
} PgClosePacket;

bool inspect_parse_packet(PgSocket *client, PktHdr *pkt, uint8_t *ps_action);
bool inspect_bind_packet(PgSocket *client, PktHdr *pkt, uint8_t *ps_action);
bool inspect_describe_packet(PgSocket *client, PktHdr *pkt, uint8_t *ps_action);

bool unmarshall_parse_packet(PgSocket *client, PktHdr *pkt, PgParsePacket **parse_packet_p);
bool unmarshall_bind_packet(PgSocket *client, PktHdr *pkt, PgBindPacket **bind_packet_p);
bool unmarshall_describe_packet(PgSocket *client, PktHdr *pkt, PgDescribePacket **describe_packet_p);
bool unmarshall_close_packet(PgSocket *client, PktHdr *pkt, PgClosePacket **close_packet_p);

bool is_close_statement_packet(PgClosePacket *close_packet);

PktBuf *create_parse_packet(char *statement, PgParsePacket *parse_packet);
PktBuf *create_parse_complete_packet(void);
PktBuf *create_describe_packet(char *statement);
PktBuf *create_close_packet(char *statement);
PktBuf *create_close_complete_packet(void);

void parse_packet_free(PgParsePacket *pkt);
