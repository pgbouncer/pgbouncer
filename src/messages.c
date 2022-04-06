#include "bouncer.h"

/* Inspect Parse packet to see if it defines a named prepared statement */
bool inspect_parse_packet(PgSocket *client, PktHdr *pkt, uint8_t *ps_action)
{
  const char *statement;

  if (!mbuf_get_string(&pkt->data, &statement))
    return false;

  if (strlen(statement) > 0) {
    slog_noise(client, "inspect_parse_packet: type=%c, len=%d, statement=%s", pkt->type, pkt->len, statement);
    *ps_action = PS_HANDLE;
  } else {
    slog_noise(client, "inspect_parse_packet: type=%c, len=%d, statement=<empty>", pkt->type, pkt->len);
    *ps_action = PS_IGNORE;
  }
  
  return true;
}

/* Inspect Bind packet to see if it defines a named prepared statement */
bool inspect_bind_packet(PgSocket *client, PktHdr *pkt, uint8_t *ps_action)
{
  const char *portal;
  const char *statement;

  if (!mbuf_get_string(&pkt->data, &portal))
    return false;

  if (!mbuf_get_string(&pkt->data, &statement))
    return false;

  if (strlen(statement) > 0) {
    slog_noise(client, "inspect_bind_packet: type=%c, len=%d, statement=%s", pkt->type, pkt->len, statement);
    *ps_action = PS_HANDLE;
  } else {
    slog_noise(client, "inspect_bind_packet: type=%c, len=%d, statement=<empty>", pkt->type, pkt->len);
    *ps_action = PS_IGNORE;
  }
  
  return true;
}

/* Inspect Describe packet to see if it defines a named prepared statement */
bool inspect_describe_packet(PgSocket *client, PktHdr *pkt, uint8_t *ps_action)
{
  char describe;
  const char *statement;

  if (!mbuf_get_char(&pkt->data, &describe))
    return false;

  if (describe == 'S') {
    if (!mbuf_get_string(&pkt->data, &statement))
      return false;

    if (strlen(statement) > 0) {
      slog_noise(client, "inspect_describe_packet: type=%c, len=%d, P/S=%c, statement=%s", pkt->type, pkt->len, describe, statement);
      *ps_action = PS_HANDLE;
    } else {
      slog_noise(client, "inspect_descibe_packet: type=%c, len=%d, P/S=%c, statement=<empty>", pkt->type, pkt->len, describe);
      *ps_action = PS_IGNORE;
    }
  } else {
    slog_noise(client, "inspect_descibe_packet: type=%c, len=%d, P/S=%c", pkt->type, pkt->len, describe);
    *ps_action = PS_IGNORE;
  }

  return true;
}

/* Unmarshall Parse packet into PgParsePacket struct for further processing */
bool unmarshall_parse_packet(PgSocket *client, PktHdr *pkt, PgParsePacket **parse_packet_p)
{
  const uint8_t *ptr;
  const char* statement;
  const char* query;
  uint16_t num_parameters;
  const uint8_t *parameter_types_bytes;

  mbuf_rewind_reader(&pkt->data);

  /* Skip first 5 bytes, because we skip the 'P' and the 4 bytes which are the length of the message */
  if (!mbuf_get_bytes(&pkt->data, 5, &ptr))
    goto failed;

  if (!mbuf_get_string(&pkt->data, &statement))
    goto failed;

  if (!mbuf_get_string(&pkt->data, &query))
    goto failed;
    
  /* number of parameter data types */
  if (!mbuf_get_uint16be(&pkt->data, &num_parameters))
    goto failed;

  if (!mbuf_get_bytes(&pkt->data, num_parameters * 4, &parameter_types_bytes))
    goto failed;
 
  *parse_packet_p = (PgParsePacket *)malloc(sizeof(PgParsePacket));
  (*parse_packet_p)->len = pkt->len;
  (*parse_packet_p)->name = strdup(statement);
  (*parse_packet_p)->query = strdup(query);
  (*parse_packet_p)->num_parameters = num_parameters;
  (*parse_packet_p)->parameter_types_bytes = (uint8_t *)malloc(4 * num_parameters);
  memcpy((*parse_packet_p)->parameter_types_bytes, parameter_types_bytes, num_parameters * 4);

  return true;

	failed:
    disconnect_client(client, true, "broken Parse packet");
	  return false;
}

/* Unmarshall (partial) Bind packet into PgBindPacket struct for further processing */
bool unmarshall_bind_packet(PgSocket *client, PktHdr *pkt, PgBindPacket **bind_packet_p)
{
  const uint8_t *ptr;
  const char *portal;
  const char *statement;

  mbuf_rewind_reader(&pkt->data);

  /* Skip first 5 bytes, because we skip the 'B' and the 4 bytes which are the length of the message */
  if (!mbuf_get_bytes(&pkt->data, 5, &ptr))
    goto failed;

  if (!mbuf_get_string(&pkt->data, &portal))
    goto failed;

  if (!mbuf_get_string(&pkt->data, &statement))
    goto failed;

  *bind_packet_p = (PgBindPacket *)malloc(sizeof(PgBindPacket));
  (*bind_packet_p)->len = pkt->len;
  (*bind_packet_p)->portal = strdup(portal);
  (*bind_packet_p)->name = strdup(statement);

  return true;

  failed:
    disconnect_client(client, true, "broken Bind packet");
	  return false;
}

/* Unmarshall Describe packet into PgDescribePacket struct for further processing */
bool unmarshall_describe_packet(PgSocket *client, PktHdr *pkt, PgDescribePacket **describe_packet_p)
{
  const uint8_t *ptr;
  char describe;
  const char *statement;

  if (incomplete_pkt(pkt))
    return false;

  mbuf_rewind_reader(&pkt->data);

  /* Skip first 5 bytes, because we skip the 'D' and the 4 bytes which are the length of the message */
  if (!mbuf_get_bytes(&pkt->data, 5, &ptr))
    goto failed;

  if (!mbuf_get_char(&pkt->data, &describe))
    goto failed;

  if (!mbuf_get_string(&pkt->data, &statement))
    goto failed;

  *describe_packet_p = (PgDescribePacket *)malloc(sizeof(PgDescribePacket));
  (*describe_packet_p)->type = describe;
  (*describe_packet_p)->name = strdup(statement);

  return true;

  failed:
    disconnect_client(client, true, "broken Describe packet");
	  return false;
}

/* Unmarshall Close packet into PgClosePacket struct for further processing */
bool unmarshall_close_packet(PgSocket *client, PktHdr *pkt, PgClosePacket **close_packet_p)
{
  const uint8_t *ptr;
  char type;
  const char *name;

  if (incomplete_pkt(pkt))
    return false;

  mbuf_rewind_reader(&pkt->data);
  
  if (!mbuf_get_bytes(&pkt->data, 5, &ptr))
    goto failed;

  if (!mbuf_get_char(&pkt->data, &type))
    return true;

  if (!mbuf_get_string(&pkt->data, &name))
    name = "";

  *close_packet_p = (PgClosePacket *)malloc(sizeof(*close_packet_p));
  (*close_packet_p)->type = type;
  (*close_packet_p)->name = strdup(name);

  slog_noise(client, "unmarshall_close_packet: type=%c, len=%d, S/P=%c, name=%s", pkt->type, pkt->len, type, name);

  return true;

	failed:
    disconnect_client(client, true, "broken Close packet");
	  return false;
}

bool is_close_statement_packet(PgClosePacket *close_packet)
{
  return close_packet->type == 'S' && strlen(close_packet->name) > 0;
}

PktBuf *create_parse_packet(char *statement, PgParsePacket *pkt)
{
  PktBuf *buf;
  buf = pktbuf_dynamic(pkt->len - strlen(pkt->name + strlen(statement)));
  pktbuf_start_packet(buf, 'P');
  pktbuf_put_string(buf, statement);
  pktbuf_put_string(buf, pkt->query);
  pktbuf_put_uint16(buf, pkt->num_parameters);
  pktbuf_put_bytes(buf, pkt->parameter_types_bytes, pkt->num_parameters * 4);
  pktbuf_finish_packet(buf);
  return buf;
}

PktBuf *create_parse_complete_packet(void)
{
  PktBuf *buf;
  buf = pktbuf_dynamic(5);
  pktbuf_start_packet(buf, '1');
  pktbuf_finish_packet(buf);
  return buf;
}

PktBuf *create_describe_packet(char *statement)
{
  PktBuf *buf;
  buf = pktbuf_dynamic(6 + strlen(statement));
  pktbuf_start_packet(buf, 'D');
  pktbuf_put_char(buf, 'S');
  pktbuf_put_string(buf, statement);
  pktbuf_finish_packet(buf);
  return buf;
}

PktBuf *create_close_packet(char *statement)
{
  PktBuf *buf;
  buf = pktbuf_dynamic(6 + strlen(statement));
  pktbuf_start_packet(buf, 'C');
  pktbuf_put_char(buf, 'S');
  pktbuf_put_string(buf, statement);
  pktbuf_finish_packet(buf);
  return buf;
}

PktBuf *create_close_complete_packet(void)
{
  PktBuf *buf;
  buf = pktbuf_dynamic(5);
  pktbuf_start_packet(buf, '3');
  pktbuf_finish_packet(buf);
  return buf;
}

void parse_packet_free(PgParsePacket *pkt)
{
  free(pkt->name);
  free(pkt->query);
  free(pkt->parameter_types_bytes);
  free(pkt);
}
