#include "bouncer.h"

#include <usual/crypto/csrandom.h>
#include <usual/hashing/spooky.h>
#include <usual/hashtab-impl.h>

static PgParsedPreparedStatement *create_prepared_statement(PgParsePacket *parse_packet)
{
  static bool initialized;
	static uint32_t rand_seed;
  PgParsedPreparedStatement *s = NULL;

	if (!initialized) {
		initialized = true;
		rand_seed = csrandom();
	}

  s = (PgParsedPreparedStatement *)malloc(sizeof(*s));
  s->name = parse_packet->name;
  s->pkt = parse_packet;
  s->query_hash[0] = rand_seed;
	s->query_hash[1] = 0;
	spookyhash(parse_packet->query, strlen(parse_packet->query), &s->query_hash[0], &s->query_hash[1]);
  
  return s;
}

static PgServerPreparedStatement *create_server_prepared_statement(PgSocket *client, PgParsedPreparedStatement *ps)
{
  PgServerPreparedStatement *s = NULL;
  char statement[23];

  s = (PgServerPreparedStatement *)malloc(sizeof(*s));
  *(uint64_t *)&s->query_hash[0] = ps->query_hash[0];
  *(uint64_t *)&s->query_hash[1] = ps->query_hash[1];
  s->bind_count = 0;

  // FIXME: length??
  snprintf(statement, 23, "B_%ld", client->link->nextUniquePreparedStatementID++);
  s->name = strdup(statement);

  return s;
}

static int bind_count_sort(struct PgServerPreparedStatement *a, struct PgServerPreparedStatement *b) {
    return (a->bind_count - b->bind_count);
}

static bool register_prepared_statement(PgSocket *server, PgServerPreparedStatement *stmt)
{
  struct PgServerPreparedStatement *current, *tmp;
  PktBuf *buf;
  unsigned int cached_query_count = HASH_COUNT(server->server_prepared_statements);

  if (cached_query_count >= (unsigned int)cf_prepared_statement_cache_queries)
  {
    HASH_SORT(server->server_prepared_statements, bind_count_sort);
    HASH_ITER(hh, server->server_prepared_statements, current, tmp) {
      HASH_DEL(server->server_prepared_statements, current);
      cached_query_count--;

      buf = create_close_packet(current->name);

      if (!pktbuf_send_immediate(buf, server)) {
        pktbuf_free(buf);
        return false;
      }

      pktbuf_free(buf);

      slog_noise(server, "prepared statement '%s' deleted from server cache", current->name);
      free(current->name);
      free(current);
      break;
    }
  }

  slog_noise(server, "prepared statement '%s' added to server cache, %d cached items", stmt->name, cached_query_count + 1);
  HASH_ADD(hh, server->server_prepared_statements, query_hash, sizeof(stmt->query_hash), stmt);

  return true;
}

bool handle_parse_command(PgSocket *client, PktHdr *pkt)
{
  PgSocket *server = client->link;
  PgParsePacket *pp;
  PgParsedPreparedStatement *ps = NULL;
  PgServerPreparedStatement *link_ps = NULL;
  PktBuf *buf;
  struct OutstandingParsePacket *opp = NULL;

  Assert(server);

  if (!unmarshall_parse_packet(client, pkt, &pp))
    return false;

  /* update stats */
  client->pool->stats.ps_client_parse_count++;

  ps = create_prepared_statement(pp);
  HASH_FIND(hh, server->server_prepared_statements, ps->query_hash, sizeof(ps->query_hash), link_ps);
  if (link_ps) {
    /* Statement already prepared on this link, do not forward packet */
    slog_debug(client, "handle_parse_command: mapping statement '%s' to '%s' (query hash '%ld%ld')", ps->name, link_ps->name, ps->query_hash[0], ps->query_hash[1]);

    buf = create_parse_complete_packet();
    if (!pktbuf_send_immediate(buf, client)) {
      pktbuf_free(buf);
      return false;
    }

    pktbuf_free(buf);
    
    /* Register statement on client link */
    HASH_ADD_KEYPTR(hh, client->prepared_statements, ps->name, strlen(ps->name), ps);
  } else {
    /* Statement not prepared on this link, sent modified P packet */
    link_ps = create_server_prepared_statement(client, ps);

    slog_debug(client, "handle_parse_command: creating mapping for statement '%s' to '%s' (query hash '%ld%ld')", ps->name, link_ps->name, ps->query_hash[0], ps->query_hash[1]);

    buf = create_parse_packet(link_ps->name, ps->pkt);

    /* update stats */
    client->pool->stats.ps_server_parse_count++;

    /* Track Parse command sent to server */
    opp = calloc(sizeof *opp, 1);
    opp->ignore = false;
    list_append(&server->server_outstanding_parse_packets, &opp->node);
    
    /* Register statement on client and server link */
    HASH_ADD_KEYPTR(hh, client->prepared_statements, ps->name, strlen(ps->name), ps);
    if (!register_prepared_statement(server, link_ps))
      return false;

    if (!pktbuf_send_queued(buf, server)) {
      return false;
    }
  }

  return true;
}

bool handle_bind_command(PgSocket *client, PktHdr *pkt_hdr, unsigned offset, struct MBuf *data, PktBuf *pkt)
{
  PgSocket *server = client->link;
  struct PgBindPacket *bp;
  PgParsedPreparedStatement *ps = NULL;
  PgServerPreparedStatement *link_ps = NULL;
  PktBuf *buf;
  struct OutstandingParsePacket *opp = NULL;

  const uint8_t *ptr;
  uint32_t len;

  Assert(server);

  if (!unmarshall_bind_packet(client, pkt_hdr, &bp))
    return false;

  /* update stats */
  client->pool->stats.ps_bind_count++;

  HASH_FIND_STR(client->prepared_statements, bp->name, ps);
  if (!ps) {
    disconnect_client(client, true, "prepared statement '%s' not found", bp->name);
	  return false;
  }

  HASH_FIND(hh, server->server_prepared_statements, ps->query_hash, sizeof(ps->query_hash), link_ps);

  if (!link_ps) {
    /* Statement is not prepared on this link, sent P packet first */
    link_ps = create_server_prepared_statement(client, ps);
    
    slog_debug(server, "handle_bind_command: prepared statement '%s' (query hash '%ld%ld') not available on server, preparing '%s' before bind", ps->name, ps->query_hash[0], ps->query_hash[1], link_ps->name);

    buf = create_parse_packet(link_ps->name, ps->pkt);

    /* update stats */
    client->pool->stats.ps_server_parse_count++;

    /* Track Parse command sent to server */    
    opp = calloc(sizeof *opp, 1);
    opp->ignore = true;
    list_append(&server->server_outstanding_parse_packets, &opp->node);
    if (!pktbuf_send_queued(buf, server)) {
      return false;
    }

    /* Register statement on server link */
    if (!register_prepared_statement(server, link_ps))
      return false;
  }

  slog_debug(client, "handle_bind_command: mapped statement '%s' (query hash '%ld%ld') to '%s'", ps->name, ps->query_hash[0], ps->query_hash[1], link_ps->name);

  len = pkt_hdr->len - strlen(ps->name) + strlen(link_ps->name);
  pktbuf_put_char(pkt, pkt_hdr->type);
  pktbuf_put_uint32(pkt, len - 1); /* length does not include type byte */
  pktbuf_put_string(pkt, bp->portal);
  pktbuf_put_string(pkt, link_ps->name);

  /* Skip original bytes we replaced */
  if (!mbuf_get_bytes(data, pkt->write_pos - strlen(link_ps->name) + strlen(ps->name), &ptr))
    return false;

  /* update stats */
  link_ps->bind_count++;

  free(bp->portal);
  free(bp->name);
  free(bp);

  return true;
}

bool handle_describe_command(PgSocket *client, PktHdr *pkt)
{
  SBuf *sbuf = &client->sbuf;
  PgSocket *server = client->link;
  PgDescribePacket *dp;
  PgParsedPreparedStatement *ps = NULL;
  PgServerPreparedStatement *link_ps = NULL;
  PktBuf *buf;

  Assert(server);

  if (!unmarshall_describe_packet(client, pkt, &dp))
    return false;


      // if (ps_name) {
      //   HASH_FIND_STR(client->prepared_statements, ps_name, ps);
      //   if (!ps) {
      //     slog_error(client, "lookup failed for prepared statement '%s'", ps_name);
      //     disconnect_client(client, true, "prepared statement '%s' not found", ps_name);
      //     return false;
      //   }
      // }

  Assert(dp->type == 'S');

  HASH_FIND_STR(client->prepared_statements, dp->name, ps);
  if (!ps) {
    disconnect_client(client, true, "prepared statement '%s' not found", dp->name);
	  return false;
  }

  HASH_FIND(hh, client->link->server_prepared_statements, ps->query_hash, sizeof(ps->query_hash), link_ps);

  // TODO: link_ps missing -> no parse, should not be possible

  sbuf_prepare_skip(sbuf, pkt->len);
  if (!sbuf_flush(sbuf))
    return false;

  slog_debug(client, "handle_describe_command: mapped statement '%s' (query hash '%ld%ld') to '%s'", ps->name, ps->query_hash[0], ps->query_hash[1], link_ps->name);

  buf = create_describe_packet(link_ps->name);

  if (!pktbuf_send_immediate(buf, server)) {
    pktbuf_free(buf);
    return false;
  }

  pktbuf_free(buf);

  return true;
}

bool handle_close_statement_command(PgSocket *client, PktHdr *pkt, PgClosePacket *close_packet)
{
  SBuf *sbuf = &client->sbuf;
  PgParsedPreparedStatement *ps = NULL;
  PktBuf *buf;

  HASH_FIND_STR(client->prepared_statements, close_packet->name, ps);
  if (ps) {
    slog_noise(client, "handle_close_command: removed '%s' from cached prepared statements, items remaining %u", close_packet->name, HASH_COUNT(client->prepared_statements));
    HASH_DELETE(hh, client->prepared_statements, ps);
    parse_packet_free(ps->pkt);
    free(ps);

    /* Do not forward packet to server */
    sbuf_prepare_skip(sbuf, pkt->len);
    if (!sbuf_flush(sbuf))
      return false;
    
    buf = create_close_complete_packet();

    if (!pktbuf_send_immediate(buf, client)) {
      pktbuf_free(buf);
      return false;
    }

    pktbuf_free(buf);
  }

  return true;
}

void ps_client_free(PgSocket *client)
{
  struct PgParsedPreparedStatement *current, *tmp;

  HASH_ITER(hh, client->prepared_statements, current, tmp) {
    HASH_DEL(client->prepared_statements, current);
    parse_packet_free(current->pkt);
    free(current);
  }

  free(client->prepared_statements);
}

void ps_server_free(PgSocket *server)
{
  struct PgServerPreparedStatement *current, *tmp_s;
  struct List *el, *tmp_l;
	struct OutstandingParsePacket *opp;

  HASH_ITER(hh, server->server_prepared_statements, current, tmp_s) {
    HASH_DEL(server->server_prepared_statements, current);
    free(current->name);
    free(current);
  }

  list_for_each_safe(el, &server->server_outstanding_parse_packets, tmp_l) {
		opp = container_of(el, struct OutstandingParsePacket, node);
		list_del(&opp->node);
		free(opp);
	}
  free(server->server_prepared_statements);
}
