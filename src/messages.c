#include "bouncer.h"

/* Inspect Parse packet to see if it defines a named prepared statement */
PreparedStatementAction inspect_parse_packet(PgSocket *client, PktHdr *pkt)
{
	const char *statement;

	if (!mbuf_get_string(&pkt->data, &statement))
		return PS_INSPECT_FAILED;

	if (!*statement) {	/* ignore empty statements */
		slog_noise(client, "inspect_parse_packet: type=%c, len=%d, statement=<empty>", pkt->type, pkt->len);
		return PS_IGNORE;
	}

	slog_noise(client, "inspect_parse_packet: type=%c, len=%d, statement=%s", pkt->type, pkt->len, statement);
	return PS_HANDLE_FULL_PACKET;
}

/* Inspect Bind packet to see if it defines a named prepared statement */
PreparedStatementAction inspect_bind_packet(PgSocket *client, PktHdr *pkt)
{
	const char *portal;
	const char *statement;

	if (!mbuf_get_string(&pkt->data, &portal))
		return PS_INSPECT_FAILED;

	if (!mbuf_get_string(&pkt->data, &statement))
		return PS_INSPECT_FAILED;

	if (!*statement) {	/* ignore empty statements */
		slog_noise(client, "inspect_bind_packet: type=%c, len=%d, statement=<empty>", pkt->type, pkt->len);
		return PS_IGNORE;
	}

	slog_noise(client, "inspect_bind_packet: type=%c, len=%d, statement=%s", pkt->type, pkt->len, statement);
	return PS_HANDLE;
}

/* Inspect Describe packet to see if it defines a named prepared statement */
PreparedStatementAction inspect_describe_or_close_packet(PgSocket *client, PktHdr *pkt)
{
	char describe;
	const char *statement;

	if (!mbuf_get_char(&pkt->data, &describe))
		return PS_INSPECT_FAILED;

	if (describe != 'S') {
		slog_noise(client, "inspect_describe_or_close_packet: type=%c, len=%d, P/S=%c", pkt->type, pkt->len, describe);
		return PS_IGNORE;
	}

	if (!mbuf_get_string(&pkt->data, &statement))
		return PS_INSPECT_FAILED;

	if (!*statement) {	/* ignore empty statements */
		slog_noise(client, "inspect_describe_or_close_packet: type=%c, len=%d, P/S=%c, statement=<empty>", pkt->type, pkt->len, describe);
		return PS_IGNORE;
	}

	slog_noise(client, "inspect_describe_or_close_packet: type=%c, len=%d, P/S=%c, statement=%s", pkt->type, pkt->len, describe, statement);
	return PS_HANDLE;
}

/*
 * Unmarshall Parse packet into PgParsePacket struct for further processing.
 *
 * Note: The PgParsePacket still references the data stored in the PktHdr. So
 * the PktHdr should not be freed until the PgParsePacket is not necessary
 * anymore.
 */
bool unmarshall_parse_packet(PgSocket *client, PktHdr *pkt, PgParsePacket *parse_packet)
{
	const char *statement;
	const char *query;
	uint16_t num_parameters;
	const uint8_t *parameter_types_bytes;
	size_t parameters_length;

	if (!mbuf_get_string(&pkt->data, &statement))
		goto failed;

	if (!mbuf_get_string(&pkt->data, &query))
		goto failed;

	/* number of parameter data types */
	if (!mbuf_get_uint16be(&pkt->data, &num_parameters))
		goto failed;

	parameters_length = (size_t) num_parameters * 4;

	if (!mbuf_get_bytes(&pkt->data, parameters_length, &parameter_types_bytes))
		goto failed;

	parse_packet->len = pkt->len;
	parse_packet->name = statement;
	parse_packet->query_and_parameters_len =
		strlen(query)
		+ 1	/* \0 */
		+ sizeof(num_parameters)
		+ parameters_length;
	parse_packet->query_and_parameters = query;

	return true;

failed:
	disconnect_client(client, true, "broken Parse packet");
	return false;
}

/*
 * Unmarshall (partial) Bind packet into PgBindPacket struct for further processing
 *
 * Note: The PgBindPacket still references the data stored in the PktHdr. So
 * the PktHdr should not be freed until the PgBindPacket is not necessary
 * anymore.
 */
bool unmarshall_bind_packet(PgSocket *client, PktHdr *pkt, PgBindPacket *bind_packet)
{
	const char *portal;
	const char *statement;

	if (!mbuf_get_string(&pkt->data, &portal))
		goto failed;

	if (!mbuf_get_string(&pkt->data, &statement))
		goto failed;

	bind_packet->len = pkt->len;
	bind_packet->portal = portal;
	bind_packet->name = statement;

	return true;

failed:
	disconnect_client(client, true, "broken Bind packet");
	return false;
}

/*
 * Unmarshall Describe packet into PgDescribePacket struct for further processing
 *
 * Note: The PgDescribePacket still references the data stored in the PktHdr. So
 * the PktHdr should not be freed until the PgDescribePacket is not necessary
 * anymore.
 */
bool unmarshall_describe_packet(PgSocket *client, PktHdr *pkt, PgDescribePacket *describe_packet)
{
	char describe;
	const char *statement;

	if (incomplete_pkt(pkt))
		return false;

	if (!mbuf_get_char(&pkt->data, &describe))
		goto failed;

	if (!mbuf_get_string(&pkt->data, &statement))
		goto failed;

	describe_packet->type = describe;
	describe_packet->name = statement;

	return true;

failed:
	disconnect_client(client, true, "broken Describe packet");
	return false;
}

/*
 * Unmarshall Close packet into PgClosePacket struct for further processing
 *
 * Note: The PgClosePacket still references the data stored in the PktHdr. So
 * the PktHdr should not be freed until the PgClosePacket is not necessary
 * anymore.
 */
bool unmarshall_close_packet(PgSocket *client, PktHdr *pkt, PgClosePacket *close_packet)
{
	char type;
	const char *name;

	if (incomplete_pkt(pkt))
		return false;

	if (!mbuf_get_char(&pkt->data, &type))
		goto failed;

	if (!mbuf_get_string(&pkt->data, &name))
		goto failed;

	close_packet->type = type;
	close_packet->name = name;

	slog_noise(client, "unmarshall_close_packet: type=%c, len=%d, S/P=%c, name=%s", pkt->type, pkt->len, type, name);
	return true;

failed:
	disconnect_client(client, true, "broken Close packet");
	return false;
}

bool is_close_named_statement_packet(PgClosePacket *close_packet)
{
	return close_packet->type == 'S' && *close_packet->name;
}
