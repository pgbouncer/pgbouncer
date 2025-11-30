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

#include "bouncer.h"

static struct event ev_stats;
static usec_t old_stamp, new_stamp;

static void reset_stats(PgStats *stat)
{
	stat->server_bytes = 0;
	stat->client_bytes = 0;
	stat->server_assignment_count = 0;
	stat->query_count = 0;
	stat->query_time = 0;
	stat->xact_count = 0;
	stat->xact_time = 0;
	stat->wait_time = 0;
	stat->client_connect_count = 0;

	stat->ps_client_parse_count = 0;
	stat->ps_server_parse_count = 0;
	stat->ps_bind_count = 0;
}

static void stat_add(PgStats *total, PgStats *stat)
{
	total->server_bytes += stat->server_bytes;
	total->client_bytes += stat->client_bytes;
	total->server_assignment_count += stat->server_assignment_count;
	total->query_count += stat->query_count;
	total->query_time += stat->query_time;
	total->xact_count += stat->xact_count;
	total->xact_time += stat->xact_time;
	total->wait_time += stat->wait_time;
	total->client_connect_count += stat->client_connect_count;

	total->ps_client_parse_count += stat->ps_client_parse_count;
	total->ps_server_parse_count += stat->ps_server_parse_count;
	total->ps_bind_count += stat->ps_bind_count;
}

static void calc_average(PgStats *avg, PgStats *cur, PgStats *old)
{
	uint64_t server_assignment_count;
	uint64_t query_count;
	uint64_t xact_count;
	uint64_t ps_client_parse_count;
	uint64_t ps_server_parse_count;
	uint64_t ps_bind_count;
	uint64_t client_connect_count;

	usec_t dur = get_cached_time() - old_stamp;

	reset_stats(avg);

	if (dur <= 0)
		return;

	query_count = cur->query_count - old->query_count;
	xact_count = cur->xact_count - old->xact_count;
	client_connect_count = cur->client_connect_count - old->client_connect_count;
	server_assignment_count = cur->server_assignment_count - old->server_assignment_count;

	avg->query_count = USEC * query_count / dur;
	avg->xact_count = USEC * xact_count / dur;
	avg->client_connect_count = USEC * client_connect_count / dur;
	avg->server_assignment_count = USEC * server_assignment_count / dur;

	avg->client_bytes = USEC * (cur->client_bytes - old->client_bytes) / dur;
	avg->server_bytes = USEC * (cur->server_bytes - old->server_bytes) / dur;

	if (query_count > 0)
		avg->query_time = (cur->query_time - old->query_time) / query_count;

	if (xact_count > 0)
		avg->xact_time = (cur->xact_time - old->xact_time) / xact_count;

	if (server_assignment_count > 0)
		avg->wait_time = (cur->wait_time - old->wait_time) / server_assignment_count;

	ps_client_parse_count = cur->ps_client_parse_count - old->ps_client_parse_count;
	ps_server_parse_count = cur->ps_server_parse_count - old->ps_server_parse_count;
	ps_bind_count = cur->ps_bind_count - old->ps_bind_count;

	avg->ps_client_parse_count = USEC * ps_client_parse_count / dur;
	avg->ps_server_parse_count = USEC * ps_server_parse_count / dur;
	avg->ps_bind_count = USEC * ps_bind_count / dur;
}

static void write_stats(PktBuf *buf, PgStats *stat, PgStats *old, char *dbname)
{
	PgStats avg;
	calc_average(&avg, stat, old);
	pktbuf_write_DataRow(buf, "sNNNNNNNNNNNNNNNNNNNNNNNN", dbname,
			     stat->server_assignment_count,
			     stat->xact_count, stat->query_count,
			     stat->client_bytes, stat->server_bytes,
			     stat->xact_time, stat->query_time,
			     stat->wait_time, stat->ps_client_parse_count,
			     stat->ps_server_parse_count, stat->ps_bind_count,
			     stat->client_connect_count,
			     avg.server_assignment_count,
			     avg.xact_count, avg.query_count,
			     avg.client_bytes, avg.server_bytes,
			     avg.xact_time, avg.query_time,
			     avg.wait_time, avg.ps_client_parse_count,
			     avg.ps_server_parse_count, avg.ps_bind_count,
			     avg.client_connect_count
			     );
}

bool admin_database_stats(PgSocket *client, struct StatList *pool_list)
{
	PgPool *pool;
	struct List *item;
	PgDatabase *cur_db = NULL;
	PgStats st_db, old_db;
	PktBuf *buf;

	reset_stats(&st_db);
	reset_stats(&old_db);

	buf = pktbuf_dynamic(512);
	if (!buf) {
		admin_error(client, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "sNNNNNNNNNNNNNNNNNNNNNNNN", "database",
				    "total_server_assignment_count",
				    "total_xact_count", "total_query_count",
				    "total_received", "total_sent",
				    "total_xact_time", "total_query_time",
				    "total_wait_time", "total_client_parse_count",
				    "total_server_parse_count", "total_bind_count",
				    "total_client_connect_count",
				    "avg_server_assignment_count",
				    "avg_xact_count", "avg_query_count",
				    "avg_recv", "avg_sent",
				    "avg_xact_time", "avg_query_time",
				    "avg_wait_time", "avg_client_parse_count",
				    "avg_server_parse_count", "avg_bind_count",
				    "avg_client_connect_count"
				    );
	statlist_for_each(item, pool_list) {
		pool = container_of(item, PgPool, head);

		if (!cur_db)
			cur_db = pool->db;

		if (pool->db != cur_db) {
			write_stats(buf, &st_db, &old_db, cur_db->name);

			cur_db = pool->db;
			reset_stats(&st_db);
			reset_stats(&old_db);
		}

		stat_add(&st_db, &pool->stats);
		stat_add(&old_db, &pool->older_stats);
	}
	if (cur_db) {
		write_stats(buf, &st_db, &old_db, cur_db->name);
	}
	admin_flush(client, buf, "SHOW");

	return true;
}

static void write_stats_totals(PktBuf *buf, PgStats *stat, PgStats *old, char *dbname)
{
	pktbuf_write_DataRow(buf, "sNNNNNNNNNNNN", dbname,
			     stat->server_assignment_count,
			     stat->xact_count, stat->query_count,
			     stat->client_bytes, stat->server_bytes,
			     stat->xact_time, stat->query_time,
			     stat->wait_time, stat->ps_client_parse_count,
			     stat->ps_server_parse_count, stat->ps_bind_count,
			     stat->client_connect_count);
}

bool admin_database_stats_totals(PgSocket *client, struct StatList *pool_list)
{
	PgPool *pool;
	struct List *item;
	PgDatabase *cur_db = NULL;
	PgStats st_db, old_db;
	PktBuf *buf;

	reset_stats(&st_db);
	reset_stats(&old_db);

	buf = pktbuf_dynamic(512);
	if (!buf) {
		admin_error(client, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "sNNNNNNNNNNNN", "database",
				    "server_assignment_count",
				    "xact_count", "query_count",
				    "bytes_received", "bytes_sent",
				    "xact_time", "query_time",
				    "wait_time", "client_parse_count",
				    "server_parse_count", "bind_count", "client_connect_count");

	statlist_for_each(item, pool_list) {
		pool = container_of(item, PgPool, head);

		if (!cur_db)
			cur_db = pool->db;

		if (pool->db != cur_db) {
			write_stats_totals(buf, &st_db, &old_db, cur_db->name);

			cur_db = pool->db;
			reset_stats(&st_db);
			reset_stats(&old_db);
		}

		stat_add(&st_db, &pool->stats);
		stat_add(&old_db, &pool->older_stats);
	}
	if (cur_db) {
		write_stats_totals(buf, &st_db, &old_db, cur_db->name);
	}
	admin_flush(client, buf, "SHOW");

	return true;
}

static void write_stats_averages(PktBuf *buf, PgStats *stat, PgStats *old, char *dbname)
{
	PgStats avg;
	calc_average(&avg, stat, old);
	pktbuf_write_DataRow(buf, "sNNNNNNNNNNNN", dbname,
			     avg.server_assignment_count,
			     avg.xact_count, avg.query_count,
			     avg.client_bytes, avg.server_bytes,
			     avg.xact_time, avg.query_time,
			     avg.wait_time, avg.ps_client_parse_count,
			     avg.ps_server_parse_count, avg.ps_bind_count,
			     avg.client_connect_count);
}

bool admin_database_stats_averages(PgSocket *client, struct StatList *pool_list)
{
	PgPool *pool;
	struct List *item;
	PgDatabase *cur_db = NULL;
	PgStats st_db, old_db;
	PktBuf *buf;

	reset_stats(&st_db);
	reset_stats(&old_db);

	buf = pktbuf_dynamic(512);
	if (!buf) {
		admin_error(client, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "sNNNNNNNNNNNN", "database",
				    "server_assignment_count",
				    "xact_count", "query_count",
				    "bytes_received", "bytes_sent",
				    "xact_time", "query_time",
				    "wait_time", "avg_client_parse_count",
				    "avg_server_parse_count", "avg_bind_count",
				    "client_connect_count");

	statlist_for_each(item, pool_list) {
		pool = container_of(item, PgPool, head);

		if (!cur_db)
			cur_db = pool->db;

		if (pool->db != cur_db) {
			write_stats_averages(buf, &st_db, &old_db, cur_db->name);

			cur_db = pool->db;
			reset_stats(&st_db);
			reset_stats(&old_db);
		}

		stat_add(&st_db, &pool->stats);
		stat_add(&old_db, &pool->older_stats);
	}
	if (cur_db) {
		write_stats_averages(buf, &st_db, &old_db, cur_db->name);
	}
	admin_flush(client, buf, "SHOW");

	return true;
}

bool show_stat_totals(PgSocket *client, struct StatList *pool_list)
{
	PgPool *pool;
	struct List *item;
	PgStats st_total, old_total, avg;
	PktBuf *buf;

	reset_stats(&st_total);
	reset_stats(&old_total);

	buf = pktbuf_dynamic(512);
	if (!buf) {
		admin_error(client, "no mem");
		return true;
	}


	statlist_for_each(item, pool_list) {
		pool = container_of(item, PgPool, head);
		stat_add(&st_total, &pool->stats);
		stat_add(&old_total, &pool->older_stats);
	}

	calc_average(&avg, &st_total, &old_total);

	pktbuf_write_RowDescription(buf, "sN", "name", "value");

#define WTOTAL(name) pktbuf_write_DataRow(buf, "sN", "total_" #name, st_total.name)
#define WAVG(name) pktbuf_write_DataRow(buf, "sN", "avg_" #name, avg.name)

	WTOTAL(server_assignment_count);
	WTOTAL(xact_count);
	WTOTAL(query_count);
	WTOTAL(client_bytes);
	WTOTAL(server_bytes);
	WTOTAL(xact_time);
	WTOTAL(query_time);
	WTOTAL(wait_time);
	WTOTAL(ps_client_parse_count);
	WTOTAL(ps_server_parse_count);
	WTOTAL(ps_bind_count);
	WTOTAL(client_connect_count);
	WAVG(server_assignment_count);
	WAVG(xact_count);
	WAVG(query_count);
	WAVG(client_bytes);
	WAVG(server_bytes);
	WAVG(xact_time);
	WAVG(query_time);
	WAVG(wait_time);
	WAVG(ps_client_parse_count);
	WAVG(ps_server_parse_count);
	WAVG(ps_bind_count);
	WAVG(client_connect_count);

	admin_flush(client, buf, "SHOW");
	return true;
}

static void refresh_stats(evutil_socket_t s, short flags, void *arg)
{
	struct List *item;
	PgPool *pool;
	PgStats old_total, cur_total;
	PgStats avg;

	reset_stats(&old_total);
	reset_stats(&cur_total);

	old_stamp = new_stamp;
	new_stamp = get_cached_time();

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		pool->older_stats = pool->newer_stats;
		pool->newer_stats = pool->stats;

		if (cf_log_stats) {
			stat_add(&cur_total, &pool->stats);
			stat_add(&old_total, &pool->older_stats);
		}
	}

	calc_average(&avg, &cur_total, &old_total);

	if (cf_log_stats) {
		log_info("stats: %" PRIu64 " xacts/s,"
			 " %" PRIu64 " queries/s,"
			 " %" PRIu64 " client parses/s,"
			 " %" PRIu64 " server parses/s,"
			 " %" PRIu64 " binds/s,"
			 " in %" PRIu64 " B/s,"
			 " out %" PRIu64 " B/s,"
			 " xact %" PRIu64 " us,"
			 " query %" PRIu64 " us,"
			 " wait %" PRIu64 " us",
			 avg.xact_count,
			 avg.query_count,
			 avg.ps_client_parse_count,
			 avg.ps_server_parse_count,
			 avg.ps_bind_count,
			 avg.client_bytes, avg.server_bytes,
			 avg.xact_time, avg.query_time,
			 avg.wait_time);
	}

	sd_notifyf(0,
		   "STATUS=stats: %" PRIu64 " xacts/s,"
		   " %" PRIu64 " queries/s,"
		   " %" PRIu64 " client parses/s,"
		   " %" PRIu64 " server parses/s,"
		   " %" PRIu64 " binds/s,"
		   " in %" PRIu64 " B/s,"
		   " out %" PRIu64 " B/s,"
		   " xact %" PRIu64 " μs,"
		   " query %" PRIu64 " μs,"
		   " wait %" PRIu64 " μs",
		   avg.xact_count,
		   avg.query_count,
		   avg.ps_client_parse_count,
		   avg.ps_server_parse_count,
		   avg.ps_bind_count,
		   avg.client_bytes, avg.server_bytes,
		   avg.xact_time, avg.query_time,
		   avg.wait_time);
}

void stats_setup(void)
{
	struct timeval period = { cf_stats_period, 0 };

	new_stamp = get_cached_time();
	old_stamp = new_stamp - USEC;

	/* launch stats */
	event_assign(&ev_stats, pgb_event_base, -1, EV_PERSIST, refresh_stats, NULL);
	if (event_add(&ev_stats, &period) < 0)
		log_warning("event_add failed: %s", strerror(errno));
}
