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
	stat->server_count = 0;
	stat->client_count = 0;
	stat->server_bytes = 0;
	stat->client_bytes = 0;
	stat->request_count = 0;
	stat->query_time = 0;
	stat->client_time = 0;
}

static void stat_add(PgStats *total, PgStats *stat)
{
	total->server_count += stat->server_count;
	total->client_count += stat->client_count;
	total->server_bytes += stat->server_bytes;
	total->client_bytes += stat->client_bytes;
	total->request_count += stat->request_count;
	total->query_time += stat->query_time;
	total->client_time += stat->client_time;
}

static void calc_average(PgStats *avg, PgStats *cur, PgStats *old)
{
	uint64_t count;
	usec_t dur = get_cached_time() - old_stamp;

	reset_stats(avg);

	if (dur <= 0)
		return;

	avg->server_count = USEC * (cur->server_count - old->server_count) / dur;
	avg->client_count = USEC * (cur->client_count - old->client_count) / dur;
	avg->request_count = USEC * (cur->request_count - old->request_count) / dur;
	avg->client_bytes = USEC * (cur->client_bytes - old->client_bytes) / dur;
	avg->server_bytes = USEC * (cur->server_bytes - old->server_bytes) / dur;

	count = cur->request_count - old->request_count;
	if (count > 0)
		avg->query_time = (cur->query_time - old->query_time) / count;

	count = cur->client_count - old->client_count;
	if (count > 0)
		avg->client_time = (cur->client_time - old->client_time) / count;
}

static void write_stats(PktBuf *buf, PgStats *stat, PgStats *old, char *dbname)
{
	PgStats avg;
	calc_average(&avg, stat, old);
	pktbuf_write_DataRow(buf, "sqqqqqqqqqqqqqq", dbname,
			     stat->request_count, stat->client_bytes,
			     stat->server_bytes, stat->query_time,
			     avg.request_count, avg.client_bytes,
			     avg.server_bytes, avg.query_time,
			     stat->server_count, stat->client_count,
			     stat->client_time, avg.server_count,
			     avg.client_count, avg.client_time);
}

bool admin_database_stats(PgSocket *client, struct StatList *pool_list)
{
	PgPool *pool;
	struct List *item;
	PgDatabase *cur_db = NULL;
	PgStats st_total, st_db, old_db, old_total;
	int rows = 0;
	PktBuf *buf;

	reset_stats(&st_total);
	reset_stats(&st_db);
	reset_stats(&old_db);
	reset_stats(&old_total);

	buf = pktbuf_dynamic(512);
	if (!buf) {
		admin_error(client, "no mem");
		return true;
	}

	pktbuf_write_RowDescription(buf, "sqqqqqqqqqqqqqq", "database",
				    "total_requests", "total_received",
				    "total_sent", "total_query_time",
				    "avg_req", "avg_recv", "avg_sent",
				    "avg_query", "total_server",
				    "total_client", "total_client_time",
				    "avg_server", "avg_client",
				    "avg_client_time");
	statlist_for_each(item, pool_list) {
		pool = container_of(item, PgPool, head);

		if (!cur_db)
			cur_db = pool->db;

		if (pool->db != cur_db) {
			write_stats(buf, &st_db, &old_db, cur_db->name);

			rows ++;
			cur_db = pool->db;
			stat_add(&st_total, &st_db);
			stat_add(&old_total, &old_db);
			reset_stats(&st_db);
			reset_stats(&old_db);
		}

		stat_add(&st_db, &pool->stats);
		stat_add(&old_db, &pool->older_stats);
	}
	if (cur_db) {
		write_stats(buf, &st_db, &old_db, cur_db->name);
		stat_add(&st_total, &st_db);
		stat_add(&old_total, &old_db);
		rows ++;
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

	pktbuf_write_RowDescription(buf, "sq", "name", "value");

#define WTOTAL(name) pktbuf_write_DataRow(buf, "sq", "total_" #name, st_total.name)
#define WAVG(name) pktbuf_write_DataRow(buf, "sq", "avg_" #name, avg.name)

	WTOTAL(request_count);
	WTOTAL(client_bytes);
	WTOTAL(server_bytes);
	WTOTAL(query_time);
	WAVG(request_count);
	WAVG(client_bytes);
	WAVG(server_bytes);
	WAVG(query_time);
	WTOTAL(server_count);
	WTOTAL(client_count);
	WTOTAL(client_time);
	WAVG(server_count);
	WAVG(client_count);
	WAVG(client_time);

	admin_flush(client, buf, "SHOW");
	return true;
}

static void refresh_stats(int s, short flags, void *arg)
{
	struct List *item;
	PgPool *pool;
	struct timeval period = { cf_stats_period, 0 };
	PgStats old_total, cur_total, avg;

	reset_stats(&old_total);
	reset_stats(&cur_total);

	old_stamp = new_stamp;
	new_stamp = get_cached_time();

	statlist_for_each(item, &pool_list) {
		pool = container_of(item, PgPool, head);
		pool->older_stats = pool->newer_stats;
		pool->newer_stats = pool->stats;

		stat_add(&cur_total, &pool->stats);
		stat_add(&old_total, &pool->older_stats);
	}
	calc_average(&avg, &cur_total, &old_total);
	/* send totals to logfile */
	log_info("Stats: %" PRIu64 " req/s,"
		 " in %" PRIu64 " b/s,"
		 " out %" PRIu64 " b/s,"
		 " query %" PRIu64 " us,"
		 " server %" PRIu64 " srv/s,"
		 " client %" PRIu64 " cli/s,"
		 " session %" PRIu64 " us",
		 avg.request_count, avg.client_bytes,
		 avg.server_bytes, avg.query_time,
		 avg.server_count, avg.client_count,
		 avg.client_time);

	safe_evtimer_add(&ev_stats, &period);
}

void stats_setup(void)
{
	struct timeval period = { cf_stats_period, 0 };

	new_stamp = get_cached_time();
	old_stamp = new_stamp - USEC;

	/* launch stats */
	evtimer_set(&ev_stats, refresh_stats, NULL);
	safe_evtimer_add(&ev_stats, &period);
}

