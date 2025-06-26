/*
 * Copyright (c) 2009  Marko Kreen
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

/** @file
 *
 * Async Postgres connection framework.
 */
#ifndef _USUAL_PGSOCKET_H_
#define _USUAL_PGSOCKET_H_

#include <usual/base.h>

#include <libpq-fe.h>

/**
 * Event types reported to user handler function.
 */
enum PgEvent {
	/** Connection establishing finished */
	PGS_CONNECT_OK,
	/** Connection establishing failed */
	PGS_CONNECT_FAILED,
	/** Got result from query either resultset or DB error */
	PGS_RESULT_OK,
	/** Query execution failed */
	PGS_RESULT_BAD,
	/** Wakeup from timed sleep */
	PGS_TIMEOUT,
};

struct PgSocket;
struct event_base;

typedef void (*pgs_handler_f)(struct PgSocket *pgs, void *arg, enum PgEvent dbev, PGresult *res);

/** Create PgSocket.
 *
 * It does not launch connection yet, use \ref pgs_connect() for that.
 *
 * @param connstr  	libpq connect string
 * @param fn		callback function for event handling
 * @param arg		extra context for callback
 * @return 		Initialized PgSocket structure
 */
struct PgSocket *pgs_create(const char *connstr, pgs_handler_f fn, void *arg);

/** Release PgSocket */
void pgs_free(struct PgSocket *db);

/** Change the event base for PgSocket */
void pgs_set_event_base(struct PgSocket *pgs, struct event_base *base);

/** Set connection lifetime (in seconds) */
void pgs_set_lifetime(struct PgSocket *pgs, double lifetime);

/** Launch connection */
void pgs_connect(struct PgSocket *db);

/** Drop connection */
void pgs_disconnect(struct PgSocket *db);

/** Send simple query */
void pgs_send_query_simple(struct PgSocket *db, const char *query);

/** Send extended query, args from varargs */
void pgs_send_query_params(struct PgSocket *db, const char *query, int nargs, ...);

/** Send extended query, args from list */
void pgs_send_query_params_list(struct PgSocket *db, const char *query, int nargs, const char *argv[]);

/** Ignore the connection for specified time */
void pgs_sleep(struct PgSocket *db, double timeout);

/** Disconnect, sleep, reconnect */
void pgs_reconnect(struct PgSocket *db, double timeout);

/** Does PgSocket have established connection */
int pgs_connection_valid(struct PgSocket *db);

/** Return underlying Postgres connection */
PGconn *pgs_get_connection(struct PgSocket *db);

bool pgs_waiting_for_reply(struct PgSocket *db);

#endif
