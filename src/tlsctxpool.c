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

/*
 * Live TLS configuration for Stream buffer 
 * TLS context pool processing for reloading of TLS configuration
 * TODO
 */

#include <pthread.h>
#include "bouncer.h" // TODO for macro define USUAL_LIBSSL_FOR_TLS a pro funkce tls_free*
#include "tlsctxpool.h"

#ifdef USUAL_LIBSSL_FOR_TLS
#define USE_TLS
#endif

#ifdef USE_TLS

#define MAX_LIVE_TLS_CTX 100
struct TlsCtxHolder {
	struct tls_config *tls_conf; // S and C: not NULL
	struct tls *tls_base; // S: not NULL, C: NULL
	/* when tls_conf and tls_base are both NULL then record is empty */
	int inUseConnectionCounter;
	bool isSelected;
	time_t created_at; // time of creation of record, informative only
};

static struct TlsCtxHolder *client_accept_base_holder;
static struct TlsCtxHolder *server_connect_conf_holder;
static struct TlsCtxHolder tlsCtxPool[MAX_LIVE_TLS_CTX];
static int tlsctxpool_max_used;

static void tlsctxpool_show( void);

static long p4p( const void * ptr);
static int idx( struct TlsCtxHolder *tch);
static void tidCheck( const char *function_name);

#define xlog_debug log_info // TODO odstranit

/**
 * helper functions for logging
 */

inline int idx( struct TlsCtxHolder *tch) {
	return tch ? tch - tlsCtxPool : -1;
}
// convert pointer for print
inline long p4p( const void * ptr) {
	return (long) ptr;
}

/**
 * helper code for check of single thread processing (=> no synchronization needed)
 */
static pthread_t threadOfFirstUsage;
inline void tidCheck( const char *function_name) {
	pthread_t t = pthread_self();
	if (!threadOfFirstUsage)
		threadOfFirstUsage = t;
	else if (t != threadOfFirstUsage) {
		log_error("%s Thread collision - current is %lx, first used was %lx", function_name, (long) t, (long) threadOfFirstUsage);
	}
}

/**
 * TLS context pool helper functions
 */

void tlsctxpool_show( void) {
	time_t now = time( NULL);
	struct TlsCtxHolder *tch = tlsCtxPool;
	log_info("tlsctxpool_show: Used %d records, Server4clients idx %d Client4servers idx %d", tlsctxpool_max_used,
			idx( client_accept_base_holder), idx( server_connect_conf_holder));
	log_info("  | idx | base     | conf     | cnt | duration [s] |");
	for (int i = tlsctxpool_max_used; i--; tch++) {
		log_info("%c | %3.3d | %8.8lx | %8.8lx | %3d%c| %12ld |",
				tch == client_accept_base_holder ? 'S' :
				tch == server_connect_conf_holder ? 'C' :
				' ',
				idx( tch), p4p(tch->tls_base), p4p(tch->tls_conf), tch->inUseConnectionCounter, tch->isSelected ? '+' : ' ',
				tch->created_at ? now - tch->created_at : 0);
	}
}

/**
 * TLS context pool controlling functions
 */

void *tlsctxpool_register( struct tls *_tls_base, struct tls_config *_tls_conf) {
	struct TlsCtxHolder *tch = tlsCtxPool;
	tidCheck("tlsctxpool_register");
	log_info("tlsctxpool_register: ptr S/C %lx/%lx", p4p( _tls_base), p4p( _tls_conf));
	tlsctxpool_clean( false);
	for (int i = MAX_LIVE_TLS_CTX; i--; tch++) {
		if (!tch->tls_base && !tch->tls_conf) {
			xlog_debug("tlsctxpool_register: stored at idx %d, ref %lx", idx(tch), p4p(tch));
			tch->tls_base = _tls_base;
			tch->tls_conf = _tls_conf;
			tch->inUseConnectionCounter = 0;
			tch->isSelected = true;
			tch->created_at = time(NULL);
			if (tlsctxpool_max_used < 1 + (tch - tlsCtxPool)) // (MAX_LIVE_TLS_CTX - i) == 1 + (tch - tlsCtxPool)
				tlsctxpool_max_used = 1 + (tch - tlsCtxPool);

			if( _tls_base) {
				if( client_accept_base_holder) {
					xlog_debug("tlsctxpool_register: released S idx %d", idx( client_accept_base_holder));
					client_accept_base_holder->isSelected = false;
				}
				xlog_debug("tlsctxpool_register: set new S record %lx", p4p(_tls_base));
				client_accept_base_holder = tch;
			} else {
				if (server_connect_conf_holder) {
					xlog_debug("tlsctxpool_register: released C idx %d", idx( server_connect_conf_holder));
					server_connect_conf_holder->isSelected = false;
				}
				xlog_debug("tlsctxpool_register: set new C record %lx", p4p(_tls_conf));
				server_connect_conf_holder = tch;
			}
			tlsctxpool_show();
			return tch;
		}
	}
	log_warning("tlsctxpool_register: TLS configuration table is full. New TLS setup is discarded. Previous values are still used.");
	return NULL;
}

void tlsctxpool_clean( bool all) {
	int last_used = -1;
	struct TlsCtxHolder *tch = tlsCtxPool;
	tidCheck("tlsctxpool_clean");
	log_info("tlsctxpool_clean: %s", all ? "ALL" : "only unreferenced");
	if( all) {
		client_accept_base_holder = NULL;
		server_connect_conf_holder = NULL;
	}
	for (int i = tlsctxpool_max_used; i--; tch++) {
		if (all || (
				( tch->tls_conf || tch->tls_base ) &&
				! tch->inUseConnectionCounter &&
				! tch->isSelected )
				) {
			xlog_debug("tlsctxpool_clean: cleaned idx %d", idx( tch));
			if(tch->tls_base)
				tls_free(tch->tls_base);
			tls_config_free(tch->tls_conf);
			tch->tls_base = NULL;
			tch->tls_conf = NULL;
			tch->inUseConnectionCounter = 0;
			tch->isSelected = false;
			tch->created_at = 0;
		}
		if( tch->tls_conf || tch->tls_base) {
			last_used = tch - tlsCtxPool; // == (tlsctxpool_max_used - i)
		}
	}
	if( tlsctxpool_max_used > last_used + 1 ) {
		log_info( "tlsctxpool_clean: Max used number changed: %d -> %d", tlsctxpool_max_used, last_used + 1);
		tlsctxpool_max_used = last_used + 1;
	}
	//tlsctxpool_show();
}

void tlsctxpool_release( void **tlsctxpool_reference) {
	struct TlsCtxHolder *tch = (struct TlsCtxHolder *)*tlsctxpool_reference;
	tidCheck("tlsctxpool_release");
	log_debug("tlsctxpool_release: idx %d, ref %lx", idx( tch), p4p( tch));
	if (tch) {
		tch->inUseConnectionCounter--;
		*tlsctxpool_reference = NULL;
		//tlsctxpool_show();
	}
}

struct tls_config *tlsctxpool_book_tls_conf( void **tlsctxpool_reference) {
	struct TlsCtxHolder *tch = server_connect_conf_holder;
	tidCheck("tlsctxpool_book_tls_conf");
	log_debug("tlsctxpool_book_tls_conf: idx %d, ref %lx", idx( tch), p4p( tch));
	*tlsctxpool_reference = tch;
	if( tch) {
		tch->inUseConnectionCounter++;
		//tlsctxpool_show();
		return tch->tls_conf;
	}
	return NULL;
}

struct tls *tlsctxpool_book_tls_base( void **tlsctxpool_reference) {
	struct TlsCtxHolder *tch = client_accept_base_holder;
	tidCheck("tlsctxpool_book_tls_base");
	log_debug("tlsctxpool_book_tls_base: idx %d, ref %lx", idx( tch), p4p( tch));
	*tlsctxpool_reference = tch;
	if( tch) {
		tch->inUseConnectionCounter++;
		//tlsctxpool_show();
		return tch->tls_base;
	}
	return NULL;
}

bool tlsctxpool_isset_conf( void) {
	return NULL != server_connect_conf_holder;
}

bool tlsctxpool_isset_base( void) {
	return NULL != client_accept_base_holder;
}

#endif
