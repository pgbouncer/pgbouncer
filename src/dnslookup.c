/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2010  Marko Kreen, Skype Technologies OÜ
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

#include <usual/netdb.h>
#include <usual/socket.h>

#if !defined(USE_EVDNS) && !defined(USE_CARES)
#define USE_GETADDRINFO_A
#endif

#ifdef USE_EVDNS
#include <event2/dns.h>
#define addrinfo evutil_addrinfo
#define freeaddrinfo evutil_freeaddrinfo
#endif /* USE_EVDNS */

#ifdef USE_CARES
#define CARES_NO_DEPRECATED
#include <ares.h>
#include <ares_dns.h>
#ifdef HAVE_ARES_NAMESER_H
#include <ares_nameser.h>
#else
#include <arpa/nameser.h>
#endif
#define ZONE_RECHECK 1
#else
/* only c-ares requires this */
#define impl_per_loop(ctx)
#endif

#ifndef ZONE_RECHECK
#define ZONE_RECHECK 0
/* no implementation, also avoid 'unused' warning */
#define impl_query_soa_serial(ctx, name) do { if (0) got_zone_serial(ctx, NULL); } while (0)
#define cf_dns_zone_check_period (0)
#endif

/*
 * There can be several client request (tokens)
 * attached to single actual request.
 */
struct DNSToken {
	struct List node;
	adns_callback_f cb_func;
	void *cb_arg;
};

/*
 * Cached DNS query (hostname).
 */
struct DNSRequest {
	struct AANode node;	/* DNSContext->req_tree */
	struct List znode;	/* DNSZone->host_list */

	struct DNSContext *ctx;
	struct DNSZone *zone;

	struct List ucb_list;	/* DNSToken->node */

	char *name;
	int namelen;

	bool done;

	struct addrinfo *result;
	struct addrinfo *current;
	struct addrinfo *oldres;

	usec_t res_ttl;

	/* when the currently-outstanding query was issued (see adns_check_stuck) */
	usec_t launch_time;

	/*
	 * A request relaunched by adns_check_stuck() can briefly have more than one
	 * query in flight, and a new resolution episode can start while an old query
	 * is still outstanding.  epoch is bumped when a new episode starts (see
	 * start_resolution), but not on a stuck relaunch; answered_epoch is the
	 * highest epoch whose result has been delivered.  Each query carries the
	 * epoch it was launched for (struct DNSQuery), and got_result_gai() accepts
	 * only an answer newer than answered_epoch -- so a late answer from a
	 * superseded query is discarded instead of clobbering the fresh result.
	 */
	unsigned epoch;
	unsigned answered_epoch;
};

/*
 * One per issued query.  Carries the epoch the query was launched for so a late
 * answer from a superseded query (a stuck-relaunch duplicate, or a straggler
 * from an earlier episode) can be recognised and discarded.  Passed to the
 * backend as the callback argument and freed by the backend glue after
 * got_result_gai() returns.
 */
struct DNSQuery {
	struct DNSRequest *req;
	unsigned epoch;
};

/* zone name serial */
struct DNSZone {
	struct List lnode;		/* DNSContext->zone_list */
	struct AANode tnode;		/* DNSContext->zone_tree */

	struct StatList host_list;	/* DNSRequest->znode */

	char *zonename;
	uint32_t serial;
};

/*
 * Top struct for DNS data.
 */
struct DNSContext {
	struct AATree req_tree;
	void *edns;

	struct AATree zone_tree;	/* DNSZone->tnode */
	struct List zone_list;		/* DNSZone->lnode */

	struct DNSZone *cur_zone;
	struct event ev_zone_timer;
	int zone_state;

	int active;	/* number of in-flight queries */
};

static void deliver_info(struct DNSRequest *req);
static void got_result_gai(int result, struct addrinfo *res, void *arg);

static void zone_register(struct DNSContext *ctx, struct DNSRequest *req);
static void zone_init(struct DNSContext *ctx);
static void zone_free(struct DNSContext *ctx);

static void got_zone_serial(struct DNSContext *ctx, uint32_t *serial);

/*
 * Custom addrinfo generation
 */

#if defined(USE_CARES)

static struct addrinfo *mk_addrinfo(const void *adr, int af)
{
	struct addrinfo *ai;

	ai = calloc(1, sizeof(*ai));
	if (!ai)
		return NULL;

	if (af == AF_INET) {
		struct sockaddr_in *sa4;
		sa4 = calloc(1, sizeof(*sa4));
		if (!sa4)
			goto failed;
		memcpy(&sa4->sin_addr, adr, 4);
		sa4->sin_family = af;
		ai->ai_addr = (struct sockaddr *)sa4;
		ai->ai_addrlen = sizeof(*sa4);
	} else if (af == AF_INET6) {
		struct sockaddr_in6 *sa6;
		sa6 = calloc(1, sizeof(*sa6));
		if (!sa6)
			goto failed;
		memcpy(&sa6->sin6_addr, adr, sizeof(sa6->sin6_addr));
		sa6->sin6_family = af;
		ai->ai_addr = (struct sockaddr *)sa6;
		ai->ai_addrlen = sizeof(*sa6);
	}
	ai->ai_protocol = IPPROTO_TCP;
	ai->ai_socktype = SOCK_STREAM;
	ai->ai_family = af;
	return ai;
failed:
	free(ai);
	return NULL;
}

#define freeaddrinfo(x) local_freeaddrinfo(x)

static void freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *cur;
	while (ai) {
		cur = ai;
		ai = ai->ai_next;
		free(cur->ai_addr);
		free(cur);
	}
}

#ifdef USE_CARES

static inline struct addrinfo *convert_hostent(const struct hostent *h)
{
	struct addrinfo *ai, *first = NULL, *last = NULL;
	int i;

	for (i = 0; h->h_addr_list[i]; i++) {
		ai = mk_addrinfo(h->h_addr_list[i], h->h_addrtype);
		if (!ai)
			goto failed;

		if (!first)
			first = ai;
		else
			last->ai_next = ai;
		last = ai;
	}
	return first;
failed:
	freeaddrinfo(first);
	return NULL;
}

#endif /* USE_CARES */

#endif /* custom addrinfo */


/*
 * ADNS with glibc's getaddrinfo_a()
 */

#ifdef USE_GETADDRINFO_A

const char *adns_get_backend(void)
{
#ifdef HAVE_GETADDRINFO_A
	return "libc"
#ifdef __GLIBC__
	       "-" STR(__GLIBC__) "." STR(__GLIBC_MINOR__);
#endif
	;
#else
	return "compat";
#endif
}

struct GaiRequest {
	struct List node;
	struct DNSQuery *q;
	struct gaicb gairq;
};

struct GaiContext {
	struct DNSContext *ctx;
	struct List gairq_list;
	struct event ev;
	struct sigevent sev;
};

static void dns_signal(int f, short ev, void *arg)
{
	struct GaiContext *gctx = arg;
	struct List *el, *tmp;
	struct GaiRequest *rq;
	int e;
	list_for_each_safe(el, &gctx->gairq_list, tmp) {
		rq = container_of(el, struct GaiRequest, node);
		e = gai_error(&rq->gairq);
		if (e == EAI_INPROGRESS)
			continue;

		/* got one */
		list_del(&rq->node);
		got_result_gai(e, rq->gairq.ar_result, rq->q);
		free(rq->q);
		free(rq);
	}
}

static bool impl_init(struct DNSContext *ctx)
{
	struct GaiContext *gctx;

	if (cf_resolv_conf && cf_resolv_conf[0]) {
		log_error("resolv_conf setting is not supported by libc adns");
		return false;
	}

	gctx = calloc(1, sizeof(*gctx));
	if (!gctx)
		return false;
	list_init(&gctx->gairq_list);
	gctx->ctx = ctx;

	gctx->sev.sigev_notify = SIGEV_SIGNAL;
	gctx->sev.sigev_signo = SIGALRM;

	evsignal_assign(&gctx->ev, pgb_event_base, SIGALRM, dns_signal, gctx);
	if (evsignal_add(&gctx->ev, NULL) < 0) {
		free(gctx);
		return false;
	}
	ctx->edns = gctx;
	return true;
}

static void impl_launch_query(struct DNSRequest *req, struct DNSQuery *q)
{
	static const struct addrinfo hints = { .ai_socktype = SOCK_STREAM };

	struct GaiContext *gctx = req->ctx->edns;
	struct GaiRequest *grq;
	int res;
	struct gaicb *cb;

	grq = calloc(1, sizeof(*grq));
	if (!grq)
		goto failed2;

	list_init(&grq->node);
	grq->q = q;
	grq->gairq.ar_name = req->name;
	grq->gairq.ar_request = &hints;
	list_append(&gctx->gairq_list, &grq->node);

	cb = &grq->gairq;
	res = getaddrinfo_a(GAI_NOWAIT, &cb, 1, &gctx->sev);
	if (res != 0)
		goto failed;
	return;

failed:
	if (res == EAI_SYSTEM) {
		log_warning("dns: getaddrinfo_a(%s)=%d, errno=%d (%s)",
			    req->name, res, errno, strerror(errno));
	} else {
		log_warning("dns: getaddrinfo_a(%s)=%d", req->name, res);
	}
	list_del(&grq->node);
	free(grq);
failed2:
	free(q);
	req->done = true;
	deliver_info(req);
}

static void impl_release(struct DNSContext *ctx)
{
	struct GaiContext *gctx = ctx->edns;
	if (gctx) {
		evsignal_del(&gctx->ev);
		free(gctx);
		ctx->edns = NULL;
	}
}

#endif /* USE_GETADDRINFO_A */


/*
 * ADNS with libevent2 <event2/dns.h>
 */

#ifdef USE_EVDNS

const char *adns_get_backend(void)
{
	return "evdns2";
}

/*
 * Confusingly, this is not the same as evdns_err_to_string().
 */
static const char *_evdns_base_resolv_conf_parse_err_to_string(int err)
{
	switch (err) {
	case 0: return "no error";
	case 1: return "failed to open file";
	case 2: return "failed to stat file";
	case 3: return "file too large";
	case 4: return "out of memory";
	case 5: return "short read from file";
	case 6: return "no nameservers listed in the file";
	default: return "[Unknown error code]";
	}
}

static bool impl_init(struct DNSContext *ctx)
{
	if (cf_resolv_conf && cf_resolv_conf[0]) {
		int err;

		ctx->edns = evdns_base_new(pgb_event_base, 0);
		if (!ctx->edns) {
			log_error("evdns_base_new failed");
			return false;
		}
		err = evdns_base_resolv_conf_parse(ctx->edns, DNS_OPTIONS_ALL,
						   cf_resolv_conf);
		if (err) {
			log_error("evdns parsing of \"%s\" failed: %s",
				  cf_resolv_conf,
				  _evdns_base_resolv_conf_parse_err_to_string(err));
			return false;
		}
	} else {
		ctx->edns = evdns_base_new(pgb_event_base, 1);
		if (!ctx->edns) {
			log_error("evdns_base_new failed");
			return false;
		}
	}
	return true;
}

/* evdns callback: unwrap the per-query token, deliver, then free it */
static void evdns_result_cb(int result, struct addrinfo *res, void *arg)
{
	struct DNSQuery *q = arg;

	got_result_gai(result, res, q);
	free(q);
}

static void impl_launch_query(struct DNSRequest *req, struct DNSQuery *q)
{
	static const struct addrinfo hints = { .ai_socktype = SOCK_STREAM };

	struct evdns_getaddrinfo_request *gai_req;
	struct evdns_base *dns = req->ctx->edns;

	gai_req = evdns_getaddrinfo(dns, req->name, NULL, &hints, evdns_result_cb, q);
	log_noise("dns: evdns_getaddrinfo(%s)=%p", req->name, gai_req);
}

static void impl_release(struct DNSContext *ctx)
{
	struct evdns_base *dns = ctx->edns;
	evdns_base_free(dns, 0);
}

#endif /* USE_EVDNS */


/*
 * ADNS with <ares.h>
 */

#ifdef USE_CARES

#define MAX_CARES_FDS 16

struct XaresFD {
	struct event ev;		/* fd event state is persistent */
	struct XaresMeta *meta;		/* pointer to parent context */
	ares_socket_t sock;		/* socket value */
	short wait;			/* EV_READ / EV_WRITE */
	bool in_use;			/* is this slot assigned */
};

struct XaresMeta {
	/* c-ares descriptor */
	ares_channel chan;

	/* how many elements in fds array are in use */
	int max_fds;

	/* static array for fds */
	struct XaresFD fds[MAX_CARES_FDS];

	/* timer event is one-shot */
	struct event ev_timer;

	/* is timer activated? */
	bool timer_active;

	/* If dns events happened during event loop,
	   timer may need recalibration. */
	bool got_events;
};

const char *adns_get_backend(void)
{
	return "c-ares " ARES_VERSION_STR;
}


/* called by libevent on timer timeout */
static void xares_timer_cb(evutil_socket_t sock, short flags, void *arg)
{
	struct DNSContext *ctx = arg;
	struct XaresMeta *meta = ctx->edns;

	ares_process_fd(meta->chan, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

	meta->timer_active = false;
	meta->got_events = true;
}

/* called by libevent on fd event */
static void xares_fd_cb(evutil_socket_t sock, short flags, void *arg)
{
	struct XaresFD *xfd = arg;
	struct XaresMeta *meta = xfd->meta;
	ares_socket_t r, w;

	r = (flags & EV_READ) ? xfd->sock : ARES_SOCKET_BAD;
	w = (flags & EV_WRITE) ? xfd->sock : ARES_SOCKET_BAD;
	ares_process_fd(meta->chan, r, w);

	meta->got_events = true;
}

/* called by c-ares on new socket creation */
static int xares_new_socket_cb(ares_socket_t sock, int sock_type, void *arg)
{
	struct DNSContext *ctx = arg;
	struct XaresMeta *meta = ctx->edns;
	struct XaresFD *xfd;
	int pos;

	/* find free slot in array */
	for (pos = 0; pos < meta->max_fds; pos++) {
		if (!meta->fds[pos].in_use)
			break;
	}
	if (pos >= MAX_CARES_FDS) {
		log_warning("c-ares fd overflow");
		return ARES_ENOMEM;
	}
	if (pos == meta->max_fds)
		meta->max_fds++;

	/* fill it */
	xfd = &meta->fds[pos];
	xfd->meta = meta;
	xfd->sock = sock;
	xfd->wait = 0;
	xfd->in_use = true;
	return ARES_SUCCESS;
}

/* called by c-ares on socket state change (r=w=0 means socket close) */
static void xares_state_cb(void *arg, ares_socket_t sock, int r, int w)
{
	struct DNSContext *ctx = arg;
	struct XaresMeta *meta = ctx->edns;
	struct XaresFD *xfd;
	int pos;
	short new_wait = 0;

	if (r)
		new_wait |= EV_READ;
	if (w)
		new_wait |= EV_WRITE;

	/* find socket */
	for (pos = 0; pos < meta->max_fds; pos++) {
		xfd = &meta->fds[pos];
		if (!xfd->in_use)
			continue;

		if (xfd->sock != sock)
			continue;

		/* no change? */
		if (xfd->wait == new_wait)
			return;

		goto re_set;
	}

	log_warning("adns: c-ares state change for unknown fd: %u", (unsigned)sock);
	return;

re_set:
	if (xfd->wait)
		event_del(&xfd->ev);
	xfd->wait = new_wait;
	if (new_wait) {
		event_assign(&xfd->ev, pgb_event_base, sock, new_wait | EV_PERSIST, xares_fd_cb, xfd);
		if (event_add(&xfd->ev, NULL) < 0)
			log_warning("adns: event_add failed: %s", strerror(errno));
	} else {
		xfd->in_use = false;
	}
	return;
}

/* called by c-ares on dns reply */
static void xares_host_cb(void *arg, int status, int timeouts, struct hostent *h)
{
	struct DNSQuery *q = arg;
	struct addrinfo *res = NULL;

	log_noise("dns: xares_host_cb(%s)=%s", q->req->name, ares_strerror(status));
	if (status == ARES_SUCCESS) {
		res = convert_hostent(h);
		got_result_gai(0, res, q);
	} else {
		log_debug("DNS lookup failed: %s - %s", q->req->name, ares_strerror(status));
		got_result_gai(0, res, q);
	}
	free(q);
}

/* send hostname query */
static void impl_launch_query(struct DNSRequest *req, struct DNSQuery *q)
{
	struct XaresMeta *meta = req->ctx->edns;
	int af;

/*
 * c-ares <= 1.10 cannot resolve CNAME with AF_UNSPEC.
 *
 * Force IPv4 there.
 *
 * Fixed in "host_callback: Fall back to AF_INET on searching with AF_UNSPEC" (c1fe47f)
 * in c-ares repo.
 */
#if ARES_VERSION <= 0x10A00
#warning c-ares <=1.10 has buggy IPv6 support; this PgBouncer build will use IPv4 only.
	af = AF_INET;
#else
	af = AF_UNSPEC;
#endif
	log_noise("dns: ares_gethostbyname(%s)", req->name);
	ares_gethostbyname(meta->chan, req->name, af, xares_host_cb, q);

	meta->got_events = true;
}

/* re-set timer if any dns event happened */
static void impl_per_loop(struct DNSContext *ctx)
{
	struct timeval tv, *tvp;
	struct XaresMeta *meta = ctx->edns;

	if (!meta->got_events)
		return;

	if (meta->timer_active) {
		event_del(&meta->ev_timer);
		meta->timer_active = false;
	}

	tvp = ares_timeout(meta->chan, NULL, &tv);
	if (tvp != NULL) {
		if (event_add(&meta->ev_timer, tvp) < 0)
			log_warning("impl_per_loop: event_add failed: %s", strerror(errno));
		meta->timer_active = true;
	}

	meta->got_events = false;
}

/* c-ares setup */
static bool impl_init(struct DNSContext *ctx)
{
	struct XaresMeta *meta;
	int err;
	int mask;
	struct ares_options opts;

	err = ares_library_init(ARES_LIB_INIT_ALL);
	if (err) {
		log_error("ares_library_init: %s", ares_strerror(err));
		return false;
	}

	meta = calloc(1, sizeof(*meta));
	if (!meta)
		return false;

	memset(&opts, 0, sizeof(opts));
	opts.sock_state_cb = xares_state_cb;
	opts.sock_state_cb_data = ctx;
	mask = ARES_OPT_SOCK_STATE_CB;
	if (cf_resolv_conf && cf_resolv_conf[0]) {
#ifdef ARES_OPT_RESOLVCONF
		opts.resolvconf_path = strdup(cf_resolv_conf);
		if (!opts.resolvconf_path) {
			free(meta);
			return false;
		}
		mask |= ARES_OPT_RESOLVCONF;
#else
		log_error("resolv_conf setting is not supported by this version of c-ares");
		free(meta);
		return false;
#endif
	}

	err = ares_init_options(&meta->chan, &opts, mask);
	if (err) {
		free(meta);
		log_error("ares_library_init: %s", ares_strerror(err));
		return false;
	}

	ares_set_socket_callback(meta->chan, xares_new_socket_cb, ctx);

	evtimer_assign(&meta->ev_timer, pgb_event_base, xares_timer_cb, ctx);

	ctx->edns = meta;
	return true;
}

/* c-ares shutdown */
static void impl_release(struct DNSContext *ctx)
{
	struct XaresMeta *meta = ctx->edns;

	ares_destroy(meta->chan);
	ares_library_cleanup();

	if (meta->timer_active)
		event_del(&meta->ev_timer);

	free(meta);
	ctx->edns = NULL;
}

/*
 * query SOA with c-ares
 */

/* called by c-ares on SOA reply */
static void xares_soa_cb(void *arg, int status, int timeouts,
			 unsigned char *abuf, int alen)
{
	struct DNSContext *ctx = arg;
	struct XaresMeta *meta = ctx->edns;
	struct ares_soa_reply *soa = NULL;

	meta->got_events = true;

	log_noise("ares SOA result: %s", ares_strerror(status));
	if (status != ARES_SUCCESS) {
		got_zone_serial(ctx, NULL);
		return;
	}

	status = ares_parse_soa_reply(abuf, alen, &soa);
	if (status == ARES_SUCCESS) {
		got_zone_serial(ctx, &soa->serial);
	} else {
		log_warning("ares_parse_soa: %s", ares_strerror(status));
		got_zone_serial(ctx, NULL);
	}

	ares_free_data(soa);
}

/* send SOA query */
static int impl_query_soa_serial(struct DNSContext *ctx, const char *zonename)
{
	struct XaresMeta *meta = ctx->edns;

	log_debug("dns: ares query SOA(%s)", zonename);
	ares_search(meta->chan, zonename, ns_c_in, ns_t_soa,
		    xares_soa_cb, ctx);

	meta->got_events = true;
	return 0;
}

#endif /* USE_CARES */


/*
 * Generic framework
 */

static void deliver_info(struct DNSRequest *req)
{
	struct DNSContext *ctx = req->ctx;
	struct DNSToken *ucb;
	struct List *el;
	const struct addrinfo *ai = req->current;
	char sabuf[128];

	ctx->active--;

loop:
	/* get next req */
	el = list_pop(&req->ucb_list);
	if (!el)
		return;
	ucb = container_of(el, struct DNSToken, node);

	/* launch callback */
	log_noise("dns: deliver_info(%s) addr=%s", req->name,
		  ai ? sa2str(ai->ai_addr, sabuf, sizeof(sabuf)) : "NULL");
	ucb->cb_func(ucb->cb_arg,
		     ai ? ai->ai_addr : NULL,
		     ai ? ai->ai_addrlen : 0);
	free(ucb);

	/* scroll req list */
	if (ai) {
		req->current = ai->ai_next;
		if (!req->current)
			req->current = req->result;
	}

	goto loop;
}

static int req_cmp(uintptr_t arg, struct AANode *node)
{
	const char *s1 = (char *)arg;
	struct DNSRequest *req = container_of(node, struct DNSRequest, node);
	return strcmp(s1, req->name);
}

static void req_reset(struct DNSRequest *req)
{
	req->done = false;
	if (req->result) {
		if (req->oldres)
			freeaddrinfo(req->oldres);
		req->oldres = req->result;
	}
	req->result = req->current = NULL;
}

static void req_free(struct AANode *node, void *arg)
{
	struct DNSToken *ucb;
	struct DNSRequest *req;
	struct List *el;
	req = container_of(node, struct DNSRequest, node);
	while ((el = list_pop(&req->ucb_list)) != NULL) {
		ucb = container_of(el, struct DNSToken, node);
		free(ucb);
	}
	req_reset(req);
	if (req->oldres) {
		freeaddrinfo(req->oldres);
		req->oldres = NULL;
	}
	if (req->zone)
		statlist_remove(&req->zone->host_list, &req->znode);
	free(req->name);
	free(req);
}

struct DNSContext *adns_create_context(void)
{
	struct DNSContext *ctx;

	log_debug("adns_create_context: %s", adns_get_backend());

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	aatree_init(&ctx->req_tree, req_cmp, req_free);
	zone_init(ctx);

	if (!impl_init(ctx)) {
		adns_free_context(ctx);
		return NULL;
	}
	return ctx;
}

void adns_free_context(struct DNSContext *ctx)
{
	if (ctx) {
		impl_release(ctx);
		aatree_destroy(&ctx->req_tree);
		zone_free(ctx);
		free(ctx);
	}
}

/* allocate a per-query token stamped with the request's current epoch */
static struct DNSQuery *new_query(struct DNSRequest *req)
{
	struct DNSQuery *q = malloc(sizeof(*q));

	if (q) {
		q->req = req;
		q->epoch = req->epoch;
	}
	return q;
}

/* test-only: the request (and its epoch) whose first lookup was dropped */
static struct DNSRequest *test_hung_req;
static unsigned test_hung_epoch;

/*
 * Issue (or re-issue) the backend query for a request and record when, so that
 * adns_check_stuck() can relaunch a request whose resolver callback never fires.
 */
static void launch_request(struct DNSRequest *req)
{
	struct DNSQuery *q;

	req->launch_time = get_cached_time();

	/*
	 * Test-only fault injection: drop the first lookup so its callback never
	 * fires, reproducing the "hung in-process resolver" that leaves a request
	 * pending forever (see adns_check_stuck / test/test_dns_stuck.py). Active
	 * only when the PGB_TEST_HANG_ONCE environment variable is set; a no-op in
	 * normal operation.  Dropped before active++/new_query, so nothing leaks.
	 */
	if (getenv("PGB_TEST_HANG_ONCE")) {
		static bool hung_once = false;
		if (!hung_once) {
			hung_once = true;
			test_hung_req = req;
			test_hung_epoch = req->epoch;
			log_warning("TEST: dropping lookup of '%s' to simulate a hung resolution",
				    req->name);
			return;
		}
	}

	req->ctx->active++;
	q = new_query(req);
	if (!q) {
		/* out of memory: fail this launch; deliver_info() balances active */
		req->done = true;
		deliver_info(req);
		return;
	}
	impl_launch_query(req, q);
}

/*
 * Start a new resolution episode: bump the epoch so the next answer is accepted
 * (and any straggler from a superseded episode is discarded) and issue the query.
 * A stuck relaunch (adns_check_stuck) instead calls launch_request() directly, so
 * it stays in the same episode and the first answer -- from whichever query --
 * wins.
 */
static void start_resolution(struct DNSRequest *req)
{
	req->epoch++;
	launch_request(req);
}

struct DNSToken *adns_resolve(struct DNSContext *ctx, const char *name, adns_callback_f cb_func, void *cb_arg)
{
	int namelen = strlen(name);
	struct DNSRequest *req;
	struct DNSToken *ucb;
	struct AANode *node;

	/* setup actual lookup */
	node = aatree_search(&ctx->req_tree, (uintptr_t)name);
	if (node) {
		req = container_of(node, struct DNSRequest, node);
	} else {
		log_noise("dns: new req: %s", name);
		req = calloc(1, sizeof(*req));
		if (!req)
			goto nomem;
		req->name = strdup(name);
		if (!req->name) {
			free(req);
			goto nomem;
		}
		req->ctx = ctx;
		req->namelen = namelen;
		list_init(&req->ucb_list);
		list_init(&req->znode);
		aatree_insert(&ctx->req_tree, (uintptr_t)req->name, &req->node);

		zone_register(ctx, req);

		start_resolution(req);
	}

	/* remember user callback */
	ucb = calloc(1, sizeof(*ucb));
	if (!ucb)
		goto nomem;
	list_init(&ucb->node);
	ucb->cb_func = cb_func;
	ucb->cb_arg = cb_arg;
	list_append(&req->ucb_list, &ucb->node);

	/* if already have final result, report it */
	if (req->done) {
		if (req->res_ttl < get_cached_time()) {
			log_noise("dns: ttl over: %s", req->name);
			req_reset(req);
			start_resolution(req);
		} else {
			deliver_info(req);
		}
	}
	/* if ->done, then we have already reported */
	return req->done ? NULL : ucb;
nomem:
	log_warning("dns(%s): req failed, no mem", name);
	cb_func(cb_arg, NULL, 0);
	return NULL;
}

static int cmp_addrinfo(const struct addrinfo *a1, const struct addrinfo *a2)
{
	if (a1->ai_family != a2->ai_family)
		return a1->ai_family - a2->ai_family;
	if (a1->ai_addrlen != a2->ai_addrlen)
		return a1->ai_addrlen - a2->ai_addrlen;

	return memcmp(a1->ai_addr, a2->ai_addr, a1->ai_addrlen);
}

/* check if new dns reply is missing some IP compared to old one */
static void check_req_result_changes(struct DNSRequest *req)
{
	struct addrinfo *ai, *aj;

	for (ai = req->oldres; ai; ai = ai->ai_next) {
		bool found = false;
		for (aj = req->result; aj; aj = aj->ai_next) {
			if (cmp_addrinfo(ai, aj) == 0) {
				found = true;
				break;
			}
		}

		/* missing IP (possible DNS failover) make connections to it dirty */
		if (!found)
			tag_host_addr_dirty(req->name, ai->ai_addr);
	}
}

/* struct addrinfo -> deliver_info() */
static void got_result_gai(int result, struct addrinfo *res, void *arg)
{
	struct DNSQuery *q = arg;
	struct DNSRequest *req = q->req;

	/*
	 * A request relaunched by adns_check_stuck() can have more than one query
	 * in flight, and a new resolution episode can start while an old query is
	 * still outstanding.  Each query carries the epoch it was launched for, so
	 * accept only an answer newer than the one already delivered; discard a late
	 * answer from a superseded query (a same-episode duplicate, or a straggler
	 * from an earlier episode) so it cannot clobber the fresh result or mark good
	 * addresses dirty.  The query still counted against ctx->active when it was
	 * launched, so drop it here.
	 */
	if (q->epoch <= req->answered_epoch) {
		log_noise("dns: discarding superseded result for '%s'", req->name);
		if (res)
			freeaddrinfo(res);
		req->ctx->active--;
		return;
	}
	req->answered_epoch = q->epoch;

	req_reset(req);

	if (result == 0 && res) {
		req->result = res;
		req->current = res;

		if (req->oldres)
			check_req_result_changes(req);

		/* show all results */
		if (cf_verbose > 1) {
			const struct addrinfo *ai = res;
			int n = 0;
			char buf[128];
			while (ai) {
				log_noise("DNS: %s[%d] = %s [%s]", req->name, n++,
					  sa2str(ai->ai_addr, buf, sizeof(buf)),
					  ai->ai_socktype == SOCK_STREAM ? "STREAM" : "OTHER");
				ai = ai->ai_next;
			}
		}
		req->res_ttl = get_cached_time() + cf_dns_max_ttl;
	} else {
		/* lookup failed */
		log_warning("DNS lookup failed: %s: result=%d", req->name, result);
		req->res_ttl = get_cached_time() + cf_dns_nxdomain_ttl;
	}

	req->done = true;

	deliver_info(req);
}

void adns_cancel(struct DNSContext *ctx, struct DNSToken *tk)
{
	list_del(&tk->node);
	memset(tk, 0, sizeof(*tk));
	free(tk);
}

void adns_info(struct DNSContext *ctx, int *names, int *zones, int *queries, int *pending)
{
	*names = ctx->req_tree.count;
	*zones = ctx->zone_tree.count;
	*queries = ctx->active;
	*pending = 0;
}

/*
 * zone code
 */

static void zone_item_free(struct AANode *n, void *arg)
{
	struct DNSZone *z = container_of(n, struct DNSZone, tnode);

	list_del(&z->lnode);
	free(z->zonename);
	free(z);
}

static int zone_item_cmp(uintptr_t val1, struct AANode *n2)
{
	const char *name1 = (const char *)val1;
	struct DNSZone *z2 = container_of(n2, struct DNSZone, tnode);
	return strcasecmp(name1, z2->zonename);
}

static void zone_init(struct DNSContext *ctx)
{
	aatree_init(&ctx->zone_tree, zone_item_cmp, zone_item_free);
	list_init(&ctx->zone_list);
}

static void zone_free(struct DNSContext *ctx)
{
	aatree_destroy(&ctx->zone_tree);
}

static void zone_register(struct DNSContext *ctx, struct DNSRequest *req)
{
	struct DNSZone *z;
	struct AANode *n;
	const char *name;

	log_debug("zone_register(%s)", req->name);

	name = strchr(req->name, '.');
	if (!name || name[1] == 0)
		return;
	name++;
	log_debug("zone_register(%s): name=%s", req->name, name);

	n = aatree_search(&ctx->zone_tree, (uintptr_t)name);
	if (n) {
		/* already exists */
		z = container_of(n, struct DNSZone, tnode);
		req->zone = z;
		statlist_append(&z->host_list, &req->znode);
		return;
	}

	/* create struct */
	z = calloc(1, sizeof(*z));
	if (!z)
		return;
	z->zonename = strdup(name);
	if (!z->zonename) {
		free(z);
		return;
	}
	statlist_init(&z->host_list, "host_list");
	list_init(&z->lnode);

	/* link */
	aatree_insert(&ctx->zone_tree, (uintptr_t)z->zonename, &z->tnode);
	list_append(&ctx->zone_list, &z->lnode);
	statlist_append(&z->host_list, &req->znode);
	req->zone = z;
}

static void zone_timer(evutil_socket_t fd, short flg, void *arg)
{
	struct DNSContext *ctx = arg;
	struct List *el;
	struct DNSZone *z;

	if (list_empty(&ctx->zone_list)) {
		ctx->zone_state = 0;
		return;
	}

	el = list_first(&ctx->zone_list);
	z = container_of(el, struct DNSZone, lnode);
	ctx->zone_state = 1;
	ctx->cur_zone = z;
	ctx->active++;
	impl_query_soa_serial(ctx, z->zonename);
}

static void launch_zone_timer(struct DNSContext *ctx)
{
	struct timeval tv;

	tv.tv_sec = cf_dns_zone_check_period / USEC;
	tv.tv_usec = cf_dns_zone_check_period % USEC;

	evtimer_assign(&ctx->ev_zone_timer, pgb_event_base, zone_timer, ctx);
	safe_evtimer_add(&ctx->ev_zone_timer, &tv);

	ctx->zone_state = 2;
}

void adns_zone_cache_maint(struct DNSContext *ctx)
{
	if (!cf_dns_zone_check_period) {
		if (ctx->zone_state == 2) {
			event_del(&ctx->ev_zone_timer);
			ctx->zone_state = 0;
		}
		ctx->cur_zone = NULL;
		return;
	} else if (ctx->zone_state == 0) {
		if (list_empty(&ctx->zone_list))
			return;
		launch_zone_timer(ctx);
	}
}

static void zone_requeue(struct DNSContext *ctx, struct DNSZone *z)
{
	struct List *el;
	struct DNSRequest *req;
	statlist_for_each(el, &z->host_list) {
		req = container_of(el, struct DNSRequest, znode);
		if (!req->done)
			continue;
		req->res_ttl = 0;
		start_resolution(req);
	}
}

static void got_zone_serial(struct DNSContext *ctx, uint32_t *serial)
{
	struct DNSZone *z = ctx->cur_zone;
	struct List *el;

	ctx->active--;

	if (!ctx->zone_state || !z)
		return;

	if (serial) {
		/* wraparound compare */
		int32_t s1 = z->serial;
		int32_t s2 = *serial;
		int32_t ds = s2 - s1;
		if (ds > 0) {
			log_info("zone '%s' serial changed: old=%u new=%u",
				 z->zonename, z->serial, *serial);
			z->serial = *serial;
			zone_requeue(ctx, z);
		} else {
			log_debug("zone '%s' unchanged: serial=%u", z->zonename, *serial);
		}
	} else {
		log_debug("failure to get zone '%s' serial", z->zonename);
	}

	el = z->lnode.next;
	if (el != &ctx->zone_list) {
		z = container_of(el, struct DNSZone, lnode);
		ctx->cur_zone = z;

		ctx->active++;
		impl_query_soa_serial(ctx, z->zonename);
	} else {
		launch_zone_timer(ctx);
	}
}

/*
 * Cache walkers
 */

struct WalkInfo {
	adns_walk_name_f name_cb;
	adns_walk_zone_f zone_cb;
	void *arg;
};

static void walk_name(struct AANode *n, void *arg)
{
	struct WalkInfo *w = arg;
	struct DNSRequest *req = container_of(n, struct DNSRequest, node);

	w->name_cb(w->arg, req->name, req->result, req->res_ttl);
}

static void walk_zone(struct AANode *n, void *arg)
{
	struct WalkInfo *w = arg;
	struct DNSZone *z = container_of(n, struct DNSZone, tnode);

	w->zone_cb(w->arg, z->zonename, z->serial, statlist_count(&z->host_list));
}

void adns_walk_names(struct DNSContext *ctx, adns_walk_name_f cb, void *arg)
{
	struct WalkInfo w;
	w.name_cb = cb;
	w.arg = arg;
	aatree_walk(&ctx->req_tree, AA_WALK_IN_ORDER, walk_name, &w);
}

void adns_walk_zones(struct DNSContext *ctx, adns_walk_zone_f cb, void *arg)
{
	struct WalkInfo w;
	w.zone_cb = cb;
	w.arg = arg;
	aatree_walk(&ctx->zone_tree, AA_WALK_IN_ORDER, walk_zone, &w);
}

/*
 * Relaunch a request whose resolver callback never fired.
 *
 * A request is relaunched only once it is ->done: adns_resolve() does so in its
 * req->done branch, and zone_requeue() skips !done requests.  So if the
 * in-process resolver never calls back (a hung resolution), the request stays
 * pending forever, and every later resolution of that name attaches to the
 * stuck request without issuing a new query -- the name is then permanently
 * unresolvable (SHOW DNS_HOSTS shows it empty, servers stay at (bad-af)) even
 * though a fresh resolver on the same host resolves it, and only a restart
 * clears it.  When dns_resolve_timeout is set, relaunch any request that has
 * been pending longer than that so recovery does not require a restart.
 */
struct StuckWalk {
	usec_t now;
	struct DNSRequest **stuck;
	int count;
	int alloc;
};

static void collect_stuck_cb(struct AANode *node, void *arg)
{
	struct StuckWalk *w = arg;
	struct DNSRequest *req = container_of(node, struct DNSRequest, node);
	struct DNSRequest **tmp;
	int n;

	if (req->done)
		return;
	if (w->now - req->launch_time < cf_dns_resolve_timeout)
		return;

	if (w->count == w->alloc) {
		n = w->alloc ? w->alloc * 2 : 16;
		tmp = realloc(w->stuck, n * sizeof(*tmp));
		if (!tmp)
			return;	/* out of memory: relaunch what we have, retry the rest next scan */
		w->stuck = tmp;
		w->alloc = n;
	}
	w->stuck[w->count++] = req;
}

static void adns_check_stuck(struct DNSContext *ctx)
{
	static usec_t last_check;
	usec_t now = get_cached_time();
	struct StuckWalk w;
	int i;

	if (!cf_dns_resolve_timeout)
		return;

	/* limit the tree walk to once per second */
	if (last_check && now - last_check < USEC)
		return;
	last_check = now;

	/* collect first, then relaunch, so the tree is not mutated mid-walk */
	w.now = now;
	w.stuck = NULL;
	w.count = 0;
	w.alloc = 0;
	aatree_walk(&ctx->req_tree, AA_WALK_IN_ORDER, collect_stuck_cb, &w);

	for (i = 0; i < w.count; i++) {
		struct DNSRequest *req = w.stuck[i];
		log_warning("dns: lookup of '%s' still pending after %d s; relaunching",
			    req->name, (int)((now - req->launch_time) / USEC));
		launch_request(req);
	}
	free(w.stuck);
}

/*
 * Test-only: once a dropped ("hung") request has recovered via a relaunch,
 * simulate its original query finally answering late, carrying the epoch it was
 * launched for.  The epoch guard in got_result_gai() must discard this stale
 * answer so it cannot clobber the fresh result.  Pair it with an active++ so the
 * discard's active-- balances (a real late query would have taken one when it
 * was launched).  Active only under PGB_TEST_LATE_STALE.
 */
static void test_late_stale(void)
{
	struct DNSRequest *req = test_hung_req;
	struct DNSQuery q;

	if (!req || !req->done || !getenv("PGB_TEST_LATE_STALE"))
		return;
	test_hung_req = NULL;

	q.req = req;
	q.epoch = test_hung_epoch;
	log_warning("TEST: delivering late stale callback for '%s'", req->name);
	req->ctx->active++;
	got_result_gai(0, NULL, &q);
}

void adns_per_loop(struct DNSContext *ctx)
{
	impl_per_loop(ctx);
	adns_check_stuck(ctx);
	test_late_stale();
}
