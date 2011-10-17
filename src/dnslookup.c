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

/*
 * Available backends:
 *
 * udns - libudns
 * getaddrinfo_a - glibc only
 * libevent1 - returns TTL, ignores hosts file.
 * libevent2 - does not return TTL, uses hosts file.
 */

#if !defined(USE_EVDNS) && !defined(USE_UDNS)
#define USE_GETADDRINFO_A
#endif

#ifdef USE_EVDNS
#ifdef EV_ET
#define USE_LIBEVENT2
#include <event2/dns.h>
#define addrinfo evutil_addrinfo
#define freeaddrinfo evutil_freeaddrinfo
#else /* !EV_ET */
#define USE_LIBEVENT1
#include <evdns.h>
#endif /* !EV_ET */
#endif /* USE_EVDNS */

#ifdef USE_UDNS
#include <udns.h>
#define ZONE_RECHECK 1
#endif

#ifndef ZONE_RECHECK
#define ZONE_RECHECK 0
#define impl_query_soa_serial(ctx, name) (0)
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

	struct List ucb_list;	/* DNSToken->node */

	const char *name;
	int namelen;

	bool done;

	struct addrinfo *result;
	struct addrinfo *current;
	struct addrinfo *oldres;

	usec_t res_ttl;
};

/* zone name serial */
struct DNSZone {
	struct List lnode;	/* DNSContext->zone_list */
	struct AANode tnode;	/* DNSContext->zone_tree */

	struct List host_list;	/* DNSRequest->znode */

	const char *zonename;
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

#if defined(USE_LIBEVENT1) || defined(USE_UDNS)

static struct addrinfo *mk_addrinfo(const struct in_addr ip4)
{
	struct addrinfo *ai;
	struct sockaddr_in *sa;
	ai = calloc(1, sizeof(*ai));
	if (!ai)
		return NULL;
	sa = calloc(1, sizeof(*sa));
	if (!sa) {
		free(ai);
		return NULL;
	}
	sa->sin_addr = ip4;
	sa->sin_family = AF_INET;
	ai->ai_addr = (struct sockaddr *)sa;
	ai->ai_addrlen = sizeof(*sa);
	return ai;
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

static struct addrinfo *convert_ipv4_result(const struct in_addr *adrs, int count)
{
	struct addrinfo *ai, *last = NULL;
	int i;

	for (i = count - 1; i >= 0; i--) {
		ai = mk_addrinfo(adrs[i]);
		if (!ai)
			goto failed;
		ai->ai_next = last;
		last = ai;
	}
	return last;
failed:
	freeaddrinfo(last);
	return NULL;
}

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
	struct DNSRequest *req;
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
		got_result_gai(e, rq->gairq.ar_result, rq->req);
		free(rq);
	}
}

static bool impl_init(struct DNSContext *ctx)
{
	struct GaiContext *gctx = calloc(1, sizeof(*gctx));
	if (!gctx)
		return false;
	list_init(&gctx->gairq_list);
	gctx->ctx = ctx;

	gctx->sev.sigev_notify = SIGEV_SIGNAL;
	gctx->sev.sigev_signo = SIGALRM;

	signal_set(&gctx->ev, SIGALRM, dns_signal, gctx);
	if (signal_add(&gctx->ev, NULL) < 0) {
		free(gctx);
		return false;
	}
	ctx->edns = gctx;
	return true;
}

static void impl_launch_query(struct DNSRequest *req)
{
	struct GaiContext *gctx = req->ctx->edns;
	struct GaiRequest *grq = calloc(1, sizeof(*grq));
	int res;
	struct gaicb *cb;

	grq = calloc(1, sizeof(*grq));
	if (!grq)
		goto failed2;

	list_init(&grq->node);
	grq->req = req;
	grq->gairq.ar_name = req->name;
	list_append(&gctx->gairq_list, &grq->node);

	cb = &grq->gairq;
	res = getaddrinfo_a(GAI_NOWAIT, &cb, 1, &gctx->sev);
	if (res != 0)
		goto failed;
	return;

failed:
	log_warning("dns: getaddrinfo_a(%s)=%d", req->name, res);
	list_del(&grq->node);
	free(grq);
failed2:
	req->done = true;
	deliver_info(req);
}

static void impl_release(struct DNSContext *ctx)
{
	struct GaiContext *gctx = ctx->edns;
	if (gctx) {
		signal_del(&gctx->ev);
		free(gctx);
		ctx->edns = NULL;
	}
}

#endif /* USE_GETADDRINFO_A */


/*
 * ADNS with libevent2 <event2/dns.h>
 */

#ifdef USE_LIBEVENT2

const char *adns_get_backend(void)
{
	return "evdns2";
}

static bool impl_init(struct DNSContext *ctx)
{
	ctx->edns = evdns_base_new(NULL, 1);
	if (!ctx->edns) {
		log_warning("evdns_base_new failed");
		return false;
	}
	return true;
}

static void impl_launch_query(struct DNSRequest *req)
{
	struct evdns_getaddrinfo_request *gai_req;
	struct evdns_base *dns = req->ctx->edns;

	gai_req = evdns_getaddrinfo(dns, req->name, NULL, NULL, got_result_gai, req);
	log_noise("dns: evdns_getaddrinfo(%s)=%p", req->name, gai_req);
}

static void impl_release(struct DNSContext *ctx)
{
	struct evdns_base *dns = ctx->edns;
	evdns_base_free(dns, 0);
}

#endif /* USE_LIBEVENT2 */


/*
 * ADNS with libevent 1.x <evdns.h>
 */

#ifdef USE_LIBEVENT1

const char *adns_get_backend(void)
{
	return "evdns1";
}

static void got_result_evdns(int result, char type, int count, int ttl, void *addresses, void *arg)
{
	struct DNSRequest *req = arg;
	struct addrinfo *ai;

	log_noise("dns: got_result_evdns: type=%d cnt=%d ttl=%d", type, count, ttl);
	if (result == DNS_IPv4_A) {
		ai = convert_ipv4_result(addresses, count);
		if (ai) {
			got_result_gai(0, ai, req);
			return;
		}
	}
	/* lookup failed */
	got_result_gai(1, NULL, req);
}

static bool impl_init(struct DNSContext *ctx)
{
	return evdns_init() == 0;
}

static void impl_launch_query(struct DNSRequest *req)
{
	int err;

	err = evdns_resolve_ipv4(req->name, 0, got_result_evdns, req);
	log_noise("dns(%s): evdns_resolve_ipv4 = %d", req->name, err);
	if (err != 0 && !req->done) {
		/* if callback was not yet called, do it now */
		got_result_gai(1, NULL, req);
	}
}

static void impl_release(struct DNSContext *ctx)
{
	evdns_shutdown(0);
}

#endif /* USE_LIBEVENT1 */


/*
 * ADNS with <udns.h>
 */

#ifdef USE_UDNS

struct UdnsMeta {
	struct dns_ctx *ctx;
	struct event ev_io;
	struct event ev_timer;
	bool timer_active;
};

const char *adns_get_backend(void)
{
	return "udns " UDNS_VERSION;
}

static void udns_timer_setter(struct dns_ctx *uctx, int timeout, void *arg)
{
	struct DNSContext *ctx = arg;
	struct UdnsMeta *udns = ctx->edns;

	log_noise("udns_timer_setter: ctx=%p timeout=%d", uctx, timeout);

	if (udns->timer_active) {
		event_del(&udns->ev_timer);
		udns->timer_active = false;
	}

	if (uctx && timeout >= 0) {
		struct timeval tv = { .tv_sec = timeout, .tv_usec = 0 };
		evtimer_add(&udns->ev_timer, &tv);
		udns->timer_active = true;
	}
}

static void udns_timer_cb(int d, short fl, void *arg)
{
	struct DNSContext *ctx = arg;
	struct UdnsMeta *udns = ctx->edns;
	time_t now = get_cached_time() / USEC;

	log_noise("udns_timer_cb");

	dns_timeouts(udns->ctx, 10, now);
}

static void udns_io_cb(int fd, short fl, void *arg)
{
	struct DNSContext *ctx = arg;
	struct UdnsMeta *udns = ctx->edns;
	time_t now = get_cached_time() / USEC;

	log_noise("udns_io_cb");

	dns_ioevent(udns->ctx, now);
}

static void udns_result_a4(struct dns_ctx *ctx, struct dns_rr_a4 *a4, void *data)
{
	struct DNSRequest *req = data;
	struct addrinfo *res = NULL;
	int err;


	err = dns_status(ctx);
	if (a4) {
		log_noise("udns_result_a4: %s: %d ips", req->name, a4->dnsa4_nrr);
		res = convert_ipv4_result(a4->dnsa4_addr, a4->dnsa4_nrr);
	}
	got_result_gai(0, res, req);
}

static void impl_launch_query(struct DNSRequest *req)
{
	struct UdnsMeta *udns = req->ctx->edns;
	struct dns_query *q;
	int flags = 0;

	q = dns_submit_a4(udns->ctx, req->name, flags, udns_result_a4, req);
	if (q) {
		log_noise("dns: udns_launch_query(%s)=%p", req->name, q);
	} else {
		log_warning("dns: udns_launch_query(%s)=NULL", req->name);
	}
}

static bool impl_init(struct DNSContext *ctx)
{
	int fd;
	struct dns_ctx *dctx;
	struct UdnsMeta *udns;

	dns_init(NULL, 0);

	dctx = dns_new(NULL);
	if (!dctx)
		return false;

	udns = calloc(1, sizeof(*udns));
	if (!udns)
		return false;
	ctx->edns = udns;
	udns->ctx = dctx;

	/* i/o callback setup */
	fd = dns_open(dctx);
	if (fd <= 0) {
		log_warning("dns_open failed: fd=%d", fd);
		return false;
	}
	event_set(&udns->ev_io, fd, EV_READ, udns_io_cb, ctx);
	event_add(&udns->ev_io, NULL);

	/* timer setup */
	evtimer_set(&udns->ev_timer, udns_timer_cb, ctx);
	dns_set_tmcbck(udns->ctx, udns_timer_setter, ctx);

	return true;
}

static void impl_release(struct DNSContext *ctx)
{
	struct UdnsMeta *udns = ctx->edns;

	event_del(&udns->ev_io);
	dns_free(udns->ctx);
	if (udns->timer_active) {
		event_del(&udns->ev_timer);
		udns->timer_active = false;
	}
}

/*
 * generic SOA query for UDNS
 */

struct SOA {
	dns_rr_common(dnssoa);

	char *dnssoa_nsname;
	char *dnssoa_hostmaster;
	uint32_t dnssoa_serial;
	uint32_t dnssoa_refresh;
	uint32_t dnssoa_retry;
	uint32_t dnssoa_expire;
	uint32_t dnssoa_minttl;
};

typedef void query_soa_fn(struct dns_ctx *ctx, struct SOA *result, void *data);

static int parse_soa(dnscc_t *qdn, dnscc_t *pkt, dnscc_t *cur, dnscc_t *end, void **result)
{
	struct SOA *soa = NULL;
	int res, len;
	struct dns_parse p;
	struct dns_rr rr;
	dnsc_t buf[DNS_MAXDN];
	char *s;

	/* calc size */
	len = 0;
	dns_initparse(&p, qdn, pkt, cur, end);
	while ((res = dns_nextrr(&p, &rr)) > 0) {
		cur = rr.dnsrr_dptr;

		res = dns_getdn(pkt, &cur, end, buf, sizeof(buf));
		if (res <= 0)
			goto failed;
		len += dns_dntop_size(buf);

		res = dns_getdn(pkt, &cur, end, buf, sizeof(buf));
		if (res <= 0)
			goto failed;
		len += dns_dntop_size(buf);

		if (cur + 5*4 != rr.dnsrr_dend)
			goto failed;
	}
	if (res < 0 || p.dnsp_nrr != 1)
		goto failed;
	len += dns_stdrr_size(&p);

	/* allocate */
	soa = malloc(sizeof(*soa) + len);
	if (!soa)
		return DNS_E_NOMEM;

	/* fill with data */
	soa->dnssoa_nrr = 1;
	dns_rewind(&p, qdn);
	dns_nextrr(&p, &rr);
	s = (char *)(soa + 1);
	cur = rr.dnsrr_dptr;

	soa->dnssoa_nsname = s;
	dns_getdn(pkt, &cur, end, buf, sizeof(buf));
	s += dns_dntop(buf, s, DNS_MAXNAME);

	soa->dnssoa_hostmaster = s;
	dns_getdn(pkt, &cur, end, buf, sizeof(buf));
	s += dns_dntop(buf, s, DNS_MAXNAME);

	soa->dnssoa_serial = dns_get32(cur + 0*4);
	soa->dnssoa_refresh = dns_get32(cur + 1*4);
	soa->dnssoa_retry = dns_get32(cur + 2*4);
	soa->dnssoa_expire = dns_get32(cur + 3*4);
	soa->dnssoa_minttl = dns_get32(cur + 4*4);

	dns_stdrr_finish((struct dns_rr_null *)soa, s, &p);

	*result = soa;
	return 0;
failed:
	log_error("parse_soa failed");
	free(soa);
	return DNS_E_PROTOCOL;
}

static struct dns_query *
submit_soa(struct dns_ctx *ctx, const char *name, int flags, query_soa_fn *cb, void *data)
{
	  return dns_submit_p(ctx, name, DNS_C_IN, DNS_T_SOA, flags,
			      parse_soa, (dns_query_fn *)cb, data);
}

/*
 * actual "get serial" part
 */

static void udns_result_soa(struct dns_ctx *uctx, struct SOA *soa, void *data)
{
	struct DNSContext *ctx = data;

	if (!soa) {
		log_debug("SOA query failed");
		got_zone_serial(ctx, NULL);
		return;
	}

	log_debug("SOA1: cname=%s qname=%s ttl=%u nrr=%u",
		  soa->dnssoa_cname, soa->dnssoa_qname,
		  soa->dnssoa_ttl, soa->dnssoa_nrr);
	log_debug("SOA2: nsname=%s hostmaster=%s serial=%u refresh=%u retry=%u expire=%u minttl=%u",
		  soa->dnssoa_nsname, soa->dnssoa_hostmaster, soa->dnssoa_serial, soa->dnssoa_refresh,
		  soa->dnssoa_retry, soa->dnssoa_expire, soa->dnssoa_minttl);

	got_zone_serial(ctx, &soa->dnssoa_serial);
}

static int impl_query_soa_serial(struct DNSContext *ctx, const char *zonename)
{
	struct UdnsMeta *udns = ctx->edns;
	struct dns_query *q;
	int flags = 0;

	log_debug("udns: impl_query_soa_serial: name=%s", zonename);
	q = submit_soa(udns->ctx, zonename, flags, udns_result_soa, ctx);
	return 0;
}

#endif /* USE_UDNS */


/*
 * Generic framework
 */

static void deliver_info(struct DNSRequest *req)
{
	struct DNSToken *ucb;
	struct List *el;
	const struct addrinfo *ai = req->current;
	char sabuf[128];

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
	list_del(&req->znode);
	free(req->name);
	free(req);
}

struct DNSContext *adns_create_context(void)
{
	struct DNSContext *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	aatree_init(&ctx->req_tree, req_cmp, req_free);
	if (!impl_init(ctx)) {
		adns_free_context(ctx);
		return NULL;
	}
	zone_init(ctx);
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
		impl_launch_query(req);

		zone_register(ctx, req);
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
			impl_launch_query(req);
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
	struct DNSRequest *req = arg;

	req_reset(req);

	if (result == 0 && res) {
		req->result = res;
		req->current = res;

		if (req->oldres)
			check_req_result_changes(req);
	} else {
		/* lookup failed */
		log_warning("lookup failed: %s: result=%d", req->name, result);
	}

	req->done = true;
	req->res_ttl = get_cached_time() + cf_dns_max_ttl;

	deliver_info(req);
}

void adns_cancel(struct DNSContext *ctx, struct DNSToken *tk)
{
	list_del(&tk->node);
	memset(tk, 0, sizeof(*tk));
	free(tk);
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
		list_append(&z->host_list, &req->znode);
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

	/* link */
	aatree_insert(&ctx->zone_tree, (uintptr_t)z->zonename, &z->tnode);
	list_append(&ctx->zone_list, &z->lnode);
	list_append(&z->host_list, &req->znode);
}

static void zone_timer(int fd, short flg, void *arg)
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
	impl_query_soa_serial(ctx, z->zonename);
}

static void launch_zone_timer(struct DNSContext *ctx)
{
	struct timeval tv;

	tv.tv_sec = cf_dns_zone_check_period / USEC;
	tv.tv_usec = cf_dns_zone_check_period % USEC;

	evtimer_set(&ctx->ev_zone_timer, zone_timer, ctx);
	evtimer_add(&ctx->ev_zone_timer, &tv);

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
	list_for_each(el, &z->host_list) {
		req = container_of(el, struct DNSRequest, znode);
		if (!req->done)
			continue;
		req->res_ttl = 0;
		impl_launch_query(req);
	}
}

static void got_zone_serial(struct DNSContext *ctx, uint32_t *serial)
{
	struct DNSZone *z = ctx->cur_zone;
	struct List *el;

	if (!ctx->zone_state || !z)
		return;

	if (serial) {
		if (*serial != z->serial) {
			log_info("zone '%s' serial changed: old=%u new=%u",
				 z->zonename, z->serial, *serial);
			z->serial = *serial;
			zone_requeue(ctx, z);
		}
	}

	el = z->lnode.next;
	if (el != &ctx->zone_list) {
		z = container_of(el, struct DNSZone, lnode);
		ctx->cur_zone = z;
		impl_query_soa_serial(ctx, z->zonename);
	} else {
		launch_zone_timer(ctx);
	}
}

