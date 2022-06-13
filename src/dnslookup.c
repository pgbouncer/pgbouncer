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

#if !defined(USE_EVDNS) && !defined(USE_UDNS) && !defined(USE_CARES)
#define USE_GETADDRINFO_A
#endif

#ifdef USE_EVDNS
#include <event2/dns.h>
#define addrinfo evutil_addrinfo
#define freeaddrinfo evutil_freeaddrinfo
#endif /* USE_EVDNS */

#ifdef USE_CARES
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

#ifdef USE_UDNS
#include <udns.h>
#define ZONE_RECHECK 1
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

#if defined(USE_UDNS) || defined(USE_CARES)

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

#if defined(USE_UDNS)

static inline struct addrinfo *convert_ipv4_result(const struct in_addr *adrs, int count)
{
	struct addrinfo *ai, *first = NULL, *last = NULL;
	int i;

	for (i = 0; i < count; i++) {
		ai = mk_addrinfo(&adrs[i], AF_INET);
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

#endif /* USE_UDNS */

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

static void impl_launch_query(struct DNSRequest *req)
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
	grq->req = req;
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

static void impl_launch_query(struct DNSRequest *req)
{
	static const struct addrinfo hints = { .ai_socktype = SOCK_STREAM };

	struct evdns_getaddrinfo_request *gai_req;
	struct evdns_base *dns = req->ctx->edns;

	gai_req = evdns_getaddrinfo(dns, req->name, NULL, &hints, got_result_gai, req);
	log_noise("dns: evdns_getaddrinfo(%s)=%p", req->name, gai_req);
}

static void impl_release(struct DNSContext *ctx)
{
	struct evdns_base *dns = ctx->edns;
	evdns_base_free(dns, 0);
}

#endif /* USE_EVDNS */


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
	if (err < 0) {
		log_warning("udns_result_a4: %s: query failed [%d]", req->name, err);
	} else if (a4) {
		log_noise("udns_result_a4: %s: %d ips", req->name, a4->dnsa4_nrr);
		res = convert_ipv4_result(a4->dnsa4_addr, a4->dnsa4_nrr);
		free(a4);
	} else {
		log_warning("udns_result_a4: %s: missing result", req->name);
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
	int err;

	if (cf_resolv_conf && cf_resolv_conf[0]) {
		log_error("resolv_conf setting is not supported by udns");
		return false;
	}

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
		log_error("dns_open failed: fd=%d", fd);
		return false;
	}
	event_assign(&udns->ev_io, pgb_event_base, fd, EV_READ | EV_PERSIST, udns_io_cb, ctx);
	err = event_add(&udns->ev_io, NULL);
	if (err < 0)
		log_warning("impl_init: event_add failed: %s", strerror(errno));

	/* timer setup */
	evtimer_assign(&udns->ev_timer, pgb_event_base, udns_timer_cb, ctx);
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
		log_noise("SOA query failed");
		got_zone_serial(ctx, NULL);
		return;
	}

	log_noise("SOA1: cname=%s qname=%s ttl=%u nrr=%u",
		  soa->dnssoa_cname, soa->dnssoa_qname,
		  soa->dnssoa_ttl, soa->dnssoa_nrr);
	log_noise("SOA2: nsname=%s hostmaster=%s serial=%u refresh=%u retry=%u expire=%u minttl=%u",
		  soa->dnssoa_nsname, soa->dnssoa_hostmaster, soa->dnssoa_serial, soa->dnssoa_refresh,
		  soa->dnssoa_retry, soa->dnssoa_expire, soa->dnssoa_minttl);

	got_zone_serial(ctx, &soa->dnssoa_serial);

	free(soa);
}

static int impl_query_soa_serial(struct DNSContext *ctx, const char *zonename)
{
	struct UdnsMeta *udns = ctx->edns;
	struct dns_query *q;
	int flags = 0;

	log_debug("udns: impl_query_soa_serial: name=%s", zonename);
	q = submit_soa(udns->ctx, zonename, flags, udns_result_soa, ctx);
	if (!q) {
		log_error("impl_query_soa_serial failed: %s", zonename);
	}
	return 0;
}

#endif /* USE_UDNS */


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

	/* If an SRV record was succesfully retrieved, store its port here. */
	int srv_port;
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

static void addrinfo_set_port_from_srv(struct addrinfo *ai, int port)
{
	struct addrinfo *cur = ai;
	while (cur) {
		if (cur->ai_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)(cur->ai_addr);
			sin->sin_port = htons(port);
		} else if (cur->ai_family == AF_INET6) {
			struct sockaddr_in6 *sin = (struct sockaddr_in6 *)(cur->ai_addr);
			sin->sin6_port = htons(port);
		}
		cur = cur->ai_next;
	}
}

/* called by c-ares on dns reply */
static void xares_host_cb(void *arg, int status, int timeouts, struct hostent *h)
{
	struct DNSRequest *req = arg;
	struct XaresMeta *meta = req->ctx->edns;
	struct addrinfo *res = NULL;

	log_noise("dns: xares_host_cb(%s)=%s", req->name, ares_strerror(status));
	if (status == ARES_SUCCESS) {
		res = convert_hostent(h);
		if (meta->srv_port) {
			addrinfo_set_port_from_srv(res, meta->srv_port);
		}

		got_result_gai(0, res, req);
	} else {
		log_debug("DNS lookup failed: %s - %s", req->name, ares_strerror(status));
		got_result_gai(0, res, req);
	}
}

static void xares_launch_host_query(struct DNSRequest *req)
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
	ares_gethostbyname(meta->chan, req->name, af, xares_host_cb, req);
	meta->got_events = true;
}

static void xares_srv_cb(void *arg, int status, int timeouts,
			  unsigned char *abuf, int alen)
{
	struct DNSRequest *req = arg;
	struct XaresMeta *meta = req->ctx->edns;
	struct ares_srv_reply *srv = NULL;

	log_noise("ares SRV result: %s", ares_strerror(status));
	if (status == ARES_SUCCESS) {
		status = ares_parse_srv_reply(abuf, alen, &srv);
	}
	if (status == ARES_SUCCESS && srv) {
		log_noise("ares SRV result using port %d", srv->port);
		/* Maybe in the future go though the list and pick the highest
		 * priority. Currently, use the first record. */
		meta->srv_port = srv->port;
		free(req->name);
		req->name = strdup(srv->host);
		ares_free_data(srv);
	}

	xares_launch_host_query(req);
}

/* send hostname query */
static void impl_launch_query(struct DNSRequest *req)
{
	struct XaresMeta *meta = req->ctx->edns;
	char full_hostname[256] = {0};
	size_t host_len;

	host_len = snprintf(full_hostname, sizeof(full_hostname),
			    "_postgres._tcp.%s", req->name);
	if (host_len >= sizeof(full_hostname))
		goto too_long;
	log_debug("dns: ares query SRV(%s)", full_hostname);
	ares_search(meta->chan, full_hostname, ns_c_in, ns_t_srv,
		    xares_srv_cb, req);
	meta->got_events = true;
	return;

too_long:
	log_warning("dns: SRV address too long, skipping");
	xares_launch_host_query(req);
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

#ifndef HAVE_ARES_PARSE_SOA_REPLY

#define ares_soa_reply		xares_soa_reply
#define ares_parse_soa_reply	xares_parse_soa_reply

struct ares_soa_reply {
	char *nsname;
	char *hostmaster;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minttl;
};

static void xares_free_soa(struct ares_soa_reply *soa)
{
	if (soa) {
		free(soa->nsname);
		free(soa->hostmaster);
		free(soa);
	}
}

/*
 * Full SOA reply packet structure (rfc1035)
 *
 * 1) header
 *   id:16, flags:16, qdcount:16, ancount:16, nscount:16, arcount:16
 *
 * 2) query (qdcount)
 *   qname:name, qtype:16, qclass:16
 *
 * 3) answer (ancount)
 *   name:name, type:16, class:16, ttl:32, rdlength:16
 *
 * 3.1) soa rdata
 *   nsname:name, hostmaster:name,
 *   serial:32, refresh:32, retry:32, expire:32, minimum:32
 *
 * 4) authority (nscount) - ignored
 *
 * 5) additional (arcount) - ignored
 */
static int ares_parse_soa_reply(const unsigned char *abuf, int alen, struct ares_soa_reply **soa_p)
{
	const unsigned char *aptr;
	long len;
	char *qname = NULL, *rr_name = NULL;
	struct ares_soa_reply *soa = NULL;
	int qdcount, ancount;
	int status;

	if (alen < NS_HFIXEDSZ)
		return ARES_EBADRESP;

	/* parse message header */
	qdcount = DNS_HEADER_QDCOUNT(abuf);
	ancount = DNS_HEADER_ANCOUNT(abuf);
	if (qdcount != 1 || ancount != 1)
		return ARES_EBADRESP;
	aptr = abuf + NS_HFIXEDSZ;

	/* allocate result struct */
	soa = calloc(1, sizeof(*soa));
	if (!soa)
		return ARES_ENOMEM;

	/* parse query */
	status = ares_expand_name(aptr, abuf, alen, &qname, &len);
	if (status != ARES_SUCCESS)
		goto failed_stat;
	aptr += len;

	/* skip qtype & qclass */
	if (aptr + NS_QFIXEDSZ > abuf + alen)
		goto failed;
	aptr += NS_QFIXEDSZ;

	/* parse RR header */
	status = ares_expand_name(aptr, abuf, alen, &rr_name, &len);
	if (status != ARES_SUCCESS)
		goto failed_stat;
	aptr += len;

	/* skip rr_type, rr_class, rr_ttl, rr_rdlen */
	if (aptr + NS_RRFIXEDSZ > abuf + alen)
		goto failed;
	aptr += NS_RRFIXEDSZ;

	/* nsname */
	status = ares_expand_name(aptr, abuf, alen, &soa->nsname, &len);
	if (status != ARES_SUCCESS)
		goto failed_stat;
	aptr += len;

	/* hostmaster */
	status = ares_expand_name(aptr, abuf, alen, &soa->hostmaster, &len);
	if (status != ARES_SUCCESS)
		goto failed_stat;
	aptr += len;

	/* integer fields */
	if (aptr + 5*4 > abuf + alen)
		goto failed;
	soa->serial = DNS__32BIT(aptr + 0*4);
	soa->refresh = DNS__32BIT(aptr + 1*4);
	soa->retry = DNS__32BIT(aptr + 2*4);
	soa->expire = DNS__32BIT(aptr + 3*4);
	soa->minttl = DNS__32BIT(aptr + 4*4);

	log_noise("ares SOA result: qname=%s rr_name=%s serial=%u", qname, rr_name, soa->serial);

	free(qname);
	free(rr_name);

	*soa_p = soa;

	return ARES_SUCCESS;

failed:
	status = ARES_EBADRESP;

failed_stat:
	xares_free_soa(soa);
	free(qname);
	free(rr_name);
	return (status == ARES_EBADNAME) ? ARES_EBADRESP : status;
}

#else /* HAVE_ARES_PARSE_SOA_REPLY */

static void xares_free_soa(struct ares_soa_reply *soa)
{
	ares_free_data(soa);
}

#endif /* HAVE_ARES_PARSE_SOA_REPLY */


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

	xares_free_soa(soa);
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

		ctx->active++;
		impl_launch_query(req);
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
			ctx->active++;
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
		ctx->active++;
		impl_launch_query(req);
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

void adns_per_loop(struct DNSContext *ctx)
{
	impl_per_loop(ctx);
}
