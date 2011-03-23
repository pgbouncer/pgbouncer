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

/*
 * getaddrinfo_a - glibc only
 * libevent1 - returns TTL, ignores hosts file.
 * libevent2 - does not return TTL, uses hosts file.
 */

#include <usual/netdb.h>

#ifndef USE_EVDNS

/* getaddrinfo_a */
#define USE_GETADDRINFO_A

#else

#ifdef EV_ET

/* libevent 2 */
#define USE_LIBEVENT2
#include <event2/dns.h>
#define addrinfo evutil_addrinfo
#define freeaddrinfo evutil_freeaddrinfo

#else

/* libevent 1 */
#define USE_LIBEVENT1
#include <evdns.h>

#endif
#endif


struct DNSToken {
	struct List node;
	adns_callback_f cb_func;
	void *cb_arg;
};

struct DNSRequest {
	struct AANode node;
	struct DNSContext *ctx;

	struct List ucb_list;

	const char *name;
	int namelen;

	bool done;

	struct addrinfo *result;
	struct addrinfo *current;

	usec_t res_ttl;
};

struct DNSContext {
	struct AATree req_tree;
	void *edns;
};

static void deliver_info(struct DNSRequest *req);

static void got_result_gai(int result, struct addrinfo *res, void *arg);


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

/*
 * ADNS with glibc's getaddrinfo_a()
 */

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

#ifdef USE_LIBEVENT2

const char *adns_get_backend(void)
{
	return "evdns2";
}

/*
 * ADNS with libevent2 <event2/dns.h>
 */

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

#endif

#ifdef USE_LIBEVENT1

const char *adns_get_backend(void)
{
	return "evdns1";
}

/*
 * ADNS with libevent 1.x <evdns.h>
 */

static struct addrinfo *mk_addrinfo(void *ip)
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
	memcpy(&sa->sin_addr, ip, 4);
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

static struct addrinfo *convert_ipv4_result(uint8_t *adrs, int count)
{
	struct addrinfo *ai, *last = NULL;
	int i;

	for (i = count - 1; i >= 0; i--) {
		ai = mk_addrinfo(adrs + i * 4);
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

#endif

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
	if (req->result)
		freeaddrinfo(req->result);
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
	return ctx;
}

void adns_free_context(struct DNSContext *ctx)
{
	if (ctx) {
		impl_release(ctx);
		aatree_destroy(&ctx->req_tree);
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
		aatree_insert(&ctx->req_tree, (uintptr_t)req->name, &req->node);
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

/* struct addrinfo -> deliver_info() */
static void got_result_gai(int result, struct addrinfo *res, void *arg)
{
	struct DNSRequest *req = arg;

	req_reset(req);

	if (result == 0) {
		req->result = res;
		req->current = res;
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

