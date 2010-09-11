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
 * libevent1 - returns TTL, ignores hosts file.
 * libevent2 - does not return TTL, uses hosts file.
 */

/* do we have libevent2? */
#ifdef EV_ET
#define LIBEVENT2
#endif

#ifdef LIBEVENT2
#include <event2/dns.h>
#else
#include <evdns.h>
#endif


struct UserCallback {
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

	int res_af;
	int res_count;
	int res_pos;
	void *res_list;
	usec_t res_ttl;
};

struct DNSContext {
	struct AATree req_tree;
	void *edns;
};

static void deliver_info(struct DNSRequest *req);


#ifdef LIBEVENT2

/*
 * ADNS with libevent2 <event2/dns.h>
 */

static void got_result_gai(int result, struct evutil_addrinfo *res, void *arg)
{
	struct DNSRequest *req = arg;
	struct evutil_addrinfo *ai;
	int count = 0;
	int af = 0;
	int adrlen;
	uint8_t *dst;

	if (result != DNS_ERR_NONE) {
		/* lookup failed */
		log_warning("lookup failed: %s: result=%d", req->name, result);
		goto failed;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		/* pick single family for this address */
		if (!af) {
			if (ai->ai_family == AF_INET) {
				af = ai->ai_family;
				req->res_af = af;
				adrlen = 4;
			} else {
				continue;
			}
		}
		if (ai->ai_family != af)
			continue;
		count++;
	}

	/* did not found usable entry */
	if (!af) {
		log_warning("dns(%s): no usable address", req->name);
		evutil_freeaddrinfo(res);
		goto failed;
	}

	log_noise("dns(%s): got_result_gai: count=%d, adrlen=%d", req->name, count, adrlen);

	req->res_pos = 0;
	req->done = true;
	req->res_count = count;
	req->res_list = malloc(adrlen * count);
	if (!req->res_list) {
		log_warning("req->res_list alloc failed");
		goto failed;
	}
	req->res_ttl = get_cached_time() + cf_dns_max_ttl;

	dst = req->res_list;
	for (ai = res; ai; ai = ai->ai_next) {
		struct sockaddr_in *in;
		if (ai->ai_family != af)
			continue;
		in = (void*)ai->ai_addr;
		log_noise("dns(%s) result: %s", req->name, inet_ntoa(in->sin_addr));
		memcpy(dst, &in->sin_addr, adrlen);
		dst += adrlen;
	}

	deliver_info(req);
	return;
failed:
	req->res_af = 0;
	req->res_list = NULL;
	deliver_info(req);
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

	gai_req = evdns_getaddrinfo(req->ctx->edns, req->name, NULL, NULL, got_result_gai, req);
	log_noise("dns: evdns_getaddrinfo(%s)=%p", req->name, gai_req);
}

static void impl_release(struct DNSContext *ctx)
{
	struct evdns_base *dns = ctx->edns;
	evdns_base_free(dns, 0);
}

#else

/*
 * ADNS with libevent 1.x <evdns.h>
 */

static void got_result_evdns(int result, char type, int count, int ttl, void *addresses, void *arg)
{
	struct DNSRequest *req = arg;
	int adrlen = 4;

	log_noise("dns: got_result_evdns: type=%d cnt=%d ttl=%d", type, count, ttl);

	req->done = true;

	if (result != DNS_ERR_NONE || count < 1) {
		/* lookup failed */
		goto failed;
	} else if (type == DNS_IPv4_A) {
		struct in_addr *a = addresses;
		log_noise("dns(%s): got_result_evdns: %s", req->name, inet_ntoa(*a));
		req->res_af = AF_INET;
		adrlen = 4;
	} else {
		log_warning("dns(%s): got_result_evdns unknown result: %d", req->name, type);
		/* unknown result */
		goto failed;
	}
	req->res_pos = 0;
	req->res_count = count;
	req->res_list = malloc(adrlen * count);
	if (!req->res_list)
		goto failed;
	memcpy(req->res_list, addresses, adrlen * count);
	req->res_ttl = get_cached_time() + cf_dns_max_ttl;
	deliver_info(req);
	return;
failed:
	req->res_af = 0;
	req->res_list = NULL;
	deliver_info(req);
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
		req->done = true;
		req->res_af = 0;
		deliver_info(req);
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
	struct UserCallback *ucb;
	struct List *el;
	const uint8_t *res = req->res_list;
	int adrlen = 0;

	if (req->res_af == AF_INET)
		adrlen = 4;
	else if (req->res_af == AF_INET6)
		adrlen = 16;
loop:
	/* get next req */
	el = list_pop(&req->ucb_list);
	if (!el)
		return;
	ucb = container_of(el, struct UserCallback, node);

	/* launch callback */
	log_noise("dns: deliver_info(%s) type=%d pos=%d", req->name, req->res_af, req->res_pos);
	ucb->cb_func(ucb->cb_arg, req->res_af, res + req->res_pos * adrlen);

	/* round-robin between results */
	if (req->res_count > 1) {
		req->res_pos++;
		if (req->res_pos >= req->res_count)
			req->res_pos = 0;
	}

	/* drop request */
	list_del(&ucb->node);
	free(ucb);

	goto loop;
}

static int req_cmp(long arg, struct AANode *node)
{
	const char *s1 = (char *)arg;
	struct DNSRequest *req = container_of(node, struct DNSRequest, node);
	return strcmp(s1, req->name);
}

static void req_free(struct AANode *node, void *arg)
{
	struct UserCallback *ucb;
	struct DNSRequest *req;
	struct List *el;
	req = container_of(node, struct DNSRequest, node);
	while ((el = list_pop(&req->ucb_list)) != NULL) {
		ucb = container_of(el, struct UserCallback, node);
		free(ucb);
	}
	free(req->res_list);
	free(req->name);
	free(req);
}

struct DNSContext *adns_create_context(void)
{
	struct DNSContext *ctx = calloc(1, sizeof(*ctx));

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

void adns_resolve(struct DNSContext *ctx, const char *name, adns_callback_f cb_func, void *cb_arg)
{
	int namelen = strlen(name);
	struct DNSRequest *req;
	struct UserCallback *ucb;
	struct AANode *node;

	/* setup actual lookup */
	node = aatree_search(&ctx->req_tree, (long)name);
	if (node) {
		req = container_of(node, struct DNSRequest, node);
	} else {
		log_noise("dns: new req: %s", name);
		req = calloc(1, sizeof(*req));
		if (!req)
			goto nomem;
		req->ctx = ctx;
		req->name = name;
		req->namelen = namelen;
		list_init(&req->ucb_list);
		aatree_insert(&ctx->req_tree, (long)req->name, &req->node);
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
			req->done = false;
			free(req->res_list);
			req->res_list = NULL;
			req->res_af = 0;

			impl_launch_query(req);
		} else
			deliver_info(req);
	}
	return;
nomem:
	log_warning("dns(%s): req failed, no mem", name);
	cb_func(cb_arg, 0, NULL);
}


