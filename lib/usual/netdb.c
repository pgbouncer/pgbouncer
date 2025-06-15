/*
 * libusual - Utility library for C
 *
 * Copyright (c) 2010  Marko Kreen, Skype Technologies
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

#include <usual/netdb.h>

#include <usual/socket.h>
#include <usual/list.h>

/* is compat function needed? */
#ifndef HAVE_GETADDRINFO_A

/* full compat if threads are available */
#ifdef HAVE_PTHREAD

#include <pthread.h>
#include <string.h>

/*
 * Basic blocking lookup
 */

static void gaia_lookup(pthread_t origin, struct gaicb *list[], int nitems, struct sigevent *sevp)
{
	struct gaicb *g;
	int i, res;

	for (i = 0; i < nitems; i++) {
		g = list[i];
		res = getaddrinfo(g->ar_name, g->ar_service, g->ar_request, &g->ar_result);
		g->_state = res;
	}

	if (!sevp || sevp->sigev_notify == SIGEV_NONE) {
		/* do nothing */
	} else if (sevp->sigev_notify == SIGEV_SIGNAL) {
		/* send signal */
		pthread_kill(origin, sevp->sigev_signo);
	} else if (sevp->sigev_notify == SIGEV_THREAD) {
		/* call function */
		sevp->sigev_notify_function(sevp->sigev_value);
	}
}

/*
 * Thread to run blocking lookup in
 */

struct GAIAContext {
	struct List req_list;
	pthread_cond_t cond;
	pthread_mutex_t lock;
	pthread_t thread;
};

struct GAIARequest {
	struct List node;
	pthread_t origin;
	int nitems;
	struct sigevent sev;
	struct gaicb *list[FLEX_ARRAY];
};

#define RQ_SIZE(n) (offsetof(struct GAIARequest,list) + (n)*(sizeof(struct gaicb *)))

static void gaia_lock_reqs(struct GAIAContext *ctx)
{
	pthread_mutex_lock(&ctx->lock);
}

static void gaia_unlock_reqs(struct GAIAContext *ctx)
{
	pthread_mutex_unlock(&ctx->lock);
}

static void *gaia_lookup_thread(void *arg)
{
	struct GAIAContext *ctx = arg;
	struct GAIARequest *rq;
	struct List *el;

	gaia_lock_reqs(ctx);
	while (1) {
		el = list_pop(&ctx->req_list);
		if (!el) {
			pthread_cond_wait(&ctx->cond, &ctx->lock);
			continue;
		}
		gaia_unlock_reqs(ctx);

		rq = container_of(el, struct GAIARequest, node);
		gaia_lookup(rq->origin, rq->list, rq->nitems, &rq->sev);
		free(rq);

		gaia_lock_reqs(ctx);
	}

	return NULL;
}

/*
 * Functions run in user thread
 */

static int gaia_post_request(struct GAIAContext *ctx, struct gaicb *list[], int nitems, struct sigevent *sevp)
{
	struct GAIARequest *rq;

	rq = malloc(RQ_SIZE(nitems));
	if (!rq)
		return EAI_MEMORY;

	list_init(&rq->node);
	rq->origin = pthread_self();
	rq->nitems = nitems;
	if (sevp)
		rq->sev = *sevp;
	else
		rq->sev.sigev_notify = SIGEV_NONE;
	memcpy(rq->list, list, sizeof(struct gaicb *));

	gaia_lock_reqs(ctx);
	list_append(&ctx->req_list, &rq->node);
	gaia_unlock_reqs(ctx);

	pthread_cond_signal(&ctx->cond);

	return 0;
}

static struct GAIAContext *gaia_create_context(void)
{
	struct GAIAContext *ctx;
	int err;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	list_init(&ctx->req_list);
	err = pthread_cond_init(&ctx->cond, NULL);
	if (err)
		goto failed;

	err = pthread_mutex_init(&ctx->lock, NULL);
	if (err)
		goto failed;

	err = pthread_create(&ctx->thread, NULL, gaia_lookup_thread, ctx);
	if (err)
		goto failed;

	return ctx;

failed:
	free(ctx);
	errno = err;
	return NULL;
}

/*
 * Final interface
 */

int getaddrinfo_a(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp)
{
	static struct GAIAContext *ctx;

	if (nitems <= 0)
		return 0;

	if (sevp && sevp->sigev_notify != SIGEV_NONE
	    && sevp->sigev_notify != SIGEV_SIGNAL
	    && sevp->sigev_notify != SIGEV_THREAD)
		goto einval;

	if (mode == GAI_WAIT) {
		gaia_lookup(pthread_self(), list, nitems, sevp);
		return 0;
	} else if (mode == GAI_NOWAIT) {
		if (!ctx) {
			ctx = gaia_create_context();
			if (!ctx)
				return EAI_MEMORY;
		}
		return gaia_post_request(ctx, list, nitems, sevp);
	}
einval:
	errno = EINVAL;
	return EAI_SYSTEM;
}

#else /* without threads not much to do */

int getaddrinfo_a(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp)
{
	errno = ENOSYS;
	return EAI_SYSTEM;
}

#endif /* !HAVE_PTHREAD_H */
#endif /* !HAVE_GETADDRINFO_A */
