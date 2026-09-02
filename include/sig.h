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
 * Signal-related structs shared between the main thread and worker threads.
 *
 * Note: this file is named "sig.h" (not "signal.h") to avoid shadowing
 * the system <signal.h> when compiled with -Iinclude.
 */

/*
 * Main-thread signal event handles (one per process).
 * handle_* functions are invoked from the event loop, not actual OS signal
 * handlers, so they have no async-signal-safety restrictions.
 */
typedef struct SignalEvent {
	struct event ev_sigterm;
	struct event ev_sigint;

#ifndef WIN32
	struct event ev_sigquit;
	struct event ev_sigusr1;
	struct event ev_sigusr2;
	struct event ev_sighup;
#endif
} SignalEvent;

/*
 * Per-worker signal forwarding infrastructure (multithread mode only).
 * The main thread receives OS signals and writes to these pipes; each
 * worker thread listens on the read end via libevent.
 */
typedef struct WorkerSignalEvents {
	evutil_socket_t pipe_sigterm[2];
	evutil_socket_t pipe_sigint[2];
	struct event *ev_sigterm;
	struct event *ev_sigint;

#ifndef WIN32
	evutil_socket_t pipe_sigquit[2];
	struct event *ev_sigquit;
#endif
} WorkerSignalEvents;

void signal_setup_main(struct event_base *base, struct SignalEvent *signal_event);
void signal_setup_worker(struct event_base *base, int thread_id);
