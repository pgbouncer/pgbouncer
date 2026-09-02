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
 * OS signal handling for pgbouncer.
 *
 * The main thread receives OS signals via libevent's evsignal mechanism and
 * forwards them to worker threads by writing to per-worker pipes.  Each
 * worker thread listens on the read end of those pipes via libevent.
 */

#include "bouncer.h"
#include <usual/signal.h>

static void handle_sigterm_main(evutil_socket_t sock, short flags, void *arg);
static void handle_sigterm(evutil_socket_t sock, short flags, void *arg);

static void request_immediate_shutdown_main(void)
{
	cf_shutdown = SHUTDOWN_IMMEDIATE;
	cleanup_unix_sockets();
	event_base_loopbreak(pgb_event_base);
	if (multithread_mode) {
		FOR_EACH_WORKER_THREAD(thread_id) {
			workers[thread_id].cf_shutdown = SHUTDOWN_IMMEDIATE;
		}
	}
}

static void request_immediate_shutdown_worker(Worker *this_thread)
{
	this_thread->cf_shutdown = SHUTDOWN_IMMEDIATE;
	event_base_loopbreak(this_thread->base);
}

static void signal_threads(evutil_socket_t signal_pipe[2])
{
	if (pipe_write(signal_pipe[1], "x", 1) <= 0)
		log_error("Failed to write to pipe");
}

static void handle_sigterm_main(evutil_socket_t sock, short flags, void *arg)
{
	if (cf_shutdown) {
		log_info("got SIGTERM while shutting down, fast exit");
		request_immediate_shutdown_main();
		if (multithread_mode) {
			FOR_EACH_WORKER_THREAD(thread_id) {
				signal_threads(workers[thread_id].worker_signal_events.pipe_sigterm);
			}
		}
		return;
	}
	log_info("got SIGTERM, shutting down, waiting for all clients disconnect");
	sd_notify(0, "STOPPING=1");
	if (cf_reboot)
		die("takeover was in progress, going down immediately");
	if (cf_pause_mode == P_SUSPEND)
		die("suspend was in progress, going down immediately");
	cf_shutdown = SHUTDOWN_WAIT_FOR_CLIENTS;
	cleanup_tcp_sockets();
	if (multithread_mode) {
		FOR_EACH_WORKER_THREAD(thread_id) {
			signal_threads(workers[thread_id].worker_signal_events.pipe_sigterm);
		}
	}
}

static void handle_sigterm(evutil_socket_t sock, short flags, void *arg)
{
	Worker *this_thread = (Worker *) pthread_getspecific(worker_key);
	char buf[1];
	if (pipe_read(workers[this_thread->thread_id].worker_signal_events.pipe_sigterm[0], buf, sizeof(buf)) <= 0) {
		log_error("[Thread %d] read SIGTERM pipe failure.", this_thread->thread_id);
		return;
	}
	if (this_thread->cf_shutdown) {
		log_info("[Thread %d] got SIGTERM while shutting down, fast exit", this_thread->thread_id);
		request_immediate_shutdown_worker(this_thread);
		return;
	}
	log_info("[Thread %d] got SIGTERM, shutting down, waiting for all clients disconnect", this_thread->thread_id);
	this_thread->cf_shutdown = SHUTDOWN_WAIT_FOR_CLIENTS;
}

static void handle_sigint_main(evutil_socket_t sock, short flags, void *arg)
{
	if (cf_shutdown) {
		log_info("got SIGINT while shutting down, fast exit");
		request_immediate_shutdown_main();
		if (multithread_mode) {
			FOR_EACH_WORKER_THREAD(thread_id) {
				signal_threads(workers[thread_id].worker_signal_events.pipe_sigint);
			}
		}
		return;
	}
	log_info("got SIGINT, shutting down, waiting for all servers connections to be released");
	sd_notify(0, "STOPPING=1");
	if (cf_reboot)
		die("takeover was in progress, going down immediately");
	if (cf_pause_mode == P_SUSPEND)
		die("suspend was in progress, going down immediately");
	cf_pause_mode = P_PAUSE;
	cf_shutdown = SHUTDOWN_WAIT_FOR_SERVERS;
	cleanup_tcp_sockets();
	if (multithread_mode) {
		FOR_EACH_WORKER_THREAD(thread_id) {
			signal_threads(workers[thread_id].worker_signal_events.pipe_sigint);
		}
	}
}

static void handle_sigint(evutil_socket_t sock, short flags, void *arg)
{
	Worker *this_thread = (Worker *) pthread_getspecific(worker_key);
	char buf[1];
	if (pipe_read(workers[this_thread->thread_id].worker_signal_events.pipe_sigint[0], buf, sizeof(buf)) <= 0) {
		log_error("[Thread %d] read SIGINT pipe failure.", this_thread->thread_id);
		return;
	}
	if (this_thread->cf_shutdown) {
		log_info("[Thread %d] got SIGINT while shutting down, fast exit", this_thread->thread_id);
		request_immediate_shutdown_worker(this_thread);
		return;
	}
	log_info("[Thread %d] got SIGINT, shutting down, waiting for all servers connections to be released", this_thread->thread_id);
	this_thread->cf_shutdown = SHUTDOWN_WAIT_FOR_SERVERS;
}

#ifndef WIN32

static void handle_sigquit_main(evutil_socket_t sock, short flags, void *arg)
{
	log_info("got SIGQUIT, fast exit");
	/* pidfile cleanup happens via atexit() */
	if (multithread_mode) {
		FOR_EACH_WORKER_THREAD(thread_id) {
			signal_threads(workers[thread_id].worker_signal_events.pipe_sigquit);
		}
		join_worker_threads();
	}
	exit(0);
}

static void handle_sigquit_worker(evutil_socket_t sock, short flags, void *arg)
{
	Worker *this_thread = (Worker *) pthread_getspecific(worker_key);
	char buf[1];
	if (pipe_read(workers[this_thread->thread_id].worker_signal_events.pipe_sigquit[0], buf, sizeof(buf)) <= 0) {
		log_error("[Thread %d] read SIGQUIT pipe failure.", this_thread->thread_id);
		return;
	}
	log_info("[Thread %d] got SIGQUIT, fast exit", this_thread->thread_id);

	pthread_exit(NULL);
}

static void handle_sigusr1(int sock, short flags, void *arg)
{
	if (cf_pause_mode == P_NONE) {
		log_info("got SIGUSR1, pausing all activity");
		if (multithread_mode) {
			/* Set pause mode on all threads */
			FOR_EACH_WORKER_THREAD(thread_id) {
				lock_worker_thread(thread_id);
				workers[thread_id].cf_pause_mode = P_PAUSE;
				unlock_worker_thread(thread_id);
			}
		}
		cf_pause_mode = P_PAUSE;
	} else {
		log_info("got SIGUSR1, but already paused/suspended");
	}
}

static void handle_sigusr2(int sock, short flags, void *arg)
{
	if (cf_shutdown) {
		log_info("got SIGUSR2 while shutting down, ignoring");
		return;
	}
	switch (cf_pause_mode) {
	case P_SUSPEND:
		log_info("got SIGUSR2, continuing from SUSPEND");
		resume_all();
		cf_pause_mode = P_NONE;
		break;
	case P_PAUSE:
		log_info("got SIGUSR2, continuing from PAUSE");
		cf_pause_mode = P_NONE;
		break;
	case P_NONE:
		log_info("got SIGUSR2, but not paused/suspended");
	}
}

/*
 * Notify systemd that we are reloading, including a CLOCK_MONOTONIC timestamp
 * in usec so that the program is compatible with a Type=notify-reload service.
 *
 * See https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 */
static void notify_reloading(void)
{
#ifdef USE_SYSTEMD
	struct timespec ts;
	usec_t usec;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	usec = (usec_t)ts.tv_sec * USEC + (usec_t)ts.tv_nsec / (usec_t)1000;
	sd_notifyf(0, "RELOADING=1\nMONOTONIC_USEC=%" PRIu64, usec);
#endif
}

static void handle_sighup(int sock, short flags, void *arg)
{
	log_info("got SIGHUP, re-reading config");

	FOR_EACH_WORKER_THREAD(thread_id) {
		lock_worker_thread(thread_id);
	}
	notify_reloading();
	load_config();
	if (!sbuf_tls_setup())
		log_error("TLS configuration could not be reloaded, keeping old configuration");
	sd_notify(0, "READY=1");
	FOR_EACH_WORKER_THREAD(thread_id) {
		unlock_worker_thread(thread_id);
	}
}
#endif

static void add_signal_handler(struct event_base *base, struct event *ev,
			       int signum, event_callback_fn handler)
{
	evsignal_assign(ev, base, signum, handler, NULL);
	if (evsignal_add(ev, NULL) < 0)
		fatal_perror("evsignal_add");
}

static void make_signal_pipe(evutil_socket_t fds[2])
{
	if (make_pipe(fds) < 0)
		fatal_perror("multithread signal pipe");
	evutil_make_socket_nonblocking(fds[0]);
	evutil_make_socket_nonblocking(fds[1]);
}

static void add_worker_signal_event(struct event_base *base, struct event **ev,
				    evutil_socket_t fd, event_callback_fn handler)
{
	*ev = event_new(base, fd, EV_READ | EV_PERSIST, handler, base);
	if (event_add(*ev, NULL) < 0)
		fatal_perror("multithread signal event add");
}

void signal_setup_main(struct event_base *base, struct SignalEvent *signal_event)
{
#ifndef WIN32
	sigset_t set;

	/* block SIGPIPE */
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	if (sigprocmask(SIG_BLOCK, &set, NULL) < 0)
		fatal_perror("sigprocmask");

	/* install handlers */
	add_signal_handler(base, &signal_event->ev_sigusr1, SIGUSR1, handle_sigusr1);
	add_signal_handler(base, &signal_event->ev_sigusr2, SIGUSR2, handle_sigusr2);
	add_signal_handler(base, &signal_event->ev_sighup, SIGHUP, handle_sighup);
	add_signal_handler(base, &signal_event->ev_sigquit, SIGQUIT, handle_sigquit_main);
#endif

	add_signal_handler(base, &signal_event->ev_sigterm, SIGTERM, handle_sigterm_main);
	add_signal_handler(base, &signal_event->ev_sigint, SIGINT, handle_sigint_main);

	if (multithread_mode) {
		FOR_EACH_WORKER_THREAD(thread_id) {
			make_signal_pipe(workers[thread_id].worker_signal_events.pipe_sigint);
			make_signal_pipe(workers[thread_id].worker_signal_events.pipe_sigterm);
#ifndef WIN32
			make_signal_pipe(workers[thread_id].worker_signal_events.pipe_sigquit);
#endif
		}
	}
}

void signal_setup_worker(struct event_base *base, int thread_id)
{
	WorkerSignalEvents *wse = &workers[thread_id].worker_signal_events;

#ifndef WIN32
	add_worker_signal_event(base, &wse->ev_sigquit, wse->pipe_sigquit[0], handle_sigquit_worker);
#endif
	add_worker_signal_event(base, &wse->ev_sigterm, wse->pipe_sigterm[0], handle_sigterm);
	add_worker_signal_event(base, &wse->ev_sigint, wse->pipe_sigint[0], handle_sigint);
}
