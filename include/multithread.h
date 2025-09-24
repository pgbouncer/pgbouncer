#include <usual/aatree.h>
#include <usual/pthread.h>
#include <usual/spinlock.h>
#include <usual/statlist.h>
#include <usual/statlist_ts.h>
#include <usual/time.h>

#include "bouncer.h"

#include <event2/event.h>
#include <event2/event_struct.h>

#define FOR_EACH_THREAD(id)         \
	for (int id = 0;                \
	     (id) < arg_thread_number;  \
	     (id)++)


#define GET_MULTITHREAD_PTR(name, thread_id) \
	(multithread_mode ? (void *)&(threads[thread_id].name) : (void *)&name)

#define GET_MULTITHREAD_CACHE_PTR(name, thread_id) \
	(multithread_mode ? (threads[thread_id].name) : (name))


#define MULTITHREAD_VISIT(multithread_mode, lock, func)                         \
	do {                                                                                                        \
		if (multithread_mode) {                                                             \
			spin_lock_acquire(lock);                                                \
			func;                                                                                       \
			spin_lock_release(lock);                                                \
		} else {                                                                                            \
			func;                                                                                       \
		}                                                               \
	} while (0)


typedef struct SignalEvent {
	/*
	 * signal handling.
	 *
	 * handle_* functions are not actual signal handlers but called from
	 * event_loop() so they have no restrictions what they can do.
	 */
	struct event ev_sigterm;
	struct event ev_sigint;

#ifndef WIN32

	struct event ev_sigquit;
	struct event ev_sigusr1;
	struct event ev_sigusr2;
	struct event ev_sighup;
#endif
} SignalEvent;


typedef struct WorkersignalEvents {
	int pipe_sigterm[2];
	int pipe_sigint[2];
	struct event *ev_sigterm;
	struct event *ev_sigint;

#ifndef WIN32
	int pipe_sigquit[2];
	int pipe_sigusr1[2];
	int pipe_sigusr2[2];
	int pipe_sighup[2];
	struct event *ev_sigquit;
	struct event *ev_sigusr1;
	struct event *ev_sigusr2;
	struct event *ev_sighup;
#endif
} WorkersignalEvents;


typedef struct Thread {
	SpinLock thread_lock;
	pthread_t worker;
	struct event_base *base;
	int thread_id;
	struct event full_maint_ev;
	struct event ev_stats;
	struct event ev_handle_request;
	int pipefd[2];
	struct StatList login_client_list;
	struct ThreadSafeStatList pool_list;
	struct ThreadSafeStatList peer_pool_list;
	struct WorkersignalEvents worker_signal_events;
	struct ThreadSafeStatList database_list;
	struct StatList autodatabase_idle_list;
	struct Slab *client_cache;
	struct Slab *server_cache;
	struct Slab *pool_cache;
	struct Slab *peer_pool_cache;
	struct Slab *db_cache;
	struct Slab *var_list_cache;
	struct Slab *iobuf_cache;
	struct Slab *server_prepared_statement_cache;
	struct Slab *outstanding_request_cache;

	/*
	 * libevent may still report events when event_del()
	 * is called from somewhere else.  So hide just freed
	 * PgSockets for one loop.
	 */
	struct StatList justfree_client_list;
	struct StatList justfree_server_list;

	struct StrPool *vpool;

	struct PktBuf *temp_pktbuf;

	struct PgPool *admin_pool;

	int cf_shutdown;
	int cf_pause_mode;	/* Thread-local pause mode */
	bool pause_ready;	/* Thread ready for pause response */
	bool wait_close_ready;	/* Thread ready for wait_close response */
	bool partial_pause;	/* Thread has database-specific pauses */
	int active_count;	/* Thread-local active count for pause/suspend */

	unsigned int seq;

	usec_t multithread_time_cache;

	MultithreadEventArgs do_full_maint_event_args;
	MultithreadEventArgs handle_request_event_args;
} Thread;

typedef struct ClientRequest {
	int fd;
	bool is_unix;
} ClientRequest;


extern Thread *threads;
extern int next_thread;

void signal_setup(struct event_base *base, struct SignalEvent *signal_event);
void start_threads(void);
void init_threads(void);
int wait_threads(void);
void clean_threads(void);
void request_pause_thread(int thread_id);
bool thread_paused(int thread_id);
void resume_thread(int thread_id);
void lock_thread(int thread_id);
void unlock_thread(int thread_id);

int get_current_thread_id(const bool multithread_mode);

usec_t get_multithread_time_with_id(int thread_id);

void multithread_reset_time_cache(void);

void multithread_event_wrapper(evutil_socket_t sock, short flags, void *arg);


bool multithread_limits_init(ConnectionLimit **limit, SpinLock *lock);
void multithread_set_limit(const char *name, ConnectionLimit **limits, SpinLock *lock, int limit);
int multithread_get_limit(const char *name, ConnectionLimit **limits, SpinLock *lock);
int multithread_get_limit_count(const char *name, ConnectionLimit **limits, SpinLock *lock);
void multithread_increase_limit_count(const char *name, ConnectionLimit **limits, SpinLock *lock);
void multithread_decrease_limit_count(const char *name, ConnectionLimit **limits, SpinLock *lock);
bool multithread_check_limit_count(const char *name, ConnectionLimit **limits, SpinLock *lock);
void multithread_free_limits(ConnectionLimit **limits);
