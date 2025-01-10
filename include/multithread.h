#include <usual/statlist.h>

#include <pthread.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#define THREAD_NUM 4


#define FOR_EACH_THREAD(id) \
	for ((id) = 0; \
	     (id) < THREAD_NUM; \
	     (id)++)


typedef struct Thread {

    struct StatList sock_list;
    pthread_t worker;
    int thread_id;
    struct event full_maint_ev;
    struct event ev_stats;
    struct event ev_handle_request;
    int pipefd[2];
    struct StatList user_list;
    struct StatList login_client_list;
    struct StatList pool_list;
    struct StatList peer_pool_list;
    struct Slab *client_cache;
    struct Slab *server_cache;
    struct Slab *pool_cache;
    struct Slab *peer_pool_cache;
    struct Slab *var_list_cache;
    struct Slab *iobuf_cache;
    struct Slab *user_cache;
    struct Slab *server_prepared_statement_cache;
} Thread;

typedef struct ClientRequest {
    int fd;
    bool is_unix;
} ClientRequest;

Thread threads[THREAD_NUM];
extern int next_thread;

void signal_setup(struct event_base * base);
void start_threads();
void init_threads();
void clean_threads();