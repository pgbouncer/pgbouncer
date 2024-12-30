#include <usual/statlist.h>

#include <pthread.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#define THREAD_NUM 4
#define THREAD_QUEUE_SIZE 100

enum ThreadStatus {
    READY,
    BUSY
};

typedef struct thread_worker_request{

} thread_worker_request;

// typedef struct Thread {

//     struct event_base * thread_event_bases;
   
//     pthread_t worker;
    
//     volatile int thread_head_slot;
    
//     volatile int thread_first_free_slot;
    
//     struct thread_worker_request thread_queue[THREAD_QUEUE_SIZE];

//     pthread_mutex_t thread_queue_tail_mutex;
    
//     pthread_cond_t thread_not_empty;

// } Thread;


typedef struct Thread {

    struct StatList sock_list;
    pthread_t worker;
    int thread_id;
    struct event full_maint_ev;
    struct event ev_stats;
    struct event ev_handle_request;
    int pipefd[2];
} Thread;

typedef struct ClientRequest {
    int fd;
    bool is_unix;
} ClientRequest;

Thread threads[THREAD_NUM];
extern int next_thread;

void signal_setup(struct event_base * base);
void start_threads();
void clean_threads();