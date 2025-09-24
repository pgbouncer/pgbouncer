#include "test_common.h"
#include <usual/statlist_ts.h>
#include <usual/string.h>
#include <usual/pthread.h>


static void test_thread_safe_statlist_simple(void *p)
{
	struct ThreadSafeStatList ts_list;
	struct List node1, node2, node3;
	struct List *popped_node;

	thread_safe_statlist_init(&ts_list, "test_list", false);

	spin_lock_acquire(&ts_list.lock);
	str_check(statlist_count(&ts_list.list) == 0 ? "OK" : "FAIL", "OK");
	spin_lock_release(&ts_list.lock);

	list_init(&node1);
	list_init(&node2);
	list_init(&node3);

	thread_safe_statlist_append(&ts_list, &node1);
	thread_safe_statlist_append(&ts_list, &node2);
	thread_safe_statlist_append(&ts_list, &node3);

	spin_lock_acquire(&ts_list.lock);
	str_check(statlist_count(&ts_list.list) == 3 ? "OK" : "FAIL", "OK");
	spin_lock_release(&ts_list.lock);

	popped_node = thread_safe_statlist_pop(&ts_list);
	tt_assert(popped_node == &node1);

	spin_lock_acquire(&ts_list.lock);
	str_check(statlist_count(&ts_list.list) == 2 ? "OK" : "FAIL", "OK");
	spin_lock_release(&ts_list.lock);

end:    ;
}


/* multithread */

#define NUM_ITERATIONS 1000
#define NUM_THREADS 4

static struct ThreadSafeStatList ts_list;

static void *thread_worker(void *arg)
{
	for (int i = 0; i < NUM_ITERATIONS; i++) {
		struct List *popped_node;
		struct List *node = malloc(sizeof(struct List));
		if (!node) continue;
		list_init(node);
		thread_safe_statlist_append(&ts_list, node);
		popped_node = thread_safe_statlist_pop(&ts_list);
		if (popped_node) free(popped_node);
	}
	return NULL;
}

static void test_thread_safe_statlist_multithreaded(void *p)
{
	pthread_t threads[NUM_THREADS];
	thread_safe_statlist_init(&ts_list, "test_list", false);
	srand(time(NULL));

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_create(&threads[i], NULL, thread_worker, NULL);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	spin_lock_acquire(&ts_list.lock);
	str_check(statlist_count(&ts_list.list) == 0 ? "OK" : "FAIL", "OK");
	spin_lock_release(&ts_list.lock);

end:    ;
}


/* iteration */

static void count_elements(struct List *item, void *ctx)
{
	int *counter = (int *)ctx;
	(*counter)++;
}

static void test_thread_safe_statlist_iteration(void *p)
{
	struct ThreadSafeStatList ts_list;
	struct List node1, node2, node3;
	struct List *item;
	int element_count;

	thread_safe_statlist_init(&ts_list, "test_list_iteration", false);

	list_init(&node1);
	list_init(&node2);
	list_init(&node3);

	thread_safe_statlist_append(&ts_list, &node1);
	thread_safe_statlist_append(&ts_list, &node2);
	thread_safe_statlist_append(&ts_list, &node3);

	element_count = 0;
	THREAD_SAFE_STATLIST_EACH(&ts_list, item, { element_count++;});

	str_check(element_count == 3 ? "OK" : "FAIL", "OK");

	element_count = 0;
	THREAD_SAFE_STATLIST_REVERSE_EACH(&ts_list, item, { element_count++;});
	str_check(element_count == 3 ? "OK" : "FAIL", "OK");

end:    ;
}


struct testcase_t statlist_ts_tests[] = {
	{ "simple", test_thread_safe_statlist_simple },
	{ "multithread", test_thread_safe_statlist_multithreaded },
	{ "iteration", test_thread_safe_statlist_iteration },
	END_OF_TESTCASES
};
