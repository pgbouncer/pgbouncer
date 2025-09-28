#include <usual/slab_ts.h>
#include <usual/pthread.h>

#include "test_common.h"


#define NUM_THREADS 4
#define NUM_ALLOCATIONS 100

static void test_slab(void *p)
{
	struct ThreadSafeSlab *ts_slab;
	void *obj1, *obj2;

	ts_slab = thread_safe_slab_create("test_slab", sizeof(int), 0, NULL, NULL, false);
	tt_assert(ts_slab != NULL);

	obj1 = thread_safe_slab_alloc(ts_slab);
	tt_assert(obj1 != NULL);

	obj2 = thread_safe_slab_alloc(ts_slab);
	tt_assert(obj2 != NULL);

	tt_assert(thread_safe_slab_active_count(ts_slab) == 2);

	thread_safe_slab_free(ts_slab, obj1);
	thread_safe_slab_free(ts_slab, obj2);
	tt_assert(thread_safe_slab_active_count(ts_slab) == 0);

	thread_safe_slab_destroy(ts_slab);
end:    ;
}

static void stats_callback(void *arg,
			   const char *slab_name,
			   unsigned size,
			   unsigned free_count,
			   unsigned total_count)
{
	int *callback_count = (int *)arg;
	(*callback_count)++;
}

static void *thread_worker(void *arg)
{
	struct ThreadSafeSlab *ts_slab = (struct ThreadSafeSlab *)arg;
	for (int i = 0; i < NUM_ALLOCATIONS; i++) {
		void *obj = thread_safe_slab_alloc(ts_slab);
		thread_safe_slab_free(ts_slab, obj);
	}
	return NULL;
}

static void test_slab_multithreaded(void *p)
{
	struct ThreadSafeSlab *ts_slab, *ts_slab1, *ts_slab2;
	void *obj1, *obj2;
	pthread_t threads[NUM_THREADS];
	int call_count = 0;

	ts_slab = thread_safe_slab_create("test_slab_mt", sizeof(int), 0, NULL, NULL, false);
	tt_assert(ts_slab != NULL);

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_create(&threads[i], NULL, thread_worker, ts_slab);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	thread_safe_slab_stats(stats_callback, &call_count);
	tt_assert(call_count == 1);
	call_count = 0;

	tt_assert(thread_safe_slab_total_count(ts_slab) >= NUM_THREADS * NUM_ALLOCATIONS);
	tt_assert(thread_safe_slab_free_count(ts_slab) == thread_safe_slab_total_count(ts_slab));
	tt_assert(thread_safe_slab_active_count(ts_slab) == 0);

	ts_slab1 = thread_safe_slab_create("stats_slab_1", sizeof(int), 0, NULL, NULL, false);
	tt_assert(ts_slab1);

	ts_slab2 = thread_safe_slab_create("stats_slab_2", sizeof(int), 0, NULL, NULL, false);
	tt_assert(ts_slab2);

	obj1 = thread_safe_slab_alloc(ts_slab1);
	tt_assert(obj1);
	obj2 = thread_safe_slab_alloc(ts_slab2);
	tt_assert(obj2);

	thread_safe_slab_stats(stats_callback, &call_count);
	tt_assert(call_count == 3);

	thread_safe_slab_free(ts_slab1, obj1);
	thread_safe_slab_free(ts_slab2, obj2);
	thread_safe_slab_destroy(ts_slab1);
	thread_safe_slab_destroy(ts_slab2);
	thread_safe_slab_destroy(ts_slab);
end:    ;
}

struct testcase_t slab_ts_tests[] = {
	{ "simple", test_slab },
	{ "multithreaded", test_slab_multithreaded },
	END_OF_TESTCASES
};
