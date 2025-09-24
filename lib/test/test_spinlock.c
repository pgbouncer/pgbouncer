#include <usual/pthread.h>
#include <usual/spinlock.h>
#include "test_common.h"

/*
 * Basic acquire and release test
 */
static void test_spin_lock_basic(void *p)
{
	SpinLock lock;
	spin_lock_init(&lock);

	spin_lock_acquire(&lock);
	int_check(lock.count, 1);

	spin_lock_release(&lock);
	int_check(lock.count, 0);

end:    ;
}

/*
 * Multithreading stress test
 */
#define NUM_THREADS 10
#define NUM_ITERATIONS 10000

static SpinLock shared_lock;
static int shared_counter = 0;

static void *thread_function(void *arg)
{
	for (int i = 0; i < NUM_ITERATIONS; i++) {
		spin_lock_acquire(&shared_lock);
		shared_counter++;
		spin_lock_release(&shared_lock);
	}
	return NULL;
}

static void test_spin_lock_multithreaded(void *p)
{
	pthread_t threads[NUM_THREADS];
	spin_lock_init(&shared_lock);

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_create(&threads[i], NULL, thread_function, NULL);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	int_check(shared_counter, NUM_THREADS * NUM_ITERATIONS);
end:    ;
}

/*
 * Multithreaded recursive locking test
 * Each thread acquires the lock 3 times recursively,
 * then releases it the same number of times.
 */
#define NUM_RECURSIVE_THREADS 5
#define RECURSIVE_DEPTH 3
#define NUM_RECURSIVE_ITERATIONS 1000

static SpinLock recursive_lock;
static int recursive_counter = 0;

static void *recursive_thread_function(void *arg)
{
	for (int i = 0; i < NUM_RECURSIVE_ITERATIONS; i++) {
		// Acquire the lock recursively
		for (int d = 0; d < RECURSIVE_DEPTH; d++) {
			spin_lock_acquire(&recursive_lock);
		}

		recursive_counter++;

		// Release the lock in reverse
		for (int d = 0; d < RECURSIVE_DEPTH; d++) {
			spin_lock_release(&recursive_lock);
		}
	}
	return NULL;
}

static void test_spin_lock_recursive(void *p)
{
	pthread_t threads[NUM_RECURSIVE_THREADS];
	spin_lock_init(&recursive_lock, true);
	for (int i = 0; i < NUM_RECURSIVE_THREADS; i++) {
		pthread_create(&threads[i], NULL, recursive_thread_function, NULL);
	}

	for (int i = 0; i < NUM_RECURSIVE_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	int_check(recursive_counter, NUM_RECURSIVE_THREADS * NUM_RECURSIVE_ITERATIONS);
end:    ;
}


/*
 * Describe test cases
 */
struct testcase_t spinlock_tests[] = {
	{ "basic", test_spin_lock_basic },
	{ "multithread", test_spin_lock_multithreaded },
	{ "recursive", test_spin_lock_recursive },
	END_OF_TESTCASES
};
