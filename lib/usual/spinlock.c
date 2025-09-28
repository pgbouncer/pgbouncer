#include <usual/logging.h>
#include <usual/spinlock.h>
#ifndef WIN32
#include <sched.h>
#endif

#define SPIN_LOCK_INITIALIZED 1

bool spin_lock_owns(SpinLock *lock)
{
#ifdef WIN32
	volatile DWORD self;
#else
	volatile pthread_t self;
#endif

	if (lock->initialized != SPIN_LOCK_INITIALIZED)
		fatal("Attempt to check an uninitialized lock!");

	self = GET_THREAD_ID();

	return THREAD_ID_EQUALS(lock->lock_word, self);
}

void spin_lock_init(SpinLock *lock, bool recursive)
{
	memset((void *)&(lock->lock_word), 0, sizeof(lock->lock_word));
	lock->count = 0;
	lock->initialized = SPIN_LOCK_INITIALIZED;
	lock->enable_recursive = recursive;
}

void spin_lock_acquire(SpinLock *lock)
{
	if (lock->initialized != SPIN_LOCK_INITIALIZED)
		fatal("Attempt to acquire an uninitialized lock!");


	if (lock->enable_recursive && spin_lock_owns(lock)) {
		lock->count++;
		return;
	}

#ifdef WIN32
	while (InterlockedCompareExchange(&lock->count, 1, 0) != 0) {
		SwitchToThread();
	}
#else
	while (!__sync_bool_compare_and_swap(&lock->count, 0, 1)) {
		sched_yield();
	}
#endif

	MEMORY_BARRIER();
	lock->lock_word = GET_THREAD_ID();
}

void spin_lock_release(SpinLock *lock)
{
	if (lock->initialized != SPIN_LOCK_INITIALIZED)
		fatal("Attempt to release an uninitialized lock!");

	if (!spin_lock_owns(lock)) {
		fatal("Thread tried to release a lock it does not own!");
	}

	if (lock->count > 1) {
		lock->count--;
		return;
	}

	RESET_LOCK_WORD(lock->lock_word);
	MEMORY_BARRIER();
	lock->count = 0;
}
