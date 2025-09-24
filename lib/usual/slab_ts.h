/*
 * Thread-safe slab allocator wrapper.
 *
 * Based on the original slab allocator by Marko Kreen, adapted for multi-threaded use.
 */

#ifndef _USUAL_THREAD_SAFE_SLAB_H_
#define _USUAL_THREAD_SAFE_SLAB_H_

#include <usual/slab.h>

struct ThreadSafeSlab;

/* Create a new thread-safe slab context */
struct ThreadSafeSlab *thread_safe_slab_create(const char *name, unsigned obj_size, unsigned align,
					       slab_init_fn init_func, CxMem *cx, bool enable_recursive_lock);

/* Destroy a thread-safe slab context */
void thread_safe_slab_destroy(struct ThreadSafeSlab *ts_slab);

/* Allocate one object from the thread-safe slab */
void *thread_safe_slab_alloc(struct ThreadSafeSlab *ts_slab) _MALLOC _MUSTCHECK;

/* Return an object back to the thread-safe slab */
void thread_safe_slab_free(struct ThreadSafeSlab *ts_slab, void *obj);

/* Get total number of objects (free + used) */
int thread_safe_slab_total_count(struct ThreadSafeSlab *ts_slab);

/* Get number of currently free objects */
int thread_safe_slab_free_count(struct ThreadSafeSlab *ts_slab);

/* Get number of currently active (in-use) objects */
int thread_safe_slab_active_count(struct ThreadSafeSlab *ts_slab);

/* Run stats callback for all slabs */
void thread_safe_slab_stats(slab_stat_fn cb_func, void *cb_arg);

#endif /* _USUAL_THREAD_SAFE_SLAB_H_ */
