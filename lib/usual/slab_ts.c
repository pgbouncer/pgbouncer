#include <usual/slab_ts.h>
#include <usual/slab_internal.h>
#include <usual/spinlock.h>
#include <usual/statlist_ts.h>


/* keep track of all active thread-safe slabs */
static struct ThreadSafeStatList thread_safe_slab_list;

__attribute__((constructor))
static void init_thread_safe_slab_list_global(void)
{
	thread_safe_statlist_init(&thread_safe_slab_list, "thread_safe_slab_list", true);
}

/*
 * Thread-safe wrapper for the primitive slab allocator.
 */
struct ThreadSafeSlab {
	struct List head;
	struct Slab *slab;
	SpinLock lock;
};

static void ts_slab_list_append(struct ThreadSafeSlab *ts_slab)
{
	thread_safe_statlist_append(&thread_safe_slab_list, &ts_slab->head);
}

static void ts_slab_list_remove(struct ThreadSafeSlab *ts_slab)
{
	thread_safe_statlist_remove(&thread_safe_slab_list, &ts_slab->head);
}

static void init_thread_safe_slab_and_store_in_list(struct ThreadSafeSlab *ts_slab, const char *name, unsigned obj_size,
						    unsigned align, slab_init_fn init_func,
						    CxMem *cx)
{
	init_slab(ts_slab->slab, name, obj_size, align, init_func, cx);
	ts_slab_list_append(ts_slab);
}

/* create a new thread-safe slab allocator */
struct ThreadSafeSlab *thread_safe_slab_create(const char *name, unsigned obj_size, unsigned align,
					       slab_init_fn init_func, CxMem *cx, bool enable_recursive_lock)
{
	struct ThreadSafeSlab *ts_slab;

	ts_slab = cx ? cx_alloc0(cx, sizeof(*ts_slab)) : calloc(1, sizeof(*ts_slab));
	if (!ts_slab)
		return NULL;

	ts_slab->slab = cx_alloc0(cx, sizeof(*(ts_slab->slab)));

	if (!ts_slab->slab) {
		free(ts_slab);
		return NULL;
	}

	list_init(&ts_slab->head);
	init_thread_safe_slab_and_store_in_list(ts_slab, name, obj_size, align, init_func, cx);
	spin_lock_init(&ts_slab->lock, enable_recursive_lock);
	return ts_slab;
}

/* free all storage associated by thread-safe slab */
void thread_safe_slab_destroy(struct ThreadSafeSlab *ts_slab)
{
	if (!ts_slab)
		return;

	ts_slab_list_remove(ts_slab);
	slab_destroy_internal(ts_slab->slab);
	free(ts_slab);
}

/* allocate one object from the slab */
void *thread_safe_slab_alloc(struct ThreadSafeSlab *ts_slab)
{
	void *obj;
	spin_lock_acquire(&ts_slab->lock);
	obj = slab_alloc(ts_slab->slab);
	spin_lock_release(&ts_slab->lock);
	return obj;
}

/* return object back to the slab */
void thread_safe_slab_free(struct ThreadSafeSlab *ts_slab, void *obj)
{
	spin_lock_acquire(&ts_slab->lock);
	slab_free(ts_slab->slab, obj);
	spin_lock_release(&ts_slab->lock);
}

/* get total number of objects allocated (capacity), including free and in-use */
int thread_safe_slab_total_count(struct ThreadSafeSlab *ts_slab)
{
	int count;
	spin_lock_acquire(&ts_slab->lock);
	count = slab_total_count(ts_slab->slab);
	spin_lock_release(&ts_slab->lock);
	return count;
}

/* get number of free objects in the slab */
int thread_safe_slab_free_count(struct ThreadSafeSlab *ts_slab)
{
	int count;
	spin_lock_acquire(&ts_slab->lock);
	count = slab_free_count(ts_slab->slab);
	spin_lock_release(&ts_slab->lock);
	return count;
}

/* get number of currently active (in-use) objects */
int thread_safe_slab_active_count(struct ThreadSafeSlab *ts_slab)
{
	int count;
	spin_lock_acquire(&ts_slab->lock);
	count = slab_active_count(ts_slab->slab);
	spin_lock_release(&ts_slab->lock);
	return count;
}

/* report stats for all slabs (global, not per instance) */
void thread_safe_slab_stats(slab_stat_fn cb_func, void *cb_arg)
{
	struct ThreadSafeSlab *ts_slab;
	struct List *item;
	const char *name;
	size_t final_size;
	unsigned free, total_count;

	spin_lock_acquire(&thread_safe_slab_list.lock);
	statlist_for_each(item, &thread_safe_slab_list.list) {
		ts_slab = container_of(item, struct ThreadSafeSlab, head);
		spin_lock_acquire(&ts_slab->lock);
		name = ts_slab->slab->name;
		final_size = ts_slab->slab->final_size;
		free = statlist_count(&ts_slab->slab->freelist);
		total_count = ts_slab->slab->total_count;
		spin_lock_release(&ts_slab->lock);

		cb_func(cb_arg, name, final_size, free, total_count);
	}
	spin_lock_release(&thread_safe_slab_list.lock);
}
