#ifndef _USUAL_THREAD_SAFE_STATLIST_H_
#define _USUAL_THREAD_SAFE_STATLIST_H_

#include <usual/statlist.h>
#include <usual/pthread.h>
#include <usual/logging.h>

/**
 * Header structure for ThreadSafeStatList.
 * This wraps StatList with a pthread mutex for thread safety.
 */
struct ThreadSafeStatList {
	struct StatList list;
	Mutex lock;
};

/** Initialize ThreadSafeStatList head */
static inline void thread_safe_statlist_init(struct ThreadSafeStatList *list, const char *name, bool enable_recursive_lock)
{
	int res;
	statlist_init(&list->list, name);
	res = mutex_init(&list->lock, enable_recursive_lock);
	if (res != 0)
		fatal("pthread_mutex_init failed: %d", res);
}

/** Add to the start of the list */
static inline void thread_safe_statlist_prepend(struct ThreadSafeStatList *list, struct List *item)
{
	mutex_lock(&list->lock);
	statlist_prepend(&list->list, item);
	mutex_unlock(&list->lock);
}

/** Add to the end of the list */
static inline void thread_safe_statlist_append(struct ThreadSafeStatList *list, struct List *item)
{
	mutex_lock(&list->lock);
	statlist_append(&list->list, item);
	mutex_unlock(&list->lock);
}

/** Remove element from the list */
static inline void thread_safe_statlist_remove(struct ThreadSafeStatList *list, struct List *item)
{
	mutex_lock(&list->lock);
	statlist_remove(&list->list, item);
	mutex_unlock(&list->lock);
}

/** Remove and return first element */
static inline struct List *thread_safe_statlist_pop(struct ThreadSafeStatList *list)
{
	struct List *item;
	mutex_lock(&list->lock);
	item = statlist_pop(&list->list);
	mutex_unlock(&list->lock);
	return item;
}

/** Return first element */
static inline struct List *thread_safe_statlist_first(struct ThreadSafeStatList *list)
{
	struct List *item;
	mutex_lock(&list->lock);
	item = statlist_first(&list->list);
	mutex_unlock(&list->lock);
	return item;
}

/** Return last element */
static inline struct List *thread_safe_statlist_last(struct ThreadSafeStatList *list)
{
	struct List *item;
	mutex_lock(&list->lock);
	item = statlist_last(&list->list);
	mutex_unlock(&list->lock);
	return item;
}

/** Is list empty */
static inline bool thread_safe_statlist_empty(struct ThreadSafeStatList *list)
{
	bool empty;
	mutex_lock(&list->lock);
	empty = statlist_empty(&list->list);
	mutex_unlock(&list->lock);
	return empty;
}

/** Return number of elements currently in list */
static inline int thread_safe_statlist_count(struct ThreadSafeStatList *list)
{
	int count;
	mutex_lock(&list->lock);
	count = statlist_count(&list->list);
	mutex_unlock(&list->lock);
	return count;
}

/** Put item before another */
static inline void thread_safe_statlist_put_before(struct ThreadSafeStatList *list, struct List *item, struct List *pos)
{
	mutex_lock(&list->lock);
	statlist_put_before(&list->list, item, pos);
	mutex_unlock(&list->lock);
}

/** Put item after another */
static inline void thread_safe_statlist_put_after(struct ThreadSafeStatList *list, struct List *item, struct List *pos)
{
	mutex_lock(&list->lock);
	statlist_put_after(&list->list, item, pos);
	mutex_unlock(&list->lock);
}

#define THREAD_SAFE_STATLIST_EACH(list_ptr, item, BODY)                 \
	do {                                                                \
		struct List *tmp;                                               \
		mutex_lock(&(list_ptr)->lock);                          \
		statlist_for_each_safe(item, &(list_ptr)->list, tmp) {          \
			BODY                                                    \
		}                                                               \
		mutex_unlock(&(list_ptr)->lock);                        \
	} while (0)


#define THREAD_SAFE_STATLIST_REVERSE_EACH(list_ptr, item, BODY)         \
	do {                                                                \
		struct List *tmp;                                               \
		mutex_lock(&(list_ptr)->lock);                          \
		statlist_for_each_reverse_safe(item, &(list_ptr)->list, tmp) {  \
			BODY                                                    \
		}                                                               \
		mutex_unlock(&(list_ptr)->lock);                        \
	} while (0)

#endif /* _USUAL_THREAD_SAFE_STATLIST_H_ */
