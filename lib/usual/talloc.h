/*
 * talloc - implementation of Talloc API.
 *
 * Copyright (c) 2013 Marko Kreen
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * @file
 *
 * Talloc - hierarchical memory allocator.
 *
 * This is reimplementation of Samba's talloc: https://talloc.samba.org/
 *
 * Features:
 * - Any allocated object can be parent to new objects.
 * - Any object can have more then one parent.
 * - References.
 * - Change parent.
 * - Built on top of <usual/cxalloc.h> API.
 *
 * Missing features:
 * - Pools.  Use <usual/cxextra.h> pools instead.
 *
 * It mostly compatible with original so that Samba's documentation is usable,
 * but it does not try to be bug-for-bug compatible.
 */

#ifndef _USUAL_TALLOC_H_
#define _USUAL_TALLOC_H_

#include <usual/base.h>

/* avoid cxalloc.h include */
struct CxMem;

/**
 * Type for untyped pointers that are usable as talloc parent.
 *
 * For situations where (void*) needs to be used.  There
 * it might be used to use TALLOC_CTX to document that
 * talloc pointer is needed.
 */
typedef void TALLOC_CTX;

/**
 * Destructor signature.
 *
 * If it returns -1, talloc_free() cancels its operation
 * and also returns -1.
 *
 * @param ptr		Object to be freed.
 * @returns 		0 on success, -1 otherwise.
 */
typedef int (*talloc_destructor_f)(void *ptr);

/**
 * Give name to "unnamed" allocations.
 *
 * By default it generates name that contains
 * talloc API function name, source file and line number.
 *
 * It can be redefined in user source files.
 */
#ifndef TALLOC_POS
#define TALLOC_POS(apifunc)     apifunc "@" __FILE__ ":" STR(__LINE__)
#endif

/**
 * Free and set pointer to NULL.
 */
#define TALLOC_FREE(ptr) do { talloc_free(ptr); (ptr) = NULL; } while (0)

/*
 * Internal functions used in macros.
 */

void *_talloc_const_name(const void *parent, size_t elem_size, size_t count,
			 bool zero_fill, const char *name) _MALLOC;
void *_talloc_format_name(const void *parent, size_t elem_size, size_t count,
			  bool zero_fill, const char *fmt, ...) _PRINTF(5, 6) _MALLOC;
int _talloc_unlink(const void *parent, const void *ptr, const char *source_pos);
int _talloc_free(const void *ptr, const char *source_pos);
void _talloc_free_children(const void *ptr, const char *source_pos);
void *_talloc_realloc(const void *parent, void *ptr, size_t elem_size, size_t count, const char *name);
void *_talloc_get_type_abort(const void *ptr, const char *name);
void *_talloc_move(const void *new_parent, void **ptr_p);
void *_talloc_reference_named(const void *new_parent, const void *ptr, const char *name);

/**
 * @name Allocate object and give name based on C type.
 *
 * Object names are set automatically based on C type.
 *
 * @{
 */

/**
 * Allocate memory for C type.
 *
 * Returned object will have memory for sizeof(type) bytes.
 *
 * @param parent	Parent context or NULL.
 * @param #type		C type of object.
 * @returns		New object or NULL on error.
 */
#ifdef DOXYGEN
type *talloc(const void *parent, #type);
#else
#define talloc(parent, type) \
	(type *)_talloc_const_name(parent, sizeof(type), 1, false, #type)
#endif

/**
 * Allocate zero-filled memory for C type.
 *
 * Returned object will have memory for sizeof(type) bytes.
 *
 * @param parent	Parent context or NULL.
 * @param #type		C type of object.
 * @returns		New object or NULL on error.
 */
#ifdef DOXYGEN
type *talloc_zero(const void *parent, #type);
#else
#define talloc_zero(parent, type) \
	(type *)_talloc_const_name(parent, sizeof(type), 1, true, #type)
#endif

/**
 * Allocate array of elements of type given.
 *
 * size = count * sizeof(type);
 *
 * @param parent	Parent context or NULL.
 * @param type		C type.
 * @param count		Number of elements.
 * @returns		New context or NULL on error.
 */
#ifdef DOXYGEN
type *talloc_array(const void *parent, #type, size_t count);
#else
#define talloc_array(parent, type, count) \
	(type *)_talloc_const_name(parent, sizeof(type), count, false, #type)
#endif

/**
 * Allocate zero-filled array of elements of type.
 *
 * size = count * sizeof(type);
 *
 * @param parent	Parent context or NULL.
 * @param type		C type.
 * @param count		Number of elements.
 * @returns		New context or NULL on error.
 */
#ifdef DOXYGEN
type *talloc_zero_array(const void *parent, #type, size_t count);
#else
#define talloc_zero_array(parent, type, count) \
	(type *)_talloc_const_name(parent, sizeof(type), count, true, #type)
#endif

/**
 * @}
 *
 * @name Allocate object and give custom name.
 *
 * @{
 */

/**
 * Allocate named object.
 *
 * Name pointer is used directly, so it should not change.
 *
 * @param parent	Parent context or NULL.
 * @param size		Length in bytes.
 * @param name		Pointer to static string, will be used directly.
 * @returns		New context or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_named_const(const void *parent, size_t size, const char *name);
#else
#define talloc_named_const(parent, size, name) \
	_talloc_const_name(parent, size, 1, false, name)
#endif

/**
 * Allocate zero-filled memory for named object.
 *
 * Name pointer is used directly, so it should not change.
 *
 * @param parent	Parent context or NULL.
 * @param size		Length in bytes.
 * @param name		Pointer to static string, will be used directly.
 * @returns		New context or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_zero_named_const(const void *parent, size_t size, const char *name);
#else
#define talloc_zero_named_const(parent, size, name) \
	_talloc_const_name(parent, size, 1, true, name)
#endif

/**
 * Allocate named context.
 *
 * Name is formatted via talloc_vasprintf() and allocated
 * as child of main object.
 *
 * @param parent	Parent context or NULL.
 * @param size		Size for allocation.
 * @param fmt		printf format for name.
 * @returns		New context or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_named(const void *parent, size_t size, const char *fmt, ...);
#else
#define talloc_named(parent, size, ...) \
	_talloc_format_name(parent, size, 1, false, __VA_ARGS__)
#endif

/**
 * Allocate new top-level named context.
 *
 * Name will be allocaten inside context.
 *
 * @param fmt	Format string for sprintf.
 * @returns	New context or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_init(const char *fmt, ...);
#else
#define talloc_init(...) \
	_talloc_format_name(NULL, 0, 0, false, __VA_ARGS__)
#endif

/**
 * @}
 *
 * @name Allocate unnamed context.
 *
 * The objects will get name based on calling location.
 *
 * @{
 */

/**
 * Allocate unnamed context.
 *
 * @param parent	Parent context or NULL.
 * @param size		Size for allocation.
 * @returns		New pointer or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_size(const void *parent, size_t size);
#else
#define talloc_size(parent, size) \
	_talloc_const_name(parent, size, 1, false, TALLOC_POS("talloc_size"))
#endif

/**
 * Allocate unnamed context with zeroed memory.
 *
 * @param parent	Parent context or NULL.
 * @param size		Size for allocation.
 * @returns		New pointer or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_zero_size(const void *parent, size_t size);
#else
#define talloc_zero_size(parent, size) \
	_talloc_const_name(parent, size, 1, true, TALLOC_POS("talloc_zero_size"))
#endif

/**
 * Allocate array of elements of type.
 *
 * @param parent	Parent context or NULL.
 * @param size		Size for one element.
 * @param count		Number of elements.
 * @returns		New pointer or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_array_size(const void *parent, size_t size, size_t count);
#else
#define talloc_array_size(parent, size, count) \
	_talloc_const_name(parent, size, count, false, TALLOC_POS("talloc_array_size"))
#endif

/**
 * Allocate unnamed context from typed pointer.
 *
 * sizeof(*(ptr)) will be used as allocation size.
 *
 * @param parent	Parent context or NULL.
 * @param ptr		Typed pointer
 * @returns		New context or NULL on error.
 */
#ifdef DOXYGEN
type *talloc_ptrtype(const void *parent, type *ptr);
#else
#define talloc_ptrtype(parent, ptr) \
	(__typeof__(ptr))_talloc_const_name(parent, sizeof(*(ptr)), 1, \
					    false, TALLOC_POS("talloc_ptrtype"))
#endif

/**
 * Allocate array of elements of type taken from pointer.
 *
 * size = count * sizeof(*ptr);
 *
 * @param parent	Parent context or NULL.
 * @param ptr		Typed pointer.
 * @param count		Number of elements.
 * @returns		New context or NULL on error.
 */
#ifdef DOXYGEN
type *talloc_array_ptrtype(const void *parent, type *ptr, size_t count);
#else
#define talloc_array_ptrtype(parent, ptr, count) \
	(typeof(ptr))_talloc_const_name(parent, sizeof(*(ptr)), count, \
					false, TALLOC_POS("talloc_array_ptrtype"))
#endif

/**
 * Allocate unnamed context as child of parent.
 *
 * @param parent	Parent context or NULL
 * @returns		New pointer or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_new(const void *parent);
#else
#define talloc_new(parent) \
	_talloc_const_name(parent, 0, 0, false, TALLOC_POS("talloc_new"))
#endif

/**
 * @}
 *
 * @name Special contexts.
 *
 * Contexts that have unusual behaviour.
 *
 * @{
 */

/**
 * Allocate context that will be freed on program exit.
 *
 * Objects allocated under this context will be freed
 * via atexit() handler, unless freed earlier.
 * This is useful to see leaked memory on program exit.
 *
 * @returns		New context or NULL on error.
 */
void *talloc_autofree_context(void);

/**
 * Allocate memory from CxMem.
 *
 * Returned pointer and all it's children will be allocated from CxMem;
 *
 * Name pointer is used directly, so it should not change.
 *
 * @param cx		CxMem context to allocate from.
 * @param size		Length in bytes.
 * @param name		Pointer to static string, will be used directly.
 * @returns		New context or NULL on error.
 */
void *talloc_from_cx(const struct CxMem *cx, size_t size, const char *name);

/**
 * Create CxMem context that uses talloc.
 *
 * This makes CxMem-based code work with talloc.
 *
 * @param parent	Parent context or NULL.
 * @param name		Pointer to static string, will be used directly.
 * @returns		New CxMem context or NULL on error.
 */
const struct CxMem *talloc_as_cx(const void *parent, const char *name);

/**
 * @}
 *
 * @name Free memory.
 *
 * @{
 */

/**
 * Set function to be called on final free.
 */
void talloc_set_destructor(const void *ptr, talloc_destructor_f destructor);
#ifndef DOXYGEN
#define talloc_set_destructor(ptr, dfn) \
	do {    int (*_dfn)(__typeof__(ptr)) = (dfn); \
		talloc_set_destructor(ptr, (talloc_destructor_f)(_dfn)); \
	} while (0)
#endif

/**
 * Free allocated context and all it's children.
 *
 * This can be called only on context that have one parent.
 * Use talloc_unlink() if object may have many references.
 *
 * @param ptr		Pointer to previously allocated area.
 * @returns 		0 on success, -1 on error.
 */
#ifdef DOXYGEN
int talloc_free(const void *ptr);
#else
#define talloc_free(ptr) \
	_talloc_free(ptr, TALLOC_POS("talloc_free"))
#endif

/**
 * @}
 *
 * @name Reallocate existing context.
 *
 * Only context that have only one reference can be reallocated.
 *
 * @{
 */

/**
 * Reallocate array.
 *
 * @param parent	Parent context or NULL.
 * @param ptr		Pointer to be reallocated.
 * @param #type		C type of one element.
 * @param count		Number of elements.
 * @returns		Reallocated context or NULL on error.
 */
#ifdef DOXYGEN
type *talloc_realloc(const void *parent, const void *ptr, #type, size_t count);
#else
#define talloc_realloc(parent, ptr, type, count) \
	(type *)_talloc_realloc(parent, ptr, sizeof(type), count, #type)
#endif

/**
 * Reallocate untyped context.
 *
 * @param parent	Parent context or NULL.
 * @param ptr		Pointer to be reallocated.
 * @param size		New length in bytes.
 * @returns		Reallocated context or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_realloc_size(const void *parent, void *ptr, size_t size);
#else
#define talloc_realloc_size(parent, ptr, size) \
	_talloc_realloc(parent, ptr, size, 1, TALLOC_POS("talloc_realloc_size"))
#endif

/**
 * Function version of realloc.
 *
 * This is guaranteed to not be macro,
 * unlike other API calls.
 *
 * @param parent	Parent context or NULL.
 * @param ptr		Pointer to be reallocated.
 * @param size		New length in bytes.
 * @returns		Reallocated context or NULL on error.
 */
void *talloc_realloc_fn(const void *parent, void *ptr, size_t size);

/**
 * @}
 *
 * @name Custom object name.
 *
 * @{
 */

/**
 * Return object name.
 *
 * Result will be always non-NULL.
 */
const char *talloc_get_name(const void *ptr);

/**
 * Set formatted name.
 *
 * Format and allocate as child of ptr.
 *
 * @param ptr		Pointer to be named.
 * @param fmt		Format string.
 * @returns		New name or NULL on error.
 */
#ifdef DOXYGEN
const char *talloc_set_name(const void *ptr, const char *fmt, ...);
#else
const char *talloc_set_name(const void *ptr, const char *fmt, ...) _PRINTF(2, 3);
#endif

/**
 * Set name pointer directly.
 *
 * @param ptr		Pointer to be named.
 * @param name		Pointer to string.
 */
void talloc_set_name_const(const void *ptr, const char *name);

/**
 * Return same pointer only if name matches, NULL otherwise.
 */
void *talloc_check_name(const void *ptr, const char *name);

/**
 * @}
 *
 * @name Type-based names.
 *
 * @{
 */

/**
 * Set context name from type.
 *
 * @param ptr		Pointer to be named.
 * @param #type		C type.
 */
#ifdef DOXYGEN
void talloc_set_type(const void *ptr, #type);
#else
#define talloc_set_type(ptr, type) \
	talloc_set_name_const(ptr, #type)
#endif

/**
 * Get typed pointer only if name matches.
 *
 * @param ptr		Pointer to be checked.
 * @param #type		C type.
 */
#ifdef DOXYGEN
type *talloc_get_type(const void *ptr, #type);
#else
#define talloc_get_type(ptr, type) \
	(type *)talloc_check_name(ptr, #type)
#endif

/**
 * Get typed pointed only if name matches, aborting otherwise.
 *
 * This is more extreme version of talloc_get_type().
 *
 * @param ptr		Pointer to be checked.
 * @param #type		C type.
 */
#ifdef DOXYGEN
type *talloc_get_type_abort(const void *ptr, #type);
#else
#define talloc_get_type_abort(ptr, type) \
	(type *)_talloc_get_type_abort(ptr, #type)
#endif

/**
 * @}
 *
 * @name Allocated area size.
 *
 * @{
 */

/** Get length of allocated area. */
size_t talloc_get_size(const void *ptr);

/**
 * Get number of elements in array.
 */
#ifdef DOXYGEN
size_t talloc_array_length(const type *array);
#else
#define talloc_array_length(array) (talloc_get_size(array) / sizeof(*(array)))
#endif

/**
 * @}
 *
 * @name Object parent.
 *
 * @{
 */

/** Get parent object. */
void *talloc_parent(const void *ptr);

/** Get parent object's name. */
const char *talloc_parent_name(const void *ptr);

/** Find direct parent based on name */
void *talloc_find_parent_byname(const void *ptr, const char *name);

/** Find direct parent based on type */
#ifdef DOXYGEN
type *talloc_find_parent_bytype(const void *ptr, #type);
#else
#define talloc_find_parent_bytype(ptr, type) \
	(type *)talloc_find_parent_byname(ptr, #type)
#endif

/**
 * @}
 *
 * @name Reference handling
 *
 * Talloc operates on references, not reference counts.
 *
 * @{
 */

/**
 * Create another reference from parent to child.
 *
 * @param new_parent	New parent context or NULL.
 * @param ptr		Target pointer that is referenced.
 * @returns		Original pointer or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_reference(const void *new_parent, const void *ptr);
#else
#define talloc_reference(new_parent, ptr) \
	(__typeof__(ptr))_talloc_reference_named(new_parent, ptr, TALLOC_POS("talloc_reference"))
#endif

/**
 * Create another reference from NULL context to child.
 *
 * @param ptr		Target pointer that is referenced.
 * @returns		0 on success, -1 on error.
 */
#ifdef DOXYGEN
int talloc_increase_ref_count(const void *ptr);
#else
#define talloc_increase_ref_count(ptr) \
	(_talloc_reference_named(NULL, ptr, \
				 TALLOC_POS("talloc_increase_ref_count")) ? 0 : -1)
#endif

/**
 * Remove parent's reference to child.
 *
 * If parent is found, unlinks and returns 0, otherwise -1.
 *
 * When removing last reference, the object is freed.
 *
 * @param parent	Parent context or NULL.
 * @param ptr		Pointer to be unlinked.
 * @returns		0 on success, -1 on error.
 */
#ifdef DOXYGEN
int talloc_unlink(const void *parent, const void *ptr);
#else
#define talloc_unlink(parent, ptr) \
	_talloc_unlink(parent, ptr, TALLOC_POS("talloc_unlink"))
#endif

/**
 * Return number of references context has.
 */
size_t talloc_reference_count(const void *ptr);

/**
 * @}
 *
 * @name Change parent
 *
 * @{
 */

/**
 * Find reference from old parent switch it to new parent.
 */
void *talloc_reparent(const void *old_parent, const void *new_parent, const void *ptr);

/**
 * Change primary parent, set old pointer to NULL.
 *
 * Useful when moving ponters between structs.
 *
 * Cannot be used on pointers that have multiple parents.
 *
 * @param new_parent	New parent.
 * @param ptr_p		Location of pointer, will be set to NULL if successful.
 * @returns		Original pointer or NULL on error.
 */
#ifdef DOXYGEN
void *talloc_move(const void *new_parent, void **ptr_p);
#else
#define talloc_move(new_parent, ptr_p) \
	(typeof(*(ptr_p)))_talloc_move(new_parent, (void **)(ptr_p))
#endif

/**
 * Change primary parent.
 *
 * Cannot be used on pointers that have multiple parents.
 *
 * @param new_parent	New parent.
 * @param ptr		Pointer to be moved.
 * @returns		Original pointer or NULL on error.
 */
void *talloc_steal(const void *new_parent, const void *ptr);

/**
 * @}
 *
 * @name String functions.
 *
 * @{
 */

/** Copy memory */
#ifdef DOXYGEN
void *talloc_memdup(const void *parent, const void *p, size_t len);
#else
void *talloc_memdup(const void *parent, const void *p, size_t len) _MALLOC;
#endif

/** Copy string */
#ifdef DOXYGEN
char *talloc_strdup(const void *parent, const char *s);
#else
char *talloc_strdup(const void *parent, const char *s) _MALLOC;
#endif

/** Copy string with size limit */
#ifdef DOXYGEN
char *talloc_strndup(const void *parent, const char *s, size_t maxlen);
#else
char *talloc_strndup(const void *parent, const char *s, size_t maxlen) _MALLOC;
#endif

/** Format string */
#ifdef DOXYGEN
char *talloc_asprintf(const void *parent, const char *fmt, ...);
#else
char *talloc_asprintf(const void *parent, const char *fmt, ...) _PRINTF(2, 3) _MALLOC;
#endif

/** Format string taking argument from va_list */
#ifdef DOXYGEN
char *talloc_vasprintf(const void *parent, const char *fmt, va_list ap);
#else
char *talloc_vasprintf(const void *parent, const char *fmt, va_list ap) _PRINTF(2, 0) _MALLOC;
#endif

/**
 * @}
 *
 * @name String append functions.
 *
 * The *_append() functions use strnlen() to get size of string in buffer.
 *
 * @{
 */

/** Append string to existing string */
char *talloc_strdup_append(char *ptr, const char *s);

/** Append string with limit to existing string */
char *talloc_strndup_append(char *ptr, const char *s, size_t maxlen);

/** Append formatted string to existing string */
#ifdef DOXYGEN
char *talloc_asprintf_append(char *ptr, const char *fmt, ...);
#else
char *talloc_asprintf_append(char *ptr, const char *fmt, ...) _PRINTF(2, 3);
#endif

/** Append formatted string to existing string */
#ifdef DOXYGEN
char *talloc_vasprintf_append(char *ptr, const char *fmt, va_list ap);
#else
char *talloc_vasprintf_append(char *ptr, const char *fmt, va_list ap) _PRINTF(2, 0);
#endif

/**
 * @}
 *
 * @name String append to complete buffer.
 *
 * The *_append_buffer() functions assume talloc_get_size() will
 * give the string length with final NUL byte.
 *
 * @{
 */

/** Append string to existing buffer */
char *talloc_strdup_append_buffer(char *ptr, const char *str);

/** Append string with limit to existing buffer */
char *talloc_strndup_append_buffer(char *ptr, const char *str, size_t maxlen);

/** Append formatted string to existing buffer */
#ifdef DOXYGEN
char *talloc_asprintf_append_buffer(char *ptr, const char *fmt, ...);
#else
char *talloc_asprintf_append_buffer(char *ptr, const char *fmt, ...) _PRINTF(2, 3);
#endif

/** Append formatted string to existing buffer */
#ifdef DOXYGEN
char *talloc_vasprintf_append_buffer(char *ptr, const char *fmt, va_list ap);
#else
char *talloc_vasprintf_append_buffer(char *ptr, const char *fmt, va_list ap) _PRINTF(2, 0);
#endif

/**
 * @}
 *
 * @name Debugging
 *
 * @{
 */

/**
 * Set log function.
 */
void talloc_set_log_fn(void (*log_fn)(const char *message));

/**
 * Restore default function.
 */
void talloc_set_log_stderr(void);

/**
 * Set function to be called on abort.
 */
void talloc_set_abort_fn(void (*abort_fn)(const char *reason));

/** Collect all parent==NULL allocations under one context */
void talloc_enable_null_tracking(void);

/** Collect all parent==NULL allocations under one context, but not autofree */
void talloc_enable_null_tracking_no_autofree(void);

/** Stop collecting all parent==NULL allocations under one context */
void talloc_disable_null_tracking(void);

/** On program exit, run talloc_report(NULL, stderr) */
void talloc_enable_leak_report(void);

/** On program exit, run talloc_report_full(NULL, stderr) */
void talloc_enable_leak_report_full(void);

/**
 * Return allocated bytes under context.
 */
size_t talloc_total_size(const void *ptr);

/**
 * Return number of contexts under context.
 */
size_t talloc_total_blocks(const void *ptr);

/**
 * Walk parents
 */
bool talloc_is_parent(const void *parent, const void *ptr);


/** Print report about context and it's immediate childs */
void talloc_report(const void *ptr, FILE *f);
/** Print report about context and it's all childs */
void talloc_report_full(const void *ptr, FILE *f);
/** Print full report about context, with customizable depth */
void talloc_report_depth_file(const void *ptr, int depth, int max_depth, FILE *f);
/** Run callback on context and it's children */
void talloc_report_depth_cb(const void *ptr, int depth, int max_depth,
			    void (*callback)(const void *ptr, int depth, int max_depth,
					     int is_ref, void *private_data),
			    void *private_data);
/** Print parents to file */
void talloc_show_parents(const void *ptr, FILE *file);

/**
 * Activate memory limit for object.
 *
 * The limit affects only new children allocated after setting it.
 * It does not take account object itself and it's current children.
 *
 * @param ptr		Targer pointer.
 * @param max_size	Limit in bytes.
 * @returns 		0 on success, -1 otherwise.
 */
int talloc_set_memlimit(const void *ptr, size_t max_size);

/** @} */

/* deprecated */
#define talloc_free_children(ptr) _talloc_free_children(ptr, TALLOC_POS("talloc_free_children"))

/* custom */
void talloc_set_debug(int level);

#endif
