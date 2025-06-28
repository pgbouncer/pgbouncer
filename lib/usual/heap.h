/*
 * Binary Heap.
 *
 * Copyright (c) 2009  Marko Kreen, Skype Technologies OÜ
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

/** @file
 * Binary heap.
 *
 * Binary heap is sort of binary tree held inside array,
 * with following 2 properties:
 * - heap property: each node is "better" than it's childs.
 * - shape property: binary tree is complete, meaning all levels
 *   except the last one are fully filled.
 *
 * Instead of "min"- or "max"-heap, this is "best"-heap,
 * as it operates with user-defined heap_is_better() functions,
 * which is used to bubble elements on top.
 */

#ifndef _USUAL_HEAP_H_
#define _USUAL_HEAP_H_

#include <usual/cxalloc.h>

/**
 * Object comparision function.
 *
 * Should return true if a needs to reach top before b,
 * false if not or equal.
 */
typedef bool (*heap_is_better_f)(const void *a, const void *b);

/**
 * Heap position storage.
 *
 * If user wants to delete elements from the middle of heap,
 * this function should be used to keep track where the element
 * is located.
 */
typedef void (*heap_save_pos_f)(void *a, unsigned pos);

/**
 * Heap object.
 */
struct Heap;


/**
 * Create new heap object.
 *
 * @param is_better_cb  Callback to decide priority.
 * @param save_pos_cb   Callback to store current index.
 * @param cx            Allocation context.
 */
struct Heap *heap_create(
	heap_is_better_f is_better_cb,
	heap_save_pos_f save_pos_cb,
	CxMem *cx);

/** Release memory allocated by heap */
void heap_destroy(struct Heap *h);

/** Put new object into heap */
bool heap_push(struct Heap *h, void *ptr);

/** Remove and return topmost object from heap */
void *heap_pop(struct Heap *h);

/** Return topmost object in heap */
void *heap_top(struct Heap *h);

/** Remove and return any object from heap by index */
void *heap_remove(struct Heap *h, unsigned pos);

/**
 * Reserve room for more elements.
 *
 * Returns false if allocation failed.
 */
bool heap_reserve(struct Heap *h, unsigned extra);


/** Return number of objects in heap */
unsigned heap_size(struct Heap *h);

/* Return object by index, for testing */
void *heap_get_obj(struct Heap *h, unsigned pos);

#endif
