/*
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
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
 * Extra allocators for cxalloc.
 */

#ifndef _USUAL_CXEXTRA_H_
#define _USUAL_CXEXTRA_H_

#include <usual/cxalloc.h>

/** Allocator that exits on error.  .ctx should be pointer to actual allocator */
extern const struct CxOps cx_nofail_ops;
/** nofail for libc */
extern CxMem cx_libc_nofail;

/**
 * Creates allocator that pools all memory together,
 * without keeping track of single objects, to be
 * freed all together in one shot.
 *
 * realloc(), free() are partially supported for the last
 * objec only.
 */
CxMem *cx_new_pool(CxMem *parent, size_t initial_size, unsigned int align);

CxMem *cx_new_pool_from_area(CxMem *parent, void *buf, size_t size, bool allow_free, unsigned int align);

/**
 * Creates allocator that remebers all allocations done
 * under it and allows all of it to be freed together.
 *
 * Supports hierarchical trees.
 */
CxMem *cx_new_tree(CxMem *parent);

#endif
