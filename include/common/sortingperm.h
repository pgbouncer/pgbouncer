/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
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

/*
 * Sorting permutation utilities.
 *
 * Maintains a permutation array that keeps elements sorted by their values.
 * Used for efficiently tracking which host has the minimum active connections.
 */

#ifndef _PGBOUNCER_SORTINGPERM_H_
#define _PGBOUNCER_SORTINGPERM_H_

/*
 * Restore sort order after incrementing x[perm[pos]].
 * Bubbles the element up (towards higher indices) as needed.
 * Returns the final position of the element.
 */
int sortingperm_restore_up(int *x, int *perm, int *invperm, int pos, int n);

/*
 * Restore sort order after decrementing x[perm[pos]].
 * Bubbles the element down (towards lower indices) as needed.
 * Returns the final position of the element.
 */
int sortingperm_restore_down(int *x, int *perm, int *invperm, int pos, int n);

#endif
