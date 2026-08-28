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

#include "common/sortingperm.h"

/*
 * Local helper: swap adjacent elements if out of order.
 * Returns 1 if a swap was made, 0 otherwise.
 */
static int sortingperm_restore_local(int *x, int *perm, int *invperm, int pos)
{
	int i1 = perm[pos];
	int i2 = perm[pos + 1];

	if (x[i1] > x[i2]) {
		perm[pos] = i2;
		perm[pos + 1] = i1;
		if (invperm) {
			invperm[i1] = pos + 1;
			invperm[i2] = pos;
		}
		return 1;
	}
	return 0;
}

/*
 * Restore sort order after incrementing x[perm[pos]].
 * Bubbles the element up (towards higher indices) as needed.
 */
int sortingperm_restore_up(int *x, int *perm, int *invperm, int pos, int n)
{
	while (pos < n - 1 && sortingperm_restore_local(x, perm, invperm, pos))
		pos++;
	return pos;
}

/*
 * Restore sort order after decrementing x[perm[pos]].
 * Bubbles the element down (towards lower indices) as needed.
 */
int sortingperm_restore_down(int *x, int *perm, int *invperm, int pos, int n)
{
	(void)n;  /* unused, but kept for API symmetry */
	while (pos > 0 && sortingperm_restore_local(x, perm, invperm, pos - 1))
		pos--;
	return pos;
}
