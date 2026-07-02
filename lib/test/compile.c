#include <usual/aatree.h>
#include <usual/base.h>
#include <usual/cbtree.h>
#include <usual/cfparser.h>
#include <usual/hashing/crc32.h>
#include <usual/daemon.h>
#include <usual/endian.h>
#include <usual/err.h>
#include <usual/fileutil.h>
#include <usual/hashtab-impl.h>
#include <usual/heap.h>
#include <usual/list.h>
#include <usual/logging.h>
#include <usual/hashing/lookup3.h>
#include <usual/mbuf.h>
#include <usual/crypto/md5.h>
#include <usual/crypto/csrandom.h>
#include <usual/misc.h>
#include <usual/safeio.h>
#include <usual/spinlock.h>
#include <usual/statlist_ts.h>
#include <usual/shlist.h>
#include <usual/signal.h>
#include <usual/slab.h>
#include <usual/socket.h>
#include <usual/statlist.h>
#include <usual/string.h>
#include <usual/tls/tls.h>
#include <usual/time.h>
#include <usual/utf8.h>

static bool heap_is_better(const void *a, const void *b)
{
	return 1;
}

int main(void)
{
	struct AATree aatree;
	struct CBTree *cbtree;
	struct md5_ctx md5;
	struct Heap *heap;
	char buf[128];

	static_assert(sizeof(int) >= 4, "unsupported int size");

	heap = heap_create(heap_is_better, NULL, NULL);
	heap_top(heap);
	aatree_init(&aatree, NULL, NULL);
	cbtree = cbtree_create(NULL, NULL, NULL, NULL);
	cbtree_destroy(cbtree);
	daemonize(NULL, false);
	hash_lookup3("foo", 3);
	if (!parse_ini_file("foo", NULL, NULL))
		log_debug("test");
	log_stats("1");
	file_size("foo");
	md5_reset(&md5);
	strlcpy(buf, "foo", sizeof(buf));
	printf("xmalloc: %p\n", xmalloc(128));
	if (0) die("0");
	csrandom();
	tls_init();
	return 0;
}
