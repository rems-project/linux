#include <nvhe/pkvm.h>
#include <nvhe/cn/cn_alloc.h>
#include <asm-generic/bug.h>
#include <linux/align.h>

/*
 * The allocator keeps an array of free lists, each one containing blocks with
 * capacity of successive powers of 2.
 *
 * If a request can not be satisfied from the corresponding list `i`, take a
 * chunk from the smallest non-empty list `j > i`, and split it into two to
 * populate `j - 1`; repeat until `i` is non-empty.
 *
 * Freed memory is *not* merged.
 *
 * Smallest list contains chunks with size 2^CN_ALLOC_MIN_ORDER, largest with
 * size 2^CN_ALLOC_MAX_ORDER.
 */

/*
 * Each chunk starts with the header; allocation reqs return a pointer just
 * past the header.
 */
typedef union hdr {
	union hdr *nxt;   /* When in free list: the next chunk in the list. */
	union hdr **src;  /* When leased out: the source list. */
} hdr;

#define HDR_SIZE ALIGN(sizeof(hdr), MAX_ALIGN_T_ALIGN)
#define SLOTS (CN_ALLOC_MAX_ORDER - CN_ALLOC_MIN_ORDER + 1)

/*
 * Pool is an array of free lists.
 */
typedef struct pool {
	hdr *mem[SLOTS];
	int cap; /* Total memory managed by the pool. */
	int initialised;
} pool;

static inline unsigned int log2(size_t s) {
	unsigned long r;
	unsigned long shift;
	r     = (s > 0xFFFFFFFF) << 8; s >>= r;
	shift = (s > 0xFFFF    ) << 4; s >>= shift; r |= shift;
	shift = (s > 0xFF      ) << 3; s >>= shift; r |= shift;
	shift = (s > 0xF       ) << 2; s >>= shift; r |= shift;
	shift = (s > 0x3       ) << 1; s >>= shift; r |= shift;
	return r | (s >> 1);
}

static inline size_t pow_2_ceil(size_t s) {
	s--;
	s |= s >> 1;
	s |= s >> 2;
	s |= s >> 4;
	s |= s >> 8;
	s |= s >> 16;
	s |= s >> 32;
	return s + 1;
}

static inline unsigned bin(size_t s) {
	unsigned ord = log2(s);
	return ord < CN_ALLOC_MIN_ORDER ? 0 : ord - CN_ALLOC_MIN_ORDER;
}

static int add_region(pool *pool, void *buf, size_t s) {
	unsigned slot;
	if (s < (1 << CN_ALLOC_MIN_ORDER) || s > (1 << CN_ALLOC_MAX_ORDER))
		return -1;
	if (buf != PTR_ALIGN(buf, MAX_ALIGN_T_ALIGN))
		return -1;
	slot = bin(s);
	((hdr *)buf)->nxt = pool->mem[slot];
	pool->mem[slot] = buf;
	pool->cap += s;
	return 0;
}

static void *__g_malloc(pool *pool, size_t s) {
	unsigned slot, i;
	hdr *nd1, *nd2;

	slot = i = bin(pow_2_ceil(s + HDR_SIZE));
	while (i < SLOTS && !pool->mem[i])
		i++;
	if (i >= SLOTS)
		return NULL;

	for (; slot < i; --i) {
		nd1 = pool->mem[i];
		pool->mem[i] = nd1->nxt;
		nd2 = ((void *)nd1) + (1 << (i + CN_ALLOC_MIN_ORDER - 1));
		nd2->nxt = pool->mem[i - 1];
		nd1->nxt = nd2;
		pool->mem[i - 1] = nd1;
	}

	nd1 = pool->mem[slot];
	pool->mem[slot] = nd1->nxt;
	nd1->src = &(pool->mem[slot]);
	return ((void *)nd1) + HDR_SIZE;
}

static void __g_free(void *p) {
	hdr *nd = p - HDR_SIZE;
	hdr **flist = nd->src;
	nd->nxt = *flist;
	*flist = nd;
}

/** Debug **/

/*
 * Heap is a single static pool, managing a single static chunk with size
 * 2^CN_ALLOC_MAX_ORDER.
 */

#define HEAP (1 << CN_ALLOC_MAX_ORDER)

static unsigned char reserved_for_heap[HEAP] __attribute__((aligned(16)));
static pool heap;

/** Public **/

static DEFINE_HYP_SPINLOCK(lock);

void *g_malloc(size_t size) {
	void *p;
	hyp_spin_lock(&lock);
	if (!READ_ONCE(heap.initialised)) {
		BUG_ON(add_region(&heap, reserved_for_heap, HEAP) != 0);
		WRITE_ONCE(heap.initialised, 1);
	}
	p = __g_malloc(&heap, size);
	hyp_spin_unlock(&lock);
	return p;
}

void g_free(void *p) {
	if (!p)
		return;
	hyp_spin_lock(&lock);
	__g_free(p);
	hyp_spin_unlock(&lock);
}

void *g_malloc_or_die(size_t size) {
	void *p = g_malloc(size);
	BUG_ON(!p);
	return p;
}

void *g_calloc(size_t n, size_t size) {
	size_t total = n * size;
	void *res = g_malloc(total);
	if (res)
		memset(res, 0, total);
	return res;
}

void *g_calloc_or_die(size_t n, size_t size) {
	void *p = g_calloc(n, size);
	BUG_ON(!p);
	return p;
}

void *g_aligned_alloc(size_t alignment, size_t size) {
	BUG_ON(alignment > MAX_ALIGN_T_ALIGN);
	return g_malloc(size);
}

void *g_aligned_alloc_or_die(size_t alignment, size_t size) {
	void *p = g_aligned_alloc(alignment, size);
	BUG_ON(!p);
	return p;
}
