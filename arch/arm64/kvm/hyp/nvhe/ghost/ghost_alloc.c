#include <nvhe/pkvm.h>
#include <nvhe/ghost/ghost_alloc.h>
#include <asm-generic/bug.h>

#ifdef CONFIG_NVHE_GHOST_MEM_DUMP_STATS
#include <nvhe/ghost/ghost_printer.h>
#endif /* CONFIG_NVHE_GHOST_MEM_DUMP_STATS */

static u64 kind_malloc_counter[ALLOC_KIND_NR];
static u64 kind_free_counter[ALLOC_KIND_NR];

#ifdef CONFIG_NVHE_GHOST_MEM_DUMP_STATS
static const char* kind_str[ALLOC_KIND_NR] = {
	[ALLOC_LOCAL_STATE]= "ALLOC_LOCAL_STATE",
	[ALLOC_VCPU]= "ALLOC_VCPU",
	[ALLOC_VM]= "ALLOC_VM",
	[ALLOC_KVM_CPU_CONTEXT]= "ALLOC_KVM_CPU_CONTEXT"
	[ALLOC_CASEMATE] = "ALLOC_CASEMATE",
};
#endif

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
 * Smallest list contains chunks with size 2^GHOST_ALLOC_MIN_ORDER, largest with
 * size 2^GHOST_ALLOC_MAX_ORDER.
 */

/*
 * Each chunk starts with the header; allocation reqs return a pointer just
 * past the header.
 */
typedef union hdr {
	union hdr *nxt;   /* When in free list: the next chunk in the list. */
	union hdr **src;  /* When leased out: the source list. */
} hdr;

#define SLOTS (GHOST_ALLOC_MAX_ORDER - GHOST_ALLOC_MIN_ORDER + 1)

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
	return ord < GHOST_ALLOC_MIN_ORDER ? 0 : ord - GHOST_ALLOC_MIN_ORDER;
}

static int add_region(pool *pool, void *buf, size_t s) {
	unsigned slot;
	if (s < (1 << GHOST_ALLOC_MIN_ORDER) || s > (1 << GHOST_ALLOC_MAX_ORDER))
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

	slot = i = bin(pow_2_ceil(s + sizeof(hdr)));
	while (i < SLOTS && !pool->mem[i])
		i++;
	if (i >= SLOTS)
		return NULL;

	for (; slot < i; --i) {
		nd1 = pool->mem[i];
		pool->mem[i] = nd1->nxt;
		nd2 = ((void *)nd1) + (1 << (i + GHOST_ALLOC_MIN_ORDER - 1));
		nd2->nxt = pool->mem[i - 1];
		nd1->nxt = nd2;
		pool->mem[i - 1] = nd1;
	}

	nd1 = pool->mem[slot];
	pool->mem[slot] = nd1->nxt;
	nd1->src = &(pool->mem[slot]);
	return ((void *)nd1) + sizeof(hdr);
}

static void __g_free(void *p) {
	hdr *nd = p - sizeof(hdr);
	hdr **flist = nd->src;
	nd->nxt = *flist;
	*flist = nd;
}

/** Debug **/

#ifdef CONFIG_NVHE_GHOST_MEM_DUMP_STATS

struct ghost_alloc_bkt_n { int order; int buffers; };

static void __g_malloc_stats(pool *pool, struct ghost_alloc_bkt_n *arr, size_t n) {
        int i = 0;
        while (i < SLOTS && i < n) {
          hdr *h = pool->mem[i];
	  arr[i] = (struct ghost_alloc_bkt_n) { .order = i + GHOST_ALLOC_MIN_ORDER, .buffers = 0 };
          while(h) {
            h = h->nxt;
	    arr[i].buffers++;
          }
          ++i;
        }
        while (i < n)
		arr[i] = (struct ghost_alloc_bkt_n) { .order = -1, .buffers = -1 };
}

void __g_malloc_dump_stats(enum alloc_kind kind, pool *pool) {
	struct ghost_alloc_bkt_n stats[SLOTS];
	__g_malloc_stats(pool, stats, SLOTS);
	ghost_printf("(malloc %s):\t", kind_str[kind]);
	for (int i = 0; i < SLOTS; i++) {
		if (i % 4 == 0)
			ghost_printf("[%d] ", 2 << stats[i].order);
		ghost_printf("%d, ", stats[i].buffers);
	}
	ghost_printf("\n");
	ghost_printf("(kinds):\n");
	for (int i=0; i<ALLOC_KIND_NR; i++) {
		long d = kind_malloc_counter[i] - kind_free_counter[i];
		ghost_printf("  [%s] malloc: %lu -- free: %lu [delta: %ld]\n", kind_str[i], kind_malloc_counter[i], kind_free_counter[i], d);
	}
}

#endif /* CONFIG_NVHE_GHOST_MEM_DUMP_STATS */

/*
 * Heap is a single static pool, managing a single static chunk with size
 * 2^GHOST_ALLOC_MAX_ORDER.
 */

#define HEAP (1 << GHOST_ALLOC_MAX_ORDER)

static unsigned char reserved_for_heap[HEAP];
static pool heap;

/** Public **/

static DEFINE_HYP_SPINLOCK(lock);

void *g_malloc(enum alloc_kind kind, size_t size) {
	void *p;
	hyp_spin_lock(&lock);
	if (!READ_ONCE(heap.initialised)) {
		add_region(&heap, reserved_for_heap, HEAP);
		WRITE_ONCE(heap.initialised, 1);
	}
	kind_malloc_counter[kind]++;
#ifdef CONFIG_NVHE_GHOST_MEM_DUMP_STATS
	__g_malloc_dump_stats(kind, &heap);
#endif /* CONFIG_NVHE_GHOST_MEM_DUMP_STATS */
	p = __g_malloc(&heap, size);
	hyp_spin_unlock(&lock);
	return p;
}

void g_free(enum alloc_kind kind, void *p) {
	if (!p)
		return;
	hyp_spin_lock(&lock);
	__g_free(p);
	kind_free_counter[kind]++;
	hyp_spin_unlock(&lock);
}

void *malloc_or_die(enum alloc_kind kind, size_t s) {
	void *p = g_malloc(kind, s);
	BUG_ON(!p);
	return p;
}
