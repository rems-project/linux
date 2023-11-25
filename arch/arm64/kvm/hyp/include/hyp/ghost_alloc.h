#ifndef __KVM_NVHE_GHOST_ALLOC_H__
#define __KVM_NVHE_GHOST_ALLOC_H__

#include <linux/types.h>

#define GHOST_ALLOC_MAX_ORDER CONFIG_NVHE_GHOST_MEM_LOG2_MB
#define GHOST_ALLOC_MIN_ORDER 5  // 32 B

void *g_malloc(size_t size);
void g_free(void *p);

#define malloc(s) g_malloc(s)
#define free(p) g_free(p)

void *malloc_or_die(size_t s);

struct ghost_alloc_bkt_n {
	int order;
	int buffers;
};

void g_malloc_stats(struct ghost_alloc_bkt_n *arr, size_t n);

#endif
