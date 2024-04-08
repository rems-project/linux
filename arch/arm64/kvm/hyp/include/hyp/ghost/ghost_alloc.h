#ifndef __KVM_NVHE_GHOST_ALLOC_H__
#define __KVM_NVHE_GHOST_ALLOC_H__

#include <linux/types.h>

#define GHOST_ALLOC_MAX_ORDER CONFIG_NVHE_GHOST_MEM_LOG2
#define GHOST_ALLOC_MIN_ORDER 5  // 32 B

void *g_malloc(size_t size);
void g_free(void *p);

#define malloc(s) g_malloc(s)
#define free(p) g_free(p)

void *malloc_or_die(size_t s);

#endif
