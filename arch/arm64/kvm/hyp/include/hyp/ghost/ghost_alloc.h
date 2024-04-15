#ifndef __KVM_NVHE_GHOST_ALLOC_H__
#define __KVM_NVHE_GHOST_ALLOC_H__

#include <linux/types.h>

#define GHOST_ALLOC_MAX_ORDER CONFIG_NVHE_GHOST_MEM_LOG2
#define GHOST_ALLOC_MIN_ORDER 5  // 32 B

enum alloc_kind {
	ALLOC_LOCAL_STATE,
	ALLOC_VCPU,
	ALLOC_VM,
	ALLOC_KIND_NR // keep this last
};

void *g_malloc(enum alloc_kind kind, size_t size);
void g_free(enum alloc_kind kind, void *p);

#define malloc(k, s) g_malloc(k, s)
#define free(k, p) g_free(k, p)

void *malloc_or_die(enum alloc_kind kind, size_t s);

#endif
