#ifndef __KVM_NVHE_GHOST_ALLOC_H__
#define __KVM_NVHE_GHOST_ALLOC_H__

#include <linux/types.h>

// XXX Kconfig for MAX_ORDER.
#define GHOST_ALLOC_MAX_ORDER 22 // 4 MB
#define GHOST_ALLOC_MIN_ORDER 5  // 32 B

void *g_malloc(size_t size);
void g_free(void *p);

#define malloc(s) g_malloc(s)
#define free(p) g_free(p)

#endif
