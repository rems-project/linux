#ifndef __KVM_NVHE_CN_ALLOC_H__
#define __KVM_NVHE_CN_ALLOC_H__

#include <linux/types.h>

#define CN_ALLOC_MAX_ORDER CONFIG_NVHE_CN_MEM_LOG2
#define CN_ALLOC_MIN_ORDER 5  // 32 B
#define MAX_ALIGN_T_ALIGN 16  // XXX PICK THIS UP FROM SOMEWHERE

void *g_malloc(size_t size);
void g_free(void *p);
void *g_calloc(size_t n, size_t size);
void *g_aligned_alloc(size_t alignment, size_t size);
void *g_malloc_or_die(size_t size);
void *g_calloc_or_die(size_t n, size_t size);
void *g_aligned_alloc_or_die(size_t alignment, size_t size);

static inline void *malloc(size_t s) { return g_malloc_or_die(s); }
static inline void free(void *p) { g_free(p); }
static inline void *calloc(size_t n, size_t s) { return g_calloc_or_die(n, s); }
static inline void *aligned_alloc(size_t a, size_t s) { return g_aligned_alloc_or_die(a, s); }

#endif
