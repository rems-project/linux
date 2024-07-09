#ifndef NVHE_GCOV_H
#define NVHE_GCOV_H NVHE_GCOV_H

#include <linux/types.h>
#include <linux/string.h>

/* GCOV structures largely stolen from gcov/clang.c, but
 * - those are not reusable; and
 * - these are less pointery.
 *
 * They are shared between EL2 and EL1.
 */

struct pkvm_gcov_fn_info {
	u32 ident;
	u32 checksum;
	u32 cfg_checksum;
	u32 num_counters;
	u64 *counters;
};

struct pkvm_gcov_info {
	const char *filename;
	unsigned int version;
	u32 checksum;
        u32 n_functions;
        struct pkvm_gcov_fn_info functions[];
};

/* EL2-only entry points. */
int pkvm_gcov_buffer_init(u64 pages);
int pkvm_gcov_buffer_add_page(u64 pfn);
int pkvm_gcov_export_module(unsigned int index);
int pkvm_gcov_reset(void);

/* Pointer relative addressing. */

static inline void *rel_pack_ptr(void **buf, const void *base, const void *p, size_t s)
{
	void *p1 = (void *) ((u64) *buf - (u64) base);
	memcpy(*buf, p, s);
	*buf += s;
	return p1;
}

static inline void *rel_unpack_ptr(const void *base, const void *p)
{
	return (void *) ((u64) p + (u64) base);
}

#endif /* NVHE_GCOV_H */
