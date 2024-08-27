#ifndef __PICOVM_PRELUDE_H
#define __PICOVM_PRELUDE_H

typedef signed long long s64;
typedef unsigned long long u64;
// typedef signed int s32;
typedef unsigned int u32;
typedef unsigned short u16;
// _Static_assert(sizeof(s64) == 8, "sizeof(s64) must be 8 bytes");
// _Static_assert(sizeof(u64) == 8, "sizeof(u64) must be 8 bytes");
// _Static_assert(sizeof(u32) == 4, "sizeof(u32) must be 4 bytes");
// _Static_assert(sizeof(u16) == 2, "sizeof(u16) must be 2 bytes");

#define U64(x)		(x ## ull)

#define BIT(nr)		(1UL << (nr))


typedef u64 phys_addr_t;
typedef u64 size_t;

typedef _Bool bool;


#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define BITS 64
#define BITMASK(h, l) \
    (((~0UL) << (l)) & (~0UL >> (BITS - 1 - (h))))

/* TODO(license) from: linux/include/uapi/linux/const.h */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

/* TODO(license) from: linux/include/linux/align.h */
/* SPDX-License-Identifier: GPL-2.0 */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))


static inline void picovm_assert(u64 x)
{
	// TODO
}


#endif /* __PICOVM_PRELUDE_H */
