#ifndef __PICOVM_PRELUDE_H
#define __PICOVM_PRELUDE_H

#include <picovm/asm/errno-base.h>
#include <picovm/asm/ptrace.h>
#include <picovm/asm/sections.h>

#include <picovm/linux/tlbflush.h>
#include <picovm/linux/memblock.h>
#include <picovm/linux/percpu-def.h>
#include <picovm/linux/types.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define BITS 64
#define BITS_PER_LONG 64
#define __GENMASK(h, l) \
  (((~0UL) << (l)) & (~0UL >> (BITS - 1 - (h))))

#define GENMASK(h, l) \
	(((l) > (h)) ? __GENMASK(l, h) : __GENMASK(h, l))

/* TODO(license) from: linux/include/uapi/linux/const.h */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

/* TODO(license) from: linux/include/linux/align.h */
/* SPDX-License-Identifier: GPL-2.0 */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)

static inline void picovm_assert(u64 x)
{
	// TODO
}

// TODO(license) copied from: include/linux/compiler_types.h
/* SPDX-License-Identifier: GPL-2.0 */
/* Is this type a native word size -- useful for atomic operations */
// #define __native_word(t) \
// 	(sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
// 	 sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
// #define compiletime_assert_atomic_type(t)				\
// 	_Static_assert(__native_word(t),				\
// 		"Need native word sized stores/loads for atomicity.")


// TODO(license) copied from: include/asm-generic/rwonce.h
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Yes, this permits 64-bit accesses on 32-bit architectures. These will
 * actually be atomic in some cases (namely Armv7 + LPAE), but for others we
 * rely on the access being split into 2x32-bit accesses for a 32-bit quantity
 * (e.g. a virtual address) and a strong prevailing wind.
 */
#define compiletime_assert_rwonce_type(t)					\
	_Static_assert(__native_word(t) || sizeof(t) == sizeof(long long),	\
		"Unsupported access size for {READ,WRITE}_ONCE().")

/*
 * Use __READ_ONCE() instead of READ_ONCE() if you do not require any
 * atomicity. Note that this may result in tears!
 */
#ifndef __READ_ONCE
#define __READ_ONCE(x)	(*(const volatile __unqual_scalar_typeof(x) *)&(x))
#endif

#define READ_ONCE(x)							\
({									\
	compiletime_assert_rwonce_type(x);				\
	__READ_ONCE(x);							\
})

#define __WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)

#define WRITE_ONCE(x, val)						\
do {									\
	compiletime_assert_rwonce_type(x);				\
	__WRITE_ONCE(x, val);						\
} while (0)

// Note: from linux/types.h
struct list_head {
	struct list_head *next, *prev;
};



#endif /* __PICOVM_PRELUDE_H */
