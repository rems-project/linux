#ifndef __PICOVM_PRELUDE_H
#define __PICOVM_PRELUDE_H

typedef signed long long s64;
typedef unsigned long long u64;
// typedef signed int s32;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
// _Static_assert(sizeof(s64) == 8, "sizeof(s64) must be 8 bytes");
// _Static_assert(sizeof(u64) == 8, "sizeof(u64) must be 8 bytes");
// _Static_assert(sizeof(u32) == 4, "sizeof(u32) must be 4 bytes");
// _Static_assert(sizeof(u16) == 2, "sizeof(u16) must be 2 bytes");

#define U64(x)		(x ## ull)

#define BIT(nr)		(1UL << (nr))


typedef u64 phys_addr_t;
typedef u64 size_t;

typedef _Bool bool;
#define true	1
#define false	0

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// TODO: add argument checks (h > l)
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



#endif /* __PICOVM_PRELUDE_H */
