#ifndef __PICOVM_PRELUDE_H
#define __PICOVM_PRELUDE_H

#include <picovm/asm/emulate.h>
#include <picovm/asm/errno-base.h>

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
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)

/* TODO(license) from: linux/include/linux/align.h */
/* SPDX-License-Identifier: GPL-2.0 */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)

static inline void picovm_assert(u64 x)
{
	// TOODO
}

// NOTE: from include/asm/sections.h
extern char __hyp_idmap_text_start[], __hyp_idmap_text_end[];
extern char __hyp_text_start[], __hyp_text_end[];
extern char __hyp_rodata_start[], __hyp_rodata_end[];
extern char __hyp_reloc_begin[], __hyp_reloc_end[];
extern char __hyp_bss_start[], __hyp_bss_end[];
extern char __idmap_text_start[], __idmap_text_end[];

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

/*
 * Raw TLBI operations.
 *
 * Where necessary, use the __tlbi() macro to avoid asm()
 * boilerplate. Drivers and most kernel code should use the TLB
 * management routines in preference to the macro below.
 *
 * The macro can be used as __tlbi(op) or __tlbi(op, arg), depending
 * on whether a particular TLBI operation takes an argument or
 * not. The macros handles invoking the asm with or without the
 * register argument as appropriate.
 */
// TODO: hardcoding in __TLBI_0 and __TLBI_1 the ARM64_WORKAROUND_REPEAT_TLBI
// patch to avoid depending on alternative in picovm
#define __TLBI_0(op, arg) asm (ARM64_ASM_PREAMBLE			       \
			       "tlbi " #op "\n"				       \
			       "dsb ish\n				       \
			       tlbi " #op	 			       \
			    : : )

#define __TLBI_1(op, arg) asm (ARM64_ASM_PREAMBLE			       \
			       "tlbi " #op ", %0\n"			       \
			       "dsb ish\n				       \
			       tlbi " #op ", %0"			       \
			    : : "r" (arg))

#define __TLBI_N(op, arg, n, ...) __TLBI_##n(op, arg)

#define __tlbi(op, ...)		__TLBI_N(op, ##__VA_ARGS__, 1, 0)
#define __tlbi_level(op, addr, level) do {				\
	u64 arg = addr;							\
	__tlbi(op, arg);						\
} while(0)

// NOTE: from include/asm-generic/barrier.h
#define dsb(option) __asm__ volatile("dsb " #option : : : "memory")

#define isb()		asm volatile("isb" : : : "memory")
#define dmb(opt)	asm volatile("dmb " #opt : : : "memory")
#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")


#define __smp_mb()	dmb(ish)

// TODO(note): this copy removes the call to kasan_check_write() and changes
// the occurences of types __uN to uN from picovm/prelude.h
#define __smp_store_release(p, v)					\
do {									\
	typeof(p) __p = (p);						\
	union { __unqual_scalar_typeof(*p) __val; char __c[1]; } __u =	\
		{ .__val = (__force __unqual_scalar_typeof(*p)) (v) };	\
	compiletime_assert_atomic_type(*p);				\
	switch (sizeof(*p)) {						\
	case 1:								\
		asm volatile ("stlrb %w1, %0"				\
				: "=Q" (*__p)				\
				: "rZ" (*(u8 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 2:								\
		asm volatile ("stlrh %w1, %0"				\
				: "=Q" (*__p)				\
				: "rZ" (*(u16 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 4:								\
		asm volatile ("stlr %w1, %0"				\
				: "=Q" (*__p)				\
				: "rZ" (*(u32 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 8:								\
		asm volatile ("stlr %x1, %0"				\
				: "=Q" (*__p)				\
				: "rZ" (*(u64 *)__u.__c)		\
				: "memory");				\
		break;							\
	}								\
} while (0)

#ifndef smp_store_release
#define smp_store_release(p, v) do { __smp_store_release(p, v); } while (0)
#endif


#endif /* __PICOVM_PRELUDE_H */
