/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Partial copy of arch/arm64/include/asm/tlbflush.h
 *
 * Copyright (C) 1999-2003 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __PICOVM_LINUX_TLBFLUSH_H
#define __PICOVM_LINUX_TLBFLUSH_H

#include<picovm/prelude.h>


// TODO(license): copied from arch/arm64/include/asm/compiler.h
#ifdef ARM64_ASM_ARCH
#define ARM64_ASM_PREAMBLE ".arch " ARM64_ASM_ARCH "\n"
#else
#define ARM64_ASM_PREAMBLE
#endif


// static __always_inline bool cpus_have_const_cap(int num)
// {
// 	// TODO: see which values of num this is called on
// 	// this is hardcoding the cpu capability
// 	return false;
// }

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


/*
 * Level-based TLBI operations.
 *
 * When ARMv8.4-TTL exists, TLBI operations take an additional hint for
 * the level at which the invalidation must take place. If the level is
 * wrong, no invalidation may take place. In the case where the level
 * cannot be easily determined, a 0 value for the level parameter will
 * perform a non-hinted invalidation.
 *
 * For Stage-2 invalidation, use the level values provided to that effect
 * in asm/stage2_pgtable.h.
 */
// TODO: commenting out the ARMv8.4-TTL stuff for now
#define TLBI_TTL_MASK		GENMASK_ULL(47, 44)

// #define __tlbi_level(op, addr, level) do {				\
// 	u64 arg = addr;							\
// 									\
// 	if (cpus_have_const_cap(ARM64_HAS_ARMv8_4_TTL) &&		\
// 	    level) {							\
// 		u64 ttl = level & 3;					\
// 		ttl |= get_trans_granule() << 2;			\
// 		arg &= ~TLBI_TTL_MASK;					\
// 		arg |= FIELD_PREP(TLBI_TTL_MASK, ttl);			\
// 	}								\
// 									\
// 	__tlbi(op, arg);						\
// } while(0)
#define __tlbi_level(op, addr, level) do {				\
	u64 arg = addr;							\
	__tlbi(op, arg);						\
} while(0)


#endif /* __PICOVM_LINUX_TLBFLUSH_H */
