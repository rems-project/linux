/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm64/include/asm/tlbflush.h
 *
 * Copyright (C) 1999-2003 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __PICOVM_ASM_TLBFLUSH_H
#define __PICOVM_ASM_TLBFLUSH_H
#ifdef CONFIG_PICOVM_STANDALONE

#ifndef __ASSEMBLY__
#include <picovm/linux/const.h>

// TODO(doc) for simplicity, K has removed the workaround
// repeat TLBI alternative
#define __TLBI_0(op, arg) asm (ARM64_ASM_PREAMBLE		\
			"tlbi " #op "\n"			\
			: : )

#define __TLBI_1(op, arg) asm (ARM64_ASM_PREAMBLE		\
			 "tlbi " #op ", %0\n"			\
			: : "r" (arg))

#define __TLBI_N(op, arg, n, ...) __TLBI_##n(op, arg)

#define __tlbi(op, ...)		__TLBI_N(op, ##__VA_ARGS__, 1, 0)


/* This macro creates a properly formatted VA operand for the TLBI */
#define __TLBI_VADDR(addr, asid)				\
	({							\
		unsigned long __ta = (addr) >> 12;		\
		__ta &= GENMASK_ULL(43, 0);			\
		__ta |= (unsigned long)(asid) << 48;		\
		__ta;						\
	})


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
#define TLBI_TTL_MASK		GENMASK_ULL(47, 44)

#if 0
#define __tlbi_level(op, addr, level) do {				\
	u64 arg = addr;							\
									\
	if (cpus_have_const_cap(ARM64_HAS_ARMv8_4_TTL) &&		\
	    level) {							\
		u64 ttl = level & 3;					\
		ttl |= get_trans_granule() << 2;			\
		arg &= ~TLBI_TTL_MASK;					\
		arg |= FIELD_PREP(TLBI_TTL_MASK, ttl);			\
	}								\
									\
	__tlbi(op, arg);						\
} while(0)
#else
// TODO(K): I have removed the level-based tlbi because this requires alternative()
#define __tlbi_level(op, addr, level)	__tlbi(op, addr)
#endif

#endif

#else
#include <asm/tlbflush.h>
#endif /* CONFIG_PICOVM_STANDALONE */
#endif /* __PICOVM_ASM_TLBFLUSH_H */
