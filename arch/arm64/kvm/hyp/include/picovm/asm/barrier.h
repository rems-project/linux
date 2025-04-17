/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm64/include/asm/barrier.h
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __PICOVM_ASM_BARRIER_H
#define __PICOVM_ASM_BARRIER_H
#ifdef CONFIG_PICOVM_STANDALONE

#ifndef __ASSEMBLY__

#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define isb()		isb()
#define dmb(opt)	dmb(#opt)
#define dsb(opt)	dsb(#opt)
#else
#define isb()		asm volatile("isb" : : : "memory")
#define dmb(opt)	asm volatile("dmb " #opt : : : "memory")
#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")
#endif


#define __smp_mb()	dmb(ish)

#ifndef __smp_store_release
#define __smp_store_release(p, v)					\
do {									\
	compiletime_assert_atomic_type(*p);				\
	__smp_mb();							\
	WRITE_ONCE(*p, v);						\
} while (0)
#endif

#ifndef smp_store_release
#define smp_store_release(p, v) do { __smp_store_release(p, v); } while (0)
#endif

#endif	/* __ASSEMBLY__ */

#else
#include <asm/barrier.h>
#endif /* CONFIG_PICOVM_STANDALONE */
#endif	/* __PICOVM_ASM_BARRIER_H */
