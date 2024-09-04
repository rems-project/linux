/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Partial copy of arch/arm64/include/asm/barrier.h
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __PICOVM_LINUX_BARRIER_H
#define __PICOVM_LINUX_BARRIER_H

#include <picovm/prelude.h>

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


#endif /* __PICOVM_LINUX_BARRIER_H */
