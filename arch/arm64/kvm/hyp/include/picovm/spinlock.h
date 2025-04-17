/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	arch/arm64/kvm/hyp/include/nvhe/spinlock.h
 */

#ifndef __PICOVM_SPINLOCK_H
#define __PICOVM_SPINLOCK_H

#include <picovm/linux/types.h>

typedef union hyp_spinlock {
	u32	__val;
	struct {
#ifdef __AARCH64EB__
		u16 next, owner;
#else
		u16 owner, next;
#endif
	};
} hyp_spinlock_t;

#define __HYP_SPIN_LOCK_INITIALIZER \
	{ .__val = 0 }

#define __HYP_SPIN_LOCK_UNLOCKED \
	((hyp_spinlock_t) __HYP_SPIN_LOCK_INITIALIZER)

#define DEFINE_HYP_SPINLOCK(x)	hyp_spinlock_t x = __HYP_SPIN_LOCK_UNLOCKED

#define hyp_spin_lock_init(l)						\
do {									\
	*(l) = __HYP_SPIN_LOCK_UNLOCKED;				\
} while (0)

#ifdef CONFIG_PICOVM_CLIGHTPLUS
extern inline void hyp_spin_lock(hyp_spinlock_t *lock);
#else
static inline void hyp_spin_lock(hyp_spinlock_t *lock)
{
#ifdef CONFIG_NVHE_GHOST_SPEC
	u64 tmp;
#else /* CONFIG_NVHE_GHOST_SPEC */
	u32 tmp;
#endif /* CONFIG_NVHE_GHOST_SPEC */
	hyp_spinlock_t lockval, newval;

	asm volatile(
	/* Atomically increment the next ticket. */
"	prfm	pstl1strm, %3\n"
"1:	ldaxr	%w0, %3\n"
"	add	%w1, %w0, #(1 << 16)\n"
"	stxr	%w2, %w1, %3\n"
"	cbnz	%w2, 1b\n"
	/* Did we get the lock? */
"	eor	%w1, %w0, %w0, ror #16\n"
"	cbz	%w1, 3f\n"
	/*
	 * No: spin on the owner. Send a local event to avoid missing an
	 * unlock before the exclusive load.
	 */
"	sevl\n"
"2:	wfe\n"
"	ldaxrh	%w2, %4\n"
"	eor	%w1, %w2, %w0, lsr #16\n"
"	cbnz	%w1, 2b\n"
	/* We got the lock. Critical section starts here. */
"3:"
	: "=&r" (lockval), "=&r" (newval), "=&r" (tmp), "+Q" (*lock)
	: "Q" (lock->owner)
	: "memory");
}
#endif

#ifdef CONFIG_PICOVM_CLIGHTPLUS
extern inline void hyp_spin_unlock(hyp_spinlock_t *lock);
#else
static inline void hyp_spin_unlock(hyp_spinlock_t *lock)
{
	u64 tmp;

	asm volatile(
	"	ldrh	%w1, %0\n"
	"	add	%w1, %w1, #1\n"
	"	stlrh	%w1, %0"
	: "=Q" (lock->owner), "=&r" (tmp)
	:
	: "memory");
}
#endif

#endif /* __PICOVM_SPINLOCK_H */
