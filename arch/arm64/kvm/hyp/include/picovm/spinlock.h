/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * A stand-alone ticket spinlock implementation for use by the non-VHE
 * KVM hypervisor code running at EL2.
 *
 * Copyright (C) 2020 Google LLC
 * Author: Will Deacon <will@kernel.org>
 *
 * Heavily based on the implementation removed by c11090474d70 which was:
 * Copyright (C) 2012 ARM Ltd.
 */

#ifndef __PICOVM_SPINLOCK_H
#define __PICOVM_SPINLOCK_H
#include <picovm/prelude.h>

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



#ifdef CONFIG_NVHE_EL2_DEBUG
static inline void hyp_assert_lock_held(hyp_spinlock_t *lock)
{
	/*
	 * The __pkvm_init() path accesses protected data-structures without
	 * holding locks as the other CPUs are guaranteed to not enter EL2
	 * concurrently at this point in time. The point by which EL2 is
	 * initialized on all CPUs is reflected in the pkvm static key, so
	 * wait until it is set before checking the lock state.
	 */
	// TODO
	// if (static_branch_likely(&kvm_protected_mode_initialized))
	// 	BUG_ON(!hyp_spin_is_locked(lock));
}
#else
static inline void hyp_assert_lock_held(hyp_spinlock_t *lock) { }
#endif

#endif /* __PICOVM_SPINLOCK_H */