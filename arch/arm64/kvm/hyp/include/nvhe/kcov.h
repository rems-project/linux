/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Thibaut Pérami <thibautp@google.com>
 */

#ifndef __ARM64_KVM_NVHE_KCOV_H__
#define __ARM64_KVM_NVHE_KCOV_H__

#include <nvhe/pkvm.h>


#ifdef CONFIG_NVHE_KCOV

/** Initialize a kcov buffer and returns an index. Negative values for errors. */
u64 __pkvm_kcov_init_buffer(uint size);

/** Map the next page in a kcov buffer */
u64 __pkvm_kcov_buffer_add_page(u64 idx, u64 pfn);

/** Tear down a kcov buffer by index */
int __pkvm_kcov_teardown_buffer(u64 idx);

/** Enable tracing for the current user thread, on the buffer at that index */
int __pkvm_kcov_enable(u64 idx);

/** Disable tracing for the current user thread. One cannot disable tracing
 * enabled by another thread */
int __pkvm_kcov_disable(void);

/** Call it on each EL2 entry point from host that require tracing, e.g. not
 * asynchronous exceptions */
void pkvm_kcov_enter_from_host(void);

/** Call it on each EL2 exit to the host */
void pkvm_kcov_exit_to_host(void);

#else

static inline u64 __pkvm_kcov_init_buffer(uint){
	return -ENOSYS;
}
static inline u64 __pkvm_kcov_buffer_add_page(u64 idx, u64 pfn){
	return -ENOSYS;
}
static inline u64 __pkvm_kcov_teardown_buffer(u64)
{
	return -ENOSYS;
}
static inline u64 __pkvm_kcov_enable(u64)
{
	return -ENOSYS;
}
static inline u64 __pkvm_kcov_disable(void)
{
	return -ENOSYS;
}

static inline void pkvm_kcov_enter_from_host(void) {}
static inline void pkvm_kcov_exit_to_host(void) {}

#endif /* CONFIG_NVHE_KCOV */

#endif /* __ARM64_KVM_NVHE_KCOV_H__ */
