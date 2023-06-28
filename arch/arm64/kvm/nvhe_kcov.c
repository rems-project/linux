/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Thibaut Pérami <thibautp@google.com>
 */

#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/kcov.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_asm.h>

void init_hyp_kcov_layout(){
	hyp_kimage_voffset = kimage_voffset;
	hyp_kimage_vaddr = kimage_vaddr;
}

int kvm_kcov_hyp_init_tracing_buffer(void *mem, uint size)
{
	int nr_page;
	int ret;
	u64 idx;

	/* The current implementation of Hyp kcov does not work for the normal
	 * NVHE (un protected) code. This is because:
	 * - In unprotected mode, the EL2 vectors are disabled when no VM is active,
	 * - The buffer sharing in the following code is done assume EL2 manages its
	 *   own page tables, a different code path need to be implemented for the
	 *   unprotected case.
	 */
	if (!is_protected_kvm_enabled())
		return -ENOSYS;

	if (WARN_ON(!is_vmalloc_addr(mem)))
		return -EINVAL;

	if (!IS_ALIGNED((u64)mem, PAGE_SIZE))
		return -EINVAL;

	if (!IS_ALIGNED(size, PTRS_PER_PTE))
		return -EINVAL;

	ret = kvm_call_hyp_nvhe(__pkvm_kcov_init_buffer, size);
	if (ret < 0)
		return ret;

	idx = ret;

	nr_page = size / PTRS_PER_PTE;

	for (uint i = 0; i < nr_page; ++i) {
		u64 pfn = vmalloc_to_pfn(mem + i * PAGE_SIZE);
		ret = kvm_call_hyp_nvhe(__pkvm_kcov_buffer_add_page, idx, pfn);
		if (ret){
			WARN_ON(kvm_kcov_hyp_teardown_tracing_buffer(idx));
			return ret;
		}
	}
	return idx;
}

int kvm_kcov_hyp_teardown_tracing_buffer(int buffer_index)
{
	int ret;

	if (WARN_ON(!is_protected_kvm_enabled()))
		return -ENOSYS;

	do {
		ret = kvm_call_hyp_nvhe(__pkvm_kcov_teardown_buffer, buffer_index);
	} while (ret == -EAGAIN);
	return ret;
}

int kvm_kcov_hyp_enable_tracing(int buffer_index)
{
	if (WARN_ON(!is_protected_kvm_enabled()))
		return -ENOSYS;

	return kvm_call_hyp_nvhe(__pkvm_kcov_enable, buffer_index);
}

int kvm_kcov_hyp_disable_tracing(void)
{
	if (WARN_ON(!is_protected_kvm_enabled()))
		return -ENOSYS;

	return kvm_call_hyp_nvhe(__pkvm_kcov_disable);
}
