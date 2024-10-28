/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Partial copy from include/asm/kvm_mmu.h
 */

#ifndef __PICOVM_MMU_H__
#define __PICOVM_MMU_H__

#include <asm/page.h>
#include <asm/memory.h>
#include <asm/mmu.h>
#include <asm/cpufeature.h>

#include <picovm/picovm_arm.h>
#include <picovm/picovm_host.h>

/*
 * NOTE: from include/asm/cacheflush.h
 *	MM Cache Management
 *	===================
 *
 *	The arch/arm64/mm/cache.S implements these methods.
 *
 *	Start addresses are inclusive and end addresses are exclusive; start
 *	addresses should be rounded down, end addresses up.
 */
extern void dcache_clean_inval_poc(unsigned long start, unsigned long end);


// NOTE: from include/asm/pgtable.h
#define phys_to_ttbr(addr)	(addr)
#define picovm_phys_to_vttbr(addr)		phys_to_ttbr(addr)

#define picovm_flush_dcache_to_poc(a,l)	\
	dcache_clean_inval_poc((unsigned long)(a), (unsigned long)(a)+(l))

/*
 * When this is (directly or indirectly) used on the TLB invalidation
 * path, we rely on a previously issued DSB so that page table updates
 * and VMID reads are correctly ordered.
 */
static __always_inline u64 picovm_get_vttbr(struct picovm_s2_mmu *mmu) {
	struct picovm_vmid *vmid = &mmu->vmid;
	u64 vmid_field, baddr;
	u64 cnp = system_supports_cnp() ? VTTBR_CNP_BIT : 0;

	baddr = mmu->pgd_phys;
	vmid_field = atomic64_read(&vmid->id) << VTTBR_VMID_SHIFT;
	vmid_field &= VTTBR_VMID_MASK(picovm_arm_vmid_bits);
	return picovm_phys_to_vttbr(baddr) | vmid_field | cnp;
}

/*
 * Must be called from hyp code running at EL2 with an updated VTTBR
 * and interrupts disabled.
 */
static __always_inline void __load_stage2(struct picovm_s2_mmu *mmu,
					  struct picovm_arch *arch)
{
	write_sysreg(arch->vtcr, vtcr_el2);
	write_sysreg(picovm_get_vttbr(mmu), vttbr_el2);
	/*
	 * ARM errata 1165522 and 1530923 require the actual execution of the
	 * above before we can switch to the EL1/EL0 translation regime used by
	 * the guest.
	 */
	asm(ALTERNATIVE("nop", "isb", ARM64_WORKAROUND_SPECULATIVE_AT));
}

#endif /* __PICOVM_MMU_H__ */
