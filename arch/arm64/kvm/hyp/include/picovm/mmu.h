/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	include/asm/kvm_mmu.h
 *	include/asm/pgtable.h
 */

#ifndef __PICOVM_MMU_H__
#define __PICOVM_MMU_H__

#include <picovm/prelude.h>
#include <picovm/host.h>

/*
 * The picovm/cache.S implements these methods.
 *
 * Start addresses are inclusive and end addresses are exclusive; start
 * addresses should be rounded down, end addresses up.
 */
extern void dcache_clean_inval_poc(unsigned long start, unsigned long end);

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
	
	u64 cnp = VTTBR_CNP_BIT;

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
	isb();
}

#endif /* __PICOVM_MMU_H__ */
