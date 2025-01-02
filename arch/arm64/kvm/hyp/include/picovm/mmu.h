/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	include/asm/kvm_mmu.h
 *	include/asm/pgtable.h
 */

#ifndef __PICOVM_MMU_H__
#define __PICOVM_MMU_H__

#include <picovm/linux/types.h>
#include <picovm/asm/atomic.h>
#include <picovm/asm/barrier.h>

#include <picovm/sysregs.h>
#include <picovm/kvm_host.h>


/*
 * The picovm/cache.S implements these methods.
 *
 * Start addresses are inclusive and end addresses are exclusive; start
 * addresses should be rounded down, end addresses up.
 */
extern void dcache_clean_inval_poc(unsigned long start, unsigned long end);


#define picovm_flush_dcache_to_poc(a,l)	\
	dcache_clean_inval_poc((unsigned long)(a), (unsigned long)(a)+(l))


struct picovm_vmid {
	atomic64_t id;
};

struct picovm_s2_mmu {
	struct picovm_vmid vmid;
	phys_addr_t	pgd_phys;	
};


#ifdef CONFIG_ARM64_PA_BITS_52
#error "picovm does not support 52-bit PA"
#else
#define phys_to_ttbr(addr)		(addr)
#endif

/*
 * When this is (directly or indirectly) used on the TLB invalidation
 * path, we rely on a previously issued DSB so that page table updates
 * and VMID reads are correctly ordered.
 */
static __always_inline u64 picovm_get_vttbr(struct picovm_s2_mmu *mmu)
{
	struct picovm_vmid *vmid = &mmu->vmid;
	u64 vmid_field, baddr;
	
	// TODO(check): this assumes FEAT_TTCNP is implemented
	u64 cnp = VTTBR_CNP_BIT;

	baddr = mmu->pgd_phys;
	vmid_field = atomic64_read(&vmid->id) << VTTBR_VMID_SHIFT;
	vmid_field &= VTTBR_VMID_MASK(kvm_arm_vmid_bits);
	return phys_to_ttbr(baddr) | vmid_field | cnp;
}

/*
 * Must be called from hyp code running at EL2 with an updated VTTBR
 * and interrupts disabled.
 */
static __always_inline void __load_stage2(struct picovm_s2_mmu *mmu, u64 vtcr)
{
	write_sysreg(vtcr, vtcr_el2);
	write_sysreg(picovm_get_vttbr(mmu), vttbr_el2);
	isb();
}

#endif /* __PICOVM_MMU_H__ */
