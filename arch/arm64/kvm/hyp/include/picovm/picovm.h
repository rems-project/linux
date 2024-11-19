/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	include/linux/arm-smccc.h
 *	include/asm/kvm_asm.h
 *	arch/arm64/include/asm/esr.h
 *	arch/arm64/include/asm/kvm_pkvm.h
 */

#ifndef __PICOVM_H
#define __PICOVM_H

#include <picovm/prelude.h>
#include <picovm/host.h>
#include <picovm/pgtable.h>
#include <picovm/spinlock.h>

/* Global state **************************************************************/
// s64 hyp_physvirt_offset;
//bool picovm_initialized;



// Fixing the page size to with pKVM uses (in the actual linux source)
// this is configurable at build time.
// #define PAGE_SHIFT	(12)
// #define PAGE_SIZE	(4096) // (U64(1) << PAGE_SHIFT)
// TODO: PAGE_MASK
// TODO: PAGE_ALIGN


/* SMCCC *********************************************************************/
// from: linux/include/linux/arm-smccc.h
#define ARM_SMCCC_FAST_CALL	        1U
#define ARM_SMCCC_TYPE_SHIFT		31

#define ARM_SMCCC_SMC_64		1
#define ARM_SMCCC_CALL_CONV_SHIFT	30

#define ARM_SMCCC_OWNER_MASK		0x3F
#define ARM_SMCCC_OWNER_SHIFT		24

#define ARM_SMCCC_FUNC_MASK		0xFFFF

#define ARM_SMCCC_CALL_VAL(type, calling_convention, owner, func_num) \
	(((type) << ARM_SMCCC_TYPE_SHIFT) | \
	((calling_convention) << ARM_SMCCC_CALL_CONV_SHIFT) | \
	(((owner) & ARM_SMCCC_OWNER_MASK) << ARM_SMCCC_OWNER_SHIFT) | \
	((func_num) & ARM_SMCCC_FUNC_MASK))

#define ARM_SMCCC_OWNER_VENDOR_HYP	6

#define SMCCC_RET_SUCCESS		0
#define SMCCC_RET_NOT_SUPPORTED		1


static inline u64 read_esr_el2(void)
{
	u64 reg;
	asm volatile("mrs %0, esr_el2": "=r" (reg));
	return reg;
}

#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))

// from linux/arch/arm64/include/asm/kvm_pkvm.h
/* Maximum number of VMs that can co-exist under pKVM. */
#define PICOVM_MAX_PVMS 255

#define HYP_MEMBLOCK_REGIONS 128

/*static inline void BUG(void)*/
/*{*/
/*	for(;;); // __builtin_unreachable();*/
/*};*/

// NOTE: from include/asm/kvm_asm.h
struct picovm_nvhe_init_params {
	unsigned long mair_el2;
	unsigned long tcr_el2;
	unsigned long tpidr_el2;
	unsigned long stack_hyp_va;
	unsigned long stack_pa;
	phys_addr_t pgd_pa;
	unsigned long hcr_el2;
	unsigned long vttbr;
	unsigned long vtcr;
};

/*
 * Holds the relevant data for maintaining the vcpu state completely at hyp.
 */
struct picovm_hyp_vcpu {
	struct picovm_vcpu vcpu;

	/* Backpointer to the host's (untrusted) vCPU instance. */
	struct picovm_vcpu *host_vcpu;

	/*
	 * If this hyp vCPU is loaded, then this is a backpointer to the
	 * per-cpu pointer tracking us. Otherwise, NULL if not loaded.
	 */
	struct pkvm_hyp_vcpu **loaded_hyp_vcpu;

	/* Tracks exit code for the protected guest. */
	u32 exit_code;

	/*
	 * Track the power state transition of a protected vcpu.
	 * Can be in one of three states:
	 * PSCI_0_2_AFFINITY_LEVEL_ON
	 * PSCI_0_2_AFFINITY_LEVEL_OFF
	 * PSCI_0_2_AFFINITY_LEVEL_PENDING
	 */
	int power_state;
};

/*
 * Holds the relevant data for running a protected vm.
 */
struct picovm_hyp_vm {
	struct picovm picovm;

	/* Backpointer to the host's (untrusted) KVM instance. */
	struct picovm *host_picovm;

	/* The guest's stage-2 page-table managed by the hypervisor. */
	struct picovm_pgtable pgt;
	hyp_spinlock_t lock;

	/*
	 * The number of vcpus initialized and ready to run.
	 * Modifying this is protected by 'vm_table_lock'.
	 */
	unsigned int nr_vcpus;

	/* Array of the hyp vCPU structures for this VM. */
	struct pkvm_hyp_vcpu *vcpus[];
};


/* Hypervisor interface ******************************************************/
// from: linux/arch/arm64/include/asm/kvm_asm.h
#define PICOVM_HOST_SMCCC_ID(id)						\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,				\
			   ARM_SMCCC_SMC_64,				\
			   ARM_SMCCC_OWNER_VENDOR_HYP,			\
			   (id))


#define __PICOVM_HOST_SMCCC_FUNC___picovm_hyp_init			0

enum __picovm_host_smccc_func {
	/* Hypercalls available only prior to pKVM finalisation */
	/* __PICOVM_HOST_SMCCC_FUNC___kvm_hyp_init */
	__PICOVM_HOST_SMCCC_FUNC___picovm_init = __PICOVM_HOST_SMCCC_FUNC___picovm_hyp_init + 1,
	__PICOVM_HOST_SMCCC_FUNC___picovm_create_private_mapping,
	__PICOVM_HOST_SMCCC_FUNC___picovm_prot_finalize,

	/* Hypercalls available after pKVM finalisation */
	__PICOVM_HOST_SMCCC_FUNC___picovm_host_share_hyp,
	__PICOVM_HOST_SMCCC_FUNC___picovm_host_unshare_hyp,
};

extern struct memblock_region hyp_memory[];
extern unsigned int hyp_memblock_nr;

static inline unsigned long __hyp_pgtable_max_pages(unsigned long nr_pages)
{
	unsigned long total = 0, i;

	/* Provision the worst case scenario */
	for (i = 0; i < PICOVM_PGTABLE_MAX_LEVELS; i++) {
		nr_pages = DIV_ROUND_UP(nr_pages, PTRS_PER_PTE);
		total += nr_pages;
	}

	return total;
}

#endif /* __PICOVM_H */
