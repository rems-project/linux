/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Derived from arch/arm/include/asm/kvm_host.h:
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 */
#ifndef __PICOVM_HOST_H__
#define __PICOVM_HOST_H__

#include <picovm/prelude.h>
#include <picovm/picovm.h>

// NOTE: based on include/asm/kvm_host.h::enum vcpu_sysreg
#define NR_SYS_REGS 157

struct picovm_vcpu_fault_info {
	u64 esr_el2; /* Hyp Syndrom Register */
	u64 far_el2; /* Hyp Fault Address Register */
	u64 hpfar_el2; /* Hyp IPA Fault Address Register */
	u64 disr_el1; /* Deferred [SError] Status Register */
};

struct picovm {
	// TODO: more fields
	int created_vcpus;
	int last_boosted_vcpu;
};

struct picovm_vcpu {
	// TODO: more fields
	struct picovm *picovm;

	int cpu;
	int vcpu_id; /* id given by userspace at creation */
	int vcpu_idx; /* index into kvm->vcpu_array */
};

struct picovm_cpu_context {
	struct user_pt_regs regs; /* sp = sp_el0 */

	u64 spsr_abt;
	u64 spsr_und;
	u64 spsr_irq;
	u64 spsr_fiq;

	u64 sys_regs[NR_SYS_REGS];

	struct picovm_vcpu *__hyp_running_vcpu;
};

struct picovm_host_data {
	struct picovm_cpu_context host_ctxt;
};

struct picovm_s2_mmu {
	atomic64_t vmid;

	/*
	 * stage2 entry level table
	 *
	 * Two picovm_s2_mmu structures in the same VM can point to the same
	 * pgd here.  This happens when running a guest using a
	 * translation regime that isn't affected by its own stage-2
	 * translation, such as a non-VHE hypervisor running at vEL2, or
	 * for vEL1/EL0 with vHCR_EL2.VM == 0.  In that case, we use the
	 * canonical stage-2 page tables.
	 */
	phys_addr_t pgd_phys;
	struct picovm_pgtable *pgt;
	struct picovm_arch *arch;
};

struct picovm_arch_memory_slot {};

typedef unsigned int picovm_handle_t;

struct picovm_protected_vm {
	picovm_handle_t handle;
	bool enabled;
};

struct picovm_arch {
	struct picovm_s2_mmu mmu;

	/* VTCR_EL2 value for this VM */
	u64 vtcr;
	/*
	 * For an untrusted host VM, 'picovm.handle' is used to lookup
	 * the associated picoVM instance in the hypervisor.
	 */
	struct picovm_protected_vm ppvm;
};

unsigned int __ro_after_init picovm_arm_vmid_bits;

#endif /* __PICOVM_HOST_H__ */
