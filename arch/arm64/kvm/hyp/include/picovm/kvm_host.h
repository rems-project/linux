/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on:
 *
 *  * arch/arm64/include/uapi/asm/ptrace.h
 *      Copyright (C) 1996-2003 Russell King
 *      Copyright (C) 2012 ARM Ltd.
 *
 *  * include/linux/arm-smccc.h
 *      Copyright (c) 2015, Linaro Limited
 *
 *  * arch/arm64/include/asm/kvm_host.h
 *  * arm/arm64/include/asm/kvm_asm.h
 *      Copyright (C) 2012,2013 - ARM Ltd
 *      Author: Marc Zyngier <marc.zyngier@arm.com>
 */
#ifndef __PICOVM_KVM_HOST_H
#define __PICOVM_KVM_HOST_H

#ifdef CONFIG_PICOVM_STANDALONE

#include <picovm/linux/types.h>
#include <picovm/per-cpu.h>

// From include/linux/arm-smccc.h
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

/*
 * Return codes defined in ARM DEN 0070A
 * ARM DEN 0070A is now merged/consolidated into ARM DEN 0028 C
 */
#define SMCCC_RET_SUCCESS			0
#define SMCCC_RET_NOT_SUPPORTED			-1



// From arm/arm64/include/asm/kvm_asm.h
#define KVM_HOST_SMCCC_ID(id)						\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,				\
			   ARM_SMCCC_SMC_64,				\
			   ARM_SMCCC_OWNER_VENDOR_HYP,			\
			   (id))


#define __KVM_HOST_SMCCC_FUNC___kvm_hyp_init			0

enum __kvm_host_smccc_func {
	/* Hypercalls available only prior to pKVM finalisation */
	/* __KVM_HOST_SMCCC_FUNC___kvm_hyp_init */
	__KVM_HOST_SMCCC_FUNC___kvm_get_mdcr_el2 = __KVM_HOST_SMCCC_FUNC___kvm_hyp_init + 1,
	__KVM_HOST_SMCCC_FUNC___pkvm_init,
	__KVM_HOST_SMCCC_FUNC___pkvm_create_private_mapping,
	__KVM_HOST_SMCCC_FUNC___pkvm_cpu_set_vector,
	__KVM_HOST_SMCCC_FUNC___kvm_enable_ssbs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_init_lrs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_get_gic_config,
	__KVM_HOST_SMCCC_FUNC___kvm_flush_vm_context,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid_ipa,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid,
	__KVM_HOST_SMCCC_FUNC___kvm_flush_cpu_context,
	__KVM_HOST_SMCCC_FUNC___pkvm_prot_finalize,

	/* Hypercalls available after pKVM finalisation */
	__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest,
	__KVM_HOST_SMCCC_FUNC___kvm_adjust_pc,
	__KVM_HOST_SMCCC_FUNC___kvm_vcpu_run,
	__KVM_HOST_SMCCC_FUNC___kvm_timer_set_cntvoff,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_save_vmcr_aprs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_restore_vmcr_aprs,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu,
	__KVM_HOST_SMCCC_FUNC___pkvm_teardown_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_sync_state,
};


// From arch/arm64/include/uapi/asm/ptrace.h
struct user_fpsimd_state {
	__uint128_t	vregs[32];
	u32		fpsr;
	u32		fpcr;
	u32		__reserved[2];
};

struct user_pt_regs {
	u64		regs[31];
	u64		sp;
	u64		pc;
	u64		pstate;
};

// From arch/arm64/include/asm/kvm_host.h
enum vcpu_sysreg {
	__INVALID_SYSREG__,   /* 0 is reserved as an invalid value */
	MPIDR_EL1,	/* MultiProcessor Affinity Register */
	CLIDR_EL1,	/* Cache Level ID Register */
	CSSELR_EL1,	/* Cache Size Selection Register */
	SCTLR_EL1,	/* System Control Register */
	ACTLR_EL1,	/* Auxiliary Control Register */
	CPACR_EL1,	/* Coprocessor Access Control */
	ZCR_EL1,	/* SVE Control */
	TTBR0_EL1,	/* Translation Table Base Register 0 */
	TTBR1_EL1,	/* Translation Table Base Register 1 */
	TCR_EL1,	/* Translation Control Register */
	ESR_EL1,	/* Exception Syndrome Register */
	AFSR0_EL1,	/* Auxiliary Fault Status Register 0 */
	AFSR1_EL1,	/* Auxiliary Fault Status Register 1 */
	FAR_EL1,	/* Fault Address Register */
	MAIR_EL1,	/* Memory Attribute Indirection Register */
	VBAR_EL1,	/* Vector Base Address Register */
	CONTEXTIDR_EL1,	/* Context ID Register */
	TPIDR_EL0,	/* Thread ID, User R/W */
	TPIDRRO_EL0,	/* Thread ID, User R/O */
	TPIDR_EL1,	/* Thread ID, Privileged */
	AMAIR_EL1,	/* Aux Memory Attribute Indirection Register */
	CNTKCTL_EL1,	/* Timer Control Register (EL1) */
	PAR_EL1,	/* Physical Address Register */
	MDSCR_EL1,	/* Monitor Debug System Control Register */
	MDCCINT_EL1,	/* Monitor Debug Comms Channel Interrupt Enable Reg */
	OSLSR_EL1,	/* OS Lock Status Register */
	DISR_EL1,	/* Deferred Interrupt Status Register */

	/* Performance Monitors Registers */
	PMCR_EL0,	/* Control Register */
	PMSELR_EL0,	/* Event Counter Selection Register */
	PMEVCNTR0_EL0,	/* Event Counter Register (0-30) */
	PMEVCNTR30_EL0 = PMEVCNTR0_EL0 + 30,
	PMCCNTR_EL0,	/* Cycle Counter Register */
	PMEVTYPER0_EL0,	/* Event Type Register (0-30) */
	PMEVTYPER30_EL0 = PMEVTYPER0_EL0 + 30,
	PMCCFILTR_EL0,	/* Cycle Count Filter Register */
	PMCNTENSET_EL0,	/* Count Enable Set Register */
	PMINTENSET_EL1,	/* Interrupt Enable Set Register */
	PMOVSSET_EL0,	/* Overflow Flag Status Set Register */
	PMUSERENR_EL0,	/* User Enable Register */

	/* Pointer Authentication Registers in a strict increasing order. */
	APIAKEYLO_EL1,
	APIAKEYHI_EL1,
	APIBKEYLO_EL1,
	APIBKEYHI_EL1,
	APDAKEYLO_EL1,
	APDAKEYHI_EL1,
	APDBKEYLO_EL1,
	APDBKEYHI_EL1,
	APGAKEYLO_EL1,
	APGAKEYHI_EL1,

	ELR_EL1,
	SP_EL1,
	SPSR_EL1,

	CNTVOFF_EL2,
	CNTV_CVAL_EL0,
	CNTV_CTL_EL0,
	CNTP_CVAL_EL0,
	CNTP_CTL_EL0,

	/* Memory Tagging Extension registers */
	RGSR_EL1,	/* Random Allocation Tag Seed Register */
	GCR_EL1,	/* Tag Control Register */
	TFSR_EL1,	/* Tag Fault Status Register (EL1) */
	TFSRE0_EL1,	/* Tag Fault Status Register (EL0) */

	/* 32bit specific registers. */
	DACR32_EL2,	/* Domain Access Control Register */
	IFSR32_EL2,	/* Instruction Fault Status Register */
	FPEXC32_EL2,	/* Floating-Point Exception Control Register */
	DBGVCR32_EL2,	/* Debug Vector Catch Register */

	/* EL2 registers */
	VPIDR_EL2,	/* Virtualization Processor ID Register */
	VMPIDR_EL2,	/* Virtualization Multiprocessor ID Register */
	SCTLR_EL2,	/* System Control Register (EL2) */
	ACTLR_EL2,	/* Auxiliary Control Register (EL2) */
	HCR_EL2,	/* Hypervisor Configuration Register */
	MDCR_EL2,	/* Monitor Debug Configuration Register (EL2) */
	CPTR_EL2,	/* Architectural Feature Trap Register (EL2) */
	HSTR_EL2,	/* Hypervisor System Trap Register */
	HACR_EL2,	/* Hypervisor Auxiliary Control Register */
	TTBR0_EL2,	/* Translation Table Base Register 0 (EL2) */
	TTBR1_EL2,	/* Translation Table Base Register 1 (EL2) */
	TCR_EL2,	/* Translation Control Register (EL2) */
	VTTBR_EL2,	/* Virtualization Translation Table Base Register */
	VTCR_EL2,	/* Virtualization Translation Control Register */
	SPSR_EL2,	/* EL2 saved program status register */
	ELR_EL2,	/* EL2 exception link register */
	AFSR0_EL2,	/* Auxiliary Fault Status Register 0 (EL2) */
	AFSR1_EL2,	/* Auxiliary Fault Status Register 1 (EL2) */
	ESR_EL2,	/* Exception Syndrome Register (EL2) */
	FAR_EL2,	/* Fault Address Register (EL2) */
	HPFAR_EL2,	/* Hypervisor IPA Fault Address Register */
	MAIR_EL2,	/* Memory Attribute Indirection Register (EL2) */
	AMAIR_EL2,	/* Auxiliary Memory Attribute Indirection Register (EL2) */
	VBAR_EL2,	/* Vector Base Address Register (EL2) */
	RVBAR_EL2,	/* Reset Vector Base Address Register */
	CONTEXTIDR_EL2,	/* Context ID Register (EL2) */
	TPIDR_EL2,	/* EL2 Software Thread ID Register */
	CNTHCTL_EL2,	/* Counter-timer Hypervisor Control register */
	SP_EL2,		/* EL2 Stack Pointer */
	CNTHP_CTL_EL2,
	CNTHP_CVAL_EL2,
	CNTHV_CTL_EL2,
	CNTHV_CVAL_EL2,

	NR_SYS_REGS	/* Nothing after this line! */
};

struct kvm_cpu_context {
	struct user_pt_regs regs;	/* sp = sp_el0 */

	u64	spsr_abt;
	u64	spsr_und;
	u64	spsr_irq;
	u64	spsr_fiq;

	struct user_fpsimd_state fp_regs;

	u64 sys_regs[NR_SYS_REGS];

	struct kvm_vcpu *__hyp_running_vcpu;
};

struct kvm_host_data {
	struct kvm_cpu_context host_ctxt;
};


struct kvm_nvhe_init_params {
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

// DEFINED IN kvm_interface.c
extern unsigned int /*__ro_after_init*/ kvm_arm_vmid_bits;

// DEFINED IN switch.c
DECLARE_PER_CPU(struct kvm_host_data, kvm_host_data);

#else
#include <asm/kvm_host.h>
#endif

#endif /* __PICOVM_KVM_HOST_H */
