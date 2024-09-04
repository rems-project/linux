// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

// #include <kvm/arm_hypercalls.h>

// #include <hyp/adjust_pc.h>

// #include <asm/pgtable-types.h>
// #include <asm/kvm_asm.h>
// #include <asm/kvm_emulate.h>
// #include <asm/kvm_host.h>
// #include <asm/kvm_hyp.h>
// #include <asm/kvm_mmu.h>

#include <picovm/prelude.h>
#include <picovm/mem_protect.h>
// #include <nvhe/mm.h>
// #include <nvhe/pkvm.h>
// #include <nvhe/trap_handler.h>

// #include <linux/irqchip/arm-gic-v3.h>
// #include <uapi/linux/psci.h>

// #include "../../sys_regs.h"


#include <picovm/picovm.h>

bool picovm_initialized;





// static void handle___pkvm_init(struct host_cpu_context *host_ctxt)
// {
// 	DECLARE_REG(phys_addr_t, phys, host_ctxt, 1);
// 	DECLARE_REG(unsigned long, size, host_ctxt, 2);
// 	DECLARE_REG(unsigned long, nr_cpus, host_ctxt, 3);
// 	DECLARE_REG(unsigned long *, per_cpu_base, host_ctxt, 4);
// 	DECLARE_REG(u32, hyp_va_bits, host_ctxt, 5);

// 	/*
// 	 * __pkvm_init() will return only if an error occurred, otherwise it
// 	 * will tail-call in __pkvm_init_finalise() which will have to deal
// 	 * with the host context directly.
// 	 */
// 	cpu_reg(host_ctxt, 1) = __pkvm_init(phys, size, nr_cpus, per_cpu_base,
// 					    hyp_va_bits);
// }







static void handle___picovm_host_share_hyp(struct host_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pfn, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = __picovm_host_share_hyp(pfn);
}

static void handle___picovm_host_unshare_hyp(struct host_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pfn, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = __picovm_host_unshare_hyp(pfn);
}



// static void handle___pkvm_create_private_mapping(struct host_cpu_context *host_ctxt)
// {
// 	DECLARE_REG(phys_addr_t, phys, host_ctxt, 1);
// 	DECLARE_REG(size_t, size, host_ctxt, 2);
// 	DECLARE_REG(enum kvm_pgtable_prot, prot, host_ctxt, 3);

// 	/*
// 	 * __pkvm_create_private_mapping() populates a pointer with the
// 	 * hypervisor start address of the allocation.
// 	 *
// 	 * However, handle___pkvm_create_private_mapping() hypercall crosses the
// 	 * EL1/EL2 boundary so the pointer would not be valid in this context.
// 	 *
// 	 * Instead pass the allocation address as the return value (or return
// 	 * ERR_PTR() on failure).
// 	 */
// 	unsigned long haddr;
// #ifdef CONFIG_NVHE_GHOST_SPEC
// 	int err = __pkvm_create_private_mapping(phys, size, prot, &haddr, HYP_HCALL);
// #else /* CONFIG_NVHE_GHOST_SPEC */
// 	int err = __pkvm_create_private_mapping(phys, size, prot, &haddr);
// #endif /* CONFIG_NVHE_GHOST_SPEC */

// 	if (err)
// 		haddr = (unsigned long)ERR_PTR(err);

// 	cpu_reg(host_ctxt, 1) = haddr;
// }

// static void handle___pkvm_prot_finalize(struct host_cpu_context *host_ctxt)
// {
// #ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
// 	hyp_puts("\n__pkvm_prot_finalize:\n");
// 	hyp_putsxnl("    CPU", hyp_smp_processor_id(), 32);
// #endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
// 	cpu_reg(host_ctxt, 1) = __pkvm_prot_finalize();
// #ifdef CONFIG_NVHE_GHOST_SPEC
// 	if (cpu_reg(host_ctxt, 1) == 0)
// 		ghost_enable_this_cpu();
// #endif /* CONFIG_NVHE_GHOST_SPEC */
// }



typedef void (*hcall_t)(struct host_cpu_context *);

#define HANDLE_FUNC(x)	[__PICOVM_HOST_SMCCC_FUNC_##x] = (hcall_t)handle_##x
static const hcall_t host_hcall[] = {
	/* ___kvm_hyp_init */
	// HANDLE_FUNC(__pkvm_init),
	// HANDLE_FUNC(__pkvm_create_private_mapping),
	// HANDLE_FUNC(__pkvm_prot_finalize),

	HANDLE_FUNC(__picovm_host_share_hyp),
	HANDLE_FUNC(__picovm_host_unshare_hyp),
};

static void handle_host_hcall(struct host_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned long, id, host_ctxt, 0);
	unsigned long hcall_min = 0;
	hcall_t hfn;

	/*
	 * If pKVM has been initialised then reject any calls to the
	 * early "privileged" hypercalls. Note that we cannot reject
	 * calls to __pkvm_prot_finalize for two reasons: (1) The static
	 * key used to determine initialisation must be toggled prior to
	 * finalisation and (2) finalisation is performed on a per-CPU
	 * basis. This is all fine, however, since __pkvm_prot_finalize
	 * returns -EPERM after the first call for a given CPU.
	 */
	if (picovm_initialized)
		hcall_min = __PICOVM_HOST_SMCCC_FUNC___picovm_prot_finalize;

	id -= KVM_HOST_SMCCC_ID(0);

	if (id < hcall_min || id >= ARRAY_SIZE(host_hcall))
		goto inval;

	hfn = host_hcall[id];
	if (!hfn)
		goto inval;

	cpu_reg(host_ctxt, 0) = SMCCC_RET_SUCCESS;
	hfn(host_ctxt);

	return;
inval:
	cpu_reg(host_ctxt, 0) = SMCCC_RET_NOT_SUPPORTED;
}


void handle_trap(struct host_cpu_context *host_ctxt)
{
	u64 esr = read_esr_el2();
	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_HVC64:
		handle_host_hcall(host_ctxt);
		break;
	case ESR_ELx_EC_SMC64:
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		handle_host_mem_abort(host_ctxt);
		break;
	default:
		BUG();
	}

}
