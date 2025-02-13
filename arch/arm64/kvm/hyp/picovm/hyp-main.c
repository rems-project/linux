// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on
 *	arch/arm64/kvm/hyp/nvhe/hyp-main.c
 */
#include <picovm/linux/types.h>
#include <picovm/asm/bug.h>
#include <picovm/per-cpu.h>
#include <picovm/sysregs.h>

#include <picovm/kvm_host.h>
#include <picovm/kvm_hyp.h>

#include <picovm/mem_protect.h>
#include <picovm/trap_handler.h>

bool picovm_initialized;

// DEFINED IN kvm_interface.c
DECLARE_PER_CPU(struct kvm_nvhe_init_params, kvm_init_params);

static void handle___kvm_get_mdcr_el2(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = read_sysreg(mdcr_el2);
}

static void handle___pkvm_cpu_set_vector(struct kvm_cpu_context *host_ctxt)
{
	// TODO: we don't care about this for now
	// DECLARE_REG(enum arm64_hyp_spectre_vector, slot, host_ctxt, 1);

	// cpu_reg(host_ctxt, 1) = pkvm_cpu_set_vector(slot);
	cpu_reg(host_ctxt, 1) = 0;
}


static void handle___pkvm_init(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(phys_addr_t, phys, host_ctxt, 1);
	DECLARE_REG(unsigned long, size, host_ctxt, 2);
	DECLARE_REG(unsigned long, nr_cpus, host_ctxt, 3);
	DECLARE_REG(unsigned long *, per_cpu_base, host_ctxt, 4);
	DECLARE_REG(u32, hyp_va_bits, host_ctxt, 5);

	/*
	 * __picovm_init() will return only if an error occurred, otherwise it
	 * will tail-call in __picovm_init_finalise() which will have to deal
	 * with the host context directly.
	 */
	cpu_reg(host_ctxt, 1) = __pkvm_init(phys, size, nr_cpus, per_cpu_base,
					    hyp_va_bits);
}

static void handle___pkvm_prot_finalize(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __pkvm_prot_finalize();
}

static void handle___pkvm_host_share_hyp(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pfn, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = __pkvm_host_share_hyp(pfn);
}

static void handle___pkvm_host_unshare_hyp(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pfn, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = __pkvm_host_unshare_hyp(pfn);
}



// static void handle___pkvm_create_private_mapping(struct host_cpu_context *host_ctxt)
// {
// 	DECLARE_REG(phys_addr_t, phys, host_ctxt, 1);
// 	DECLARE_REG(size_t, size, host_ctxt, 2);
// 	DECLARE_REG(enum kvm_pgtable_prot, prot, host_ctxt, 3);
//
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
//
// 	if (err)
// 		haddr = (unsigned long)ERR_PTR(err);
//
// 	cpu_reg(host_ctxt, 1) = haddr;
// }



typedef void (*hcall_t)(struct kvm_cpu_context *);

#define HANDLE_FUNC(x)	[__KVM_HOST_SMCCC_FUNC_##x] = (hcall_t)handle_##x
static const hcall_t host_hcall[] = {
	/* ___kvm_hyp_init */
	HANDLE_FUNC(__kvm_get_mdcr_el2),
	HANDLE_FUNC(__pkvm_init),
	// HANDLE_FUNC(__pkvm_create_private_mapping),
	HANDLE_FUNC(__pkvm_cpu_set_vector),
	HANDLE_FUNC(__pkvm_prot_finalize),

	HANDLE_FUNC(__pkvm_host_share_hyp),
	HANDLE_FUNC(__pkvm_host_unshare_hyp),
};


// From include/linux/kernel.h
// #define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
// #define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
// #define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static void handle_host_hcall(struct kvm_cpu_context *host_ctxt)
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
		hcall_min = __KVM_HOST_SMCCC_FUNC___pkvm_prot_finalize;

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


void handle_trap(struct kvm_cpu_context *host_ctxt)
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
