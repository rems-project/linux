#ifndef __PICOVM_H
#define __PICOVM_H
#include <picovm/prelude.h>
#include <picovm/memory.h>

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


/* Exception syndrome register ***********************************************/
// from: linux/archarm64/include/asm/esr.h
#define ESR_ELx_EC_FP_ASIMD	(0x07)
#define ESR_ELx_EC_HVC64	(0x16)
#define ESR_ELx_EC_SMC64	(0x17)
#define ESR_ELx_EC_SVE		(0x19)
#define ESR_ELx_EC_IABT_LOW	(0x20)
#define ESR_ELx_EC_DABT_LOW	(0x24)

#define ESR_ELx_EC_SHIFT	(26)
#define ESR_ELx_EC_WIDTH	(6)
#define ESR_ELx_EC_MASK		(U64(0x3F) << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr)		(((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)

static inline u64 read_esr_el2(void)
{
	u64 reg;
	asm volatile("mrs %0, esr_el2": "=r" (reg));
	return reg;
}












static inline void BUG(void)
{
	for(;;); // __builtin_unreachable();
}



struct user_pt_regs {
	u64 regs[31];
	u64 sp;
	u64 pc;
	u64 pstate;
};

struct host_cpu_context {
	struct user_pt_regs regs;	/* sp = sp_el0 */
};

#define cpu_reg(ctxt, r)	(ctxt)->regs.regs[r]
#define DECLARE_REG(type, name, ctxt, reg)	\
				type name = (type)cpu_reg(ctxt, (reg))





/* Hypervisor interface ******************************************************/
// from: linux/arch/arm64/include/asm/kvm_asm.h
#define KVM_HOST_SMCCC_ID(id)						\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,				\
			   ARM_SMCCC_SMC_64,				\
			   ARM_SMCCC_OWNER_VENDOR_HYP,			\
			   (id))


#define __PICOVM_HOST_SMCCC_FUNC___kvm_hyp_init			0

enum __picovm_host_smccc_func {
	/* Hypercalls available only prior to pKVM finalisation */
	/* __PICOVM_HOST_SMCCC_FUNC___kvm_hyp_init */
	__PICOVM_HOST_SMCCC_FUNC___picovm_init = __PICOVM_HOST_SMCCC_FUNC___kvm_hyp_init + 1,
	__PICOVM_HOST_SMCCC_FUNC___picovm_create_private_mapping,
	__PICOVM_HOST_SMCCC_FUNC___picovm_prot_finalize,

	/* Hypercalls available after pKVM finalisation */
	__PICOVM_HOST_SMCCC_FUNC___picovm_host_share_hyp,
	__PICOVM_HOST_SMCCC_FUNC___picovm_host_unshare_hyp,
};







// TODO: hyp_virt_to_phys()

static inline phys_addr_t hyp_pfn_to_phys(u64 pfn)
{
	return pfn << PAGE_SHIFT;
}

// static inline void* __hyp_va(phys_addr_t phys)
// {
// 	return (void*)(phys - hyp_physvirt_offset);
// }

#endif /* __PICOVM_H */
