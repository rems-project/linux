#include <asm/asm-offsets.h>
#include <linux/linkage.h>
#include "nvhe/ghost/ghost_asm_ids.h"

        // looks like it would be more idiomatic to use a C enum instead of the ghost_asm_ids.h #define's, and then have this in C code instead of asm, using read_sysreg_el2, following sysreg-sr.h
        
	// size of unsigned long
#define SZ 8

	SYM_CODE_START(ghost_get_sysregs)

//	mrs	x1,id_aa64pfr0_el1
//	str	x1, [x0, #(SZ * GHOST_ID_AA64PFR0_EL1)]
//	mrs	x1,edscr                      // maybe not mrs-readable?
//	str	x1, [x0, #(SZ * GHOST_EDSCR)]
	mov	x1, sp
	str	x1, [x0, #(SZ * GHOST_SP)]
	mrs	x1,hcr_el2
	str	x1, [x0, #(SZ * GHOST_HCR_EL2)]
	mrs	x1,mair_el2
	str	x1, [x0, #(SZ * GHOST_MAIR_EL2)]
	mrs	x1,mdcr_el2
	str	x1, [x0, #(SZ * GHOST_MDCR_EL2)]
	//mrs	x1,mdcr_el3
	//str	x1, [x0, #(SZ * GHOST_MDCR_EL3)]
	//mrs	x1,mdscr_el1
	//str	x1, [x0, #(SZ * GHOST_MDSCR_EL1)]
	//mrs	x1,mpidr_el1
	//str	x1, [x0, #(SZ * GHOST_MPIDR_EL1)]
	//mrs	x1,osdlr_el1
	//str	x1, [x0, #(SZ * GHOST_OSDLR_EL1)]
	//mrs	x1,oslsr_el1
	//str	x1, [x0, #(SZ * GHOST_OSLSR_EL1)]
	mrs	x1,daif
	str	x1, [x0, #(SZ * GHOST_PSTATE_DAIF)]
	mrs	x1,CurrentEL
	str	x1, [x0, #(SZ * GHOST_PSTATE_CURRENTEL)]
//	mrs	x1,pstate_nrw
//	str	x1, [x0, #(SZ * GHOST_PSTATE_NRW)]
	mrs	x1,SPSEL
	str	x1, [x0, #(SZ * GHOST_PSTATE_SPSEL)]
	//mrs	x1,scr_el3
	//str	x1, [x0, #(SZ * GHOST_SCR_EL3)]
	//mrs	x1,sctlr_el1
	//str	x1, [x0, #(SZ * GHOST_SCTLR_EL1)]
	mrs	x1,sctlr_el2
	str	x1, [x0, #(SZ * GHOST_SCTLR_EL2)]
	//mrs	x1,tcr_el1
	//str	x1, [x0, #(SZ * GHOST_TCR_EL1)]
	mrs	x1,tcr_el2
	str	x1, [x0, #(SZ * GHOST_TCR_EL2)]
	mrs	x1,tpidr_el2
	str	x1, [x0, #(SZ * GHOST_TPIDR_EL2)]
	mrs	x1,vtcr_el2
	str	x1, [x0, #(SZ * GHOST_VTCR_EL2)]
	mrs	x1,vttbr_el2
	str	x1, [x0, #(SZ * GHOST_VTTBR_EL2)]
	mrs	x1,ttbr0_el2
	str	x1, [x0, #(SZ * GHOST_TTBR0_EL2)]


	mrs	x1,elr_el2
	str	x1, [x0, #(SZ * GHOST_ELR_EL2)]
	mrs	x1,esr_el2
	str	x1, [x0, #(SZ * GHOST_ESR_EL2)]
	mrs	x1,far_el2
	str	x1, [x0, #(SZ * GHOST_FAR_EL2)]
	mrs	x1,hpfar_el2
	str	x1, [x0, #(SZ * GHOST_HPFAR_EL2)]
        

	mrs	x1,id_aa64afr0_el1
        str	x1, [x0, #(SZ * GHOST_ID_AA64AFR0_EL1 )]
	mrs	x1,id_aa64afr1_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64AFR1_EL1 )]
	mrs	x1,id_aa64pfr0_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64PFR0_EL1 )]
	mrs	x1,id_aa64pfr1_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64PFR1_EL1 )]
	mrs	x1,id_aa64dfr0_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64DFR0_EL1 )]
	mrs	x1,id_aa64dfr1_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64DFR1_EL1 )]
	mrs	x1,id_aa64mmfr0_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64MMFR0_EL1)]
	mrs	x1,id_aa64mmfr1_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64MMFR1_EL1)]
	mrs	x1,id_aa64mmfr2_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64MMFR2_EL1)]
	mrs	x1,id_aa64isar0_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64ISAR0_EL1)]
	mrs	x1,id_aa64isar1_el1	
        str	x1, [x0, #(SZ * GHOST_ID_AA64ISAR1_EL1)]

	mrs	x1,spsr_el2
	str	x1, [x0, #(SZ * GHOST_SPSR_EL2)]
        
	ret

	SYM_CODE_END(ghost_get_sysregs)


// PS HACK: snapshot the main EL2 system registers into a struct kvm_nvhe_init_params struct as defined in kvm_asm.h.  Call with a pointer to that struct in x0

	SYM_CODE_START(___kvm_get_sysregs)

	mrs	x1, tpidr_el2
	str	x1, [x0, #NVHE_INIT_TPIDR_EL2]

	mov	x1, sp
	str	x1, [x0, #NVHE_INIT_STACK_HYP_VA]

	mrs	x1, mair_el2
	str	x1, [x0, #NVHE_INIT_MAIR_EL2]

	mrs	x1, hcr_el2
	str	x1, [x0, #NVHE_INIT_HCR_EL2]

	mrs	x1, vttbr_el2
	str	x1, [x0, #NVHE_INIT_VTTBR]

	mrs	x1, vtcr_el2
	str	x1, [x0, #NVHE_INIT_VTCR]

	mrs	x1, ttbr0_el2
	str	x1, [x0, #NVHE_INIT_PGD_PA]

	mrs	x1, tcr_el2
	str	x1, [x0, #NVHE_INIT_TCR_EL2]

	ret

	SYM_CODE_END(___kvm_get_sysregs)
