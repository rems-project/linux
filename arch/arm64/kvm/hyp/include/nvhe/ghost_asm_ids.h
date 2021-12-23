// the kernel has a fancy scheme for generating macros with the offsets of structs so that they can be used inside asm. I've not tried to use that - instead, we'll just have indices.

#ifndef _GHOST_ASM_IDS_H
#define  _GHOST_ASM_IDS_H


//#define GHOST__INVALID__SYSREG 
#define GHOST_SP 1
//GHOST_EDSCR 
#define GHOST_HCR_EL2 2
#define GHOST_MAIR_EL2 3
#define GHOST_MDCR_EL2 4
//#define GHOST_MDCR_EL3 5
//#define GHOST_MDSCR_EL1 6   sysregs-sr.h common state
//#define GHOST_MPIDR_EL1 7   sysregs-sr.h el1 state
//#define GHOST_OSDLR_EL1 8      // OS Double Lock Register, not in sysregs-sr.h
//#define GHOST_OSLSR_EL1 9      // OS Lock Status Register, not in sysregs-sr.h
#define GHOST_PSTATE_DAIF 10
#define GHOST_PSTATE_CURRENTEL 11
//GHOST_PSTATE_NRW
#define GHOST_PSTATE_SPSEL 12
//#define GHOST_SCR_EL3 13
//#define GHOST_SCTLR_EL1 14   sysregs-sr.h el1 state
#define GHOST_SCTLR_EL2 15
//#define GHOST_TCR_EL1 16   sysregs-sr.h el1 state
#define GHOST_TCR_EL2 17
#define GHOST_TPIDR_EL2 18
#define GHOST_VTCR_EL2 19
#define GHOST_VTTBR_EL2 20
#define GHOST_TTBR0_EL2 21

#define GHOST_ELR_EL2 22
#define GHOST_ESR_EL2 23
#define GHOST_FAR_EL2 24
#define GHOST_HPFAR_EL2 25

// none of the ID registers are in sysregs-sr.h
//The AArch64 Auxiliary Feature registers
#define GHOST_ID_AA64AFR0_EL1 26
#define GHOST_ID_AA64AFR1_EL1 27
//The AArch64 Processor Feature registers
#define GHOST_ID_AA64PFR0_EL1 28
#define GHOST_ID_AA64PFR1_EL1 29
//The AArch64 Debug Feature registers
#define GHOST_ID_AA64DFR0_EL1 30
#define GHOST_ID_AA64DFR1_EL1 31
//The AArch64 Memory Model Feature registers
#define GHOST_ID_AA64MMFR0_EL1 32
#define GHOST_ID_AA64MMFR1_EL1 33
#define GHOST_ID_AA64MMFR2_EL1 34
//The AArch64 Instruction Set Attribute registers
#define GHOST_ID_AA64ISAR0_EL1 35
#define GHOST_ID_AA64ISAR1_EL1 36

#define GHOST_SPSR_EL2 37

#define GHOST_NR_SYSREGS 38




//GHOST_SP
//GHOST_PSTATE_DAIF
//GHOST_PSTATE_CURRENTEL
//GHOST_PSTATE_SPSEL

#define GHOST_EL2_REGS { \
  GHOST_HCR_EL2,	 \
  GHOST_MAIR_EL2,	 \
  GHOST_MDCR_EL2,	 \
  GHOST_SCTLR_EL2,	 \
  GHOST_TCR_EL2,	 \
  GHOST_TPIDR_EL2,	 \
  GHOST_VTCR_EL2,	 \
  GHOST_VTTBR_EL2,	 \
  GHOST_TTBR0_EL2,	 \
  GHOST_ELR_EL2,	 \
  GHOST_ESR_EL2,	 \
  GHOST_FAR_EL2,	 \
  GHOST_HPFAR_EL2,	 \
  GHOST_SPSR_EL2,        \
	  }



#endif //  _GHOST_ASM_IDS_H
