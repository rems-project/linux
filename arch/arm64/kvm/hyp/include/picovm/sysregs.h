/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on:
 *
 *  * arch/arm64/include/asm/sysreg.h
 *      Copyright (C) 2014 ARM Ltd.
 *      Author: Catalin Marinas <catalin.marinas@arm.com>
 *
 *  * arch/arm64/include/asm/esr.h
 *      Copyright (C) 2013 - ARM Ltd
 *      Author: Marc Zyngier <marc.zyngier@arm.com>
 */
#ifndef __PICOVM_SYSREGS_H
#define __PICOVM_SYSREGS_H

#include <picovm/linux/const.h>
#include <picovm/linux/bits.h>

// Saved Program Status Register (SPSR_ELn)
// M[3:0], bits [3:0]
#define SPSR_ELn_M_SHIFT	(0)
#define SPSR_ELn_M_MASK		(UL(0b1111) << SPSR_ELn_M_SHIFT)

#define SPSR_ELn_M_EL0t		(UL(0b0000))
#define SPSR_ELn_M_EL1h		(UL(0b0101))


// Physical Address Register (PAR_EL1)
// F, bit[0]
#define PAR_EL1_F	BIT(0)


// Hypervisor Configuration Register (HCR_EL2)
#define HCR_VM		(UL(1) << 0)


//  Virtualization Translation Table Base Register (VTTBR_EL2)
#define VTTBR_CNP_BIT		(UL(1))
#define VTTBR_VMID_SHIFT	(UL(48))
#define VTTBR_VMID_MASK(size)	(_AT(u64, (1 << size) - 1) << VTTBR_VMID_SHIFT)


// Exception Syndrome Register
#define ESR_ELx_EC_SHIFT	(26)
#define ESR_ELx_EC_WIDTH	(6)
#define ESR_ELx_EC_MASK		(UL(0x3F) << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr)		(((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)

#define ESR_ELx_EC_FP_ASIMD	(0x07)
#define ESR_ELx_EC_HVC64	(0x16)	/* EL2 and above */
#define ESR_ELx_EC_SMC64	(0x17)	/* EL2 and above */
#define ESR_ELx_EC_SVE		(0x19)
#define ESR_ELx_EC_IABT_LOW	(0x20)
#define ESR_ELx_EC_IABT_CUR	(0x21)
#define ESR_ELx_EC_DABT_LOW	(0x24)
#define ESR_ELx_EC_DABT_CUR	(0x25)

#define ESR_ELx_S1PTW_SHIFT	(7)
#define ESR_ELx_S1PTW		(UL(1) << ESR_ELx_S1PTW_SHIFT)

#define ESR_ELx_FSC_TYPE	(0x3C)
#define ESR_ELx_FSC_PERM	(0x0C)


// Virtualization Translation Control Register (VTCR_EL2)
#define VTCR_EL2_SL0_SHIFT	(6)
#define VTCR_EL2_SL0_MASK	(UL(0b11) << VTCR_EL2_SL0_SHIFT)

#define VTCR_EL2_TG0_SHIFT	(14)
#define VTCR_EL2_TG0_MASK	(UL(0b11) << VTCR_EL2_TG0_SHIFT)

#define VTCR_EL2_PS_SHIFT	(16)

#define VTCR_EL2_HA		(1 << 21)

#define VTCR_EL2_VS_SHIFT	19
#define VTCR_EL2_VS_8BIT	(0 << VTCR_EL2_VS_SHIFT)
#define VTCR_EL2_VS_16BIT	(1 << VTCR_EL2_VS_SHIFT)


#define TCR_SH0_SHIFT		12
#define TCR_SH0_MASK		(UL(3) << TCR_SH0_SHIFT)
#define TCR_SH0_INNER		(UL(3) << TCR_SH0_SHIFT)

#define TCR_ORGN0_SHIFT		10
#define TCR_ORGN0_WBWA		(UL(1) << TCR_ORGN0_SHIFT)

#define TCR_IRGN0_SHIFT		8
#define TCR_IRGN0_WBWA		(UL(1) << TCR_IRGN0_SHIFT)

#define VTCR_EL2_SH0_INNER	TCR_SH0_INNER
#define VTCR_EL2_ORGN0_WBWA	TCR_ORGN0_WBWA
#define VTCR_EL2_IRGN0_WBWA	TCR_IRGN0_WBWA

// TODO: ???
#define VTCR_EL2_T0SZ(x)	(UL(64) - (x))


#ifdef CONFIG_ARM64_4K_PAGES
#define TCR_TG0_SHIFT		14
#define TCR_TG0_4K		(UL(0) << TCR_TG0_SHIFT)
#define VTCR_EL2_TG0_4K		TCR_TG0_4K
#define VTCR_EL2_TGRAN			VTCR_EL2_TG0_4K
#define VTCR_EL2_TGRAN_SL0_BASE		2UL
#endif


// Common VTCR_EL2 Flags
#define VTCR_EL2_RES1		(1U << 31) // Reserved bit must be 1
#define VTCR_EL2_COMMON_BITS \
	(VTCR_EL2_SH0_INNER | VTCR_EL2_ORGN0_WBWA | VTCR_EL2_IRGN0_WBWA | VTCR_EL2_RES1)
#define VTCR_EL2_FLAGS	(VTCR_EL2_COMMON_BITS | VTCR_EL2_TGRAN)



// AArch64 Memory Model Feature Register 0 (ID_AA64MMFR0_EL1)
// PARange, bits[3:0]
#define ID_AA64MMFR0_EL1_PARANGE_SHIFT	0
#define ID_AA64MMFR0_EL1_PARANGE_48	UL(0b0101)




#define ID_AA64MMFR1_EL1_VMIDBits_SHIFT                 4
#define ID_AA64MMFR1_EL1_VMIDBits_16                    UL(0b0010)


#ifdef CONFIG_ARM64_PA_BITS_52
#error "picovm does not support 52-bit physical addresses"
#else
#define ID_AA64MMFR0_EL1_PARANGE_MAX	ID_AA64MMFR0_EL1_PARANGE_48
#endif

#ifndef __ASSEMBLY__
#include <picovm/linux/types.h>

static inline u64 read_esr_el2(void)
{
	u64 reg;
	asm volatile("mrs %0, esr_el2": "=r" (reg));
	return reg;
}


/*
 * The "Z" constraint normally means a zero immediate, but when combined with
 * the "%x0" template means XZR.
 */
#define write_sysreg(v, r) do {			\
	u64 __val = (u64)(v);			\
	asm volatile("msr " #r ", %x0"		\
		     : : "rZ" (__val));		\
} while (0)

#define read_sysreg(r) ({				\
	u64 __val;					\
	asm volatile("mrs %0, " #r : "=r" (__val));	\
	__val;						\
})
#endif
#endif /* __PICOVM_SYSREGS_H */
