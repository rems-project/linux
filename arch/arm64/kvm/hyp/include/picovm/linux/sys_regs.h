/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	include/asm/cpufeature.h
 *	arch/arm64/include/asm/sysreg-def.h
 *	include/asm/kvm_arm.h
 */

#ifndef __PICOVM_SYS_REGS_H
#define __PICOVM_SYS_REGS_H

#include <asm/cpufeature.h>

#define ID_AA64MMFR0_EL1_PARANGE_SHIFT 0
#define ID_AA64MMFR0_EL1_PARANGE_WIDTH 4

#define ID_AA64MMFR1_EL1_VMIDBits                       GENMASK(7, 4)
#define ID_AA64MMFR1_EL1_VMIDBits_MASK                  GENMASK(7, 4)
#define ID_AA64MMFR1_EL1_VMIDBits_SHIFT                 4
#define ID_AA64MMFR1_EL1_VMIDBits_WIDTH                 4

/* Hyp Configuration Register (HCR) bits */
#define HCR_VM		(UL(1) << 0)

/* VTTBR bits */
#define VTTBR_CNP_BIT		(UL(1))
#define VTTBR_VMID_SHIFT	(UL(48))
#define VTTBR_VMID_MASK(size) (_AT(u64, (1 << size) - 1) << VTTBR_VMID_SHIFT)

/* Hyp Prefetch Fault Address Register (HPFAR/HDFAR) */
#define HPFAR_MASK	(~UL(0xf))


/* 
 * VTCR_EL2 Registers bits:
 *
 * The VTCR_EL2 register controls the setting for Stage-2 memory translations,
 * which are used in virtualization to translate guest physical addresses to
 * host physical addresses.
 */

// Physical Address Size (PS) - Defines the size of the physical address space supported by the translation tables
#define TCR_EL2_PS_SHIFT    16
#define TCR_EL2_PS_MASK     (7 << TCR_EL2_PS_SHIFT)

// Translation Granule (TG0) - Defines page size granularity for Stage-2 transitions
#define TCR_TG0_SHIFT        14                      // TG0 field position
#define TCR_TG0_MASK         (UL(3) << TCR_TG0_SHIFT)  // Mask for TG0 field
#define TCR_TG0_4K           (UL(0) << TCR_TG0_SHIFT)  // 4KB granularity

// VTCR_EL2-specific TG0 definitions
#define VTCR_EL2_TG0_4K      TCR_TG0_4K
#define VTCR_EL2_TGRAN       VTCR_EL2_TG0_4K         // Default granularity (4KB)
#define VTCR_EL2_TGRAN_SL0_BASE 2UL                  // SL0 base value for TG0

// Sharing (SH0) - Configures memory sharing between processors
#define TCR_SH0_SHIFT        12                      // SH0 field position
#define TCR_SH0_MASK         (UL(3) << TCR_SH0_SHIFT)  // Mask for SH0 field
#define TCR_SH0_INNER        (UL(3) << TCR_SH0_SHIFT)  // Inner-shareable

// Outer Cacheability (ORGN0) - Configures outer memory cacheability
#define TCR_ORGN0_SHIFT      10                      // ORGN0 field position
#define TCR_ORGN0_MASK       (UL(3) << TCR_ORGN0_SHIFT) // Mask for ORGN0 field
#define TCR_ORGN0_NC         (UL(0) << TCR_ORGN0_SHIFT) // Non-cacheable
#define TCR_ORGN0_WBWA       (UL(1) << TCR_ORGN0_SHIFT) // Write-back, write-allocate

// Inner Cacheability (IRGN0) - Configures inner memory cacheability
#define TCR_IRGN0_SHIFT      8                       // IRGN0 field position
#define TCR_IRGN0_MASK       (UL(3) << TCR_IRGN0_SHIFT) // Mask for IRGN0 field
#define TCR_IRGN0_NC         (UL(0) << TCR_IRGN0_SHIFT) // Non-cacheable
#define TCR_IRGN0_WBWA       (UL(1) << TCR_IRGN0_SHIFT) // Write-back, write-allocate

// T0SZ - Translation Table Size
#define VTCR_EL2_T0SZ_MASK   0x3f                   // Mask for T0SZ field
#define VTCR_EL2_T0SZ(x)     TCR_T0SZ(x)            // Translate size helper

// SL0 - Starting Level in Translation Table Walk
#define VTCR_EL2_SL0_SHIFT   6                      // SL0 field position
#define VTCR_EL2_SL0_MASK    (3 << VTCR_EL2_SL0_SHIFT) // Mask for SL0 field

// VS - Virtualization address size
#define VTCR_EL2_VS_SHIFT    19                     // VS field position
#define VTCR_EL2_VS_8BIT     (0 << VTCR_EL2_VS_SHIFT) // 8-bit virtualization
#define VTCR_EL2_VS_16BIT    (1 << VTCR_EL2_VS_SHIFT) // 16-bit virtualization

// Hardware Access
#define VTCR_EL2_HA		(1 << 21)

// TCR flags
#define TCR_T0SZ_OFFSET		0
#define TCR_T0SZ(x)		((64UL - (x)) << TCR_T0SZ_OFFSET)

// VTCR -> TCR
#define VTCR_EL2_PS_SHIFT	TCR_EL2_PS_SHIFT
#define VTCR_EL2_PS_MASK	TCR_EL2_PS_MASK
#define VTCR_EL2_TG0_SHIFT	TCR_TG0_SHIFT
#define VTCR_EL2_TG0_MASK	TCR_TG0_MASK
#define VTCR_EL2_TG0_4K		TCR_TG0_4K
#define VTCR_EL2_SH0_MASK	TCR_SH0_MASK
#define VTCR_EL2_SH0_INNER	TCR_SH0_INNER
#define VTCR_EL2_ORGN0_MASK	TCR_ORGN0_MASK
#define VTCR_EL2_ORGN0_WBWA	TCR_ORGN0_WBWA
#define VTCR_EL2_IRGN0_MASK	TCR_IRGN0_MASK
#define VTCR_EL2_IRGN0_WBWA	TCR_IRGN0_WBWA
#define VTCR_EL2_T0SZ(x)	TCR_T0SZ(x)

// Helper Macros for SL0 and Levels
#define VTCR_EL2_LVLS_TO_SL0(levels) \
    ((VTCR_EL2_TGRAN_SL0_BASE - (4 - (levels))) << VTCR_EL2_SL0_SHIFT)

#define VTCR_EL2_SL0_TO_LVLS(sl0) \
    ((sl0) + 4 - VTCR_EL2_TGRAN_SL0_BASE)

#define VTCR_EL2_LVLS(vtcr)		\
	VTCR_EL2_SL0_TO_LVLS(((vtcr) & VTCR_EL2_SL0_MASK) >> VTCR_EL2_SL0_SHIFT)

// Common VTCR_EL2 Flags
#define VTCR_EL2_RES1        (1U << 31)             // Reserved bit must be 1
#define VTCR_EL2_COMMON_BITS \
    (VTCR_EL2_SH0_INNER | VTCR_EL2_ORGN0_WBWA | VTCR_EL2_IRGN0_WBWA | VTCR_EL2_RES1)
#define VTCR_EL2_FLAGS	(VTCR_EL2_COMMON_BITS | VTCR_EL2_TGRAN)

#endif
