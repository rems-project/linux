/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm64/kvm/hyp/nvhe/sys_regs.c
 */

#include <picovm/prelude.h>

/*
 * Copies of the host's CPU features registers holding sanitized values at hyp.
 * These are first initialized in 
 * arch/arm64/kvm/arm.c::static int __init init_hyp_mode(void)
 */

// Processor Feature Register 0 (PFR0):
// Provides information about core features like virtualization and secure execution support.
u64 id_aa64pfr0_el1_sys_val;
// Processor Feature Register 1 (PFR1): 
// Extends PFR0 with additional core feature support details.
u64 id_aa64pfr1_el1_sys_val;

// Instruction Set Attribute Register 0 (ISAR0): 
// Describes supported instruction set features such as cryptographic instructions.
u64 id_aa64isar0_el1_sys_val;
// Instruction Set Attribute Register 1 (ISAR1): 
// Extends ISAR0 with additional details about advanced instruction set features.
u64 id_aa64isar1_el1_sys_val;
// Instruction Set Attribute Register 2 (ISAR2): 
// Provides further information about additional instruction set features.
u64 id_aa64isar2_el1_sys_val;
 
// Memory Model Feature Register 0 (MMFR0): 
// Details memory model capabilities such as physical address size and translation granularity.
u64 id_aa64mmfr0_el1_sys_val;
// Memory Model Feature Register 1 (MMFR1):
// Extends MMFR0 with more memory management features, such as hardware access flags.
u64 id_aa64mmfr1_el1_sys_val;
// Memory Model Feature Register 2 (MMFR2): 
// Further extends MMFR0 and MMFR1 with advanced memory management features.
u64 id_aa64mmfr2_el1_sys_val;
// Statistical Profiling Extension Register 0 (SMFR0): 
// Provides information about the statistical profiling features supported by the processor.
u64 id_aa64smfr0_el1_sys_val; 

