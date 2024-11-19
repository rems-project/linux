/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	include/asm/kvm_hyp.h
 */

#ifndef __PICOVM_HYP_H__
#define __PICOVM_HYP_H__

#include <picovm/prelude.h>

// Check sys_regs.c
extern u64 id_aa64pfr0_el1_sys_val;
extern u64 id_aa64pfr1_el1_sys_val;
extern u64 id_aa64isar0_el1_sys_val;
extern u64 id_aa64isar1_el1_sys_val;
extern u64 id_aa64isar2_el1_sys_val;
extern u64 id_aa64mmfr0_el1_sys_val;
extern u64 id_aa64mmfr1_el1_sys_val;
extern u64 id_aa64mmfr2_el1_sys_val;
extern u64 id_aa64smfr0_el1_sys_val;


extern unsigned int __ro_after_init picovm_arm_vmid_bits;

DECLARE_PER_CPU(struct picovm_cpu_context, picovm_hyp_ctxt);
DECLARE_PER_CPU(unsigned long, picovm_hyp_vector);
DECLARE_PER_CPU(struct picovm_nvhe_init_params, picovm_init_params);

#define read_sysreg_elx(r,nvh,vh)					\
	({								\
		u64 reg;						\
		asm volatile(ALTERNATIVE(__mrs_s("%0", r##nvh),	\
					 __mrs_s("%0", r##vh),		\
					 ARM64_HAS_VIRT_HOST_EXTN)	\
			     : "=r" (reg));				\
		reg;							\
	})

#define write_sysreg_elx(v,r,nvh,vh)					\
	do {								\
		u64 __val = (u64)(v);					\
		asm volatile(ALTERNATIVE(__msr_s(r##nvh, "%x0"),	\
					 __msr_s(r##vh, "%x0"),		\
					 ARM64_HAS_VIRT_HOST_EXTN)	\
					 : : "rZ" (__val));		\
	} while (0)

/*
 * Unified accessors for registers that have a different encoding
 * between VHE and non-VHE. They must be specified without their "ELx"
 * encoding, but with the SYS_ prefix, as defined in asm/sysreg.h.
 */

#define read_sysreg_el0(r)	read_sysreg_elx(r, _EL0, _EL02)
#define write_sysreg_el0(v,r)	write_sysreg_elx(v, r, _EL0, _EL02)
#define read_sysreg_el1(r)	read_sysreg_elx(r, _EL1, _EL12)
#define write_sysreg_el1(v,r)	write_sysreg_elx(v, r, _EL1, _EL12)
#define read_sysreg_el2(r)	read_sysreg_elx(r, _EL2, _EL1)
#define write_sysreg_el2(v,r)	write_sysreg_elx(v, r, _EL2, _EL1)

void __picovm_init_switch_pgd(phys_addr_t phys, unsigned long size,
			      phys_addr_t pgd, void *sp, void *cont_fn);
int __picovm_init(phys_addr_t phys, unsigned long size, unsigned long nr_cpus,
		  unsigned long *per_cpu_base, u32 hyp_va_bits);
void __noreturn __host_enter(struct picovm_cpu_context *host_ctxt);
#endif /* __PICOVM_HYP_H__ */
