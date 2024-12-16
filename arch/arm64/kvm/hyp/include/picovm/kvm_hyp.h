/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PICOVM_KVM_HYP_H
#define __PICOVM_KVM_HYP_H

#ifdef CONFIG_PICOVM_STANDALONE

#include <picovm/linux/types.h>
#include <picovm/per-cpu.h>

#include <picovm/kvm_host.h>

DECLARE_PER_CPU(struct kvm_nvhe_init_params, kvm_init_params);

// DEFINED IN nvhe/hyp-init.S
void __pkvm_init_switch_pgd(phys_addr_t phys, unsigned long size,
			    phys_addr_t pgd, void *sp, void *cont_fn);

int __pkvm_init(phys_addr_t phys, unsigned long size, unsigned long nr_cpus,
		unsigned long *per_cpu_base, u32 hyp_va_bits);

// DEFINED IN host.S
void __noreturn __host_enter(struct kvm_cpu_context *host_ctxt);

#else
#include <asm/kvm_hyp.h>
#endif /* CONFIG_PICOVM_STANDALONE */
#endif /* __PICOVM_KVM_HYP_H */
