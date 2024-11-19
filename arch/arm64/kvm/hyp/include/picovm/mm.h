/* SPDX-License-Identifier: GPL-2.0-only */
/* 
 * Based on
 *	arch/arm64/kvm/hyp/include/nvhe/mm.h
 *	arch/arm64/include/asm/spectre.h
 */

#ifndef __PICOVM_MM_H
#define __PICOVM_MM_H

#include <picovm/pgtable.h>
#include <picovm/spinlock.h>

extern struct picovm_pgtable picovm_pgtable;
extern hyp_spinlock_t picovm_pgd_lock;

//// interfaces for mm.c
int hyp_create_pcpu_fixmap(void);
int hyp_create_idmap(u32 hyp_va_bits);
int hyp_map_vectors(void);

int picovm_create_mappings(void *from, void *to, enum picovm_pgtable_prot prot);
int picovm_create_mappings_locked(void *from, void *to, enum picovm_pgtable_prot prot);
int __picovm_create_private_mapping(phys_addr_t phys, size_t size,
				  enum picovm_pgtable_prot prot,
				  unsigned long *haddr);
int picovm_alloc_private_va_range(size_t size, unsigned long *haddr);

//// helper macros

extern char __bp_harden_hyp_vecs[];

#define BP_HARDEN_EL2_SLOTS 4
#define SZ_2K 0x00000800
#define __BP_HARDEN_HYP_VECS_SZ	((BP_HARDEN_EL2_SLOTS - 1) * SZ_2K)

#endif /* __PICOVM_MM_H */
