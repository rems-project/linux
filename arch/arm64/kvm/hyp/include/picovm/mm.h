/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PICOVM_MM_H__
#define __PICOVM_MM_H__

/*
 * INTERFACE of picovm/mm.c
 */
#include <picovm/pgtable.h>
#include <picovm/spinlock.h>

extern struct picovm_pgtable picovm_pgtable;
extern hyp_spinlock_t picovm_pgd_lock;

int picovm_alloc_private_va_range(size_t size, unsigned long *haddr);
#ifdef CONFIG_PICOVM_CLIGHTPLUS
int picovm_create_mappings_locked(void *from, void *to, u64 prot);
int picovm_create_mappings(void *from, void *to, u64 prot);
int __picovm_create_private_mapping(phys_addr_t phys, size_t size,
				  u64 prot,
				  unsigned long *haddr);
#else
int picovm_create_mappings_locked(void *from, void *to, enum picovm_pgtable_prot prot);
int picovm_create_mappings(void *from, void *to, enum picovm_pgtable_prot prot);
int __picovm_create_private_mapping(phys_addr_t phys, size_t size,
				  enum picovm_pgtable_prot prot,
				  unsigned long *haddr);
#endif
int hyp_create_pcpu_fixmap(void);
int hyp_create_idmap(u32 hyp_va_bits);
int hyp_map_vectors(void);

#endif /* __PICOVM_MM_H__ */
