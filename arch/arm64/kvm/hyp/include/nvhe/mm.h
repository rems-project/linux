/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_HYP_MM_H
#define __KVM_HYP_MM_H

#include <asm/kvm_pgtable.h>
#include <asm/spectre.h>
#include <linux/memblock.h>
#include <linux/types.h>

#include <nvhe/memory.h>
#include <nvhe/spinlock.h>

extern struct kvm_pgtable pkvm_pgtable;
extern hyp_spinlock_t pkvm_pgd_lock;
extern const struct pkvm_module_ops module_ops;

int hyp_create_fixmap(void);
void *hyp_fixmap_map(phys_addr_t phys);
void hyp_fixmap_unmap(void);
void *hyp_fixblock_map(phys_addr_t phys, size_t *size);
void hyp_fixblock_unmap(void);
void hyp_poison_page(phys_addr_t phys, size_t size);

int hyp_create_idmap(u32 hyp_va_bits);
int hyp_map_vectors(void);
int hyp_back_vmemmap(phys_addr_t back);
int pkvm_cpu_set_vector(enum arm64_hyp_spectre_vector slot);
#ifdef CONFIG_NVHE_GHOST_SPEC
#include <nvhe/ghost/ghost_mapping_reqs.h>
int pkvm_create_mappings(void *from, void *to, enum kvm_pgtable_prot prot, enum mapping_req_kind kind, u64 cpu);
#else /* CONFIG_NVHE_GHOST_SPEC */
int pkvm_create_mappings(void *from, void *to, enum kvm_pgtable_prot prot);
#endif /* CONFIG_NVHE_GHOST_SPEC */
int pkvm_create_mappings_locked(void *from, void *to, enum kvm_pgtable_prot prot);
#ifdef CONFIG_NVHE_GHOST_SPEC
int __pkvm_create_private_mapping(phys_addr_t phys, size_t size,
				  enum kvm_pgtable_prot prot,
				  unsigned long *haddr,
				  enum mapping_req_kind kind);
#else /* CONFIG_NVHE_GHOST_SPEC */
int __pkvm_create_private_mapping(phys_addr_t phys, size_t size,
				  enum kvm_pgtable_prot prot,
				  unsigned long *haddr);
#endif /* CONFIG_NVHE_GHOST_SPEC */
int pkvm_create_stack(phys_addr_t phys, unsigned long *haddr);
int pkvm_alloc_private_va_range(size_t size, unsigned long *haddr);
void pkvm_remove_mappings(void *from, void *to);
unsigned long pkvm_remove_mappings_locked(void *from, void *to);
phys_addr_t __pkvm_private_range_pa(void *va);
int __hyp_allocator_map(unsigned long start, phys_addr_t phys);

int __pkvm_map_module_pages(u64 pfn, void *va, u64 nr_pages, enum kvm_pgtable_prot prot,
			    bool is_protected);
int __pkvm_unmap_module_pages(u64 pfn, void *va, u64 nr_pages);
void *__pkvm_alloc_module_va(u64 nr_pages);
#ifdef CONFIG_PKVM_STRICT_CHECKS
void assert_in_mod_range(unsigned long addr, size_t size);
#else
static inline void assert_in_mod_range(unsigned long addr, size_t size) { }
#endif /* CONFIG_PKVM_STRICT_CHECKS */

#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
void get_fixmap(void);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
#endif /* __KVM_HYP_MM_H */
