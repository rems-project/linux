/* SPDX-License-Identifier: GPL-2.0-only */
// TODO(note/license) based on arch/arm64/kvm/hyp/include/nvhe/mm.h
#ifndef __PICOVM_MM_H
#define __PICOVM_MM_H

#include <picovm/picovm_pgtable.h>
#include <picovm/spinlock.h>

extern struct picovm_pgtable picovm_pgtable;
extern hyp_spinlock_t picovm_pgd_lock;

int picovm_create_mappings(void *from, void *to, enum picovm_pgtable_prot prot);
int picovm_create_mappings_locked(void *from, void *to, enum picovm_pgtable_prot prot);
int picovm_alloc_private_va_range(size_t size, unsigned long *haddr);

#endif /* __PICOVM_MM_H */
