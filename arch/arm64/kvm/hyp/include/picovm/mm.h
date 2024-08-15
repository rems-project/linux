/* SPDX-License-Identifier: GPL-2.0-only */
// TODO(note/license) based on arch/arm64/kvm/hyp/include/nvhe/mm.h
#ifndef __PICOVM_MM_H
#define __PICOVM_MM_H
#include <picovm/picovm_pgtable.h>

int picovm_create_mappings_locked(void *from, void *to, enum picovm_pgtable_prot prot);

#endif /* __PICOVM_MM_H */
