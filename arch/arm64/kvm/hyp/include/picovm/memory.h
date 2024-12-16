/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm64/kvm/hyp/include/nvhe/memory.h
 *
 */
#ifndef __PICOVM_MEMORY_H
#define __PICOVM_MEMORY_H

#include <picovm/linux/types.h>
#include <picovm/linux/compiler.h>

// DEFINED IN kvm_interface.c
extern s64 hyp_physvirt_offset;

#define __hyp_va(phys)	((void *)((phys_addr_t)(phys) - hyp_physvirt_offset))
#define __hyp_pa(x) (((phys_addr_t)(x)) + hyp_physvirt_offset)

static inline void *hyp_phys_to_virt(phys_addr_t phys)
{
	return __hyp_va(phys);
}

static inline phys_addr_t hyp_virt_to_phys(void *addr)
{
	return __hyp_pa(addr);
}

#define hyp_pfn_to_phys(pfn)	((phys_addr_t)((pfn) << PAGE_SHIFT))

#endif /* __PICOVM_MEMORY_H */
