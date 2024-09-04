/* SPDX-License-Identifier: GPL-2.0-only */
/* based on pkvm-core-6.4:arch/arm64/kvm/hyp/include/nvhe/memory.h */
#ifndef __PICOVM_MEMORY_H
#define __PICOVM_MEMORY_H

#include <picovm/prelude.h>

// TODO: duplicating for the linux header to remain standalone
#ifndef __ro_after_init
#define __ro_after_init __attribute__((__section__(".data..ro_after_init")))
#endif

// from: linux/arch/arm64/include/asm/kvm_host.h
// s64 __ro_after_init hyp_physvirt_offset;
extern s64 hyp_physvirt_offset;

// from: linux/arch/arm64/include/asm/kvm_mmu.h
#define __hyp_pa(x) (((phys_addr_t)(x)) + hyp_physvirt_offset)


// TODO: based on linux/arch/arm64/include/asm/page-def.h
// TODO(note): we fix page size to 4K
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

// align to the NEXT page boundary
#define PAGE_ALIGN(addr)	ALIGN(addr, PAGE_SIZE)

// align to the PREVIOUS page boundary
#define PAGE_ALIGN_DOWN(addr) 	ALIGN_DOWN(addr, PAGE_SIZE)


// TODO(picovm) was a macro in NVHE called __hyp_va + an inline function
static inline void* hyp_phys_to_virt(phys_addr_t phys)
{
	return (void*)(phys - hyp_physvirt_offset);
}

static inline phys_addr_t hyp_virt_to_phys(void *addr)
{
	return __hyp_pa(addr);
}

#endif /* __PICOVM_MEMORY_H */
