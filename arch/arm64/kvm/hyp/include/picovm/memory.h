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

// extern u64 __hyp_vmemmap;
// #define hyp_vmemmap ((struct hyp_page *)__hyp_vmemmap)
//
// TODO(picovm) was a macro in NVHE called __hyp_va + an inline function
static inline void *hyp_phys_to_virt(phys_addr_t phys)
{
  return (void*)(phys - hyp_physvirt_offset);
}

static inline phys_addr_t hyp_virt_to_phys(void *addr)
{
  return __hyp_pa(addr);
}

#define hyp_phys_to_pfn(phys)	((phys) >> PAGE_SHIFT)
#define hyp_pfn_to_phys(pfn)	((phys_addr_t)((pfn) << PAGE_SHIFT))
// #define hyp_phys_to_page(phys)	(&hyp_vmemmap[hyp_phys_to_pfn(phys)])
// #define hyp_virt_to_page(virt)	hyp_phys_to_page(__hyp_pa(virt))
#define hyp_virt_to_pfn(virt)	hyp_phys_to_pfn(__hyp_pa(virt))

// #define hyp_page_to_pfn(page)	((struct hyp_page *)(page) - hyp_vmemmap)
// #define hyp_page_to_phys(page)  hyp_pfn_to_phys((hyp_page_to_pfn(page)))
// #define hyp_page_to_virt(page)	__hyp_va(hyp_page_to_phys(page))
// #define hyp_page_to_pool(page)	(((struct hyp_page *)page)->pool)

#endif /* __PICOVM_MEMORY_H */
