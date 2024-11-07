/* SPDX-License-Identifier: GPL-2.0-only */
/* based on pkvm-core-6.4:arch/arm64/kvm/hyp/include/nvhe/memory.h */
#ifndef __PICOVM_MEMORY_H
#define __PICOVM_MEMORY_H

#include <picovm/prelude.h>

// NOTE: duplicating for the linux header to remain standalone
#ifndef __ro_after_init
#define __ro_after_init __attribute__((__section__(".data..ro_after_init")))
#endif

// from: linux/arch/arm64/include/asm/kvm_host.h
// s64 __ro_after_init hyp_physvirt_offset;
extern s64 hyp_physvirt_offset;

// from: linux/arch/arm64/include/asm/kvm_mmu.h
#define __hyp_pa(x) (((phys_addr_t)(x)) + hyp_physvirt_offset)


// NOTE: based on linux/arch/arm64/include/asm/page-def.h
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

static inline int ilog2(unsigned long x)
{
    int log = 0;
    while (x >>= 1) ++log;
    return log;
}

static inline int fls64(unsigned long x)
{
    int position = 0;
    while (x != 0) {
        x >>= 1;
        position++;
    }
    return position;
}


/**
 * get_order - Determine the allocation order of a memory size
 * @size: The size for which to get the order
 *
 * Determine the allocation order of a particular sized block of memory.  This
 * is on a logarithmic scale, where:
 *
 *	0 -> 2^0 * PAGE_SIZE and below
 *	1 -> 2^1 * PAGE_SIZE to 2^0 * PAGE_SIZE + 1
 *	2 -> 2^2 * PAGE_SIZE to 2^1 * PAGE_SIZE + 1
 *	3 -> 2^3 * PAGE_SIZE to 2^2 * PAGE_SIZE + 1
 *	4 -> 2^4 * PAGE_SIZE to 2^3 * PAGE_SIZE + 1
 *	...
 *
 * The order returned is used to find the smallest allocation granule required
 * to hold an object of the specified size.
 *
 * The result is undefined if the size is 0.
 */
static inline const int get_order(unsigned long size)
{
	if (__builtin_constant_p(size)) {
		if (!size)
			return BITS_PER_LONG - PAGE_SHIFT;

		if (size < (1UL << PAGE_SHIFT))
			return 0;

		return ilog2((size) - 1) - PAGE_SHIFT + 1;
	}

	size--;
	size >>= PAGE_SHIFT;
	return fls64(size);
}

#endif /* __PICOVM_MEMORY_H */
