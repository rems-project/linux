#include <picovm/prelude.h>
#include <picovm/memory.h>
#include <picovm/spinlock.h>
#include <picovm/picovm_pgtable.h>

#include <picovm/linux/memblock.h>

struct picovm_pgtable picovm_pgtable;

// TODO: this comes from arch/arm64/include/asm/kvm_pkvm.h
// need to make sure this does not go out of sync somehow
#define HYP_MEMBLOCK_REGIONS	128

struct memblock_region hyp_memory[HYP_MEMBLOCK_REGIONS];
unsigned int hyp_memblock_nr;


int picovm_create_mappings_locked(void *from, void *to, enum picovm_pgtable_prot prot)
{
	unsigned long start = (unsigned long)from;
	unsigned long end = (unsigned long)to;
	unsigned long virt_addr;
	phys_addr_t phys;

	//TODO(picovm):(don't need this?) hyp_assert_lock_held(&pkvm_pgd_lock);

	start = start & PAGE_MASK;
	end = PAGE_ALIGN(end);

	for (virt_addr = start; virt_addr < end; virt_addr += PAGE_SIZE) {
		int err;

		phys = hyp_virt_to_phys((void *)virt_addr);
		err = picovm_pgtable_hyp_map(&picovm_pgtable, virt_addr, PAGE_SIZE,
					     phys, prot);
		if (err)
			return err;
	}

	return 0;
}
