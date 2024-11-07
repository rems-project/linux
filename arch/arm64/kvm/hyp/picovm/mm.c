#include <picovm/prelude.h>

#include <picovm/memory.h>
#include <picovm/spinlock.h>
#include <picovm/pgtable.h>

struct picovm_pgtable picovm_pgtable;
hyp_spinlock_t picovm_pgd_lock;

// TODO: this comes from arch/arm64/include/asm/kvm_pkvm.h
// need to make sure this does not go out of sync somehow
#define HYP_MEMBLOCK_REGIONS	128

struct memblock_region hyp_memory[HYP_MEMBLOCK_REGIONS];
unsigned int hyp_memblock_nr;

static u64 __io_map_base;

int picovm_alloc_private_va_range(size_t size, unsigned long *haddr)
{
	unsigned long base, addr;
	int ret = 0;

	hyp_spin_lock(&picovm_pgd_lock);

	/* Align the allocation based on the order of its size */
	addr = ALIGN(__io_map_base, PAGE_SIZE << get_order(size));

	/* The allocated size is always a multiple of PAGE_SIZE */
	base = addr + PAGE_ALIGN(size);

	/* Are we overflowing on the vmemmap ? */
	__io_map_base = base;
	*haddr = addr;

	hyp_spin_unlock(&picovm_pgd_lock);

	return ret;
}

static int __picovm_create_mappings(unsigned long start, unsigned long size, 
                                    unsigned long phys, enum picovm_pgtable_prot prot)
{
  int err;
  hyp_spin_lock(&picovm_pgd_lock);
  err = picovm_pgtable_hyp_map(&picovm_pgtable, start ,size, phys, prot);
  hyp_spin_unlock(&picovm_pgd_lock);
}

int picovm_create_mappings_locked(void *from, void *to, enum picovm_pgtable_prot prot)
{
	unsigned long start = (unsigned long)from;
	unsigned long end = (unsigned long)to;
	unsigned long virt_addr;
	phys_addr_t phys;

	//TODO(picovm):(don't need this?) hyp_assert_lock_held(&picovm_pgd_lock);

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

int picovm_create_mappings(void *from, void *to, enum picovm_pgtable_prot prot)
{
	int ret;

	hyp_spin_lock(&picovm_pgd_lock);
	ret = picovm_create_mappings_locked(from, to, prot);
	hyp_spin_unlock(&picovm_pgd_lock);

	return ret;
}


int hyp_create_idmap(u32 hyp_va_bits)
{
	unsigned long start, end;

	start = hyp_virt_to_phys((void *)__hyp_idmap_text_start);
	start = ALIGN_DOWN(start, PAGE_SIZE);

	end = hyp_virt_to_phys((void *)__hyp_idmap_text_end);
	end = ALIGN(end, PAGE_SIZE);

	return __picovm_create_mappings(start, end - start, start, PAGE_HYP_EXEC);
}
