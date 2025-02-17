/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm64/kvm/hyp/nvhe/mm.c
 *
 */
#include <picovm/asm/errno-base.h>

#include <picovm/per-cpu.h>
#include <picovm/asm/rwonce.h>
#include <picovm/asm/barrier.h>
#include <picovm/asm/tlbflush.h>
#include <picovm/getorder.h>

#include <picovm/page.h>
#include <picovm/memory.h>

#include <picovm/spinlock.h>
#include <picovm/mem_protect.h>
#include <picovm/pgtable.h>


struct picovm_pgtable picovm_pgtable;
hyp_spinlock_t picovm_pgd_lock;

static u64 __io_map_base;
struct hyp_fixmap_slot {
	u64 addr;
	picovm_pte_t *ptep;
};

static DEFINE_PER_CPU(struct hyp_fixmap_slot, fixmap_slots);

static int __picovm_create_mappings(unsigned long start, unsigned long size, 
                                    unsigned long phys, enum picovm_pgtable_prot prot)
{
	int err;

	hyp_spin_lock(&picovm_pgd_lock);
	err = picovm_pgtable_hyp_map(&picovm_pgtable, start, size, phys, prot);
	hyp_spin_unlock(&picovm_pgd_lock);

	return err;
}

int picovm_alloc_private_va_range(size_t size, unsigned long *haddr)
{
	unsigned long base, addr, cur;
	int ret = 0;

	hyp_spin_lock(&picovm_pgd_lock);

	/* Align the allocation based on the order of its size */
	addr = ALIGN(__io_map_base, PAGE_SIZE << get_order(size));

	/* The allocated size is always a multiple of PAGE_SIZE */
	base = addr + PAGE_ALIGN(size);

	/* Are we overflowing on the vmemmap ? */
	__io_map_base = base;
	*haddr = addr;

	for (cur = addr; cur < __io_map_base; cur += PAGE_SIZE) {
		ret = picovm_pgtable_hyp_early_map_invalid(&picovm_pgtable, cur);
		if (ret)
			goto out;
	}

out:
	hyp_spin_unlock(&picovm_pgd_lock);

	return ret;
}

static int __picovm_create_private_mapping(phys_addr_t phys, size_t size,
				  enum picovm_pgtable_prot prot,
				  unsigned long *haddr)
{
	unsigned long addr;
	int err;

	size = PAGE_ALIGN(size + offset_in_page(phys));
	err = picovm_alloc_private_va_range(size, &addr);
	if (err)
		return err;

	err = __picovm_create_mappings(addr, size, phys, prot);
	if (err)
		return err;

	*haddr = addr + offset_in_page(phys);
	return err;
}


int picovm_create_mappings_locked(void *from, void *to, enum picovm_pgtable_prot prot)
{
	unsigned long start = (unsigned long)from;
	unsigned long end = (unsigned long)to;
	unsigned long virt_addr;
	phys_addr_t phys;

	start = start & PAGE_MASK;
	end = PAGE_ALIGN(end);

	for (virt_addr = start; virt_addr < end; virt_addr += PAGE_SIZE) {
		int err;

		err = picovm_pgtable_hyp_early_map_invalid(&picovm_pgtable, virt_addr);
		if (err)
			return err;

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

static void fixmap_clear_slot(struct hyp_fixmap_slot *slot)
{
	picovm_pte_t *ptep = slot->ptep;
	u64 addr = slot->addr;

	WRITE_ONCE(*ptep, *ptep & ~PICOVM_PTE_VALID);
	/*
	 * Irritatingly, the architecture requires that we use inner-shareable
	 * broadcast TLB invalidation here in case another CPU speculates
	 * through our fixmap and decides to create an "amalagamation of the
	 * values held in the TLB" due to the apparent lack of a
	 * break-before-make sequence.
	 *
	 * https://lore.kernel.org/kvm/20221017115209.2099-1-will@kernel.org/T/#mf10dfbaf1eaef9274c581b81c53758918c1d0f03
	 */
	dsb(ishst);
	__tlbi_level(vale2is, __TLBI_VADDR(addr, 0), (PICOVM_PGTABLE_MAX_LEVELS - 1));
	dsb(ish);
	isb();
}

static int __create_fixmap_slot_cb(const struct picovm_pgtable_visit_ctx *ctx)
{
	struct hyp_fixmap_slot *slot = per_cpu_ptr(&fixmap_slots, (u64)ctx->arg);

	if (!picovm_pte_valid(ctx->old))
		return -EINVAL;

	slot->addr = ctx->addr;
	slot->ptep = ctx->ptep;
	/*
	 * Clear the PTE, but keep the page-table page refcount elevated to
	 * prevent it from ever being freed. This lets us manipulate the PTEs
	 * by hand safely without ever needing to allocate memory.
	 */
	fixmap_clear_slot(slot);

	return 0;
}


static int create_fixmap_slot(u64 addr, u64 cpu)
{
	struct picovm_pgtable_walker walker = {
		.cb	= __create_fixmap_slot_cb,
		.arg = (void *)cpu,
	};

	return picovm_pgtable_walk(&picovm_pgtable, addr, PAGE_SIZE, &walker);
}

int hyp_create_pcpu_fixmap(void)
{
	unsigned long addr, i;
	int ret;

	for (i = 0; i < hyp_nr_cpus; i++) {
		ret = picovm_alloc_private_va_range(PAGE_SIZE, &addr);
		if (ret)
			return ret;

		ret = picovm_pgtable_hyp_map(&picovm_pgtable, addr, PAGE_SIZE,
					  __hyp_pa(__hyp_bss_start), PAGE_HYP);
		if (ret)
			return ret;

		ret = create_fixmap_slot(addr, i);
		if (ret)
			return ret;
	}

	return 0;
}

int hyp_create_idmap(u32 hyp_va_bits)
{
	int ret;
	unsigned long start, cur, end;

	start = hyp_virt_to_phys((void *)__hyp_idmap_text_start);
	start = ALIGN_DOWN(start, PAGE_SIZE);

	end = hyp_virt_to_phys((void *)__hyp_idmap_text_end);
	end = ALIGN(end, PAGE_SIZE);

	__io_map_base = start & BIT(hyp_va_bits - 2);
	__io_map_base ^= BIT(hyp_va_bits - 2);

	for (cur = start; cur < end; cur += PAGE_SIZE) {
		ret = picovm_pgtable_hyp_early_map_invalid(&picovm_pgtable, cur);
		if (ret)
			return ret;
	}

	return __picovm_create_mappings(start, end - start, start, PAGE_HYP_EXEC);
}

// DEFINED IN arch/arm64/kvm/hyp/hyp-entry.S
extern unsigned char __bp_harden_hyp_vecs[];

// Copied from arch/arm64/include/asm/spectre.h
#define SZ_2K	0x00000800
#define BP_HARDEN_EL2_SLOTS 4
#define __BP_HARDEN_HYP_VECS_SZ	((BP_HARDEN_EL2_SLOTS - 1) * SZ_2K)

static void *__hyp_bp_vect_base;
int hyp_map_vectors(void)
{
	phys_addr_t phys;
	unsigned long bp_base;
	int ret;

	phys = __hyp_pa(__bp_harden_hyp_vecs);
	ret = __picovm_create_private_mapping(phys, __BP_HARDEN_HYP_VECS_SZ,
					    PAGE_HYP_EXEC, &bp_base);
	if (ret)
		return ret;

	__hyp_bp_vect_base = (void *)bp_base;

	return 0;
}
