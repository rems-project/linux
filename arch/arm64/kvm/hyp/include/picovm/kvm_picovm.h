/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __PICOVM_KVM_PICOVM_H
#define __PICOVM_KVM_PICOVM_H

#include <picovm/linux/types.h>
#include <picovm/linux/memblock.h>
#include <picovm/pgtable.h>

// DEFINED IN kvm_interface.c
extern struct memblock_region hyp_memory[];
extern unsigned int hyp_memblock_nr;


#include <picovm/page.h>
#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
#define SZ_1G	0x40000000

static inline unsigned long __hyp_pgtable_max_pages(unsigned long nr_pages)
{
	unsigned long total = 0, i;

	/* Provision the worst case scenario */
	for (i = 0; i < PICOVM_PGTABLE_MAX_LEVELS; i++) {
		nr_pages = DIV_ROUND_UP(nr_pages, PTRS_PER_PTE);
		total += nr_pages;
	}

	return total;
}

static inline unsigned long __hyp_pgtable_total_pages(void)
{
	unsigned long res = 0, i;

	/* Cover all of memory with page-granularity */
	for (i = 0; i < hyp_memblock_nr; i++) {
		struct memblock_region *reg = &hyp_memory[i];
		res += __hyp_pgtable_max_pages(reg->size >> PAGE_SHIFT);
	}

	return res;
}

static inline unsigned long hyp_s1_pgtable_pages(void)
{
	unsigned long res;

	res = __hyp_pgtable_total_pages();

	/* Allow 1 GiB for private mappings */
	res += __hyp_pgtable_max_pages(SZ_1G >> PAGE_SHIFT);

	return res;
}

static inline unsigned long host_s2_pgtable_pages(void)
{
	unsigned long res;

	/*
	 * Include an extra 16 pages to safely upper-bound the worst case of
	 * concatenated pgds.
	 */
	res = __hyp_pgtable_total_pages() + 16;

	/* Allow 1 GiB for MMIO mappings */
	res += __hyp_pgtable_max_pages(SZ_1G >> PAGE_SHIFT);

	return res;
}

#endif /* __PICOVM_KVM_PICOVM_H */
