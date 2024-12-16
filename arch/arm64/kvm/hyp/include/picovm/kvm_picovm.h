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

#endif /* __PICOVM_KVM_PICOVM_H */
