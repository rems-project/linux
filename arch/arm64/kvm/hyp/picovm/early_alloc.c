// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <picovm/prelude.h>
#include <picovm/picovm_pgtable.h>
#include <picovm/early_alloc.h>
#include <picovm/memory.h>

// NOTE: based on linux/arch/arm64/kvm/hyp/nvhe/early_alloc.c
s64 __ro_after_init hyp_physvirt_offset;

static unsigned long base;
static unsigned long end;
static unsigned long cur;


unsigned long hyp_early_alloc_nr_used_pages(void)
{
	return (cur - base) >> PAGE_SHIFT;
}

void *hyp_early_alloc_contig(unsigned int nr_pages)
{
	unsigned long size = (nr_pages << PAGE_SHIFT);
	void *ret = (void *)cur;

	if (!nr_pages)
		return NULL;

	if (end - cur < size)
		return NULL;

	cur += size;
  // TODO: include/asm...
	memset(ret, 0, size);

	return ret;
}

void *hyp_early_alloc_page(void)
{
	return hyp_early_alloc_contig(1);
}

static void hyp_early_alloc_get_page(void *addr) { }
static void hyp_early_alloc_put_page(void *addr) { }

void hyp_early_alloc_init(void *virt, unsigned long size)
{
	base = cur = (unsigned long)virt;
	end = base + size;
}

