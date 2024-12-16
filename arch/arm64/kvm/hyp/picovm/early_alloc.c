// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm64/kvm/hyp/nvhe/early_alloc.c
 */
#include <picovm/linux/types.h>
#include <picovm/page.h>
#include <picovm/lib/string.h>

#include <picovm/early_alloc.h>

static unsigned long base;
static unsigned long end;
static unsigned long cur;

// TODO: unused so far by picovm (pKVM uses it in its setup.c)
// unsigned long hyp_early_alloc_nr_used_pages(void)
// {
// 	return (cur - base) >> PAGE_SHIFT;
// }

void *hyp_early_alloc_contig(unsigned int nr_pages)
{
	unsigned long size = (nr_pages << PAGE_SHIFT);
	void *ret = (void *)cur;

	if (!nr_pages)
		return NULL;

	if (end - cur < size)
		return NULL;

	cur += size;
	memset(ret, 0, size);

	return ret;
}

void *hyp_early_alloc_page(void)
{
	return hyp_early_alloc_contig(1);
}

void hyp_early_alloc_init(void *virt, unsigned long size)
{
	base = cur = (unsigned long)virt;
	end = base + size;
}
