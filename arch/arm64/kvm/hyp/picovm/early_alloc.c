// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm64/kvm/hyp/nvhe/early_alloc.c
 */
#include <picovm/linux/types.h>
#include <picovm/page.h>
#include <picovm/lib/string.h>

#include <picovm/early_alloc.h>

static unsigned long hyp_base;
static unsigned long hyp_end;
static unsigned long hyp_cur;

static unsigned long host_base;
static unsigned long host_end;
static unsigned long host_cur;

// TODO: unused so far by picovm (pKVM uses it in its setup.c)
// unsigned long hyp_early_alloc_nr_used_pages(void)
// {
// 	return (cur - base) >> PAGE_SHIFT;
// }

void *early_alloc_contig(unsigned long *base, unsigned long *end, unsigned long *cur, unsigned int nr_pages)
{
	unsigned long size = (nr_pages << PAGE_SHIFT);
	void *ret = (void *)(*cur);

	if (!nr_pages)
		return NULL;

	if (*end - *cur < size)
		return NULL;

	*cur += size;
	memset(ret, 0, size);

	return ret;
}

void *hyp_early_alloc_contig(unsigned int nr_pages)
{
	return early_alloc_contig(&hyp_base, &hyp_end, &hyp_cur, nr_pages);
}

void *hyp_early_alloc_page(void)
{
	return hyp_early_alloc_contig(1);
}

void hyp_early_alloc_init(void *virt, unsigned long size)
{
	hyp_base = hyp_cur = (unsigned long)virt;
	hyp_end = hyp_base + size;
}

void *host_stage2_early_alloc_contig(unsigned int nr_pages)
{
	return early_alloc_contig(&host_base, &host_end, &host_cur, nr_pages);
}

void *host_stage2_early_alloc_page(void)
{
	return host_stage2_early_alloc_contig(1);
}

void host_stage2_early_alloc_init(void *virt, unsigned long size)
{
	host_base = host_cur = (unsigned long)virt;
	host_end = host_base + size;
}
