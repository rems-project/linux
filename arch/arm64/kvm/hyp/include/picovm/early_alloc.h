/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PICOVM_HYP_EARLY_ALLOC_H
#define __PICOVM_HYP_EARLY_ALLOC_H

void hyp_early_alloc_init(void *virt, unsigned long size);
// unsigned long hyp_early_alloc_nr_used_pages(void);
void *hyp_early_alloc_page(void);
void *hyp_early_alloc_contig(unsigned int nr_pages);

#endif /* __PICOVM_HYP_EARLY_ALLOC_H */
