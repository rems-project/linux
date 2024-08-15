/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#ifndef __PICOVM_MEM_PROTECT_H
#define __PICOVM_MEM_PROTECT_H

#include <picovm/prelude.h>
#include <picovm/picovm_pgtable.h>
#include <picovm/picovm.h>


// TODO(doc/license): based on linux/arch/arm64/kvm/hyp/include/nvhe/mem_protect.h::enum pkvm_page_state
enum picovm_page_state {
	PICOVM_PAGE_OWNED		= 0ULL,
	PICOVM_PAGE_SHARED_OWNED	= PICOVM_PGTABLE_PROT_SW0,
	PICOVM_PAGE_SHARED_BORROWED	= PICOVM_PGTABLE_PROT_SW1,
	__PICOVM_PAGE_RESERVED		= PICOVM_PGTABLE_PROT_SW0 |
					  PICOVM_PGTABLE_PROT_SW1,

	/* Meta-states which aren't encoded directly in the PTE's SW bits */
	PICOVM_NOPAGE,
};

// TODO(doc/license): based on linux/arch/arm64/kvm/hyp/include/nvhe/mem_protect.h
#define PICOVM_PAGE_STATE_PROT_MASK	(PICOVM_PGTABLE_PROT_SW0 | PICOVM_PGTABLE_PROT_SW1)
static inline enum picovm_pgtable_prot picovm_mkstate(enum picovm_pgtable_prot prot,
						      enum picovm_page_state state)
{
	return (prot & ~PICOVM_PAGE_STATE_PROT_MASK) | state;
}


int __picovm_host_share_hyp(u64 pfn);
int __picovm_host_unshare_hyp(u64 pfn);

void handle_host_mem_abort(struct host_cpu_context *host_ctxt);


#endif /* __PICOVM_MEM_PROTECT_H */
