/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	arch/arm64/kvm/hyp/include/nvhe/mem_protect.h
 */

#ifndef __PICOVM_MEM_PROTECT_H
#define __PICOVM_MEM_PROTECT_H

#include <picovm/host.h>
#include <picovm/hyp.h>
#include <picovm/picovm.h>
#include <picovm/pgtable.h>

enum picovm_page_state {
	PICOVM_PAGE_OWNED		= 0ULL,
	PICOVM_PAGE_SHARED_OWNED	= PICOVM_PGTABLE_PROT_SW0,
	PICOVM_PAGE_SHARED_BORROWED	= PICOVM_PGTABLE_PROT_SW1,
	__PICOVM_PAGE_RESERVED		= PICOVM_PGTABLE_PROT_SW0 |
					  PICOVM_PGTABLE_PROT_SW1,

	/* Meta-states which aren't encoded directly in the PTE's SW bits */
	PICOVM_NOPAGE,
};

#define PICOVM_PAGE_STATE_PROT_MASK	(PICOVM_PGTABLE_PROT_SW0 | PICOVM_PGTABLE_PROT_SW1)
static inline enum picovm_pgtable_prot picovm_mkstate(enum picovm_pgtable_prot prot,
						      enum picovm_page_state state)
{
	return (prot & ~PICOVM_PAGE_STATE_PROT_MASK) | state;
}

static inline enum picovm_page_state picovm_getstate(enum picovm_pgtable_prot prot)
{
	return prot & PICOVM_PAGE_STATE_PROT_MASK;
}

struct host_mmu {
	struct picovm_arch arch;
	struct picovm_pgtable pgt;
	hyp_spinlock_t lock;
};
extern struct host_mmu host_mmu;

/* This corresponds to page-table locking order */
enum picovm_component_id {
	PICOVM_ID_HOST,
	PICOVM_ID_HYP,
	PICOVM_ID_GUEST,
};

extern unsigned long hyp_nr_cpus;

bool addr_is_memory(phys_addr_t phys);
int picovm_host_prepare_stage2(void *pgt_pool_base);
int host_stage2_idmap_locked(phys_addr_t addr, u64 size, enum picovm_pgtable_prot prot);
int host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id);

int __picovm_prot_finalize(void);
int __picovm_host_share_hyp(u64 pfn);
int __picovm_host_unshare_hyp(u64 pfn);

void handle_host_mem_abort(struct picovm_cpu_context *host_ctxt);


#endif /* __PICOVM_MEM_PROTECT_H */
