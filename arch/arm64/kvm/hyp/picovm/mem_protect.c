#include <picovm/mem_protect.h>
#include <picovm/mm.h>

// TODO(doc): the host Stage 2 page table
struct picovm_pgtable host_pgt;


static inline void picovm_lock_component(void)
{
	// TODO
}

static inline void picovm_unlock_component(void)
{
	// TODO
}

static int __host_check_page_state_range(u64 addr, u64 size,
					 enum picovm_page_state state)
{
	// TODO
	return 0;
}

int host_stage2_idmap_locked(phys_addr_t addr, u64 size,
			     enum picovm_pgtable_prot prot)
{
	// TODO
	// TODO(doc) we don't do the host_stage2_try from actual pKVM
	return picovm_pgtable_stage2_map(&host_pgt, addr, size, addr,
					 prot /*, &host_s2_pool, 0 */);
}


static int __host_set_page_state_range(u64 addr, u64 size,
				       enum picovm_page_state state)
{
	enum picovm_pgtable_prot prot = picovm_mkstate(PICOVM_HOST_MEM_PROT, state);

	return host_stage2_idmap_locked(addr, size, prot);
}

static int __hyp_check_page_state_range(u64 addr, u64 size,
					enum picovm_page_state state)
{
	// TODO
	return 0;
}


/* TODO: need to had a check that the page is not in picovm's private memory, i.e.:
		* backing a page table (picovm's or the host's)
		* backing the code/stack/... of picovm
*/
int __picovm_host_share_hyp(u64 pfn)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)hyp_phys_to_virt(host_addr);

	picovm_lock_component();

	ret = __host_check_page_state_range(host_addr, PAGE_SIZE, PICOVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	if ( !(IS_ENABLED(CONFIG_NVHE_EL2_DEBUG)) )
		goto do_share;

	ret = __hyp_check_page_state_range(hyp_addr, PAGE_SIZE, PICOVM_NOPAGE);
	if (ret)
		goto unlock;

do_share:
	// BEGIN WARN_ON()
	ret = __host_set_page_state_range(host_addr, PAGE_SIZE, PICOVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	{
		void *start = (void *)hyp_addr;
		void *end = start + PAGE_SIZE;
		enum picovm_pgtable_prot prot;

		prot = (PAGE_HYP & ~PICOVM_PAGE_STATE_PROT_MASK) | PICOVM_PAGE_SHARED_BORROWED;
		ret = picovm_create_mappings_locked(start, end, prot);

	}
	// END WARN_ON()
unlock:
	picovm_unlock_component();
	return ret;
}

int __picovm_host_unshare_hyp(u64 pfn)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)hyp_phys_to_virt(host_addr);

	picovm_lock_component();

	ret = __host_check_page_state_range(host_addr, PAGE_SIZE, PICOVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	if ( !(IS_ENABLED(CONFIG_NVHE_EL2_DEBUG)) )
		goto do_unshare;

	ret = __hyp_check_page_state_range(hyp_addr, PAGE_SIZE, PICOVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

do_unshare:
	// BEGIN WARN_ON()
	ret = __host_set_page_state_range(host_addr, PAGE_SIZE, PICOVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	{
    ret = picovm_pgtable_hyp_unmap(&picovm_pgtable, hyp_addr, PAGE_SIZE);
	}
	// END WARN_ON()
unlock:
	picovm_unlock_component();
	return ret;

	// TODO
	return 0;
}
