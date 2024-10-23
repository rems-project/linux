#include <picovm/picovm_pgtable.h>
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

// TODO: how to implement zalloc pages
static void *host_s2_zalloc_pages_exact(size_t size)
{
  // TODO
  void *addr;
	// void *addr = hyp_alloc_pages(&host_s2_pool, get_order(size));
	//
	// hyp_split_page(hyp_virt_to_page(addr));
	//
	// /*
	//  * The size of concatenated PGDs is always a power of two of PAGE_SIZE,
	//  * so there should be no need to free any of the tail pages to make the
	//  * allocation exact.
	//  */
	// WARN_ON(size != (PAGE_SIZE << get_order(size)));

	return addr;
}

struct check_walk_data {
	enum picovm_page_state	desired;
	enum picovm_page_state	(*get_page_state)(picovm_pte_t pte, u64 addr);
};

static int __check_page_state_visitor(const struct picovm_pgtable_visit_ctx *ctx)
{
	struct check_walk_data *d = ctx->arg;

	return d->get_page_state(ctx->old, ctx->addr) == d->desired ? 0 : -1;
}

static int check_page_state_range(struct picovm_pgtable *pgt, u64 addr, u64 size,
				  struct check_walk_data *data)
{
	struct picovm_pgtable_walker walker = {
		.cb	= __check_page_state_visitor,
		.arg	= data,
	};

	return picovm_pgtable_walk(pgt, addr, size, &walker);
}

static enum picovm_page_state host_get_page_state(picovm_pte_t pte, u64 addr)
{
	// if (!addr_is_allowed_memory(addr))
	// 	return PICOVM_NOPAGE;

	if (!picovm_pte_valid(pte) && pte)
		return PICOVM_NOPAGE;

	return picovm_getstate(picovm_pgtable_stage2_pte_prot(pte));
}


static int __host_check_page_state_range(u64 addr, u64 size,
					 enum picovm_page_state state)
{
  struct check_walk_data d = {
    .desired = state,
    .get_page_state = host_get_page_state
  };
  
  // hyp_assert_lock_held(&host_mmu.lock);
	return check_page_state_range(&host_pgt, addr, size, &d);
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
