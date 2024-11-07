#include <picovm/prelude.h>

#include <picovm/mm.h>
#include <picovm/hyp.h>
#include <picovm/mm.h>
#include <picovm/mmu.h>
#include <picovm/pgtable.h>
#include <picovm/mem_protect.h>


// TODO(doc): the host Stage 2 page table
struct host_mmu host_mmu;

static void guest_lock_component(struct picovm_hyp_vm *vm)
{
  // TODO
}

static void guest_unlock_component(struct picovm_hyp_vm *vm)
{
  // TODO
}

static void host_lock_component(void)
{
  hyp_spin_lock(&host_mmu.lock);
}

static void host_unlock_component(void)
{
  hyp_spin_unlock(&host_mmu.lock);
}

static inline void picovm_lock_component(void)
{
	// TODO
}

static inline void picovm_unlock_component(void)
{
	// TODO
}

struct picovm_mem_range {
	u64 start;
	u64 end;
};

static struct memblock_region *find_mem_range(phys_addr_t addr, struct picovm_mem_range *range)
{
	int cur, left = 0, right = hyp_memblock_nr;
	struct memblock_region *reg;
	phys_addr_t end;

	range->start = 0;
	range->end = ULONG_MAX;

	/* The list of memblock regions is sorted, binary search it */
	while (left < right) {
		cur = (left + right) >> 1;
		reg = &hyp_memory[cur];
		end = reg->base + reg->size;
		if (addr < reg->base) {
			right = cur;
			range->end = reg->base;
		} else if (addr >= end) {
			left = cur + 1;
			range->start = end;
		} else {
			range->start = reg->base;
			range->end = end;
			return reg;
		}
	}

	return NULL;
}

bool addr_is_memory(phys_addr_t phys)
{
	struct picovm_mem_range range;

	return !!find_mem_range(phys, &range);
}

static bool addr_is_allowed_memory(phys_addr_t phys)
{
	struct memblock_region *reg;
	struct picovm_mem_range range;

	reg = find_mem_range(phys, &range);

	return reg && !(reg->flags & MEMBLOCK_NOMAP);
}

static bool is_in_mem_range(u64 addr, struct picovm_mem_range *range)
{
	return range->start <= addr && addr < range->end;
}

static bool range_is_memory(u64 start, u64 end)
{
	struct picovm_mem_range r;

	if (!find_mem_range(start, &r))
		return false;

	return is_in_mem_range(end - 1, &r);
}

static void write_vtcr_el2(u64 val)
{
  asm volatile("msr vtcr_el2, %0" : : "r" (val));
}


int picovm_host_prepare_stage2(void)
{
	struct picovm_s2_mmu *mmu = &host_mmu.arch.mmu;
	int ret;

	prepare_host_vtcr();
	hyp_spin_lock_init(&host_mmu.lock);
	ret = picovm_pgtable_stage2_init(&host_mmu.pgt, mmu);
	if (ret)
		return ret;

	return 0;
}


static int host_stage2_idmap(u64 addr)
{
	struct picovm_mem_range range;

	bool is_memory = !!find_mem_range(addr, &range);
	enum picovm_pgtable_prot prot;
	int ret;

	prot = is_memory ? PICOVM_HOST_MEM_PROT : PICOVM_HOST_MMIO_PROT;

	host_lock_component();
  	ret = picovm_pgtable_stage2_map(&host_mmu.pgt, range.start, range.end - range.start, addr, prot);
	host_unlock_component();

	return ret;
}

static void host_inject_abort(struct host_cpu_context *host_ctxt)
{
	u64 spsr = read_sysreg_el2(SYS_SPSR);
	u64 esr = read_sysreg_el2(SYS_ESR);
	u64 ventry, ec;

	/* Repaint the ESR to report a same-level fault if taken from EL1 */
	if ((spsr & PSR_MODE_MASK) != PSR_MODE_EL0t) {
		ec = ESR_ELx_EC(esr);
		if (ec == ESR_ELx_EC_DABT_LOW)
			ec = ESR_ELx_EC_DABT_CUR;
		else if (ec == ESR_ELx_EC_IABT_LOW)
			ec = ESR_ELx_EC_IABT_CUR;
		else
			WARN_ON(1);
		esr &= ~ESR_ELx_EC_MASK;
		esr |= ec << ESR_ELx_EC_SHIFT;
	}

	/*
	 * Since S1PTW should only ever be set for stage-2 faults, we're pretty
	 * much guaranteed that it won't be set in ESR_EL1 by the hardware. So,
	 * let's use that bit to allow the host abort handler to differentiate
	 * this abort from normal userspace faults.
	 *
	 * Note: although S1PTW is RES0 at EL1, it is guaranteed by the
	 * architecture to be backed by flops, so it should be safe to use.
	 */
	esr |= ESR_ELx_S1PTW;

	write_sysreg_el1(esr, SYS_ESR);
	write_sysreg_el1(spsr, SYS_SPSR);
	write_sysreg_el1(read_sysreg_el2(SYS_ELR), SYS_ELR);
	write_sysreg_el1(read_sysreg_el2(SYS_FAR), SYS_FAR);

	ventry = read_sysreg_el1(SYS_VBAR);
	ventry += get_except64_offset(spsr, PSR_MODE_EL1h, except_type_sync);
	write_sysreg_el2(ventry, SYS_ELR);

	spsr = get_except64_cpsr(spsr, system_supports_mte(),
				 read_sysreg_el1(SYS_SCTLR), PSR_MODE_EL1h);
	write_sysreg_el2(spsr, SYS_SPSR);
}

void handle_host_mem_abort(struct host_cpu_context *host_ctxt)
{
	struct picovm_vcpu_fault_info fault;
	u64 esr, addr;
	int ret = 0;

	esr = read_sysreg_el2(SYS_ESR);
	// BUG_ON(!__get_fault_info(esr, &fault));

	addr = (fault.hpfar_el2 & HPFAR_MASK) << 8;
	ret = host_stage2_idmap(addr);

	if (ret == -EPERM)
		host_inject_abort(host_ctxt);
	else
		BUG_ON(ret && ret != -EAGAIN);
}

int __picovm_prot_finalize(void)
{
	struct picovm_s2_mmu *mmu = &host_mmu.arch.mmu;
	struct picovm_nvhe_init_params *params = this_cpu_ptr(&picovm_init_params);

	if (params->hcr_el2 & HCR_VM)
		return -EPERM;

	params->vttbr = picovm_get_vttbr(mmu);
	params->vtcr = host_mmu.arch.vtcr;
	params->hcr_el2 |= HCR_VM;

	/*
	 * The CMO below not only cleans the updated params to the
	 * PoC, but also provides the DSB that ensures ongoing
	 * page-table walks that have started before we trapped to EL2
	 * have completed.
	 */
	picovm_flush_dcache_to_poc(params, sizeof(*params));

	write_sysreg(params->hcr_el2, hcr_el2);
	__load_stage2(&host_mmu.arch.mmu, &host_mmu.arch);

	/*
	 * Make sure to have an ISB before the TLB maintenance below but only
	 * when __load_stage2() doesn't include one already.
	 */
	asm(ALTERNATIVE("isb", "nop", ARM64_WORKAROUND_SPECULATIVE_AT));

	/* Invalidate stale HCR bits that may be cached in TLBs */
	__tlbi(vmalls12e1);
	dsb(nsh);
	isb();

	return 0;
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
	return check_page_state_range(&host_mmu.pgt, addr, size, &d);
}

int host_stage2_idmap_locked(phys_addr_t addr, u64 size,
			     enum picovm_pgtable_prot prot)
{
	// TODO(doc) we don't do the host_stage2_try from actual pKVM
	return picovm_pgtable_stage2_map(&host_mmu.pgt, addr, size, addr,
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
}
