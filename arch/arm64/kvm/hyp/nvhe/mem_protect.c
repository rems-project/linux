// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>
#include <asm/stage2_pgtable.h>

#include <hyp/fault.h>

#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>

#ifdef CONFIG_NVHE_GHOST_SPEC

#include <hyp/ghost_extra_debug-pl011.h>
#include <nvhe/ghost_pgtable.h>
#include <nvhe/ghost_compute_abstraction.h>
#include <nvhe/ghost_control.h>

#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
#include <nvhe/ghost_simplified_model.h>
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

//horrible hack for ghost code in nvhe/iommu/s2mpu.c
// but in the default build # CONFIG_KVM_S2MPU is not set
// and (looking in the Makefile) it seems that file isn't even linked in
// void __kvm_nvhe_ghost_dump_s2mpus(u64 indent);

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wunused-variable"

#endif /* CONFIG_NVHE_GHOST_SPEC */

#define KVM_HOST_S2_FLAGS (KVM_PGTABLE_S2_NOFWB | KVM_PGTABLE_S2_IDMAP)

struct host_mmu host_mmu;

static struct hyp_pool host_s2_pool;

static DEFINE_PER_CPU(struct pkvm_hyp_vm *, __current_vm);
#define current_vm (*this_cpu_ptr(&__current_vm))

static void guest_lock_component(struct pkvm_hyp_vm *vm)
{
	hyp_spin_lock(&vm->lock);
	current_vm = vm;
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ghost_exec_enabled())
		record_and_check_abstraction_vm_pre(vm);
#endif /* CONFIG_NVHE_GHOST_SPEC */
}

static void guest_unlock_component(struct pkvm_hyp_vm *vm)
{
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ghost_exec_enabled())
		record_and_copy_abstraction_vm_post(vm);
#endif /* CONFIG_NVHE_GHOST_SPEC */
	current_vm = NULL;
	hyp_spin_unlock(&vm->lock);
}

static void host_lock_component(void)
{
	hyp_spin_lock(&host_mmu.lock);
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ghost_exec_enabled())
		record_and_check_abstraction_host_pre();
#endif /* CONFIG_NVHE_GHOST_SPEC */
}

static void host_unlock_component(void)
{
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ghost_exec_enabled())
		record_and_copy_abstraction_host_post();
#endif /* CONFIG_NVHE_GHOST_SPEC */
	hyp_spin_unlock(&host_mmu.lock);
}



static void hyp_lock_component(void)
{
	hyp_spin_lock(&pkvm_pgd_lock);
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ghost_exec_enabled())
		record_and_check_abstraction_pkvm_pre();
#endif /* CONFIG_NVHE_GHOST_SPEC */
}

static void hyp_unlock_component(void)
{
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ghost_exec_enabled())
		record_and_copy_abstraction_pkvm_post();
#endif /* CONFIG_NVHE_GHOST_SPEC */
	hyp_spin_unlock(&pkvm_pgd_lock);
}

static void *host_s2_zalloc_pages_exact(size_t size)
{
	void *addr = hyp_alloc_pages(&host_s2_pool, get_order(size));

	hyp_split_page(hyp_virt_to_page(addr));

	/*
	 * The size of concatenated PGDs is always a power of two of PAGE_SIZE,
	 * so there should be no need to free any of the tail pages to make the
	 * allocation exact.
	 */
	WARN_ON(size != (PAGE_SIZE << get_order(size)));

	return addr;
}

static void *host_s2_zalloc_page(void *pool)
{
	return hyp_alloc_pages(pool, 0);
}

static void host_s2_get_page(void *addr)
{
	hyp_get_page(&host_s2_pool, addr);
}

static void host_s2_put_page(void *addr)
{
	hyp_put_page(&host_s2_pool, addr);
}

static void host_s2_free_removed_table(void *addr, u32 level)
{
	kvm_pgtable_stage2_free_removed(&host_mmu.mm_ops, addr, level);
}

static int prepare_s2_pool(void *pgt_pool_base)
{
	unsigned long nr_pages, pfn;
	int ret;

	pfn = hyp_virt_to_pfn(pgt_pool_base);
	nr_pages = host_s2_pgtable_pages();
	ret = hyp_pool_init(&host_s2_pool, pfn, nr_pages, 0);
	if (ret)
		return ret;

	host_mmu.mm_ops = (struct kvm_pgtable_mm_ops) {
		.zalloc_pages_exact = host_s2_zalloc_pages_exact,
		.zalloc_page = host_s2_zalloc_page,
		.free_removed_table = host_s2_free_removed_table,
		.phys_to_virt = hyp_phys_to_virt,
		.virt_to_phys = hyp_virt_to_phys,
		.page_count = hyp_page_count,
		.get_page = host_s2_get_page,
		.put_page = host_s2_put_page,
	};

	return 0;
}

static void prepare_host_vtcr(void)
{
	u32 parange, phys_shift;

	/* The host stage 2 is id-mapped, so use parange for T0SZ */
	parange = kvm_get_parange(id_aa64mmfr0_el1_sys_val);
	phys_shift = id_aa64mmfr0_parange_to_phys_shift(parange);

	host_mmu.arch.vtcr = kvm_get_vtcr(id_aa64mmfr0_el1_sys_val,
					  id_aa64mmfr1_el1_sys_val, phys_shift);
}

static bool host_stage2_force_pte_cb(u64 addr, u64 end, enum kvm_pgtable_prot prot);

int kvm_host_prepare_stage2(void *pgt_pool_base)
{
	struct kvm_s2_mmu *mmu = &host_mmu.arch.mmu;
	int ret;

	prepare_host_vtcr();
	hyp_spin_lock_init(&host_mmu.lock);
	mmu->arch = &host_mmu.arch;

	ret = prepare_s2_pool(pgt_pool_base);
	if (ret)
		return ret;

	ret = __kvm_pgtable_stage2_init(&host_mmu.pgt, mmu,
					&host_mmu.mm_ops, KVM_HOST_S2_FLAGS,
					host_stage2_force_pte_cb);
	if (ret)
		return ret;

	mmu->pgd_phys = __hyp_pa(host_mmu.pgt.pgd);
	mmu->pgt = &host_mmu.pgt;
	atomic64_set(&mmu->vmid.id, 0);

	return 0;
}

static bool guest_stage2_force_pte_cb(u64 addr, u64 end,
				      enum kvm_pgtable_prot prot)
{
	return true;
}

static void *guest_s2_zalloc_pages_exact(size_t size)
{
	void *addr = hyp_alloc_pages(&current_vm->pool, get_order(size));

	WARN_ON(size != (PAGE_SIZE << get_order(size)));
	hyp_split_page(hyp_virt_to_page(addr));

	return addr;
}

static void guest_s2_free_pages_exact(void *addr, unsigned long size)
{
	u8 order = get_order(size);
	unsigned int i;

	for (i = 0; i < (1 << order); i++)
		hyp_put_page(&current_vm->pool, addr + (i * PAGE_SIZE));
}

static void *guest_s2_zalloc_page(void *mc)
{
	struct hyp_page *p;
	void *addr;

	addr = hyp_alloc_pages(&current_vm->pool, 0);
	if (addr)
		return addr;

	addr = pop_hyp_memcache(mc, hyp_phys_to_virt);
	if (!addr)
		return addr;

	memset(addr, 0, PAGE_SIZE);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	for (u64 p = (u64)addr; p < (u64)addr + PAGE_SIZE; p += sizeof(u64)) {
		ghost_simplified_model_step_write(WMO_plain, hyp_virt_to_phys((u64 *)p), 0);
	}
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	p = hyp_virt_to_page(addr);
	memset(p, 0, sizeof(*p));
	p->refcount = 1;

	return addr;
}

static void guest_s2_get_page(void *addr)
{
	hyp_get_page(&current_vm->pool, addr);
}

static void guest_s2_put_page(void *addr)
{
	hyp_put_page(&current_vm->pool, addr);
}

static void clean_dcache_guest_page(void *va, size_t size)
{
	__clean_dcache_guest_page(hyp_fixmap_map(__hyp_pa(va)), size);
	hyp_fixmap_unmap();
}

static void invalidate_icache_guest_page(void *va, size_t size)
{
	__invalidate_icache_guest_page(hyp_fixmap_map(__hyp_pa(va)), size);
	hyp_fixmap_unmap();
}

int kvm_guest_prepare_stage2(struct pkvm_hyp_vm *vm, void *pgd)
{
	struct kvm_s2_mmu *mmu = &vm->kvm.arch.mmu;
	unsigned long nr_pages;
	int ret;

	nr_pages = kvm_pgtable_stage2_pgd_size(vm->kvm.arch.vtcr) >> PAGE_SHIFT;
	ret = hyp_pool_init(&vm->pool, hyp_virt_to_pfn(pgd), nr_pages, 0);
	if (ret)
		return ret;

	hyp_spin_lock_init(&vm->lock);
	vm->mm_ops = (struct kvm_pgtable_mm_ops) {
		.zalloc_pages_exact	= guest_s2_zalloc_pages_exact,
		.free_pages_exact	= guest_s2_free_pages_exact,
		.zalloc_page		= guest_s2_zalloc_page,
		.phys_to_virt		= hyp_phys_to_virt,
		.virt_to_phys		= hyp_virt_to_phys,
		.page_count		= hyp_page_count,
		.get_page		= guest_s2_get_page,
		.put_page		= guest_s2_put_page,
		.dcache_clean_inval_poc	= clean_dcache_guest_page,
		.icache_inval_pou	= invalidate_icache_guest_page,
	};

	guest_lock_component(vm);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	ghost_simplified_model_step_hint(GHOST_HINT_SET_ROOT_LOCK, (u64)mmu->pgt->pgd, (u64)&vm->lock);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	ret = __kvm_pgtable_stage2_init(mmu->pgt, mmu, &vm->mm_ops, 0,
					guest_stage2_force_pte_cb);
	guest_unlock_component(vm);
	if (ret)
		return ret;

	vm->kvm.arch.mmu.pgd_phys = __hyp_pa(vm->pgt.pgd);

	return 0;
}

static int reclaim_walker(const struct kvm_pgtable_visit_ctx *ctx,
			  enum kvm_pgtable_walk_flags visit)
{
	kvm_pte_t pte = *ctx->ptep;
	struct hyp_page *page;

	if (!kvm_pte_valid(pte))
		return 0;

	page = hyp_phys_to_page(kvm_pte_to_phys(pte));
	switch (pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte))) {
	case PKVM_PAGE_OWNED:
		page->flags |= HOST_PAGE_NEED_POISONING;
		fallthrough;
	case PKVM_PAGE_SHARED_BORROWED:
	case PKVM_PAGE_SHARED_OWNED:
		page->flags |= HOST_PAGE_PENDING_RECLAIM;
		break;
	default:
		return -EPERM;
	}

	return 0;
}

void reclaim_guest_pages(struct pkvm_hyp_vm *vm, struct kvm_hyp_memcache *mc)
{

	struct kvm_pgtable_walker walker = {
		.cb     = reclaim_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF
	};
	void *addr;

	host_lock_component();
	guest_lock_component(vm);

	/* Reclaim all guest pages and dump all pgtable pages in the hyp_pool */
	BUG_ON(kvm_pgtable_walk(&vm->pgt, 0, BIT(vm->pgt.ia_bits), &walker));
	kvm_pgtable_stage2_destroy(&vm->pgt);
	vm->kvm.arch.mmu.pgd_phys = 0ULL;

	guest_unlock_component(vm);
	host_unlock_component();

	/* Drain the hyp_pool into the memcache */
	addr = hyp_alloc_pages(&vm->pool, 0);
	while (addr) {
		memset(hyp_virt_to_page(addr), 0, sizeof(struct hyp_page));
		push_hyp_memcache(mc, addr, hyp_virt_to_phys);
		WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(addr), 1));
		addr = hyp_alloc_pages(&vm->pool, 0);
	}
}

int __pkvm_prot_finalize(void)
{
	struct kvm_s2_mmu *mmu = &host_mmu.arch.mmu;
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);

	if (params->hcr_el2 & HCR_VM)
		return -EPERM;

	params->vttbr = kvm_get_vttbr(mmu);
	params->vtcr = host_mmu.arch.vtcr;
	params->hcr_el2 |= HCR_VM;

	/*
	 * The CMO below not only cleans the updated params to the
	 * PoC, but also provides the DSB that ensures ongoing
	 * page-table walks that have started before we trapped to EL2
	 * have completed.
	 */
	kvm_flush_dcache_to_poc(params, sizeof(*params));

	write_sysreg(params->hcr_el2, hcr_el2);
	__load_stage2(&host_mmu.arch.mmu, &host_mmu.arch);

	/*
	 * Make sure to have an ISB before the TLB maintenance below but only
	 * when __load_stage2() doesn't include one already.
	 */
	asm(ALTERNATIVE("isb", "nop", ARM64_WORKAROUND_SPECULATIVE_AT));

	/* Invalidate stale HCR bits that may be cached in TLBs */
	__tlbi(vmalls12e1);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	ghost_simplified_model_step_tlbi1(TLBI_vmalls12e1);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	dsb(nsh);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	ghost_simplified_model_step_dsb(DSB_nsh);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	isb();
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	ghost_simplified_model_step_isb();
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

#ifdef CONFIG_NVHE_GHOST_SPEC
	record_abstraction_loaded_vcpu_and_check_none();
	this_cpu_ptr(&ghost_cpu_run_state)->guest_running = false;

#ifdef CONFIG_NVHE_GHOST_SPEC_NOISy
	if (GHOST_DUMP_CPU_STATE_ON_INIT) {
		ghost_dump_sysregs();
	}
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */

#endif /* CONFIG_NVHE_GHOST_SPEC */
	return 0;
}

static int host_stage2_unmap_dev_all(void)
{
	struct kvm_pgtable *pgt = &host_mmu.pgt;
	struct memblock_region *reg;
	u64 addr = 0;
	int i, ret;

	/* Unmap all non-memory regions to recycle the pages */
	for (i = 0; i < hyp_memblock_nr; i++, addr = reg->base + reg->size) {
		reg = &hyp_memory[i];
		ret = kvm_pgtable_stage2_unmap(pgt, addr, reg->base - addr);
		if (ret)
			return ret;
	}
	return kvm_pgtable_stage2_unmap(pgt, addr, BIT(pgt->ia_bits) - addr);
}

struct kvm_mem_range {
	u64 start;
	u64 end;
};

static struct memblock_region *find_mem_range(phys_addr_t addr, struct kvm_mem_range *range)
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
	struct kvm_mem_range range;

	return !!find_mem_range(phys, &range);
}

static bool addr_is_allowed_memory(phys_addr_t phys)
{
	struct memblock_region *reg;
	struct kvm_mem_range range;

	reg = find_mem_range(phys, &range);

	return reg && !(reg->flags & MEMBLOCK_NOMAP);
}

static bool is_in_mem_range(u64 addr, struct kvm_mem_range *range)
{
	return range->start <= addr && addr < range->end;
}

static bool range_is_memory(u64 start, u64 end)
{
	struct kvm_mem_range r;

	if (!find_mem_range(start, &r))
		return false;

	return is_in_mem_range(end - 1, &r);
}

static inline int __host_stage2_idmap(u64 start, u64 end,
				      enum kvm_pgtable_prot prot)
{
	return kvm_pgtable_stage2_map(&host_mmu.pgt, start, end - start, start,
				      prot, &host_s2_pool, 0);
}

/*
 * The pool has been provided with enough pages to cover all of memory with
 * page granularity, but it is difficult to know how much of the MMIO range
 * we will need to cover upfront, so we may need to 'recycle' the pages if we
 * run out.
 */
#define host_stage2_try(fn, ...)					\
	({								\
		int __ret;						\
		hyp_assert_lock_held(&host_mmu.lock);			\
		__ret = fn(__VA_ARGS__);				\
		if (__ret == -ENOMEM) {					\
			__ret = host_stage2_unmap_dev_all();		\
			if (!__ret)					\
				__ret = fn(__VA_ARGS__);		\
		}							\
		__ret;							\
	 })

static inline bool range_included(struct kvm_mem_range *child,
				  struct kvm_mem_range *parent)
{
	return parent->start <= child->start && child->end <= parent->end;
}

static int host_stage2_adjust_range(u64 addr, struct kvm_mem_range *range)
{
	struct kvm_mem_range cur;
	kvm_pte_t pte;
	u32 level;
	int ret;

	hyp_assert_lock_held(&host_mmu.lock);
	ret = kvm_pgtable_get_leaf(&host_mmu.pgt, addr, &pte, &level);
	if (ret)
		return ret;

	if (kvm_pte_valid(pte))
		return -EAGAIN;

	if (pte)
		return -EPERM;

	do {
		u64 granule = kvm_granule_size(level);
		cur.start = ALIGN_DOWN(addr, granule);
		cur.end = cur.start + granule;
		level++;
	} while ((level < KVM_PGTABLE_MAX_LEVELS) &&
			!(kvm_level_supports_block_mapping(level) &&
			  range_included(&cur, range)));

	*range = cur;

	return 0;
}

int host_stage2_idmap_locked(phys_addr_t addr, u64 size,
			     enum kvm_pgtable_prot prot)
{
	return host_stage2_try(__host_stage2_idmap, addr, addr + size, prot);
}

int host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id)
{
	return host_stage2_try(kvm_pgtable_stage2_set_owner, &host_mmu.pgt,
			       addr, size, &host_s2_pool, owner_id);
}

static bool host_stage2_force_pte_cb(u64 addr, u64 end, enum kvm_pgtable_prot prot)
{
	/*
	 * Block mappings must be used with care in the host stage-2 as a
	 * kvm_pgtable_stage2_map() operation targeting a page in the range of
	 * an existing block will delete the block under the assumption that
	 * mappings in the rest of the block range can always be rebuilt lazily.
	 * That assumption is correct for the host stage-2 with RWX mappings
	 * targeting memory or RW mappings targeting MMIO ranges (see
	 * host_stage2_idmap() below which implements some of the host memory
	 * abort logic). However, this is not safe for any other mappings where
	 * the host stage-2 page-table is in fact the only place where this
	 * state is stored. In all those cases, it is safer to use page-level
	 * mappings, hence avoiding to lose the state because of side-effects in
	 * kvm_pgtable_stage2_map().
	 */
	if (range_is_memory(addr, end))
		return prot != PKVM_HOST_MEM_PROT;
	else
		return prot != PKVM_HOST_MMIO_PROT;
}

static int host_stage2_idmap(u64 addr)
{
	struct kvm_mem_range range;

	// PS: t012345he mm.c struct memblock_region hyp_memory[] is initialised by pkvm.c register_memblock_regions to a sorted copy of the regions available to linux, using the include/linux/memblock.h for_each_mem_region (struct memblock_region is also defined there).  I guess hyp_memory[] is constant after initialisation?   The find_mem_range above finds the enclosing region for addr if there is one, writing into range.  The memblock_region's have flags (HOTPLUG/MIRROR/NOMAP), but find_mem_range ignores them, so I think we can abstract hyp_memory[] to just a set of physical addresses (closed under the same-4K-page relation) (or, equivalently, a set of page addresses or page frame numbers) (or reuse our mapping and maplet code).
	// In the QEMU boot these are:
	//  base:0x........40000000 base':0x.......1385b0000 size:0x........f85b0000 flags:
	// -base:0x.......1385b0000 base':0x.......138750000 size:0x..........1a0000 flags:
	// -base:0x.......138750000 base':0x.......13bc20000 size:0x.........34d0000 flags:
	// -base:0x.......13bc20000 base':0x.......13c000000 size:0x..........3e0000 flags:
	// -base:0x.......13c000000 base':0x.......140000000 size:0x.........4000000 flags:
	// Why five contiguous regions?   Different permissions.
        // I'll only pay attention to the memory case for now, not the device case

	bool is_memory = !!find_mem_range(addr, &range);
	enum kvm_pgtable_prot prot;
	int ret;

	prot = is_memory ? PKVM_HOST_MEM_PROT : PKVM_HOST_MMIO_PROT;

	host_lock_component();

#ifdef CONFIG_NVHE_GHOST_SPEC
	bool ghost_check = ghost_control_check_enabled(__func__);
	u64 i=0; /* base indent */
	int cur;
	mapping mapping_pre, mapping_post; // interpretation of pgt on entry and exit
	mapping mapping_pre_annot, mapping_post_annot; // interpretation of pgtable on entry and exit, cut down to annot parts
	//mapping mapping_requested;
	mapping mapping_hyp_memory;
	mapping mapping_post_nonannot;
	if (ghost_check) {
		hyp_putsxn("\nhost_stage2_idmap addr",addr,64); hyp_putc('\n');
		//hyp_putsxn("kvm_iommu_ops.host_stage2_adjust_mmio_range",(u64)kvm_iommu_ops.host_stage2_adjust_mmio_range,64);
		//hyp_putsp("\n");
		ghost_dump_hyp_memory(i+2);
		//	ghost_dump_s2mpus(i+2);
		// (we can't meaningfully record the on-entry host pagetable abstraction until we've taken the lock - and in any case, instead of recomputing the abstraction, we should be able to pull it from the lock invariant)
	}

	if (ghost_check) {
		ghost_lock_maplets();
		mapping_pre = ghost_record_pgtable_and_check(host_mmu.pgt.ghost_mapping, &host_mmu.pgt, true/*dump*/, "host_mmu.pgt", i+2);
		ghost_dump_pgtable_locked(&host_mmu.pgt,"before: host_mmu.pgt", i);
		ghost_unlock_maplets();
	}
	// PS: the host_stage2_adjust_range uses kvm_pgtable_get_leaf (which does a kvm_pgtable_walk) to find the current pte and level for addr. If there's a valid entry, it returns -EAGAIN (presumably another thread has mapped it since the fault); if there's a nonzero invalid entry, it returns -EPERM (indicating that there's another owner and we shouldn't map it); otherwise it iterates from this level downwards looking for a level at which the level supports a block mapping for a block included in the range.  (Though in the pKVM boot it doesn't seem to ever make block mappings for actual memory??)  The tree geometry means that there won't be any annotated ptes if we find a proper block mapping.
#endif /* CONFIG_NVHE_GHOST_SPEC */

	ret = host_stage2_adjust_range(addr, &range);
	if (ret)
		goto unlock;

	ret = host_stage2_idmap_locked(range.start, range.end - range.start, prot);

#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ghost_check) {
		// sketch of the postcondition - punting on sundry cases
		// some of this is common with pgtable.c stage2 postconditions and should be abstracted out when we know better what they all are
		ghost_lock_maplets();
		mapping_post = ghost_record_pgtable(&host_mmu.pgt, "host_stage2_idmap post", i+2);
		ghost_dump_pgtable_locked(&host_mmu.pgt,"after: host_mmu.pgt", i);
		// the atomicity is interesting here: after the host_unlock_component(), what remains guaranteed?

		// the naive postcondition would check mapping_post included in mapping_pre + mapping_requested, but that would be wrong, as the code might map more than the requested address - any block contained in a memblock_region.  Ignoring device memory, the upper bound is really the hyp_memory[] minus the annotation parts of the on-entry mapping.  So we first compute the interpretation of those two.   For device memory, it looks as if currently (with s2mpu.c not turned on) we should allow _any_ non-hyp_memory mapping, but at PKVM_HOST_MMIO_PROT.  So how is that supposed to protect devices from guests?  IIRC Will said the s2mpu.c is turned on in later versions.


		// we think the hyp_memory is constant, while the annotations will change; they should be ghost state for the spec, but here we'll compute them from the host tables on entry
		mapping_hyp_memory = mapping_empty_();
		for (cur=0; cur<hyp_memblock_nr; cur++)
			extend_mapping_coalesce(&mapping_hyp_memory, hyp_memory[cur].base, hyp_memory[cur].size / PAGE_SIZE, maplet_target_mapped(hyp_memory[cur].base, DUMMY_ATTR, dummy_aal()));
		mapping_pre_annot = mapping_annot(mapping_pre);

		// NB this addr might have been "guessed" - so the following is (at least) awkward to talk about in the top-level spec - it's not necessarily the fault address.  We tend to think a pure safety spec is what we should go for, without any progress result, and so we should omit this here.  The underlying `pgtable.c:kvm_pgtable_stage2_map` will have a stronger spec that we'll weaken for its usag
		// postcondition: if addr is in memory and is not annotated in the stage 2 map, it's in mapping_post
		//if (mapping_in_domain(addr, mapping_hyp_memory) && !mapping_in_domain(addr, mapping_pre_annot)) {
		//	mapping_requested = mapping_singleton(ALIGN_DOWN(addr,PAGE_SIZE), ALIGN_DOWN(addr,PAGE_SIZE), 1, DUMMY_ATTR);
		//	mapping_submapping(mapping_requested, mapping_post, "host_stage2_idmap post", "mapping_requested", "mapping_post", i+2);
		//} else {
		//	mapping_requested = mapping_empty_();
		//	hyp_putspi("addr not in memory or annotated in stage 2, so nothing to check\n", i+2);
		//}

		// postcondition: mapping_post minus annotations included in hyp_memory minus annotations
		mapping_post_nonannot = mapping_nonannot(mapping_post);
		mapping_submapping(mapping_post_nonannot, mapping_hyp_memory, "host_stage2_idmap post", "mapping_post_nonannot", "mapping_hyp_memory", i+2);
		mapping_disjoint(mapping_post_nonannot, mapping_pre_annot, "host_stage2_idmap post", "mapping_post_nonannot", "mapping_pre_annot", i+2);

		// postcondition: mapping_post and mapping_pre have the same annotation part
		mapping_post_annot = mapping_annot(mapping_post);
		mapping_equal(mapping_pre_annot, mapping_post_annot, "host_stage2_idmap post annot equal", "mapping_pre_annot", "mapping_post_annot", i+2);

		// record updated interpretation
                free_mapping(host_mmu.pgt.ghost_mapping);
		host_mmu.pgt.ghost_mapping = mapping_post;

		free_mapping(mapping_pre);
		/* NOT:	free_mapping(mapping_post);*/
		free_mapping(mapping_pre_annot);
		free_mapping(mapping_post_annot);
		free_mapping(mapping_post_nonannot);
		//free_mapping(mapping_requested);
		free_mapping(mapping_hyp_memory);
		ghost_unlock_maplets();
		//ghost_dump_pgtable(host_mmu.pgt,"after: host_mmu.pgt", i);
		//ghost_dump_pgtable_diff(mapping_pre, host_mmu.pgt,"host_mmu.pgt", i);
		// and we need to wrap this local postcondition back up into the host lock invariant when we unlock it below
	}
#endif /* CONFIG_NVHE_GHOST_SPEC */

unlock:
	host_unlock_component();

	return ret;
}

static void host_inject_abort(struct kvm_cpu_context *host_ctxt)
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

void handle_host_mem_abort(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_vcpu_fault_info fault;
	u64 esr, addr;
	int ret = 0;

#ifdef CONFIG_NVHE_GHOST_SPEC
	GHOST_LOG_CONTEXT_ENTER();
#endif /* CONFIG_NVHE_GHOST_SPEC */

	esr = read_sysreg_el2(SYS_ESR);
	BUG_ON(!__get_fault_info(esr, &fault));

	addr = (fault.hpfar_el2 & HPFAR_MASK) << 8;
	ret = host_stage2_idmap(addr);

	if (ret == -EPERM)
		host_inject_abort(host_ctxt);
	else
		BUG_ON(ret && ret != -EAGAIN);
#ifdef CONFIG_NVHE_GHOST_SPEC
	GHOST_LOG_CONTEXT_EXIT();
#endif /* CONFIG_NVHE_GHOST_SPEC */
}

struct pkvm_mem_transition {
	u64				nr_pages;

	struct {
		enum pkvm_component_id	id;
		/* Address in the initiator's address space */
		u64			addr;

		union {
			struct {
				/* Address in the completer's address space */
				u64	completer_addr;
			} host;
			struct {
				u64	completer_addr;
			} hyp;
			struct {
				struct pkvm_hyp_vcpu *hyp_vcpu;
			} guest;
		};
	} initiator;

	struct {
		enum pkvm_component_id	id;

		union {
			struct {
				struct pkvm_hyp_vcpu *hyp_vcpu;
				phys_addr_t phys;
			} guest;
		};
	} completer;
};

struct pkvm_mem_share {
	const struct pkvm_mem_transition	tx;
	const enum kvm_pgtable_prot		completer_prot;
};

struct pkvm_mem_donation {
	const struct pkvm_mem_transition	tx;
};

struct check_walk_data {
	enum pkvm_page_state	desired;
	enum pkvm_page_state	(*get_page_state)(kvm_pte_t pte, u64 addr);
};

static int __check_page_state_visitor(const struct kvm_pgtable_visit_ctx *ctx,
				      enum kvm_pgtable_walk_flags visit)
{
	struct check_walk_data *d = ctx->arg;

	return d->get_page_state(ctx->old, ctx->addr) == d->desired ? 0 : -EPERM;
}

static int check_page_state_range(struct kvm_pgtable *pgt, u64 addr, u64 size,
				  struct check_walk_data *data)
{
	struct kvm_pgtable_walker walker = {
		.cb	= __check_page_state_visitor,
		.arg	= data,
		.flags	= KVM_PGTABLE_WALK_LEAF,
	};

	return kvm_pgtable_walk(pgt, addr, size, &walker);
}

static enum pkvm_page_state host_get_page_state(kvm_pte_t pte, u64 addr)
{
	if (!addr_is_allowed_memory(addr))
		return PKVM_NOPAGE;

	if (!kvm_pte_valid(pte) && pte)
		return PKVM_NOPAGE;

	return pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte));
}

static int __host_check_page_state_range(u64 addr, u64 size,
					 enum pkvm_page_state state)
{
	struct check_walk_data d = {
		.desired	= state,
		.get_page_state	= host_get_page_state,
	};

	hyp_assert_lock_held(&host_mmu.lock);
	return check_page_state_range(&host_mmu.pgt, addr, size, &d);
}

static int __host_set_page_state_range(u64 addr, u64 size,
				       enum pkvm_page_state state)
{
	enum kvm_pgtable_prot prot = pkvm_mkstate(PKVM_HOST_MEM_PROT, state);

	return host_stage2_idmap_locked(addr, size, prot);
}

static int host_request_owned_transition(u64 *completer_addr,
					 const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;
	u64 addr = tx->initiator.addr;

	*completer_addr = tx->initiator.host.completer_addr;
	return __host_check_page_state_range(addr, size, PKVM_PAGE_OWNED);
}

static int host_request_unshare(u64 *completer_addr,
				const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;
	u64 addr = tx->initiator.addr;

	*completer_addr = tx->initiator.host.completer_addr;
	return __host_check_page_state_range(addr, size, PKVM_PAGE_SHARED_OWNED);
}

static int host_initiate_share(u64 *completer_addr,
			       const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;
	u64 addr = tx->initiator.addr;

	*completer_addr = tx->initiator.host.completer_addr;
	return __host_set_page_state_range(addr, size, PKVM_PAGE_SHARED_OWNED);
}

static int host_initiate_unshare(u64 *completer_addr,
				 const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;
	u64 addr = tx->initiator.addr;

	*completer_addr = tx->initiator.host.completer_addr;
	return __host_set_page_state_range(addr, size, PKVM_PAGE_OWNED);
}

static int host_initiate_donation(u64 *completer_addr,
				  const struct pkvm_mem_transition *tx)
{
	u8 owner_id = tx->completer.id;
	u64 size = tx->nr_pages * PAGE_SIZE;

	*completer_addr = tx->initiator.host.completer_addr;
	return host_stage2_set_owner_locked(tx->initiator.addr, size, owner_id);
}

static bool __host_ack_skip_pgtable_check(const struct pkvm_mem_transition *tx)
{
	return !(IS_ENABLED(CONFIG_NVHE_EL2_DEBUG) ||
		 tx->initiator.id != PKVM_ID_HYP);
}

static int __host_ack_transition(u64 addr, const struct pkvm_mem_transition *tx,
				 enum pkvm_page_state state)
{
	u64 size = tx->nr_pages * PAGE_SIZE;

	if (__host_ack_skip_pgtable_check(tx))
		return 0;

	return __host_check_page_state_range(addr, size, state);
}

static int host_ack_share(u64 addr, const struct pkvm_mem_transition *tx,
			  enum kvm_pgtable_prot perms)
{
	if (perms != PKVM_HOST_MEM_PROT)
		return -EPERM;

	return __host_ack_transition(addr, tx, PKVM_NOPAGE);
}

static int host_ack_donation(u64 addr, const struct pkvm_mem_transition *tx)
{
	return __host_ack_transition(addr, tx, PKVM_NOPAGE);
}

static int host_ack_unshare(u64 addr, const struct pkvm_mem_transition *tx)
{
	return __host_ack_transition(addr, tx, PKVM_PAGE_SHARED_BORROWED);
}

static int host_complete_share(u64 addr, const struct pkvm_mem_transition *tx,
			       enum kvm_pgtable_prot perms)
{
	u64 size = tx->nr_pages * PAGE_SIZE;

	return __host_set_page_state_range(addr, size, PKVM_PAGE_SHARED_BORROWED);
}

static int host_complete_unshare(u64 addr, const struct pkvm_mem_transition *tx)
{
	u8 owner_id = tx->initiator.id;
	u64 size = tx->nr_pages * PAGE_SIZE;

	return host_stage2_set_owner_locked(addr, size, owner_id);
}

static int host_complete_donation(u64 addr, const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;
	u8 host_id = tx->completer.id;

	return host_stage2_set_owner_locked(addr, size, host_id);
}

static enum pkvm_page_state hyp_get_page_state(kvm_pte_t pte, u64 addr)
{
	if (!kvm_pte_valid(pte))
		return PKVM_NOPAGE;

	return pkvm_getstate(kvm_pgtable_hyp_pte_prot(pte));
}

#ifdef CONFIG_NVHE_GHOST_SPEC
// non-static to expose to ghost.
/*static*/ int __hyp_check_page_state_range(u64 addr, u64 size,
					enum pkvm_page_state state)
#else /* CONFIG_NVHE_GHOST_SPEC */
static int __hyp_check_page_state_range(u64 addr, u64 size,
					enum pkvm_page_state state)
#endif /* CONFIG_NVHE_GHOST_SPEC */
{
	struct check_walk_data d = {
		.desired	= state,
		.get_page_state	= hyp_get_page_state,
	};

	hyp_assert_lock_held(&pkvm_pgd_lock);
	return check_page_state_range(&pkvm_pgtable, addr, size, &d);
}

static int hyp_request_donation(u64 *completer_addr,
				const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;
	u64 addr = tx->initiator.addr;

	*completer_addr = tx->initiator.hyp.completer_addr;
	return __hyp_check_page_state_range(addr, size, PKVM_PAGE_OWNED);
}

static int hyp_initiate_donation(u64 *completer_addr,
				 const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;
	int ret;

	*completer_addr = tx->initiator.hyp.completer_addr;
	ret = kvm_pgtable_hyp_unmap(&pkvm_pgtable, tx->initiator.addr, size);
	return (ret != size) ? -EFAULT : 0;
}

static bool __hyp_ack_skip_pgtable_check(const struct pkvm_mem_transition *tx)
{
	return !(IS_ENABLED(CONFIG_NVHE_EL2_DEBUG) ||
		 tx->initiator.id != PKVM_ID_HOST);
}

static int hyp_ack_share(u64 addr, const struct pkvm_mem_transition *tx,
			 enum kvm_pgtable_prot perms)
{
	u64 size = tx->nr_pages * PAGE_SIZE;

	if (perms != PAGE_HYP)
		return -EPERM;

	if (__hyp_ack_skip_pgtable_check(tx))
		return 0;

	return __hyp_check_page_state_range(addr, size, PKVM_NOPAGE);
}

static int hyp_ack_unshare(u64 addr, const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;

	if (tx->initiator.id == PKVM_ID_HOST && hyp_page_count((void *)addr))
		return -EBUSY;

	if (__hyp_ack_skip_pgtable_check(tx))
		return 0;

	return __hyp_check_page_state_range(addr, size,
					    PKVM_PAGE_SHARED_BORROWED);
}

static int hyp_ack_donation(u64 addr, const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;

	if (__hyp_ack_skip_pgtable_check(tx))
		return 0;

	return __hyp_check_page_state_range(addr, size, PKVM_NOPAGE);
}

static int hyp_complete_share(u64 addr, const struct pkvm_mem_transition *tx,
			      enum kvm_pgtable_prot perms)
{
	void *start = (void *)addr, *end = start + (tx->nr_pages * PAGE_SIZE);
	enum kvm_pgtable_prot prot;

	prot = pkvm_mkstate(perms, PKVM_PAGE_SHARED_BORROWED);
	return pkvm_create_mappings_locked(start, end, prot);
}

static int hyp_complete_unshare(u64 addr, const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;
	int ret = kvm_pgtable_hyp_unmap(&pkvm_pgtable, addr, size);

	return (ret != size) ? -EFAULT : 0;
}

static int hyp_complete_donation(u64 addr,
				 const struct pkvm_mem_transition *tx)
{
	void *start = (void *)addr, *end = start + (tx->nr_pages * PAGE_SIZE);
	enum kvm_pgtable_prot prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_OWNED);

	return pkvm_create_mappings_locked(start, end, prot);
}

static enum pkvm_page_state guest_get_page_state(kvm_pte_t pte, u64 addr)
{
	if (!kvm_pte_valid(pte))
		return PKVM_NOPAGE;

	return pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte));
}

static int __guest_check_page_state_range(struct pkvm_hyp_vcpu *vcpu, u64 addr,
					  u64 size, enum pkvm_page_state state)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct check_walk_data d = {
		.desired	= state,
		.get_page_state	= guest_get_page_state,
	};

	hyp_assert_lock_held(&vm->lock);
	return check_page_state_range(&vm->pgt, addr, size, &d);
}

static int guest_ack_share(u64 addr, const struct pkvm_mem_transition *tx,
			   enum kvm_pgtable_prot perms)
{
	u64 size = tx->nr_pages * PAGE_SIZE;

	if (perms != KVM_PGTABLE_PROT_RWX)
		return -EPERM;

	return __guest_check_page_state_range(tx->completer.guest.hyp_vcpu,
					      addr, size, PKVM_NOPAGE);
}

static int guest_ack_donation(u64 addr, const struct pkvm_mem_transition *tx)
{
	u64 size = tx->nr_pages * PAGE_SIZE;

	return __guest_check_page_state_range(tx->completer.guest.hyp_vcpu,
					      addr, size, PKVM_NOPAGE);
}

static int guest_complete_share(u64 addr, const struct pkvm_mem_transition *tx,
				enum kvm_pgtable_prot perms)
{
	struct pkvm_hyp_vcpu *vcpu = tx->completer.guest.hyp_vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 size = tx->nr_pages * PAGE_SIZE;
	enum kvm_pgtable_prot prot;

	prot = pkvm_mkstate(perms, PKVM_PAGE_SHARED_BORROWED);
	return kvm_pgtable_stage2_map(&vm->pgt, addr, size, tx->completer.guest.phys,
				      prot, &vcpu->vcpu.arch.pkvm_memcache, 0);
}

static int guest_complete_donation(u64 addr, const struct pkvm_mem_transition *tx)
{
	enum kvm_pgtable_prot prot = pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED);
	struct pkvm_hyp_vcpu *vcpu = tx->completer.guest.hyp_vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 size = tx->nr_pages * PAGE_SIZE;

	return kvm_pgtable_stage2_map(&vm->pgt, addr, size, tx->completer.guest.phys,
				      prot, &vcpu->vcpu.arch.pkvm_memcache, 0);
}

static int __guest_get_completer_addr(u64 *completer_addr, phys_addr_t phys,
				      const struct pkvm_mem_transition *tx)
{
	switch (tx->completer.id) {
	case PKVM_ID_HOST:
		*completer_addr = phys;
		break;
	case PKVM_ID_HYP:
		*completer_addr = (u64)__hyp_va(phys);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int __guest_request_page_transition(u64 *completer_addr,
					   const struct pkvm_mem_transition *tx,
					   enum pkvm_page_state desired)
{
	struct pkvm_hyp_vcpu *vcpu = tx->initiator.guest.hyp_vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	enum pkvm_page_state state;
	phys_addr_t phys;
	kvm_pte_t pte;
	u32 level;
	int ret;

	if (tx->nr_pages != 1)
		return -E2BIG;

	ret = kvm_pgtable_get_leaf(&vm->pgt, tx->initiator.addr, &pte, &level);
	if (ret)
		return ret;

	state = guest_get_page_state(pte, tx->initiator.addr);
	if (state == PKVM_NOPAGE)
		return -EFAULT;

	if (state != desired)
		return -EPERM;

	/*
	 * We only deal with page granular mappings in the guest for now as
	 * the pgtable code relies on being able to recreate page mappings
	 * lazily after zapping a block mapping, which doesn't work once the
	 * pages have been donated.
	 */
	if (level != KVM_PGTABLE_MAX_LEVELS - 1)
		return -EINVAL;

	phys = kvm_pte_to_phys(pte);
	if (!addr_is_allowed_memory(phys))
		return -EINVAL;

	return __guest_get_completer_addr(completer_addr, phys, tx);
}

static int guest_request_share(u64 *completer_addr,
			       const struct pkvm_mem_transition *tx)
{
	return __guest_request_page_transition(completer_addr, tx,
					       PKVM_PAGE_OWNED);
}

static int guest_request_unshare(u64 *completer_addr,
				 const struct pkvm_mem_transition *tx)
{
	return __guest_request_page_transition(completer_addr, tx,
					       PKVM_PAGE_SHARED_OWNED);
}

static int __guest_initiate_page_transition(u64 *completer_addr,
					    const struct pkvm_mem_transition *tx,
					    enum pkvm_page_state state)
{
	struct pkvm_hyp_vcpu *vcpu = tx->initiator.guest.hyp_vcpu;
	struct kvm_hyp_memcache *mc = &vcpu->vcpu.arch.pkvm_memcache;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 size = tx->nr_pages * PAGE_SIZE;
	u64 addr = tx->initiator.addr;
	enum kvm_pgtable_prot prot;
	phys_addr_t phys;
	kvm_pte_t pte;
	int ret;

	ret = kvm_pgtable_get_leaf(&vm->pgt, addr, &pte, NULL);
	if (ret)
		return ret;

	phys = kvm_pte_to_phys(pte);
	prot = pkvm_mkstate(kvm_pgtable_stage2_pte_prot(pte), state);
	ret = kvm_pgtable_stage2_map(&vm->pgt, addr, size, phys, prot, mc, 0);
	if (ret)
		return ret;

	return __guest_get_completer_addr(completer_addr, phys, tx);
}

static int guest_initiate_share(u64 *completer_addr,
				const struct pkvm_mem_transition *tx)
{
	return __guest_initiate_page_transition(completer_addr, tx,
						PKVM_PAGE_SHARED_OWNED);
}

static int guest_initiate_unshare(u64 *completer_addr,
				  const struct pkvm_mem_transition *tx)
{
	return __guest_initiate_page_transition(completer_addr, tx,
						PKVM_PAGE_OWNED);
}

static int check_share(struct pkvm_mem_share *share)
{
	const struct pkvm_mem_transition *tx = &share->tx;
	u64 completer_addr;
	int ret;

	switch (tx->initiator.id) {
	case PKVM_ID_HOST:
		ret = host_request_owned_transition(&completer_addr, tx);
		break;
	case PKVM_ID_GUEST:
		ret = guest_request_share(&completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		return ret;

	switch (tx->completer.id) {
	case PKVM_ID_HOST:
		ret = host_ack_share(completer_addr, tx, share->completer_prot);
		break;
	case PKVM_ID_HYP:
		ret = hyp_ack_share(completer_addr, tx, share->completer_prot);
		break;
	case PKVM_ID_GUEST:
		ret = guest_ack_share(completer_addr, tx, share->completer_prot);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int __do_share(struct pkvm_mem_share *share)
{
	const struct pkvm_mem_transition *tx = &share->tx;
	u64 completer_addr;
	int ret;

	switch (tx->initiator.id) {
	case PKVM_ID_HOST:
		ret = host_initiate_share(&completer_addr, tx);
		break;
	case PKVM_ID_GUEST:
		ret = guest_initiate_share(&completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		return ret;

	switch (tx->completer.id) {
	case PKVM_ID_HOST:
		ret = host_complete_share(completer_addr, tx, share->completer_prot);
		break;
	case PKVM_ID_HYP:
		ret = hyp_complete_share(completer_addr, tx, share->completer_prot);
		break;
	case PKVM_ID_GUEST:
		ret = guest_complete_share(completer_addr, tx, share->completer_prot);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

/*
 * do_share():
 *
 * The page owner grants access to another component with a given set
 * of permissions.
 *
 * Initiator: OWNED	=> SHARED_OWNED
 * Completer: NOPAGE	=> SHARED_BORROWED
 */
static int do_share(struct pkvm_mem_share *share)
{
	int ret;

	ret = check_share(share);
	if (ret)
		return ret;

	return WARN_ON(__do_share(share));
}

static int check_unshare(struct pkvm_mem_share *share)
{
	const struct pkvm_mem_transition *tx = &share->tx;
	u64 completer_addr;
	int ret;

	switch (tx->initiator.id) {
	case PKVM_ID_HOST:
		ret = host_request_unshare(&completer_addr, tx);
		break;
	case PKVM_ID_GUEST:
		ret = guest_request_unshare(&completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		return ret;

	switch (tx->completer.id) {
	case PKVM_ID_HOST:
		ret = host_ack_unshare(completer_addr, tx);
		break;
	case PKVM_ID_HYP:
		ret = hyp_ack_unshare(completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int __do_unshare(struct pkvm_mem_share *share)
{
	const struct pkvm_mem_transition *tx = &share->tx;
	u64 completer_addr;
	int ret;

	switch (tx->initiator.id) {
	case PKVM_ID_HOST:
		ret = host_initiate_unshare(&completer_addr, tx);
		break;
	case PKVM_ID_GUEST:
		ret = guest_initiate_unshare(&completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		return ret;

	switch (tx->completer.id) {
	case PKVM_ID_HOST:
		ret = host_complete_unshare(completer_addr, tx);
		break;
	case PKVM_ID_HYP:
		ret = hyp_complete_unshare(completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

/*
 * do_unshare():
 *
 * The page owner revokes access from another component for a range of
 * pages which were previously shared using do_share().
 *
 * Initiator: SHARED_OWNED	=> OWNED
 * Completer: SHARED_BORROWED	=> NOPAGE
 */
static int do_unshare(struct pkvm_mem_share *share)
{
	int ret;

	ret = check_unshare(share);
	if (ret)
		return ret;

	return WARN_ON(__do_unshare(share));
}

static int check_donation(struct pkvm_mem_donation *donation)
{
	const struct pkvm_mem_transition *tx = &donation->tx;
	u64 completer_addr;
	int ret;

	switch (tx->initiator.id) {
	case PKVM_ID_HOST:
		ret = host_request_owned_transition(&completer_addr, tx);
		break;
	case PKVM_ID_HYP:
		ret = hyp_request_donation(&completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		return ret;

	switch (tx->completer.id) {
	case PKVM_ID_HOST:
		ret = host_ack_donation(completer_addr, tx);
		break;
	case PKVM_ID_HYP:
		ret = hyp_ack_donation(completer_addr, tx);
		break;
	case PKVM_ID_GUEST:
		ret = guest_ack_donation(completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int __do_donate(struct pkvm_mem_donation *donation)
{
	const struct pkvm_mem_transition *tx = &donation->tx;
	u64 completer_addr;
	int ret;

	switch (tx->initiator.id) {
	case PKVM_ID_HOST:
		ret = host_initiate_donation(&completer_addr, tx);
		break;
	case PKVM_ID_HYP:
		ret = hyp_initiate_donation(&completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		return ret;

	switch (tx->completer.id) {
	case PKVM_ID_HOST:
		ret = host_complete_donation(completer_addr, tx);
		break;
	case PKVM_ID_HYP:
		ret = hyp_complete_donation(completer_addr, tx);
		break;
	case PKVM_ID_GUEST:
		ret = guest_complete_donation(completer_addr, tx);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

/*
 * do_donate():
 *
 * The page owner transfers ownership to another component, losing access
 * as a consequence.
 *
 * Initiator: OWNED	=> NOPAGE
 * Completer: NOPAGE	=> OWNED
 */
static int do_donate(struct pkvm_mem_donation *donation)
{
	int ret;

	ret = check_donation(donation);
	if (ret)
		return ret;

	return WARN_ON(__do_donate(donation));
}

int __pkvm_host_share_hyp(u64 pfn)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)__hyp_va(host_addr);
	struct pkvm_mem_share share = {
		.tx	= {
			.nr_pages	= 1,
			.initiator	= {
				.id	= PKVM_ID_HOST,
				.addr	= host_addr,
				.host	= {
					.completer_addr = hyp_addr,
				},
			},
			.completer	= {
				.id	= PKVM_ID_HYP,
			},
		},
		.completer_prot	= PAGE_HYP,
	};

	host_lock_component();
	hyp_lock_component();

	ret = do_share(&share);

	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

int __pkvm_guest_share_host(struct pkvm_hyp_vcpu *vcpu, u64 ipa)
{
	int ret;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct pkvm_mem_share share = {
		.tx	= {
			.nr_pages	= 1,
			.initiator	= {
				.id	= PKVM_ID_GUEST,
				.addr	= ipa,
				.guest	= {
					.hyp_vcpu = vcpu,
				},
			},
			.completer	= {
				.id	= PKVM_ID_HOST,
			},
		},
		.completer_prot	= PKVM_HOST_MEM_PROT,
	};

	host_lock_component();
	guest_lock_component(vm);

	ret = do_share(&share);

	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

int __pkvm_guest_unshare_host(struct pkvm_hyp_vcpu *vcpu, u64 ipa)
{
	int ret;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct pkvm_mem_share share = {
		.tx	= {
			.nr_pages	= 1,
			.initiator	= {
				.id	= PKVM_ID_GUEST,
				.addr	= ipa,
				.guest	= {
					.hyp_vcpu = vcpu,
				},
			},
			.completer	= {
				.id	= PKVM_ID_HOST,
			},
		},
		.completer_prot	= PKVM_HOST_MEM_PROT,
	};

	host_lock_component();
	guest_lock_component(vm);

	ret = do_unshare(&share);

	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

int __pkvm_host_unshare_hyp(u64 pfn)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)__hyp_va(host_addr);
	struct pkvm_mem_share share = {
		.tx	= {
			.nr_pages	= 1,
			.initiator	= {
				.id	= PKVM_ID_HOST,
				.addr	= host_addr,
				.host	= {
					.completer_addr = hyp_addr,
				},
			},
			.completer	= {
				.id	= PKVM_ID_HYP,
			},
		},
		.completer_prot	= PAGE_HYP,
	};

	host_lock_component();
	hyp_lock_component();

	ret = do_unshare(&share);

	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

int __pkvm_host_donate_hyp(u64 pfn, u64 nr_pages)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)__hyp_va(host_addr);
	struct pkvm_mem_donation donation = {
		.tx	= {
			.nr_pages	= nr_pages,
			.initiator	= {
				.id	= PKVM_ID_HOST,
				.addr	= host_addr,
				.host	= {
					.completer_addr = hyp_addr,
				},
			},
			.completer	= {
				.id	= PKVM_ID_HYP,
			},
		},
	};

	host_lock_component();
	hyp_lock_component();

	ret = do_donate(&donation);

	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

int __pkvm_hyp_donate_host(u64 pfn, u64 nr_pages)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)__hyp_va(host_addr);
	struct pkvm_mem_donation donation = {
		.tx	= {
			.nr_pages	= nr_pages,
			.initiator	= {
				.id	= PKVM_ID_HYP,
				.addr	= hyp_addr,
				.hyp	= {
					.completer_addr = host_addr,
				},
			},
			.completer	= {
				.id	= PKVM_ID_HOST,
			},
		},
	};

	host_lock_component();
	hyp_lock_component();

	ret = do_donate(&donation);

	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

int hyp_pin_shared_mem(void *from, void *to)
{
	u64 cur, start = ALIGN_DOWN((u64)from, PAGE_SIZE);
	u64 end = PAGE_ALIGN((u64)to);
	u64 size = end - start;
	int ret;

	host_lock_component();
	hyp_lock_component();

	ret = __host_check_page_state_range(__hyp_pa(start), size,
					    PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	ret = __hyp_check_page_state_range(start, size,
					   PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

	for (cur = start; cur < end; cur += PAGE_SIZE)
		hyp_page_ref_inc(hyp_virt_to_page(cur));

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

void hyp_unpin_shared_mem(void *from, void *to)
{
	u64 cur, start = ALIGN_DOWN((u64)from, PAGE_SIZE);
	u64 end = PAGE_ALIGN((u64)to);

	host_lock_component();
	hyp_lock_component();

	for (cur = start; cur < end; cur += PAGE_SIZE)
		hyp_page_ref_dec(hyp_virt_to_page(cur));

	hyp_unlock_component();
	host_unlock_component();
}

int __pkvm_host_share_guest(u64 pfn, u64 gfn, struct pkvm_hyp_vcpu *vcpu)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 guest_addr = hyp_pfn_to_phys(gfn);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct pkvm_mem_share share = {
		.tx	= {
			.nr_pages	= 1,
			.initiator	= {
				.id	= PKVM_ID_HOST,
				.addr	= host_addr,
				.host	= {
					.completer_addr = guest_addr,
				},
			},
			.completer	= {
				.id	= PKVM_ID_GUEST,
				.guest	= {
					.hyp_vcpu = vcpu,
					.phys = host_addr,
				},
			},
		},
		.completer_prot	= KVM_PGTABLE_PROT_RWX,
	};

	host_lock_component();
	guest_lock_component(vm);

	ret = do_share(&share);

	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

int __pkvm_host_donate_guest(u64 pfn, u64 gfn, struct pkvm_hyp_vcpu *vcpu)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 guest_addr = hyp_pfn_to_phys(gfn);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct pkvm_mem_donation donation = {
		.tx	= {
			.nr_pages	= 1,
			.initiator	= {
				.id	= PKVM_ID_HOST,
				.addr	= host_addr,
				.host	= {
					.completer_addr = guest_addr,
				},
			},
			.completer	= {
				.id	= PKVM_ID_GUEST,
				.guest	= {
					.hyp_vcpu = vcpu,
					.phys = host_addr,
				},
			},
		},
	};

	host_lock_component();
	guest_lock_component(vm);

#ifdef CONFIG_NVHE_GHOST_SPEC
	// here (inside the locks) we could snapshot the abstraction of the host and guest pagetables, or (if we maintain them) use prevoiusly recorded ghost state for them in the postcondition
	// do_donate uses check_donation which uses host_request_owned_transition and (if the donation works) calls guest_ack_donation. The former uses kvm_pgtable_walk for __check_page_stage_visitor to check that all this address range is PKVM_PAGE_OWNED (and that any valid ptes satisfy addr_is_allowed_memory() )
	// Then host_initiate_donation uses host_stage2_set_owner_locked
	// and guest_complete_donation uses kvm_pgtable_stage2_map (plus magic for pvmfw)

	// Do we anywhere tell the guest we've done this?  Not as far as I can see
	bool ghost_check = ghost_control_check_enabled(__func__);
	u64 i=0; /* base indent */
	mapping mapping_host_pre, mapping_host_post; // interpretation of pgt on entry and exit
	mapping mapping_guest_pre, mapping_guest_post; // interpretation of pgt on entry and exit
	if (ghost_check) {
		hyp_putsxn("\n__pkvm_host_donate_guest host_addr",host_addr,64); hyp_putc('\n');
		hyp_putsxn("__pkvm_host_donate_guest guest_addr",guest_addr,64); hyp_putc('\n');
		// record host pgtable
		mapping_host_pre = ghost_record_pgtable_and_check(host_mmu.pgt.ghost_mapping, &host_mmu.pgt,/*dump*/true, "host_mmu.pgt", i);


		// record guest pgtable
		mapping_guest_pre = ghost_record_pgtable_and_check(vm->pgt.ghost_mapping, &vm->pgt,/*dump*/true, "vm->pgt", i);

	}

#endif /* CONFIG_NVHE_GHOST_SPEC */

	ret = do_donate(&donation);

#ifdef CONFIG_NVHE_GHOST_SPEC
	// postcondition: if that PKVM_PAGE_OWNED check then the host ownership (and any mapping) has been removed, and the guest mapping has been added.  Plus magic for pvmfw

	// TODO
	// now we need a more slick way of computing the different parts of the host pgt, for different predicates on the annotations
#endif /* CONFIG_NVHE_GHOST_SPEC */

	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

static int hyp_zero_page(phys_addr_t phys)
{
	void *addr;

	addr = hyp_fixmap_map(phys);
	if (!addr)
		return -EINVAL;

	memset(addr, 0, PAGE_SIZE);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	for (u64 p = (u64)addr; p < (u64)addr + PAGE_SIZE; p += sizeof(u64)) {
		ghost_simplified_model_step_write(WMO_plain, hyp_virt_to_phys((u64 *)p), 0);
	}
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

	/*
	 * Prefer kvm_flush_dcache_to_poc() over __clean_dcache_guest_page()
	 * here as the latter may elide the CMO under the assumption that FWB
	 * will be enabled on CPUs that support it. This is incorrect for the
	 * host stage-2 and would otherwise lead to a malicious host potentially
	 * being able to read the contents of newly reclaimed guest pages.
	 */
	kvm_flush_dcache_to_poc(addr, PAGE_SIZE);
	hyp_fixmap_unmap();
	return 0;
}

int __pkvm_host_reclaim_page(u64 pfn)
{
	u64 addr = hyp_pfn_to_phys(pfn);
	struct hyp_page *page;
	kvm_pte_t pte;
	int ret;

	host_lock_component();

	ret = kvm_pgtable_get_leaf(&host_mmu.pgt, addr, &pte, NULL);
	if (ret)
		goto unlock;

	if (host_get_page_state(pte, addr) == PKVM_PAGE_OWNED)
		goto unlock;

	page = hyp_phys_to_page(addr);
	if (!(page->flags & HOST_PAGE_PENDING_RECLAIM)) {
		ret = -EPERM;
		goto unlock;
	}

	if (page->flags & HOST_PAGE_NEED_POISONING) {
		ret = hyp_zero_page(addr);
		if (ret)
			goto unlock;
		page->flags &= ~HOST_PAGE_NEED_POISONING;
	}

	ret = host_stage2_set_owner_locked(addr, PAGE_SIZE, PKVM_ID_HOST);
	if (ret)
		goto unlock;
	page->flags &= ~HOST_PAGE_PENDING_RECLAIM;

unlock:
	host_unlock_component();

	return ret;
}
