// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_hypevents.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>
#include <asm/stage2_pgtable.h>

#include <hyp/fault.h>

#include <nvhe/gfp.h>
#include <nvhe/iommu.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/modules.h>

#ifdef CONFIG_NVHE_GHOST_SPEC
#include <nvhe/ghost/ghost_serial.h>
#include <nvhe/ghost/ghost_control.h>
#include <nvhe/ghost/ghost_misc.h>
#include <nvhe/ghost/ghost_recording.h>
#include <nvhe/ghost/ghost_call_data.h>
#ifdef CONFIG_NVHE_GHOST_SPEC_DUMP_STATE_RAW_HOST
#include <nvhe/ghost/ghost_spec.h> // for ghost_print_this_hypercall
#endif
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
#include <nvhe/ghost/ghost_simplified_model.h>
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif /* CONFIG_NVHE_GHOST_SPEC */

#define KVM_HOST_S2_FLAGS (KVM_PGTABLE_S2_NOFWB | KVM_PGTABLE_S2_IDMAP)

struct host_mmu host_mmu;

struct pkvm_moveable_reg pkvm_moveable_regs[PKVM_NR_MOVEABLE_REGS];
unsigned int pkvm_moveable_regs_nr;

#ifdef CONFIG_NVHE_GHOST_SPEC
/*static*/ struct hyp_pool host_s2_pool;
#else /* CONFIG_NVHE_GHOST_SPEC */
static struct hyp_pool host_s2_pool;
#endif /* CONFIG_NVHE_GHOST_SPEC */

static DEFINE_PER_CPU(struct pkvm_hyp_vm *, __current_vm);
#define current_vm (*this_cpu_ptr(&__current_vm))

static struct kvm_pgtable_pte_ops host_s2_pte_ops;
static bool host_stage2_force_pte(u64 addr, u64 end, enum kvm_pgtable_prot prot);
static bool host_stage2_pte_is_counted(kvm_pte_t pte, u32 level);
static bool guest_stage2_pte_is_counted(kvm_pte_t pte, u32 level);

static struct kvm_pgtable_pte_ops guest_s2_pte_ops = {
	.pte_is_counted_cb = guest_stage2_pte_is_counted
};

static void guest_lock_component(struct pkvm_hyp_vm *vm)
{
	hyp_spin_lock(&vm->pgtable_lock);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_lock(hyp_virt_to_phys(&vm->pgtable_lock));
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	current_vm = vm;
#ifdef CONFIG_NVHE_GHOST_SPEC
	record_and_check_abstraction_vm_pre(vm);
#endif /* CONFIG_NVHE_GHOST_SPEC */
}

static void guest_unlock_component(struct pkvm_hyp_vm *vm)
{
#ifdef CONFIG_NVHE_GHOST_SPEC
	record_and_copy_abstraction_vm_post(vm);
#endif /* CONFIG_NVHE_GHOST_SPEC */
	current_vm = NULL;
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_unlock(hyp_virt_to_phys(&vm->pgtable_lock));
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	hyp_spin_unlock(&vm->pgtable_lock);
}

static void host_lock_component(void)
{
	hyp_spin_lock(&host_mmu.lock);
#ifdef CONFIG_NVHE_GHOST_SPEC
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_lock(hyp_virt_to_phys(&host_mmu.lock));
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
#ifdef CONFIG_NVHE_GHOST_SPEC_DUMP_STATE_RAW_HOST
	if (__this_cpu_read(ghost_print_this_hypercall)) {
		ghost_printf("host pgtable pre (mapping):\n");
		ghost_dump_pgtable(&host_mmu.pgt, "host_kvm.pgt", 2);
		ghost_printf("\n");
		ghost_printf("host pgtable pre (raw):\n");
		dump_pgtable(host_mmu.pgt);
		ghost_printf("\n");
	}
#endif /* CONFIG_NVHE_GHOST_SPEC_DUMP_STATE_RAW_HOST */
	record_and_check_abstraction_host_pre();
#endif /* CONFIG_NVHE_GHOST_SPEC */
}

static void host_unlock_component(void)
{
#ifdef CONFIG_NVHE_GHOST_SPEC
#ifdef CONFIG_NVHE_GHOST_SPEC_DUMP_STATE_RAW_HOST
	if (__this_cpu_read(ghost_print_this_hypercall)) {
		ghost_printf("host pgtable post (mapping):\n");
		ghost_dump_pgtable(&host_mmu.pgt, "host_kvm.pgt", 2);
		ghost_printf("\n");
		ghost_printf("host pgtable post (raw):\n");
		dump_pgtable(host_mmu.pgt);
		ghost_printf("\n");
	}
#endif /* CONFIG_NVHE_GHOST_SPEC_DUMP_STATE_RAW_HOST */
	record_and_copy_abstraction_host_post();
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_unlock(hyp_virt_to_phys(&host_mmu.lock));
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
#endif /* CONFIG_NVHE_GHOST_SPEC */
	hyp_spin_unlock(&host_mmu.lock);
}

static void hyp_lock_component(void)
{
	hyp_spin_lock(&pkvm_pgd_lock);
#ifdef CONFIG_NVHE_GHOST_SPEC
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_lock(hyp_virt_to_phys(&pkvm_pgd_lock));
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	record_and_check_abstraction_pkvm_pre();
#endif /* CONFIG_NVHE_GHOST_SPEC */
}

static void hyp_unlock_component(void)
{
#ifdef CONFIG_NVHE_GHOST_SPEC
	record_and_copy_abstraction_pkvm_post();
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_unlock(hyp_virt_to_phys(&pkvm_pgd_lock));
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
#endif /* CONFIG_NVHE_GHOST_SPEC */
	hyp_spin_unlock(&pkvm_pgd_lock);
}

#define for_each_hyp_page(__p, __st, __sz)				\
	for (struct hyp_page *__p = hyp_phys_to_page(__st),		\
			     *__e = __p + ((__sz) >> PAGE_SHIFT);	\
	     __p < __e; __p++)

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

static void host_s2_free_unlinked_table(void *addr, s8 level)
{
	kvm_pgtable_stage2_free_unlinked(&host_mmu.mm_ops, host_mmu.pgt.pte_ops,
					 addr, level);
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
		.free_unlinked_table = host_s2_free_unlinked_table,
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

	host_mmu.arch.mmu.vtcr = kvm_get_vtcr(id_aa64mmfr0_el1_sys_val,
					      id_aa64mmfr1_el1_sys_val, phys_shift);
}

static int prepopulate_host_stage2(void)
{
	struct memblock_region *reg;
	int i, ret = 0;

	for (i = 0; i < hyp_memblock_nr; i++) {
		reg = &hyp_memory[i];
		ret = host_stage2_idmap_locked(reg->base, reg->size, PKVM_HOST_MEM_PROT);
		if (ret)
			return ret;
	}

	return ret;
}

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

	host_s2_pte_ops.force_pte_cb = host_stage2_force_pte;
	host_s2_pte_ops.pte_is_counted_cb = host_stage2_pte_is_counted;

	ret = __kvm_pgtable_stage2_init(&host_mmu.pgt, mmu,
					&host_mmu.mm_ops, KVM_HOST_S2_FLAGS,
					&host_s2_pte_ops);
	if (ret)
		return ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
	ghost_lock_maplets();
	host_mmu.ghost_mapping = mapping_empty_();
	ghost_unlock_maplets();
#endif /* CONFIG_NVHE_GHOST_SPEC */

	mmu->pgd_phys = __hyp_pa(host_mmu.pgt.pgd);
	mmu->pgt = &host_mmu.pgt;
	atomic64_set(&mmu->vmid.id, 0);

	return prepopulate_host_stage2();
}

static bool guest_stage2_pte_is_counted(kvm_pte_t pte, u32 level)
{
	/*
	 * The refcount tracks valid entries as well as invalid entries if they
	 * encode ownership of a page to another entity than the page-table
	 * owner, whose id is 0.
	 */
	return !!pte;
}

static void *guest_s2_zalloc_pages_exact(size_t size)
{
	void *addr = hyp_alloc_pages(&current_vm->pool, get_order(size));

	WARN_ON(!addr || size != (PAGE_SIZE << get_order(size)));
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
	unsigned long order;

	addr = hyp_alloc_pages(&current_vm->pool, 0);
	if (addr)
		return addr;

	addr = pop_hyp_memcache(mc, hyp_phys_to_virt, &order);
	if (!addr)
		return addr;

	WARN_ON(order);
	memset(addr, 0, PAGE_SIZE);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_init(hyp_virt_to_phys(addr), PAGE_SIZE);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	p = hyp_virt_to_page(addr);
	hyp_set_page_refcounted(p);
	p->order = 0;

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

static void guest_s2_free_unlinked_table(void *addr, s8 level)
{
	/* We are trying to collapse a table into a block mapping. This is forbidden. */
	WARN_ON(1);
}

static void __apply_guest_page(void *va, size_t size,
			       void (*func)(void *addr, size_t size))
{
	size += va - PTR_ALIGN_DOWN(va, PAGE_SIZE);
	va = PTR_ALIGN_DOWN(va, PAGE_SIZE);
	size = PAGE_ALIGN(size);

	while (size) {
		size_t map_size = PAGE_SIZE;
		void *map;

		if (IS_ALIGNED((unsigned long)va, PMD_SIZE) && size >= PMD_SIZE)
			map = hyp_fixblock_map(__hyp_pa(va), &map_size);
		else
			map = hyp_fixmap_map(__hyp_pa(va));

		func(map, map_size);

		if (map_size == PMD_SIZE)
			hyp_fixblock_unmap();
		else
			hyp_fixmap_unmap();

		size -= map_size;
		va += map_size;
	}
}

static void clean_dcache_guest_page(void *va, size_t size)
{
	__apply_guest_page(va, size, __clean_dcache_guest_page);
}

static void invalidate_icache_guest_page(void *va, size_t size)
{
	__apply_guest_page(va, size, __invalidate_icache_guest_page);
}

static void __hyp_flush_page(void *addr, size_t size)
{
	/*
	 * Prefer kvm_flush_dcache_to_poc() over __clean_dcache_guest_page()
	 * here as the latter may elide the CMO under the assumption that FWB
	 * will be enabled on CPUs that support it. This is incorrect for the
	 * host stage-2 and would otherwise lead to a malicious host potentially
	 * being able to read the contents of newly reclaimed guest pages.
	 */
	kvm_flush_dcache_to_poc(addr, size);
}

static void hyp_flush_page(phys_addr_t phys, size_t size)
{
	__apply_guest_page(__hyp_va(phys), size, __hyp_flush_page);
}

int kvm_guest_prepare_stage2(struct pkvm_hyp_vm *vm, void *pgd)
{
	struct kvm_s2_mmu *mmu = &vm->kvm.arch.mmu;
	unsigned long nr_pages;
	int ret;

	nr_pages = kvm_pgtable_stage2_pgd_size(mmu->vtcr) >> PAGE_SHIFT;
	ret = hyp_pool_init(&vm->pool, hyp_virt_to_pfn(pgd), nr_pages, 0);
	if (ret)
		return ret;

	hyp_spin_lock_init(&vm->pgtable_lock);
	vm->mm_ops = (struct kvm_pgtable_mm_ops) {
		.zalloc_pages_exact	= guest_s2_zalloc_pages_exact,
		.free_pages_exact	= guest_s2_free_pages_exact,
		.zalloc_page		= guest_s2_zalloc_page,
		.free_unlinked_table	= guest_s2_free_unlinked_table,
		.phys_to_virt		= hyp_phys_to_virt,
		.virt_to_phys		= hyp_virt_to_phys,
		.page_count		= hyp_page_count,
		.get_page		= guest_s2_get_page,
		.put_page		= guest_s2_put_page,
		.dcache_clean_inval_poc	= clean_dcache_guest_page,
		.icache_inval_pou	= invalidate_icache_guest_page,
	};

	guest_lock_component(vm);
	ret = __kvm_pgtable_stage2_init(mmu->pgt, mmu, &vm->mm_ops, 0,
					&guest_s2_pte_ops);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_hint(GHOST_HINT_SET_ROOT_LOCK, hyp_virt_to_phys(mmu->pgt->pgd), hyp_virt_to_phys(&vm->pgtable_lock));
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	guest_unlock_component(vm);
	if (ret)
		return ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
	ghost_lock_maplets();
	vm->ghost_mapping = mapping_empty_();
	ghost_unlock_maplets();
#endif /* CONFIG_NVHE_GHOST_SPEC */

	vm->kvm.arch.mmu.pgd_phys = __hyp_pa(vm->pgt.pgd);

	return 0;
}

void destroy_hyp_vm_pgt(struct pkvm_hyp_vm *vm)
{
	guest_lock_component(vm);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	// TODO: BS: fold this into the stage2 table free?
	casemate_model_step_hint(GHOST_HINT_RELEASE_TABLE, vm->kvm.arch.mmu.pgd_phys, 0);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	kvm_pgtable_stage2_destroy(&vm->pgt);
	vm->kvm.arch.mmu.pgd_phys = 0ULL;
	guest_unlock_component(vm);
}

void drain_hyp_pool(struct hyp_pool *pool, struct kvm_hyp_memcache *mc)
{
	WARN_ON(reclaim_hyp_pool(pool, mc, INT_MAX) != -ENOMEM);
}

static int ___pkvm_guest_relinquish_to_module(struct pkvm_hyp_vcpu *vcpu, u64 ipa, u64 phys,
					      kvm_pte_t pte)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct hyp_page *page;

	if (pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte)) != PKVM_PAGE_SHARED_BORROWED)
		return -EPERM;

	page = hyp_phys_to_page(phys);
	if (get_host_state(page) != PKVM_MODULE_SHARED_OWNED_PAGE)
		return -EPERM;

	/*
	 * We're guaranteed by the caller to be operating on existing last-level entries, so no
	 * risk of getting -ENOMEM here.
	 */
	WARN_ON(kvm_pgtable_stage2_annotate(&vm->pgt, ipa, PAGE_SIZE, &vcpu->vcpu.arch.stage2_mc,
					    KVM_ACCEPT_MODULE_PROT_NOTE));
	set_host_state(page, PKVM_MODULE_OWNED_PAGE);

	return 0;
}

static enum pkvm_page_state guest_get_page_state(kvm_pte_t pte, u64 addr);
int __pkvm_guest_relinquish_to_host(struct pkvm_hyp_vcpu *vcpu,
				    u64 ipa, u64 flags, u64 *ppa)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	enum pkvm_page_state state;
	u64 phys = 0, addr;
	kvm_pte_t pte;
	s8 level;
	int ret;

	if (!pkvm_hyp_vcpu_is_protected(vcpu))
		return 0;

	host_lock_component();
	guest_lock_component(vm);

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret || !kvm_pte_valid(pte))
		goto end;

	/* We don't support splitting non-leaf mappings */
	if (level != KVM_PGTABLE_LAST_LEVEL) {
		ret = -E2BIG;
		goto end;
	}

	addr = ALIGN_DOWN(ipa, kvm_granule_size(level));
	phys = kvm_pte_to_phys(pte);
	phys += ipa - addr;
	if (!addr_is_memory(phys)) {
		ret = -EPERM;
		goto end;
	}
	/* page might be used for DMA! */
	if (hyp_page_count(hyp_phys_to_virt(phys))) {
		ret = -EBUSY;
		goto end;
	}

	state = guest_get_page_state(pte, addr);
	if (state != PKVM_PAGE_OWNED) {
		ret = ___pkvm_guest_relinquish_to_module(vcpu, ipa, phys, pte);
		goto end;
	}

	/* Zap the guest stage2 pte and return ownership to the host */
	WARN_ON(kvm_pgtable_stage2_unmap(&vm->pgt, ipa, PAGE_SIZE));

	if (!(flags & KVM_FUNC_MEM_RELINQUISH_NO_POISON))
		hyp_poison_page(phys, PAGE_SIZE);
	else
		hyp_flush_page(phys, PAGE_SIZE);
	psci_mem_protect_dec(1);

	WARN_ON(host_stage2_set_owner_locked(phys, PAGE_SIZE, PKVM_ID_HOST));

	if (pkvm_ipa_range_has_pvmfw(vm, ipa, ipa + PAGE_SIZE))
		vm->kvm.arch.pkvm.pvmfw_load_addr = PVMFW_INVALID_LOAD_ADDR;
end:
	guest_unlock_component(vm);
	host_unlock_component();

	*ppa = phys;

	return ret;
}

int __pkvm_prot_finalize(void)
{
	struct kvm_s2_mmu *mmu = &host_mmu.arch.mmu;
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);

	if (params->hcr_el2 & HCR_VM)
		return -EPERM;

	params->vttbr = kvm_get_vttbr(mmu);
	params->vtcr = mmu->vtcr;
	params->hcr_el2 |= HCR_VM;

	/*
	 * The CMO below not only cleans the updated params to the
	 * PoC, but also provides the DSB that ensures ongoing
	 * page-table walks that have started before we trapped to EL2
	 * have completed.
	 */
	kvm_flush_dcache_to_poc(params, sizeof(*params));

	write_sysreg_hcr(params->hcr_el2);
	__load_stage2(&host_mmu.arch.mmu, &host_mmu.arch);

	/*
	 * Make sure to have an ISB before the TLB maintenance below but only
	 * when __load_stage2() doesn't include one already.
	 */
	asm(ALTERNATIVE("isb", "nop", ARM64_WORKAROUND_SPECULATIVE_AT));

	/* Invalidate stale HCR bits that may be cached in TLBs */
	__tlbi(vmalls12e1);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_tlbi(TLBI_vmalls12e1);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	dsb(nsh);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_dsb(DxB_nsh);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	isb();
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_isb();
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

	__pkvm_close_module_registration();

#ifdef CONFIG_NVHE_GHOST_SPEC
	record_abstraction_common();
	init_abstraction_thread_local();
	record_abstraction_loaded_vcpu_and_check_none();
	this_cpu_ptr(&ghost_cpu_run_state)->guest_running = false;

	if (ghost_print_on("setup")) {
		ghost_dump_sysregs();
	}

#endif /* CONFIG_NVHE_GHOST_SPEC */
	return 0;
}

int host_stage2_unmap_reg_locked(phys_addr_t start, u64 size)
{
	hyp_assert_lock_held(&host_mmu.lock);

	return kvm_pgtable_stage2_reclaim_leaves(&host_mmu.pgt, start, size);
}

static int host_stage2_unmap_unmoveable_regs(void)
{
	struct kvm_pgtable *pgt = &host_mmu.pgt;
	struct pkvm_moveable_reg *reg;
	u64 addr = 0;
	int i, ret;

	/* Unmap all unmoveable regions to recycle the pages */
	for (i = 0; i < pkvm_moveable_regs_nr; i++) {
		reg = &pkvm_moveable_regs[i];
		if (reg->start > addr) {
			ret = host_stage2_unmap_reg_locked(addr, reg->start - addr);
			if (ret)
				return ret;
		}
		addr = max(addr, reg->start + reg->size);
	}
	return host_stage2_unmap_reg_locked(addr, BIT(pgt->ia_bits) - addr);
}

/*
 * Ensure the PFN range is contained within PA-range.
 *
 * This check is also robust to overflows and is therefore a requirement before
 * using a pfn/nr_pages pair from an untrusted source.
 */
static bool pfn_range_is_valid(u64 pfn, u64 nr_pages)
{
	u64 limit = BIT(kvm_phys_shift(&host_mmu.arch.mmu) - PAGE_SHIFT);

	return pfn < limit && ((limit - pfn) >= nr_pages);
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

static enum kvm_pgtable_prot default_host_prot(bool is_memory)
{
	return is_memory ? PKVM_HOST_MEM_PROT : PKVM_HOST_MMIO_PROT;
}

static enum kvm_pgtable_prot default_hyp_prot(phys_addr_t phys)
{
	return addr_is_memory(phys) ? PAGE_HYP : PAGE_HYP_DEVICE;
}

bool addr_is_memory(phys_addr_t phys)
{
	struct kvm_mem_range range;

	return !!find_mem_range(phys, &range);
}

static bool is_in_mem_range(u64 addr, struct kvm_mem_range *range)
{
	return range->start <= addr && addr < range->end;
}

static int check_range_allowed_memory(u64 start, u64 end)
{
	struct memblock_region *reg;
	struct kvm_mem_range range;

	/*
	 * Callers can't check the state of a range that overlaps memory and
	 * MMIO regions, so ensure [start, end[ is in the same kvm_mem_range.
	 */
	reg = find_mem_range(start, &range);
	if (!is_in_mem_range(end - 1, &range))
		return -EINVAL;

	if (!reg || reg->flags & MEMBLOCK_NOMAP)
		return -EPERM;

	return 0;
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
 * The pool has been provided with enough pages to cover all of moveable regions
 * with page granularity, but it is difficult to know how much of the
 * non-moveable regions we will need to cover upfront, so we may need to
 * 'recycle' the pages if we run out.
 */
#define host_stage2_try(fn, ...)					\
	({								\
		int __ret;						\
		hyp_assert_lock_held(&host_mmu.lock);			\
		__ret = fn(__VA_ARGS__);				\
		if (__ret == -ENOMEM) {					\
			__ret = host_stage2_unmap_unmoveable_regs();		\
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
	u64 granule;
	s8 level;
	int ret;

	hyp_assert_lock_held(&host_mmu.lock);
	ret = kvm_pgtable_get_leaf(&host_mmu.pgt, addr, &pte, &level);
	if (ret)
		return ret;

	if (kvm_pte_valid(pte))
		return -EAGAIN;

	if (pte) {
		WARN_ON(addr_is_memory(addr) &&
			get_host_state(hyp_phys_to_page(addr)) != PKVM_NOPAGE);
		return -EPERM;
	}

	for (; level <= KVM_PGTABLE_LAST_LEVEL; level++) {
		if (!kvm_level_supports_block_mapping(level))
			continue;
		granule = kvm_granule_size(level);
		cur.start = ALIGN_DOWN(addr, granule);
		cur.end = cur.start + granule;
		if (!range_included(&cur, range))
			continue;
		*range = cur;
		return 0;
	}

	WARN_ON(1);

	return -EINVAL;
}

int host_stage2_idmap_locked(phys_addr_t addr, u64 size,
			     enum kvm_pgtable_prot prot)
{
	return host_stage2_try(__host_stage2_idmap, addr, addr + size, prot);
}

static void __host_update_page_state(phys_addr_t addr, u64 size, enum pkvm_page_state state)
{
	for_each_hyp_page(page, addr, size)
		set_host_state(page, state);
}

#define KVM_MAX_OWNER_ID		PKVM_ID_MAX

static kvm_pte_t kvm_init_invalid_leaf_owner(u8 owner_id)
{
	return FIELD_PREP(KVM_INVALID_PTE_OWNER_MASK, owner_id);
}

static int __host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id, bool is_memory,
					  enum pkvm_page_state nopage_state, bool update_iommu)
{
	kvm_pte_t annotation;
	enum kvm_pgtable_prot prot;
	int ret;

	if (owner_id > KVM_MAX_OWNER_ID)
		return -EINVAL;

	if (owner_id == PKVM_ID_HOST) {
		prot = default_host_prot(range_is_memory(addr, addr + size));
		ret = host_stage2_idmap_locked(addr, size, prot);
	} else {
		annotation = kvm_init_invalid_leaf_owner(owner_id);
		ret = host_stage2_try(kvm_pgtable_stage2_annotate,
				&host_mmu.pgt,
				addr, size, &host_s2_pool, annotation);
	}

	if (ret)
		return ret;

	if (update_iommu) {
		prot = owner_id == PKVM_ID_HOST ? PKVM_HOST_MEM_PROT : 0;
		kvm_iommu_host_stage2_idmap(addr, addr + size, prot);
		kvm_iommu_host_stage2_idmap_complete(!!prot);
	}
	if (!is_memory)
		return 0;

	/* Don't forget to update the vmemmap tracking for the host */
	if (owner_id == PKVM_ID_HOST)
		__host_update_page_state(addr, size, PKVM_PAGE_OWNED);
	else
		__host_update_page_state(addr, size, PKVM_NOPAGE | nopage_state);

	return 0;
}
int host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id)
{
	return __host_stage2_set_owner_locked(addr, size, owner_id, addr_is_memory(addr), 0, true);
}

static bool host_stage2_force_pte(u64 addr, u64 end, enum kvm_pgtable_prot prot)
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
	return prot != default_host_prot(range_is_memory(addr, end));
}

static bool host_stage2_pte_is_counted(kvm_pte_t pte, u32 level)
{
	u64 phys;

	if (!kvm_pte_valid(pte))
		return !!pte;

	if (kvm_pte_table(pte, level))
		return true;

	phys = kvm_pte_to_phys(pte);
	if (addr_is_memory(phys))
		return (pte & KVM_HOST_S2_DEFAULT_MASK) !=
			KVM_HOST_S2_DEFAULT_MEM_PTE;

	return (pte & KVM_HOST_S2_DEFAULT_MASK) != KVM_HOST_S2_DEFAULT_MMIO_PTE;
}

static int host_stage2_idmap(u64 addr)
{
	struct kvm_mem_range range;

#ifdef CONFIG_NVHE_GHOST_SPEC
	// PS: t012345he mm.c struct memblock_region hyp_memory[] is initialised by pkvm.c register_memblock_regions to a sorted copy of the regions available to linux, using the include/linux/memblock.h for_each_mem_region (struct memblock_region is also defined there).  I guess hyp_memory[] is constant after initialisation?   The find_mem_range above finds the enclosing region for addr if there is one, writing into range.  The memblock_region's have flags (HOTPLUG/MIRROR/NOMAP), but find_mem_range ignores them, so I think we can abstract hyp_memory[] to just a set of physical addresses (closed under the same-4K-page relation) (or, equivalently, a set of page addresses or page frame numbers) (or reuse our mapping and maplet code).
	// In the QEMU boot these are:
	//  base:0x........40000000 base':0x.......1385b0000 size:0x........f85b0000 flags:
	// -base:0x.......1385b0000 base':0x.......138750000 size:0x..........1a0000 flags:
	// -base:0x.......138750000 base':0x.......13bc20000 size:0x.........34d0000 flags:
	// -base:0x.......13bc20000 base':0x.......13c000000 size:0x..........3e0000 flags:
	// -base:0x.......13c000000 base':0x.......140000000 size:0x.........4000000 flags:
	// Why five contiguous regions?   Different permissions.
        // I'll only pay attention to the memory case for now, not the device case
#endif /* CONFIG_NVHE_GHOST_SPEC */

	bool is_memory = !!find_mem_range(addr, &range);
	enum kvm_pgtable_prot prot = default_host_prot(is_memory);
	int ret;

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
		mapping_pre = ghost_record_pgtable_and_check(host_mmu.ghost_mapping, &host_mmu.pgt, true/*dump*/, "host_mmu.pgt", i+2);
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
		mapping_post = ghost_record_pgtable(&host_mmu.pgt, NULL, NULL, "host_stage2_idmap post", i+2);
		ghost_dump_pgtable_locked(&host_mmu.pgt,"after: host_mmu.pgt", i);
		// the atomicity is interesting here: after the host_unlock_component(), what remains guaranteed?

		// the naive postcondition would check mapping_post included in mapping_pre + mapping_requested, but that would be wrong, as the code might map more than the requested address - any block contained in a memblock_region.  Ignoring device memory, the upper bound is really the hyp_memory[] minus the annotation parts of the on-entry mapping.  So we first compute the interpretation of those two.   For device memory, it looks as if currently (with s2mpu.c not turned on) we should allow _any_ non-hyp_memory mapping, but at PKVM_HOST_MMIO_PROT.  So how is that supposed to protect devices from guests?  IIRC Will said the s2mpu.c is turned on in later versions.


		// we think the hyp_memory is constant, while the annotations will change; they should be ghost state for the spec, but here we'll compute them from the host tables on entry
		mapping_hyp_memory = mapping_empty_();
		for (cur=0; cur<hyp_memblock_nr; cur++) {
			u64 phys = hyp_memory[cur].base;
			u64 nr_pages = hyp_memory[cur].size / PAGE_SIZE;
			extend_mapping_coalesce(&mapping_hyp_memory, GHOST_STAGE2, phys, nr_pages, maplet_target_mapped_ext(phys, nr_pages, DUMMY_ATTR, DUMMY_ATTR, DUMMY_ATTR));
		}
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
                free_mapping(host_mmu.ghost_mapping);
		host_mmu.ghost_mapping = mapping_post;

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

static void (*illegal_abt_notifier)(struct user_pt_regs *regs);

int __pkvm_register_illegal_abt_notifier(void (*cb)(struct user_pt_regs *))
{
	return cmpxchg(&illegal_abt_notifier, NULL, cb) ? -EBUSY : 0;
}

static void host_inject_abort(struct kvm_cpu_context *host_ctxt)
{
	u64 spsr = read_sysreg_el2(SYS_SPSR);
	u64 esr = read_sysreg_el2(SYS_ESR);
	u64 ventry, ec;

	if (READ_ONCE(illegal_abt_notifier))
		illegal_abt_notifier(&host_ctxt->regs);

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


static bool is_dabt(u64 esr)
{
	return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW;
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
	if (!__get_fault_info(esr, &fault)) {
		/* Setting the address to an invalid value for use in tracing. */
		addr = (u64)-1;
		/*
		 * We've presumably raced with a page-table change which caused
		 * AT to fail, try again.
		 */
#ifdef CONFIG_NVHE_GHOST_SPEC
	GHOST_LOG_CONTEXT_EXIT();
#endif /* CONFIG_NVHE_GHOST_SPEC */
		return;
	}


	/*
	 * Yikes, we couldn't resolve the fault IPA. This should reinject an
	 * abort into the host when we figure out how to do that.
	 */
	BUG_ON(!(fault.hpfar_el2 & HPFAR_EL2_NS));
	addr = FIELD_GET(HPFAR_EL2_FIPA, fault.hpfar_el2) << 12;
	addr |= fault.far_el2 & FAR_MASK;

	if (is_dabt(esr) && !addr_is_memory(addr) &&
	    kvm_iommu_host_dabt_handler(&host_ctxt->regs, esr, addr))
#ifdef CONFIG_NVHE_GHOST_SPEC
	{
		GHOST_LOG_CONTEXT_EXIT();
		return;
	}
#else
		return;
#endif /* CONFIG_NVHE_GHOST_SPEC */


	switch (esr & ESR_ELx_FSC_TYPE) {
	case ESR_ELx_FSC_FAULT:
		ret = host_stage2_idmap(addr);
		break;
	case ESR_ELx_FSC_PERM:
		ret = module_handle_host_perm_fault(&host_ctxt->regs, esr, addr);
		ret = ret ? 0 /* handled */ : -EPERM;
		break;
	default:
		ret = -EPERM;
		break;
	}

	if (ret == -EPERM)
		host_inject_abort(host_ctxt);
	else
		BUG_ON(ret && ret != -EAGAIN);

	trace_host_mem_abort(esr, addr);
#ifdef CONFIG_NVHE_GHOST_SPEC
	GHOST_LOG_CONTEXT_EXIT();
#endif /* CONFIG_NVHE_GHOST_SPEC */
}

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

static enum pkvm_page_state host_get_mmio_page_state(kvm_pte_t pte, u64 addr)
{
	enum pkvm_page_state state = 0;
	enum kvm_pgtable_prot prot;

	WARN_ON(addr_is_memory(addr));

	if (!kvm_pte_valid(pte) && pte)
		return PKVM_NOPAGE;

	prot = kvm_pgtable_stage2_pte_prot(pte);
	if (kvm_pte_valid(pte)) {
		if ((prot & KVM_PGTABLE_PROT_RWX) != PKVM_HOST_MMIO_PROT)
			state = PKVM_PAGE_RESTRICTED_PROT;
	}

	return state | pkvm_getstate(prot);
}

enum host_check_page_state_flags {
	HOST_CHECK_NULL_REFCNT		= BIT(0),
	HOST_CHECK_IS_MEMORY		= BIT(1),
	HOST_CHECK_ALLOW_NO_MAP		= BIT(2),
};

static int ___host_check_page_state_range(u64 addr, u64 size,
					  enum pkvm_page_state state,
					  enum host_check_page_state_flags flags)
{
	struct check_walk_data d = {
		.desired	= state,
		.get_page_state	= host_get_mmio_page_state,
	};
	struct memblock_region *reg;
	struct kvm_mem_range range;
	u64 end;

	if (check_add_overflow(addr, size, &end))
		return -EINVAL;

	/* Can't check the state of both MMIO and memory regions at once */
	reg = find_mem_range(addr, &range);
	if (!reg && (flags & HOST_CHECK_IS_MEMORY))
		return -EINVAL;

	if (!is_in_mem_range(end - 1, &range))
		return -EINVAL;

	hyp_assert_lock_held(&host_mmu.lock);

	/* MMIO state is still in the page-table */
	if (!reg)
		return check_page_state_range(&host_mmu.pgt, addr, size, &d);

	if (reg->flags & MEMBLOCK_NOMAP && !(flags & HOST_CHECK_ALLOW_NO_MAP))
		return -EPERM;

	for_each_hyp_page(page, addr, size) {
		if (get_host_state(page) != state)
			return -EPERM;
		if ((flags & HOST_CHECK_NULL_REFCNT) && hyp_refcount_get(page->refcount))
			return -EINVAL;
	}

	/*
	 * All memory pages with restricted permissions will already be covered
	 * by other states (e.g. PKVM_MODULE_OWNED_PAGE), so no need to retrieve
	 * the PKVM_PAGE_RESTRICTED_PROT state from the PTE.
	 */
	return 0;
}

static int __host_check_page_state_range(u64 addr, u64 size,
					 enum pkvm_page_state state)
{
	enum host_check_page_state_flags flags = HOST_CHECK_IS_MEMORY;

	if (state == PKVM_PAGE_OWNED)
		flags |= HOST_CHECK_NULL_REFCNT;

	/* Check the refcount of PAGE_OWNED pages as those may be used for DMA. */
	return ___host_check_page_state_range(addr, size, state, flags);
}

static int __host_set_page_state_range(u64 addr, u64 size,
				       enum pkvm_page_state state)
{
	if (get_host_state(hyp_phys_to_page(addr)) == PKVM_NOPAGE) {
		int ret = host_stage2_idmap_locked(addr, size, PKVM_HOST_MEM_PROT);

		if (ret)
			return ret;
		kvm_iommu_host_stage2_idmap(addr, addr + size, PKVM_HOST_MEM_PROT);
		kvm_iommu_host_stage2_idmap_complete(true);
	}

	__host_update_page_state(addr, size, state);

	return 0;
}

static void __hyp_set_page_state_range(phys_addr_t phys, u64 size, enum pkvm_page_state state)
{
	for_each_hyp_page(page, phys, size)
		set_hyp_state(page, state);
}

static enum pkvm_page_state hyp_get_page_state_mmio(kvm_pte_t pte, u64 addr)
{
	enum pkvm_page_state state = 0;
	enum kvm_pgtable_prot prot;

	if (!kvm_pte_valid(pte))
		return PKVM_NOPAGE;
	prot = kvm_pgtable_hyp_pte_prot(pte);
	if (kvm_pte_valid(pte) && ((prot & KVM_PGTABLE_PROT_RWX) != PAGE_HYP)) {
		state = PKVM_PAGE_RESTRICTED_PROT;
	}
	return state | pkvm_getstate(prot);
}

static int __hyp_check_page_state_range(phys_addr_t phys, u64 size,
					enum pkvm_page_state state)
{
	if (!range_is_memory(phys, phys + size)) {
		struct check_walk_data d = {
			.desired	= state,
			.get_page_state	= hyp_get_page_state_mmio,
		};

		hyp_assert_lock_held(&pkvm_pgd_lock);
		return check_page_state_range(&pkvm_pgtable, (u64)hyp_phys_to_virt(phys), size, &d);
	}

	for_each_hyp_page(page, phys, size) {
		if (get_hyp_state(page) != state)
			return -EPERM;
	}

	return 0;
}

int hyp_check_range_owned(u64 phys_addr, u64 size)
{
	int ret;

	hyp_lock_component();
	ret = __hyp_check_page_state_range(phys_addr, size, PKVM_PAGE_OWNED);
	hyp_unlock_component();

	return ret;
}

static enum pkvm_page_state guest_get_page_state(kvm_pte_t pte, u64 addr)
{
	enum pkvm_page_state state = 0;
	enum kvm_pgtable_prot prot;

	if (!kvm_pte_valid(pte)) {
		state = PKVM_NOPAGE;

		if (pte == KVM_INVALID_PTE_MMIO_NOTE)
			state |= PKVM_MMIO;
		else if (pte == KVM_ACCEPT_MODULE_PROT_NOTE)
			state |= PKVM_ACCEPT_MODULE_OWNED;

		return state;
	}

	prot = kvm_pgtable_stage2_pte_prot(pte);
	if (kvm_pte_valid(pte) && ((prot & KVM_PGTABLE_PROT_RWX) != KVM_PGTABLE_PROT_RWX))
		state = PKVM_PAGE_RESTRICTED_PROT;

	return state | pkvm_getstate(prot);
}

static int __guest_check_page_state_range(struct pkvm_hyp_vm *vm, u64 addr,
					  u64 size, enum pkvm_page_state state)
{
	struct check_walk_data d = {
		.desired	= state,
		.get_page_state	= guest_get_page_state,
	};
	u64 end;

	if (check_add_overflow(addr, size, &end))
		return -EINVAL;

	hyp_assert_lock_held(&vm->pgtable_lock);
	return check_page_state_range(&vm->pgt, addr, size, &d);
}

struct guest_request_walker_data {
	union {
		kvm_pte_t		pte_start; /* guest_request_walker() */
		unsigned long		ipa_start; /* guest_request_ioguard_walker() */
	};
	u64			size;
	enum pkvm_page_state	desired_state;
	int			max_ptes;
};

#define GUEST_WALKER_DATA_INIT(__state)							\
{											\
	.size		= 0,								\
	.desired_state	= __state,							\
	/*										\
	 * In the very unlucky case where we have:					\
	 *   1. A block-aligned start address						\
	 *   2. An existing table							\
	 *   3. Contiguous phys for the entire table					\
	 *										\
	 * The guest stage-2 mapping of that range would try to collapse the existing	\
	 * table into a block mapping. We do not want this to happen: the		\
	 * stage-2 geometry must remain synchronized with the host's			\
	 * kvm_pinned_page tree at all time.						\
	 *										\
	 * As a mitigation, limit the number of processed PTEs to half the size		\
	 * of a table on a 4K page-size system.						\
	 */										\
	.max_ptes	= 256,								\
}

static int guest_request_walker(const struct kvm_pgtable_visit_ctx *ctx,
				enum kvm_pgtable_walk_flags visit)
{
	struct guest_request_walker_data *data = (struct guest_request_walker_data *)ctx->arg;
	enum pkvm_page_state state;
	kvm_pte_t pte = *ctx->ptep;
	phys_addr_t phys;
	u64 granule_size;

	state = guest_get_page_state(pte, 0);
	if (data->desired_state != state)
		return (state == PKVM_NOPAGE) ? -ENOENT : -EPERM;

	/* state != PKVM_NOPAGE but invalid PTE? */
	if (WARN_ON(!kvm_pte_valid(pte)))
		return -EINVAL;

	granule_size = kvm_granule_size(ctx->level);
	phys = kvm_pte_to_phys(pte);

	/* First PTE */
	if (!data->size) {
		/* Request starts in the middle of a huge-mapping */
		if (!IS_ALIGNED(ctx->start, granule_size))
			return -E2BIG;

		data->pte_start = pte;
		data->size = granule_size;

		goto end;
	}

	if (kvm_pgtable_stage2_pte_prot(pte) !=
	    kvm_pgtable_stage2_pte_prot(data->pte_start))
		return -EINVAL;

	/* Can only describe physically contiguous mappings */
	if ((phys != kvm_pte_to_phys(data->pte_start) + data->size))
		return -ERANGE;

	data->size += granule_size;

end:
	/* Request ends in the middle of a huge-mapping */
	if (ctx->start + data->size > ctx->end)
		return -E2BIG;

	return --data->max_ptes > 0 ? 0 : -ERANGE;
}

static int __guest_request_page_transition(u64 ipa, kvm_pte_t *__pte, u64 *__nr_pages,
					   struct pkvm_hyp_vcpu *vcpu,
					   enum pkvm_page_state desired)
{
	struct guest_request_walker_data data = GUEST_WALKER_DATA_INIT(desired);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct kvm_pgtable_walker walker = {
		.cb     = guest_request_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF,
		.arg    = (void *)&data,
	};
	phys_addr_t phys;
	size_t size;
	int ret;

	if (check_mul_overflow(*__nr_pages, PAGE_SIZE, &size) ||
	    ipa >= ipa + size)
		return -EINVAL;

	ret = kvm_pgtable_walk(&vm->pgt, ipa, size, &walker);
	/*
	 * Walker reached data.max_ptes or a non-physically-contiguous mapping.
	 * Proceed with the current valid region. The guest will have to issue a new call for the
	 * leftover.
	 */
	if (ret == -ERANGE)
		ret = 0;
	else if (ret)
		return ret;

	if (WARN_ON(!kvm_pte_valid(data.pte_start)))
		return -EINVAL;

	phys = kvm_pte_to_phys(data.pte_start);
	ret = check_range_allowed_memory(phys, phys + data.size);
	if (ret)
		return ret;

	*__pte = data.pte_start;
	*__nr_pages = data.size >> PAGE_SHIFT;

	return 0;
}

int __pkvm_host_share_hyp(u64 pfn)
{
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 size = PAGE_SIZE;
	int ret;

#if !defined(CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR_host_share_hyp_NO_LOCKING)
	host_lock_component();
	hyp_lock_component();
#endif /* !defined(CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR_host_share_hyp_NO_LOCKING) */

	ret = __host_check_page_state_range(phys, size, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;
	ret = __hyp_check_page_state_range(phys, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	__hyp_set_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED);
	WARN_ON(__host_set_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED));

unlock:
#if !defined(CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR_host_share_hyp_NO_LOCKING)
	hyp_unlock_component();
	host_unlock_component();
#endif /* !defined(CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR_host_share_hyp_NO_LOCKING) */

	return ret;
}

int __pkvm_host_unshare_hyp(u64 pfn)
{
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 virt = (u64)__hyp_va(phys);
	u64 size = PAGE_SIZE;
	int ret;

	host_lock_component();
	hyp_lock_component();

	ret = __host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;
	ret = __hyp_check_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;
	if (hyp_page_count((void *)virt)) {
		ret = -EBUSY;
		goto unlock;
	}

	__hyp_set_page_state_range(phys, size, PKVM_NOPAGE);
	WARN_ON(__host_set_page_state_range(phys, size, PKVM_PAGE_OWNED));

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

int __pkvm_guest_share_hyp_page(struct pkvm_hyp_vcpu *vcpu, u64 ipa, u64 *hyp_va)
{
	int ret;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	kvm_pte_t pte;
	u64 phys;
	enum kvm_pgtable_prot prot;
	void *virt;
	u64 nr_pages = 1;

	hyp_lock_component();
	guest_lock_component(vm);

	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vcpu, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	phys = kvm_pte_to_phys(pte);

	virt = __hyp_va(phys);
	if (IS_ENABLED(CONFIG_NVHE_EL2_DEBUG)) {
		ret = __hyp_check_page_state_range(phys, PAGE_SIZE, PKVM_NOPAGE);
		if (ret)
			goto unlock;
	}

	__hyp_set_page_state_range(phys, PAGE_SIZE, PKVM_PAGE_SHARED_BORROWED);
	prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_SHARED_BORROWED);
	ret = pkvm_create_mappings_locked(virt, virt + PAGE_SIZE, prot);
	if (ret) {
		/*
		 * Repaint the return code as we need to distinguish between the
		 * no memory from the guest which is recoverable and no memory
		 * from the hypervisor.
		 */
		if (ret == -ENOMEM)
			ret = -EBUSY;
		goto unlock;
	}

	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, phys,
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_OWNED),
				     &vcpu->vcpu.arch.stage2_mc, 0);
	if (!ret)
		*hyp_va = (u64)virt;
unlock:
	guest_unlock_component(vm);
	hyp_unlock_component();

	return ret;
}

int __pkvm_guest_unshare_hyp_page(struct pkvm_hyp_vcpu *vcpu, u64 ipa)
{
	int ret;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	kvm_pte_t pte;
	u64 phys, virt, nr_pages = 1;

	hyp_lock_component();
	guest_lock_component(vm);

	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vcpu, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	phys = kvm_pte_to_phys(pte);

	virt = (u64)__hyp_va(phys);
	ret = __hyp_check_page_state_range(phys, PAGE_SIZE, PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

	__hyp_set_page_state_range(phys, PAGE_SIZE, PKVM_NOPAGE);
	WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, virt, PAGE_SIZE) != PAGE_SIZE);
	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, phys,
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED),
				     &vcpu->vcpu.arch.stage2_mc, 0);
unlock:
	guest_unlock_component(vm);
	hyp_unlock_component();

	return ret;
}

int __pkvm_guest_share_ffa_page(struct pkvm_hyp_vcpu *vcpu, u64 ipa, phys_addr_t *phys)
{
	int ret;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	kvm_pte_t pte;
	u64 nr_pages = 1;
	phys_addr_t pa;

	guest_lock_component(vm);
	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vcpu, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	pa = kvm_pte_to_phys(pte);
	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, pa,
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_OWNED),
				     &vcpu->vcpu.arch.stage2_mc, 0);
	if (!ret)
		*phys = pa;
unlock:
	guest_unlock_component(vm);

	return ret;
}

/*
 * The caller is responsible for tracking the FFA state and this function
 * should only be called for IPAs that have previously been shared with FFA.
 */
int __pkvm_guest_unshare_ffa_page(struct pkvm_hyp_vcpu *vcpu, u64 ipa)
{
	int ret;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	kvm_pte_t pte;
	u64 nr_pages = 1;

	guest_lock_component(vm);
	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vcpu, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, kvm_pte_to_phys(pte),
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED),
				     &vcpu->vcpu.arch.stage2_mc, 0);
unlock:
	guest_unlock_component(vm);

	return ret;
}

static int pkvm_host_donate_hyp(u64 pfn, u64 nr_pages, enum kvm_pgtable_prot prot,
				enum host_check_page_state_flags flags)
{
	u64 size, phys;
	void *virt;
	int ret;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	phys = hyp_pfn_to_phys(pfn);
	size = nr_pages * PAGE_SIZE;
	virt = __hyp_va(phys);

	host_lock_component();
	hyp_lock_component();

	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED, flags);
	if (ret)
		goto unlock;
	ret = __hyp_check_page_state_range(phys, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	/*
	 * Only allow hyp MMIO transitions to/from the host
	 */
	if (range_is_memory(phys, phys + size))
		__hyp_set_page_state_range(phys, size, PKVM_PAGE_OWNED);

	ret = pkvm_create_mappings_locked(virt, virt + size, prot);
	if (ret) {
		WARN_ON(ret != -ENOMEM);
		/* We might have failed halfway through, so remove anything we've installed */
		pkvm_remove_mappings_locked(virt, virt + size);
		goto unlock;
	}
	WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_HYP));

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

/* The Swiss Army knife of memory donation */
int ___pkvm_host_donate_hyp_prot(u64 pfn, u64 nr_pages,
				 bool accept_mmio, enum kvm_pgtable_prot prot)
{
	enum host_check_page_state_flags flags = HOST_CHECK_NULL_REFCNT;

	if (!accept_mmio)
		flags |= HOST_CHECK_IS_MEMORY;

	return pkvm_host_donate_hyp(pfn, nr_pages, prot, flags);
}

int ___pkvm_host_donate_hyp(u64 pfn, u64 nr_pages, bool accept_mmio)
{
	return ___pkvm_host_donate_hyp_prot(pfn, nr_pages, accept_mmio,
					    default_hyp_prot(hyp_pfn_to_phys(pfn)));
}

int __pkvm_host_donate_hyp(u64 pfn, u64 nr_pages)
{
	return ___pkvm_host_donate_hyp(pfn, nr_pages, false);
}

int __pkvm_host_donate_sglist_hyp(struct pkvm_sglist_page *sglist, size_t nr_pages)
{
	int p, ret;

	host_lock_component();
	hyp_lock_component();

	/* Checking we are reading hyp private memory */
	WARN_ON(__hyp_check_page_state_range((u64)sglist, nr_pages * sizeof(*sglist),
					     PKVM_PAGE_OWNED));

	for (p = 0; p < nr_pages; p++) {
		u8 max_order = get_order(PMD_SIZE);
		size_t size;
		u64 phys;

		if (sglist[p].order > max_order) {
			ret = -EINVAL;
			goto unlock;
		}
		size = PAGE_SIZE << sglist[p].order;

		if (!pfn_range_is_valid(sglist[p].pfn, size >> PAGE_SHIFT)) {
			ret = -EINVAL;
			goto unlock;
		}
		phys = hyp_pfn_to_phys(sglist[p].pfn);

		ret = __host_check_page_state_range(phys, size, PKVM_PAGE_OWNED);
		if (ret)
			goto unlock;

		ret = __hyp_check_page_state_range((u64)__hyp_va(phys), size, PKVM_NOPAGE);
		if (ret)
			goto unlock;
	}

	for (p = 0; p < nr_pages; p++) {
		size_t size = PAGE_SIZE << sglist[p].order;
		u64 phys = hyp_pfn_to_phys(sglist[p].pfn);
		enum kvm_pgtable_prot prot;

		prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_OWNED);
		ret = pkvm_create_mappings_locked(__hyp_va(phys), __hyp_va(phys) + size, prot);
		if (ret) {
			WARN_ON(ret != -ENOMEM);

			kvm_iommu_host_stage2_idmap_complete(false);

			/* Rollback */
			for (; p >= 0; p--) {
				phys = hyp_pfn_to_phys(sglist[p].pfn);
				size = PAGE_SIZE << sglist[p].order;

				pkvm_remove_mappings_locked(__hyp_va(phys), __hyp_va(phys) + size);
				WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST));
			}

			goto unlock;
		}

		WARN_ON(__host_stage2_set_owner_locked(phys, size, PKVM_ID_HYP, true, 0, false));
		kvm_iommu_host_stage2_idmap(phys, phys + size, 0);
	}

	kvm_iommu_host_stage2_idmap_complete(false);

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

static int pkvm_hyp_donate_guest(struct pkvm_hyp_vcpu *vcpu, u64 pfn, u64 gfn)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	u64 hyp_addr = (u64)__hyp_va(phys);
	size_t size = PAGE_SIZE;
	enum kvm_pgtable_prot prot;
	int ret;

	if (addr_is_memory(phys))
		return -EINVAL;

	hyp_assert_lock_held(&pkvm_pgd_lock);
	hyp_assert_lock_held(&vm->pgtable_lock);

	ret = __hyp_check_page_state_range(phys, size, PKVM_PAGE_OWNED);
	if (ret)
		return ret;
	ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
	if (ret)
		return ret;

	WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, hyp_addr, size) != size);
	prot = pkvm_mkstate(KVM_PGTABLE_PROT_RW | KVM_PGTABLE_PROT_NORMAL_NC,
			      PKVM_PAGE_OWNED);
	return WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
					      &vcpu->vcpu.arch.stage2_mc, 0));
}

int __pkvm_hyp_donate_host(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn);
	u64 virt = (u64)__hyp_va(phys);
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size))
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	host_lock_component();
	hyp_lock_component();

	ret = __hyp_check_page_state_range(phys, size, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;
	ret = ___host_check_page_state_range(phys, size, PKVM_NOPAGE, 0);
	if (ret)
		goto unlock;

	/* See __pkvm_host_donate_hyp_locked() */
	if (range_is_memory(phys, phys + size))
		__hyp_set_page_state_range(phys, size, PKVM_NOPAGE);
	WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, virt, size) != size);
	WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST));

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

/*
 * Rejects MMIO regions and does not update the IOMMU. Use with care!
 */
int __pkvm_host_donate_ffa(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn), end;
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size) ||
	    check_add_overflow(phys, size, &end))
		return -EINVAL;

	host_lock_component();

	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED,
					     HOST_CHECK_IS_MEMORY |
						     HOST_CHECK_NULL_REFCNT |
						     HOST_CHECK_ALLOW_NO_MAP);
	if (ret)
		goto unlock;

	WARN_ON(__host_stage2_set_owner_locked(phys, size, PKVM_ID_FFA, true, 0, false));
unlock:
	host_unlock_component();
	return ret;
}

/*
 * Just like __pkvm_donate_ffa, rejects MMIO regions and does not update the IOMMU.
 */
int __pkvm_host_reclaim_ffa(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn), end;
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size) ||
	    check_add_overflow(phys, size, &end))
		return -EINVAL;

	host_lock_component();

	ret = ___host_check_page_state_range(phys, size, PKVM_NOPAGE,
					     HOST_CHECK_IS_MEMORY |
						     HOST_CHECK_ALLOW_NO_MAP);
	if (ret)
		goto unlock;

	WARN_ON(__host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST, true, 0, false));
unlock:
	host_unlock_component();
	return ret;
}

#define MODULE_PROT_ALLOWLIST (KVM_PGTABLE_PROT_RWX |		\
			       KVM_PGTABLE_PROT_DEVICE |	\
			       KVM_PGTABLE_PROT_NORMAL_NC |	\
			       KVM_PGTABLE_PROT_PXN |		\
			       KVM_PGTABLE_PROT_UXN)

int module_change_host_page_prot(u64 pfn, enum kvm_pgtable_prot prot,
				 u64 nr_pages, bool update_iommu)
{
	u64 i, end, addr = hyp_pfn_to_phys(pfn);
	struct hyp_page *page = NULL;
	struct kvm_mem_range range;
	struct memblock_region *reg;
	int ret;

	if ((prot & MODULE_PROT_ALLOWLIST) != prot)
		return -EINVAL;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &end) ||
			check_add_overflow(addr, end, &end))
		return -EINVAL;

	reg = find_mem_range(addr, &range);
	if (end > range.end) {
		/* Specified range not in a single mmio or memory block. */
		return -EPERM;
	}

	host_lock_component();
	/*
	 * There is no hyp_vmemmap covering MMIO regions, which makes tracking
	 * of module-owned MMIO regions hard, so we trust the modules not to
	 * mess things up.
	 */
	if (!reg)
		goto update;

	/* Range is memory: we can track module ownership. */
	page = hyp_phys_to_page(addr);

	/*
	 * Modules can only modify pages they already own, and pristine host
	 * pages. The entire range must be consistently one or the other.
	 */
	if (get_host_state(page) & PKVM_MODULE_OWNED_PAGE) {
		/* The entire range must be module-owned. */
		ret = -EPERM;
		for (i = 1; i < nr_pages; i++) {
			if (!(get_host_state(&page[i]) & PKVM_MODULE_OWNED_PAGE))
				goto unlock;
		}
	} else {
		/* The entire range must be pristine. */
		ret = ___host_check_page_state_range(addr, nr_pages << PAGE_SHIFT,
						     PKVM_PAGE_OWNED, HOST_CHECK_NULL_REFCNT);
		if (ret)
			goto unlock;
	}

update:
	if (!prot) {
		ret = __host_stage2_set_owner_locked(addr, nr_pages << PAGE_SHIFT,
						     PKVM_ID_PROTECTED, !!reg,
						     PKVM_MODULE_OWNED_PAGE,
						     update_iommu);
	} else {
		ret = host_stage2_idmap_locked(
				addr, nr_pages << PAGE_SHIFT, prot);
		if (update_iommu) {
			kvm_iommu_host_stage2_idmap(addr, end, prot);
			kvm_iommu_host_stage2_idmap_complete(!!prot);
		}
	}

	if (WARN_ON(ret) || !page || !prot)
		goto unlock;

	for (i = 0; i < nr_pages; i++) {
		if (prot != KVM_PGTABLE_PROT_RWX)
			set_host_state(&page[i], PKVM_MODULE_OWNED_PAGE);
		else
			set_host_state(&page[i], PKVM_PAGE_OWNED);
	}

unlock:
	host_unlock_component();
	return ret;
}

int hyp_pin_shared_mem(void *from, void *to)
{
	u64 cur, start = ALIGN_DOWN((u64)from, PAGE_SIZE);
	u64 end = PAGE_ALIGN((u64)to);
	u64 phys = __hyp_pa(start);
	u64 size = end - start;
	struct hyp_page *p;
	int ret;

	host_lock_component();
	hyp_lock_component();

	ret = __host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	ret = __hyp_check_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

	for (cur = start; cur < end; cur += PAGE_SIZE) {
		p = hyp_virt_to_page(cur);
		hyp_page_ref_inc(p);
		if (p->refcount == 1)
			ret = pkvm_create_mappings_locked((void *)cur,
							  (void *)cur + PAGE_SIZE,
							  PAGE_HYP);
	}

	if (ret) {
		WARN_ON(ret != -ENOMEM);
		/* We might have failed halfway through, so remove anything we've installed */
		end = cur;
		for (cur = start; cur < end; cur += PAGE_SIZE) {
			p = hyp_virt_to_page(cur);
			hyp_page_ref_dec(p);
			if (p->refcount == 0)
				pkvm_remove_mappings_locked((void *)cur, (void *)cur + PAGE_SIZE);
		}
	}

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

void hyp_unpin_shared_mem(void *from, void *to)
{
	u64 cur, start = ALIGN_DOWN((u64)from, PAGE_SIZE);
	u64 end = PAGE_ALIGN((u64)to);
	struct hyp_page *p;

	host_lock_component();
	hyp_lock_component();

	for (cur = start; cur < end; cur += PAGE_SIZE) {
		p = hyp_virt_to_page(cur);
		if (p->refcount == 1)
			WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, cur, PAGE_SIZE) != PAGE_SIZE);
		hyp_page_ref_dec(p);
	}

	hyp_unlock_component();
	host_unlock_component();
}

int __pkvm_host_share_ffa(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn);
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size))
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	host_lock_component();
	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED,
					     HOST_CHECK_IS_MEMORY |
						     HOST_CHECK_NULL_REFCNT |
						     HOST_CHECK_ALLOW_NO_MAP);
	if (!ret)
		ret = __host_set_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED);
	host_unlock_component();

	return ret;
}

int __pkvm_host_unshare_ffa(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn);
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size))
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	host_lock_component();
	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED,
					     HOST_CHECK_IS_MEMORY |
						     HOST_CHECK_ALLOW_NO_MAP);
	if (!ret)
		ret = __host_set_page_state_range(phys, size, PKVM_PAGE_OWNED);
	host_unlock_component();

	return ret;
}

static int __guest_check_transition_size(u64 phys, u64 ipa, u64 nr_pages, u64 *size)
{
	size_t block_size;

	if (nr_pages == 1) {
		*size = PAGE_SIZE;
		return 0;
	}

	/* We solely support second to last level huge mapping */
	block_size = kvm_granule_size(KVM_PGTABLE_LAST_LEVEL - 1);

	if (nr_pages != block_size >> PAGE_SHIFT)
		return -EINVAL;

	if (!IS_ALIGNED(phys | ipa, block_size))
		return -EINVAL;

	*size = block_size;
	return 0;
}

static void __hyp_poison_page(void *addr, size_t size)
{
	memset(addr, 0, size);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	casemate_model_step_init(hyp_virt_to_phys(addr), size);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	__hyp_flush_page(addr, size);
}

void hyp_poison_page(phys_addr_t phys, size_t size)
{
	__apply_guest_page(__hyp_va(phys), size, __hyp_poison_page);
}

static int get_valid_guest_pte(struct pkvm_hyp_vm *vm, u64 ipa, kvm_pte_t *ptep, u64 *physp,
			       size_t size)
{
	kvm_pte_t pte;
	s8 level;
	int ret;

	if (size != PAGE_SIZE && size != PMD_SIZE)
		return -EINVAL;

	if (ipa != ALIGN_DOWN(ipa, size))
		return -EINVAL;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret)
		return ret;
	if (!kvm_pte_valid(pte))
		return -ENOENT;
	if (kvm_granule_size(level) != size)
		return -E2BIG;

	*ptep = pte;
	*physp = kvm_pte_to_phys(pte);

	return 0;
}

/* Return PA for an owned guest IPA or request it, and repeat the guest HVC */
int pkvm_get_guest_pa_request(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
			      size_t ipa_size_request, u64 *out_pa, s8 *out_level)
{
	struct kvm_hyp_req *req;
	kvm_pte_t pte;
	enum pkvm_page_state state;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);

	guest_lock_component(vm);
	WARN_ON(kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, out_level));
	guest_unlock_component(vm);
	if (!kvm_pte_valid(pte)) {
		/* Page not mapped, create a request*/
		req = pkvm_hyp_req_reserve(hyp_vcpu, KVM_HYP_REQ_TYPE_MAP);
		if (!req)
			return -ENOMEM;

		req->map.guest_ipa = ipa;
		req->map.size = ipa_size_request;
		return -ENOENT;
	}

	state = pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte));
	if (state != PKVM_PAGE_OWNED)
		return -EPERM;

	*out_pa = kvm_pte_to_phys(pte);
	*out_pa |= (ipa & (kvm_granule_size(*out_level) - 1)) & PAGE_MASK;
	return 0;
}

static int ___pkvm_module_unshare_guest(struct pkvm_hyp_vm *vm, u64 phys, u64 ipa, u64 size)
{

	if (___host_check_page_state_range(phys, size, PKVM_MODULE_SHARED_OWNED_PAGE, HOST_CHECK_IS_MEMORY))
		return -EPERM;

	if (__guest_check_page_state_range(vm, ipa, size, PKVM_PAGE_SHARED_BORROWED))
		return -EPERM;

	WARN_ON(kvm_pgtable_stage2_unmap(&vm->pgt, ipa, size));
	set_host_state(hyp_phys_to_page(phys), PKVM_MODULE_OWNED_PAGE);

	return 0;
}

int __pkvm_host_reclaim_page_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *vm)
{
	u64 phys, size, ipa = hyp_pfn_to_phys(gfn);
	kvm_pte_t pte;
	int ret;

	ret = __guest_check_transition_size(0, ipa, nr_pages, &size);
	if (ret)
		return ret;

	host_lock_component();
	guest_lock_component(vm);

	ret = get_valid_guest_pte(vm, ipa, &pte, &phys, size);
	if (ret)
		goto unlock;

	switch ((int)guest_get_page_state(pte, ipa)) {
	case PKVM_PAGE_OWNED:
		WARN_ON(__host_check_page_state_range(phys, size, PKVM_NOPAGE));
		hyp_poison_page(phys, size);
		psci_mem_protect_dec(nr_pages);
		break;
	case PKVM_PAGE_SHARED_BORROWED:
	case PKVM_PAGE_SHARED_BORROWED | PKVM_PAGE_RESTRICTED_PROT:
		if (__host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED)) {
			ret = ___pkvm_module_unshare_guest(vm, phys, ipa, size);
			goto unlock;
		}
		break;
	case PKVM_PAGE_SHARED_OWNED:
		if (__host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED)) {
			/* Presumably a page shared via FF-A, will be handled separately */
			ret = -EBUSY;
			goto unlock;
		}
		break;
	default:
		ret = -EPERM;
		goto unlock;
	}

	/* We could avoid TLB inval, it is done per VMID on the finalize path */
	WARN_ON(kvm_pgtable_stage2_unmap(&vm->pgt, ipa, size));
	WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST));

unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

int __pkvm_guest_share_host(u64 gfn, struct pkvm_hyp_vcpu *vcpu, u64 nr_pages, u64 *nr_shared)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);
	kvm_pte_t pte;
	size_t size;
	u64 phys;
	int ret;

	host_lock_component();
	guest_lock_component(vm);
	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vcpu, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	phys = kvm_pte_to_phys(pte);
	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size)) {
		ret = -EINVAL;
		goto unlock;
	}

	ret = __host_check_page_state_range(phys, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	WARN_ON(__host_set_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED));
	psci_mem_protect_dec(nr_pages);
	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys,
				       pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_OWNED),
				       &vcpu->vcpu.arch.stage2_mc, 0));
	*nr_shared = nr_pages;
unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

int __pkvm_guest_unshare_host(u64 gfn, struct pkvm_hyp_vcpu *vcpu, u64 nr_pages, u64 *nr_unshared)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);
	kvm_pte_t pte;
	size_t size;
	u64 phys;
	int ret;

	host_lock_component();
	guest_lock_component(vm);
	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vcpu, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	phys = kvm_pte_to_phys(pte);
	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size)) {
		ret = -EINVAL;
		goto unlock;
	}

	ret = __host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

	ret = 0;
	WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_GUEST));
	psci_mem_protect_inc(nr_pages);
	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys,
				       pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED),
				       &vcpu->vcpu.arch.stage2_mc, 0));
	*nr_unshared = nr_pages;
unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

static int __host_set_owner_guest(struct pkvm_hyp_vcpu *vcpu, u64 phys, u64 ipa,
				  size_t size, bool update_iommu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 nr_pages = size >> PAGE_SHIFT;
	int ret;

	WARN_ON(__host_stage2_set_owner_locked(phys, size, PKVM_ID_GUEST, true, 0, update_iommu));
	psci_mem_protect_inc(nr_pages);
	if (pkvm_ipa_range_has_pvmfw(vm, ipa, ipa + size)) {
		ret = pkvm_load_pvmfw_pages(vm, ipa, phys, size);
		if (WARN_ON(ret)) {
			psci_mem_protect_dec(nr_pages);
			return ret;
		}
	}

	return 0;
}

static int ___pkvm_check_module_share_guest(struct pkvm_hyp_vm *vm, u64 phys, u64 ipa, u64 size)
{
	if (___host_check_page_state_range(phys, size, PKVM_NOPAGE | PKVM_MODULE_OWNED_PAGE,
					   HOST_CHECK_IS_MEMORY))
		return -EFAULT;

	if (__guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE | PKVM_ACCEPT_MODULE_OWNED))
		return -EFAULT;

	if (module_guest_accept_module_owned_share(phys, ipa, size, vm))
		return -EFAULT;

	return 0;
}

static void ___pkvm_do_module_share_guest(struct pkvm_hyp_vcpu *vcpu, u64 phys, u64 ipa, u64 size)
{
	enum kvm_pgtable_prot prot = pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_BORROWED);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);

	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
				       &vcpu->vcpu.arch.stage2_mc, 0));
	__host_update_page_state(phys, size, PKVM_MODULE_SHARED_OWNED_PAGE);
}

static int ___pkvm_module_share_guest(u64 pfn, u64 gfn, u64 nr_pages, struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 size = nr_pages * PAGE_SIZE;
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	int ret;

	ret = ___pkvm_check_module_share_guest(vm, phys, ipa, size);
	if (!ret)
		___pkvm_do_module_share_guest(vcpu, phys, ipa, size);

	return ret;
}

int __pkvm_host_donate_guest(u64 pfn, u64 gfn, u64 nr_pages, struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	enum kvm_pgtable_prot prot;
	u64 size;
	int ret;

	ret = __guest_check_transition_size(phys, ipa, nr_pages, &size);
	if (ret)
		return ret;

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
		hyp_putsxn("\n__pkvm_host_donate_guest host_addr",phys,64); hyp_putc('\n');
		hyp_putsxn("__pkvm_host_donate_guest guest_addr",ipa,64); hyp_putc('\n');
		// record host pgtable
		mapping_host_pre = ghost_record_pgtable_and_check(host_mmu.ghost_mapping, &host_mmu.pgt,/*dump*/true, "host_mmu.pgt", i);


		// record guest pgtable
		mapping_guest_pre = ghost_record_pgtable_and_check(vm->ghost_mapping, &vm->pgt,/*dump*/true, "vm->pgt", i);

	}
#endif /* CONFIG_NVHE_GHOST_SPEC */

	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED,
					     HOST_CHECK_NULL_REFCNT |
					     HOST_CHECK_IS_MEMORY);
	if (ret) {
		if (ret == -EPERM)
			ret = ___pkvm_module_share_guest(pfn, gfn, nr_pages, vcpu);
		goto unlock;
	}

	ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	WARN_ON(__host_set_owner_guest(vcpu, phys, ipa, size, true));
	prot = pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED);
	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
		&vcpu->vcpu.arch.stage2_mc, 0));
unlock:
#ifdef CONFIG_NVHE_GHOST_SPEC
	// postcondition: if that PKVM_PAGE_OWNED check then the host ownership (and any mapping) has been removed, and the guest mapping has been added.  Plus magic for pvmfw

	// TODO
	// now we need a more slick way of computing the different parts of the host pgt, for different predicates on the annotations
#endif /* CONFIG_NVHE_GHOST_SPEC */
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

struct kvm_hyp_pinned_page *hyp_ppages;

static int __copy_hyp_ppages(struct pkvm_hyp_vcpu *vcpu)
{
	struct kvm_hyp_pinned_page *ppage, *hyp_ppage;

	WARN_ON(!hyp_ppages);

	ppage = next_kvm_hyp_pinned_page(vcpu->vcpu.arch.hyp_reqs, NULL, true);
	if (!ppage)
		return -EINVAL;

	hyp_ppage = hyp_ppages;

	do {
		memcpy(hyp_ppage, ppage, sizeof(*ppage));
		ppage = next_kvm_hyp_pinned_page(vcpu->vcpu.arch.hyp_reqs, ppage, true);
		hyp_ppage++; /* No risk to overflow hyp_ppages */
	} while (ppage);

	hyp_ppage->order = 0xFF;

	return 0;
}

#define for_each_hyp_ppage(hyp_ppage)						\
	for (hyp_ppage = hyp_ppages; (hyp_ppage)->order != 0xFF; (hyp_ppage)++)

static int ___pkvm_module_share_guest_sglist(struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct kvm_hyp_pinned_page *ppage = hyp_ppages;

	for_each_hyp_ppage(ppage) {
		u64 phys = hyp_pfn_to_phys(ppage->pfn);
		u64 ipa = hyp_pfn_to_phys(ppage->gfn);
		u64 size;

		if (check_shl_overflow(PAGE_SIZE, ppage->order, &size))
			return -EINVAL;

		if (___pkvm_check_module_share_guest(vm, phys, ipa, size))
			return -EFAULT;
	}

	for_each_hyp_ppage(ppage) {
		u64 phys = hyp_pfn_to_phys(ppage->pfn);
		u64 ipa = hyp_pfn_to_phys(ppage->gfn);
		u64 size = PAGE_SIZE << ppage->order;

		___pkvm_do_module_share_guest(vcpu, phys, ipa, size);
	}

	return 0;
}

int __pkvm_host_donate_sglist_guest(struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct kvm_hyp_pinned_page *ppage = hyp_ppages;
	int ret;

	host_lock_component();
	guest_lock_component(vm);

	ret = __copy_hyp_ppages(vcpu);
	if (ret)
		goto unlock;

	for_each_hyp_ppage(ppage) {
		u64 phys = hyp_pfn_to_phys(ppage->pfn);
		u64 ipa = hyp_pfn_to_phys(ppage->gfn);
		size_t size;

		if (check_shl_overflow(PAGE_SIZE, ppage->order, &size)) {
			ret = -EINVAL;
			goto unlock;
		}

		ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED,
						     HOST_CHECK_NULL_REFCNT |
						     HOST_CHECK_IS_MEMORY);
		if (ret) {
			if (ret == -EPERM)
				ret = ___pkvm_module_share_guest_sglist(vcpu);
			goto unlock;
		}

		ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
		if (ret)
			goto unlock;
	}

	/*
	 * Update the IOMMU outside of __host_set_owner_guest() so that
	 * we can batch up the operations with a single call to
	 * kvm_iommu_host_stage2_idmap_complete().
	 */
	for_each_hyp_ppage(ppage) {
		size_t size = PAGE_SIZE << ppage->order;
		u64 phys = hyp_pfn_to_phys(ppage->pfn);

		kvm_iommu_host_stage2_idmap(phys, phys + size, 0);
	}
	kvm_iommu_host_stage2_idmap_complete(false);

	for_each_hyp_ppage(ppage) {
		size_t size = PAGE_SIZE << ppage->order;
		u64 phys = hyp_pfn_to_phys(ppage->pfn);
		u64 ipa = hyp_pfn_to_phys(ppage->gfn);
		enum kvm_pgtable_prot prot;

		/* We already updated the IOMMU */
		WARN_ON(__host_set_owner_guest(vcpu, phys, ipa, size, false));
		prot = pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED);
		WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
					       &vcpu->vcpu.arch.stage2_mc, 0));
	}

unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

int __pkvm_host_share_guest(u64 pfn, u64 gfn, u64 nr_pages, struct pkvm_hyp_vcpu *vcpu,
			    enum kvm_pgtable_prot prot)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	u64 size;
	int ret;

	if (prot & ~KVM_PGTABLE_PROT_RWX)
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	ret = __guest_check_transition_size(phys, ipa, nr_pages, &size);
	if (ret)
		return ret;

	if (phys >= phys + size || ipa >= ipa + size)
		return -EINVAL;

	ret = check_range_allowed_memory(phys, phys + size);
	if (ret)
		return ret;

	host_lock_component();
	guest_lock_component(vm);

	ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	for_each_hyp_page(page, phys, size) {
		switch (get_host_state(page)) {
		case PKVM_PAGE_OWNED:
			continue;
		case PKVM_PAGE_SHARED_OWNED:
			if (page->host_share_guest_count == U32_MAX) {
				ret = -EBUSY;
				goto unlock;
			}

			/* Only host to np-guest multi-sharing is tolerated */
			if (page->host_share_guest_count)
				continue;

			fallthrough;
		default:
			ret = -EPERM;
			goto unlock;
		}
	}

	for_each_hyp_page(page, phys, size) {
		set_host_state(page, PKVM_PAGE_SHARED_OWNED);
		page->host_share_guest_count++;
	}

	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys,
				       pkvm_mkstate(prot, PKVM_PAGE_SHARED_BORROWED),
				       &vcpu->vcpu.arch.stage2_mc, 0));

unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

static int __check_host_shared_guest(struct pkvm_hyp_vm *vm, u64 *__phys, u64 ipa, u64 size)
{
	enum pkvm_page_state state;
	kvm_pte_t pte;
	u64 phys;
	s8 level;
	int ret;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret)
		return ret;
	if (!kvm_pte_valid(pte))
		return -ENOENT;
	if (size && kvm_granule_size(level) != size)
		return -E2BIG;

	if (!size)
		size = kvm_granule_size(level);

	state = guest_get_page_state(pte, ipa) & ~PKVM_PAGE_RESTRICTED_PROT;
	if (state != PKVM_PAGE_SHARED_BORROWED)
		return -EPERM;

	phys = kvm_pte_to_phys(pte);
	if (phys >= phys + size)
		return -EINVAL;

	ret = check_range_allowed_memory(phys, phys + size);
	if (WARN_ON(ret))
		return ret;

	for_each_hyp_page(page, phys, size) {
		if (get_host_state(page) != PKVM_PAGE_SHARED_OWNED)
			return -EPERM;
		if (WARN_ON(!page->host_share_guest_count))
			return -EINVAL;
	}

	*__phys = phys;

	return 0;
}

int __pkvm_host_unshare_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *vm)
{
	u64 ipa = hyp_pfn_to_phys(gfn);
	u64 size, phys;
	int ret;

	ret = __guest_check_transition_size(0, ipa, nr_pages, &size);
	if (ret)
		return ret;

	host_lock_component();
	guest_lock_component(vm);

	ret = __check_host_shared_guest(vm, &phys, ipa, size);
	if (ret)
		goto unlock;

	ret = kvm_pgtable_stage2_unmap(&vm->pgt, ipa, size);
	if (ret)
		goto unlock;

	for_each_hyp_page(page, phys, size) {
		/* __check_host_shared_guest() protects against underflow */
		page->host_share_guest_count--;
		if (!page->host_share_guest_count)
			set_host_state(page, PKVM_PAGE_OWNED);
	}

unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

static void assert_host_shared_guest(struct pkvm_hyp_vm *vm, u64 ipa, u64 size)
{
	u64 phys;
	int ret;

	if (!IS_ENABLED(CONFIG_PKVM_STRICT_CHECKS))
		return;

	host_lock_component();
	guest_lock_component(vm);

	ret = __check_host_shared_guest(vm, &phys, ipa, size);

	guest_unlock_component(vm);
	host_unlock_component();

	WARN_ON(ret && ret != -ENOENT);
}

int __pkvm_host_relax_perms_guest(u64 gfn, struct pkvm_hyp_vcpu *vcpu, enum kvm_pgtable_prot prot)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);
	int ret;

	if (pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	if (prot & ~KVM_PGTABLE_PROT_RWX)
		return -EINVAL;

	assert_host_shared_guest(vm, ipa, 0);
	guest_lock_component(vm);
	ret = kvm_pgtable_stage2_relax_perms(&vm->pgt, ipa, prot, 0);
	guest_unlock_component(vm);

	return ret;
}

int __pkvm_host_wrprotect_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *vm)
{
	u64 size, ipa = hyp_pfn_to_phys(gfn);
	int ret;

	if (pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	ret = __guest_check_transition_size(0, ipa, nr_pages, &size);
	if (ret)
		return ret;

	assert_host_shared_guest(vm, ipa, size);
	guest_lock_component(vm);
	ret = kvm_pgtable_stage2_wrprotect(&vm->pgt, ipa, size);
	guest_unlock_component(vm);

	return ret;
}

int __pkvm_host_test_clear_young_guest(u64 gfn, u64 nr_pages, bool mkold, struct pkvm_hyp_vm *vm)
{
	u64 size, ipa = hyp_pfn_to_phys(gfn);
	int ret;

	if (pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	ret = __guest_check_transition_size(0, ipa, nr_pages, &size);
	if (ret)
		return ret;

	assert_host_shared_guest(vm, ipa, size);
	guest_lock_component(vm);
	ret = kvm_pgtable_stage2_test_clear_young(&vm->pgt, ipa, size, mkold);
	guest_unlock_component(vm);

	return ret;
}

int __pkvm_host_mkyoung_guest(u64 gfn, struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);

	if (pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	assert_host_shared_guest(vm, ipa, 0);
	guest_lock_component(vm);
	kvm_pgtable_stage2_mkyoung(&vm->pgt, ipa, 0);
	guest_unlock_component(vm);

	return 0;
}

int __pkvm_host_split_guest(u64 gfn, u64 size, struct pkvm_hyp_vcpu *vcpu)
{
	struct kvm_hyp_memcache *mc = &vcpu->vcpu.arch.stage2_mc;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);
	int ret;

	if (size != PMD_SIZE)
		return -EINVAL;

	guest_lock_component(vm);

	/*
	 * stage2_split() already checks the existing mapping is valid and PMD-level.
	 * No other check is necessary.
	 */

	ret = kvm_pgtable_stage2_split(&vm->pgt, ipa, size, mc);

	guest_unlock_component(vm);

	return ret;
}

static bool __check_ioguard_page(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	kvm_pte_t pte;
	s8 level;
	int ret;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret)
		return false;

	/* Must be a PAGE_SIZE mapping with our annotation */
	return (BIT(ARM64_HW_PGTABLE_LEVEL_SHIFT(level)) == PAGE_SIZE &&
		pte == KVM_INVALID_PTE_MMIO_NOTE);
}

static int guest_request_ioguard_walker(const struct kvm_pgtable_visit_ctx *ctx,
					enum kvm_pgtable_walk_flags visit)
{

	struct guest_request_walker_data *data = (struct guest_request_walker_data *)ctx->arg;
	enum pkvm_page_state state;
	kvm_pte_t pte = *ctx->ptep;
	u64 granule_size;

	state = guest_get_page_state(pte, 0) & ~PKVM_MMIO;
	if (state != PKVM_NOPAGE)
		return -EPERM;

	granule_size = kvm_granule_size(ctx->level);

	/* First PTE */
	if (!data->size)
		data->ipa_start = ctx->addr & ~(granule_size - 1);

	data->size += granule_size;

	return --data->max_ptes > 0 ? 0 : -ERANGE;
}

int __pkvm_install_ioguard_page(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
				u64 nr_pages, u64 *nr_guarded)
{
	struct guest_request_walker_data data = GUEST_WALKER_DATA_INIT(PKVM_NOPAGE);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct kvm_pgtable_walker walker = {
		.cb     = guest_request_ioguard_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF,
		.arg    = (void *)&data,
	};
	u64 end;
	int ret;

	if (!test_bit(KVM_ARCH_FLAG_MMIO_GUARD, &vm->kvm.arch.flags))
		return -EINVAL;

	if (!PAGE_ALIGNED(ipa))
		return -EINVAL;

	guest_lock_component(vm);

	ret = kvm_pgtable_walk(&vm->pgt, ipa, nr_pages << PAGE_SHIFT, &walker);
	/* Walker reached data.max_ptes */
	if (ret == -ERANGE)
		ret = 0;
	else if (ret)
		goto unlock;

	/* Intersection between the requested region and what has been verified */
	end = min(ipa + (nr_pages << PAGE_SHIFT), data.ipa_start + data.size);
	if (ipa >= end) {
		ret = -EINVAL;
		goto unlock;
	}

	*nr_guarded = (end - ipa) >> PAGE_SHIFT;
	ret = kvm_pgtable_stage2_annotate(&vm->pgt, ipa, end - ipa,
					  &hyp_vcpu->vcpu.arch.stage2_mc,
					  KVM_INVALID_PTE_MMIO_NOTE);

unlock:
	guest_unlock_component(vm);
	return ret;
}

bool __pkvm_check_ioguard_page(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 ipa, end;
	bool ret;

	if (!kvm_vcpu_dabt_isvalid(&hyp_vcpu->vcpu))
		return false;

	if (!test_bit(KVM_ARCH_FLAG_MMIO_GUARD, &vm->kvm.arch.flags))
		return true;

	ipa  = kvm_vcpu_get_fault_ipa(&hyp_vcpu->vcpu);
	ipa |= FAR_TO_FIPA_OFFSET(kvm_vcpu_get_hfar(&hyp_vcpu->vcpu));
	end = ipa + kvm_vcpu_dabt_get_as(&hyp_vcpu->vcpu) - 1;

	guest_lock_component(vm);
	ret = __check_ioguard_page(hyp_vcpu, ipa);
	if ((end & PAGE_MASK) != (ipa & PAGE_MASK))
		ret &= __check_ioguard_page(hyp_vcpu, end);
	guest_unlock_component(vm);

	return ret;
}

static int __pkvm_remove_ioguard_page(struct pkvm_hyp_vm *vm, u64 ipa)
{
	int ret;
	kvm_pte_t pte;
	s8 level;

	hyp_assert_lock_held(&vm->pgtable_lock);

	if (!test_bit(KVM_ARCH_FLAG_MMIO_GUARD, &vm->kvm.arch.flags))
		return -EINVAL;

	if (!PAGE_ALIGNED(ipa))
		return -EINVAL;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret)
		return ret;

	if (BIT(ARM64_HW_PGTABLE_LEVEL_SHIFT(level)) == PAGE_SIZE &&
	    pte == KVM_INVALID_PTE_MMIO_NOTE)
		return kvm_pgtable_stage2_unmap(&vm->pgt, ipa, PAGE_SIZE);

	return kvm_pte_valid(pte) ? -EEXIST : -EINVAL;
}

int __pkvm_install_guest_mmio(struct pkvm_hyp_vcpu *hyp_vcpu, u64 pfn, u64 gfn)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 ipa = gfn << PAGE_SHIFT;
	int ret;

	hyp_lock_component();
	guest_lock_component(vm);
	ret = __pkvm_remove_ioguard_page(vm, ipa);
	if (ret)
		goto out_unlock;
	ret = pkvm_hyp_donate_guest(hyp_vcpu, pfn, gfn);
out_unlock:
	guest_unlock_component(vm);
	hyp_unlock_component();
	return ret;
}

static int guest_annot_module_prot_walker(const struct kvm_pgtable_visit_ctx *ctx,
					  enum kvm_pgtable_walk_flags visit)
{
	kvm_pte_t pte = *ctx->ptep;

	if (!pte || pte == KVM_ACCEPT_MODULE_PROT_NOTE)
		return 0;

	return -EBUSY;
}

int __pkvm_accept_module_prot_page(u64 ipa, u64 nr_pages)
{
	struct pkvm_hyp_vcpu *vcpu;
	struct pkvm_hyp_vm *vm;
	struct kvm_pgtable_walker walker = {
		.cb     = guest_annot_module_prot_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF,
	};
	int ret;

	if (!PAGE_ALIGNED(ipa))
		return -EINVAL;

	vcpu = pkvm_get_loaded_hyp_vcpu();
	if (!vcpu || !pkvm_hyp_vcpu_is_protected(vcpu))
		return -EINVAL;

	vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	guest_lock_component(vm);

	ret = kvm_pgtable_walk(&vm->pgt, ipa, nr_pages << PAGE_SHIFT, &walker);
	if (ret)
		goto unlock;

	ret = kvm_pgtable_stage2_annotate(&vm->pgt, ipa, nr_pages << PAGE_SHIFT,
					  &vcpu->vcpu.arch.stage2_mc,
					  KVM_ACCEPT_MODULE_PROT_NOTE);

unlock:
	guest_unlock_component(vm);
	return ret;
}

int host_stage2_get_leaf(phys_addr_t phys, kvm_pte_t *ptep, s8 *level)
{
	int ret;

	host_lock_component();
	ret = kvm_pgtable_get_leaf(&host_mmu.pgt, phys, ptep, level);
	host_unlock_component();

	return ret;
}

#ifdef CONFIG_NVHE_EL2_DEBUG
struct pkvm_expected_state {
	enum pkvm_page_state host;
	enum pkvm_page_state hyp;
	enum pkvm_page_state guest[2]; /* [ gfn, gfn + 1 ] */
};

static struct pkvm_expected_state selftest_state;
static struct hyp_page *selftest_page;

static struct pkvm_hyp_vm selftest_vm = {
	.kvm = {
		.arch = {
			.mmu = {
				.arch = &selftest_vm.kvm.arch,
				.pgt = &selftest_vm.pgt,
			},
		},
	},
};

static struct pkvm_hyp_vcpu selftest_vcpu = {
	.vcpu = {
		.arch = {
			.hw_mmu = &selftest_vm.kvm.arch.mmu,
		},
		.kvm = &selftest_vm.kvm,
	},
};

static void init_selftest_vm(void *virt)
{
	struct hyp_page *p = hyp_virt_to_page(virt);
	int i;

	selftest_vm.kvm.arch.mmu.vtcr = host_mmu.arch.mmu.vtcr;
	WARN_ON(kvm_guest_prepare_stage2(&selftest_vm, virt));

	for (i = 0; i < pkvm_selftest_pages(); i++) {
		if (p[i].refcount)
			continue;
		p[i].refcount = 1;
		hyp_put_page(&selftest_vm.pool, hyp_page_to_virt(&p[i]));
	}
}

static u64 selftest_ipa(void)
{
	return BIT(selftest_vm.pgt.ia_bits - 1);
}

static void assert_page_state(void)
{
	void *virt = hyp_page_to_virt(selftest_page);
	u64 size = PAGE_SIZE << selftest_page->order;
	struct pkvm_hyp_vcpu *vcpu = &selftest_vcpu;
	u64 phys = hyp_virt_to_phys(virt);
	u64 ipa[2] = { selftest_ipa(), selftest_ipa() + PAGE_SIZE };
	struct pkvm_hyp_vm *vm;

	vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);

	host_lock_component();
	WARN_ON(__host_check_page_state_range(phys, size, selftest_state.host));
	host_unlock_component();

	hyp_lock_component();
	WARN_ON(__hyp_check_page_state_range(phys, size, selftest_state.hyp));
	hyp_unlock_component();

	guest_lock_component(&selftest_vm);
	WARN_ON(__guest_check_page_state_range(vm, ipa[0], size, selftest_state.guest[0]));
	WARN_ON(__guest_check_page_state_range(vm, ipa[1], size, selftest_state.guest[1]));
	guest_unlock_component(&selftest_vm);
}

#define assert_transition_res(res, fn, ...)		\
	do {						\
		WARN_ON(fn(__VA_ARGS__) != res);	\
		assert_page_state();			\
	} while (0)

void pkvm_ownership_selftest(void *base)
{
	enum kvm_pgtable_prot prot = KVM_PGTABLE_PROT_RWX;
	void *virt = hyp_alloc_pages(&host_s2_pool, 0);
	struct pkvm_hyp_vcpu *vcpu = &selftest_vcpu;
	struct pkvm_hyp_vm *vm = &selftest_vm;
	u64 phys, size, pfn, gfn;

	WARN_ON(!virt);
	selftest_page = hyp_virt_to_page(virt);
	selftest_page->refcount = 0;
	init_selftest_vm(base);

	size = PAGE_SIZE << selftest_page->order;
	phys = hyp_virt_to_phys(virt);
	pfn = hyp_phys_to_pfn(phys);
	gfn = hyp_phys_to_pfn(selftest_ipa());

	selftest_state.host = PKVM_NOPAGE;
	selftest_state.hyp = PKVM_PAGE_OWNED;
	selftest_state.guest[0] = selftest_state.guest[1] = PKVM_NOPAGE;
	assert_page_state();
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_ffa, pfn, 1);
	assert_transition_res(-EPERM,	hyp_pin_shared_mem, virt, virt + size);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);

	selftest_state.host = PKVM_PAGE_OWNED;
	selftest_state.hyp = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_ffa, pfn, 1);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);
	assert_transition_res(-EPERM,	hyp_pin_shared_mem, virt, virt + size);

	selftest_state.host = PKVM_PAGE_SHARED_OWNED;
	selftest_state.hyp = PKVM_PAGE_SHARED_BORROWED;
	assert_transition_res(0,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);

	assert_transition_res(0,	hyp_pin_shared_mem, virt, virt + size);
	assert_transition_res(0,	hyp_pin_shared_mem, virt, virt + size);
	hyp_unpin_shared_mem(virt, virt + size);
	WARN_ON(hyp_page_count(virt) != 1);
	assert_transition_res(-EBUSY,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);

	hyp_unpin_shared_mem(virt, virt + size);
	assert_page_state();
	WARN_ON(hyp_page_count(virt));

	selftest_state.host = PKVM_PAGE_OWNED;
	selftest_state.hyp = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_host_unshare_hyp, pfn);

	selftest_state.host = PKVM_PAGE_SHARED_OWNED;
	selftest_state.hyp = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);
	assert_transition_res(-EPERM,	hyp_pin_shared_mem, virt, virt + size);

	selftest_state.host = PKVM_PAGE_OWNED;
	selftest_state.hyp = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_host_unshare_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_ffa, pfn, 1);

	selftest_state.host = PKVM_PAGE_SHARED_OWNED;
	selftest_state.guest[0] = PKVM_PAGE_SHARED_BORROWED;
	assert_transition_res(0,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	hyp_pin_shared_mem, virt, virt + size);

	selftest_state.guest[1] = PKVM_PAGE_SHARED_BORROWED;
	assert_transition_res(0,	__pkvm_host_share_guest, pfn, gfn + 1, 1, vcpu, prot);
	WARN_ON(hyp_virt_to_page(virt)->host_share_guest_count != 2);

	selftest_state.guest[0] = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_host_unshare_guest, gfn, 1, vm);

	selftest_state.guest[1] = PKVM_NOPAGE;
	selftest_state.host = PKVM_PAGE_OWNED;
	assert_transition_res(0,	__pkvm_host_unshare_guest, gfn + 1, 1, vm);

	selftest_state.host = PKVM_NOPAGE;
	selftest_state.hyp = PKVM_PAGE_OWNED;
	assert_transition_res(0,	__pkvm_host_donate_hyp, pfn, 1);

	selftest_page->refcount = 1;
	hyp_put_page(&host_s2_pool, virt);
}
#endif

static u64 __pkvm_ptdump_get_host_config(enum pkvm_ptdump_ops op)
{
	u64 ret = 0;

	host_lock_component();
	if (op == PKVM_PTDUMP_GET_LEVEL)
		ret = host_mmu.pgt.start_level;
	else
		ret = host_mmu.pgt.ia_bits;
	host_unlock_component();

	return ret;
}

static u64 __pkvm_ptdump_get_guest_config(pkvm_handle_t handle, enum pkvm_ptdump_ops op)
{
	struct pkvm_hyp_vm *vm;
	u64 ret = 0;

	vm = get_pkvm_hyp_vm(handle);
	if (!vm)
		return -EINVAL;

	if (op == PKVM_PTDUMP_GET_LEVEL)
		ret = vm->pgt.start_level;
	else
		ret = vm->pgt.ia_bits;

	put_pkvm_hyp_vm(vm);
	return ret;
}

u64 __pkvm_ptdump_get_config(pkvm_handle_t handle, enum pkvm_ptdump_ops op)
{
	if (!handle)
		return __pkvm_ptdump_get_host_config(op);

	return __pkvm_ptdump_get_guest_config(handle, op);
}

static int pkvm_ptdump_walker(const struct kvm_pgtable_visit_ctx *ctx,
			      enum kvm_pgtable_walk_flags visit)
{
	struct pkvm_ptdump_log_hdr **log_hdr = ctx->arg;
	ssize_t avail_space = PAGE_SIZE - (*log_hdr)->w_index - sizeof(struct pkvm_ptdump_log_hdr);
	struct pkvm_ptdump_log *log;

	if (avail_space < sizeof(struct pkvm_ptdump_log)) {
		if ((*log_hdr)->pfn_next == INVALID_PTDUMP_PFN)
			return -ENOMEM;

		*log_hdr = hyp_phys_to_virt(hyp_pfn_to_phys((*log_hdr)->pfn_next));
		WARN_ON((*log_hdr)->w_index);
	}

	log = (struct pkvm_ptdump_log *)((void *)*log_hdr + (*log_hdr)->w_index +
					 sizeof(struct pkvm_ptdump_log_hdr));
	log->pfn = ctx->addr >> PAGE_SHIFT;
	log->valid = ctx->old & PTE_VALID;
	log->r = FIELD_GET(KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R, ctx->old);
	log->w = FIELD_GET(KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W, ctx->old);
	log->xn = FIELD_GET(KVM_PTE_LEAF_ATTR_HI_S2_XN, ctx->old);
	log->table = FIELD_GET(KVM_PTE_TYPE, ctx->old);
	log->level = ctx->level;
	log->page_state = FIELD_GET(PKVM_PAGE_STATE_PROT_MASK, ctx->old);

	(*log_hdr)->w_index += sizeof(struct pkvm_ptdump_log);
	return 0;
}

static void pkvm_ptdump_teardown_log(struct pkvm_ptdump_log_hdr *log_hva,
				     struct pkvm_ptdump_log_hdr *cur)
{
	struct pkvm_ptdump_log_hdr *tmp, *log = (void *)kern_hyp_va(log_hva);
	bool next_log_invalid = false;

	while (log != cur && !next_log_invalid) {
		next_log_invalid = log->pfn_next == INVALID_PTDUMP_PFN;
		tmp = hyp_phys_to_virt(hyp_pfn_to_phys(log->pfn_next));
		WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(log), 1));
		log = tmp;
	}
}

static int pkvm_ptdump_setup_log(struct pkvm_ptdump_log_hdr *log_hva)
{
	int ret;
	struct pkvm_ptdump_log_hdr *log = (void *)kern_hyp_va(log_hva);

	if (!PAGE_ALIGNED(log))
		return -EINVAL;

	for (;;) {
		ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn(log), 1);
		if (ret) {
			pkvm_ptdump_teardown_log(log_hva, log);
			return ret;
		}

		log->w_index = 0;
		if (log->pfn_next == INVALID_PTDUMP_PFN)
			break;

		log = hyp_phys_to_virt(hyp_pfn_to_phys(log->pfn_next));
	}

	return 0;
}

static int pkvm_ptdump_walk_host(struct kvm_pgtable_walker *walker)
{
	int ret;

	host_lock_component();
	ret = kvm_pgtable_walk(&host_mmu.pgt, 0, BIT(host_mmu.pgt.ia_bits), walker);
	host_unlock_component();

	return ret;
}

static int pkvm_ptdump_walk_guest(struct pkvm_hyp_vm *vm, struct kvm_pgtable_walker *walker)
{
	int ret;

	guest_lock_component(vm);

	ret = kvm_pgtable_walk(&vm->pgt, 0, BIT(vm->pgt.ia_bits), walker);

	guest_unlock_component(vm);

	return ret;
}

u64 __pkvm_ptdump_walk_range(pkvm_handle_t handle, struct pkvm_ptdump_log_hdr *log)
{
	struct pkvm_hyp_vm *vm;
	int ret;
	struct pkvm_ptdump_log_hdr *log_hyp = kern_hyp_va(log);
	struct kvm_pgtable_walker walker = {
		.cb     = pkvm_ptdump_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF,
		.arg    = &log_hyp,
	};

	ret = pkvm_ptdump_setup_log(log);
	if (ret)
		return ret;

	if (!handle)
		ret = pkvm_ptdump_walk_host(&walker);
	else {
		vm = get_pkvm_hyp_vm(handle);
		if (!vm) {
			ret = -EINVAL;
			goto teardown;
		}

		ret = pkvm_ptdump_walk_guest(vm, &walker);
		put_pkvm_hyp_vm(vm);
	}
teardown:
	pkvm_ptdump_teardown_log(log, NULL);
	return ret;
}

static void __pkvm_use_dma_page(phys_addr_t phys)
{
	struct hyp_page *p = hyp_phys_to_page(phys);

	hyp_page_ref_inc(p);
}

static void __pkvm_unuse_dma_page(phys_addr_t phys)
{
	struct hyp_page *p = hyp_phys_to_page(phys);

	hyp_page_ref_dec(p);
}

static int __pkvm_use_dma_locked(phys_addr_t phys, size_t size, struct pkvm_hyp_vcpu *hyp_vcpu)
{
	int i;
	int ret = 0;
	struct kvm_mem_range r;
	size_t nr_pages = size >> PAGE_SHIFT;
	struct memblock_region *reg = find_mem_range(phys, &r);

	if (!pfn_range_is_valid(hyp_phys_to_pfn(phys), nr_pages) ||
	    !is_in_mem_range(phys + size - 1, &r))
		return -EINVAL;
	/*
	 * Some differences between handling of RAM and device memory:
	 * - The hyp vmemmap area for device memory is not backed by physical
	 *   pages in the hyp page tables.
	 * - However, in some cases modules can donate MMIO, as they can't be
	 *   refcounted, taint them by marking them as shared borrowed, and that
	 *   will prevent any future transition.
	 */
	if (!reg) {
		enum kvm_pgtable_prot prot;

		if (hyp_vcpu)
			return -EINVAL;
		for (i = 0; i < nr_pages; i++) {
			u64 addr = phys + i * PAGE_SIZE;

			ret = ___host_check_page_state_range(addr, PAGE_SIZE,
							     PKVM_PAGE_SHARED_BORROWED, 0);
			/* Page already borrowed */
			if (!ret)
				continue;
			ret = ___host_check_page_state_range(addr, PAGE_SIZE,
							     PKVM_PAGE_OWNED, 0);
			if (ret)
				return ret;
		}
		prot = pkvm_mkstate(PKVM_HOST_MMIO_PROT, PKVM_PAGE_SHARED_BORROWED);
		WARN_ON(host_stage2_idmap_locked(phys, size, prot));
	} else {

		/* For VMs, we know if we reach this point the VM has access to the page. */
		if (!hyp_vcpu) {
			for_each_hyp_page(page, phys, size) {
				if (get_host_state(page) != PKVM_PAGE_OWNED)
					return -EPERM;
			}
		}

		for (i = 0; i < nr_pages; i++)
			__pkvm_use_dma_page(phys + i * PAGE_SIZE);
	}

	return ret;
}

/*
 * __pkvm_use_dma - Mark memory as used for DMA
 * @phys:	physical address of the DMA region
 * @size:	size of the DMA region
 * When a page is mapped in an IOMMU page table for DMA, it must
 * not be donated to a guest or the hypervisor we ensure this with:
 * - Host can only map pages that are OWNED
 * - Any page that is mapped is refcounted
 * - Donation/Sharing is prevented if a page is refcounted.
 * - Any MMIO ever mapped in the IOMMU can't be donated/shared.
 * In case in the future shared pages are allowed to be mapped,
 * similar checks are needed in host_request_unshare() and
 * host_ack_unshare()
 */
int __pkvm_use_dma(phys_addr_t phys, size_t size, struct pkvm_hyp_vcpu *hyp_vcpu)
{
	int ret;

	host_lock_component();
	ret = __pkvm_use_dma_locked(phys, size, hyp_vcpu);
	host_unlock_component();
	return ret;
}

/*
 * Must be called after a __pkvm_host_use_dma() for the same
 * range, typically after a page was unmapped from an IOMMU.
 */
int __pkvm_unuse_dma(phys_addr_t phys, size_t size, struct pkvm_hyp_vcpu *hyp_vcpu)
{
	int i;
	size_t nr_pages = size >> PAGE_SHIFT;

	if (!pfn_range_is_valid(hyp_phys_to_pfn(phys), nr_pages))
		return -EINVAL;

	if (!range_is_memory(phys, phys + size)) {
		WARN_ON(hyp_vcpu);
		return 0;
	}
	host_lock_component();

	for (i = 0; i < nr_pages; i++)
		__pkvm_unuse_dma_page(phys + i * PAGE_SIZE);

	host_unlock_component();
	return 0;
}

/* Get a PA and use the page for DMA */
int pkvm_get_guest_pa_request_use_dma(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
                                     size_t ipa_size_request, u64 *out_pa, s8 *level)
{
	int ret;

	host_lock_component();
	ret = pkvm_get_guest_pa_request(hyp_vcpu, ipa, ipa_size_request,
					out_pa, level);
	if (ret)
		goto out_ret;
	WARN_ON(__pkvm_use_dma_locked(*out_pa, kvm_granule_size(*level), hyp_vcpu));
out_ret:
	host_unlock_component();
	return ret;
}
