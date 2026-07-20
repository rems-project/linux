// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>

#include <nvhe/alloc.h>
#include <nvhe/early_alloc.h>
#include <nvhe/ffa.h>
#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/serial.h>
#include <nvhe/trap_handler.h>

#ifdef CONFIG_NVHE_GHOST_SPEC
#include <nvhe/ghost/ghost_serial.h>
#include <nvhe/ghost/ghost_control.h>
#include <nvhe/ghost/ghost_misc.h>
#include <nvhe/ghost/ghost_recording.h>
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
#include <casemate.h>
#include <nvhe/ghost/ghost_sm_driver.h>
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
#endif /* CONFIG_NVHE_GHOST_SPEC */

unsigned long hyp_nr_cpus;

phys_addr_t pvmfw_base;
phys_addr_t pvmfw_size;

#define hyp_percpu_size ((unsigned long)__per_cpu_end - \
			 (unsigned long)__per_cpu_start)

#ifdef CONFIG_NVHE_GHOST_SPEC
// Ghost: removed static (perhaps better to add explicit ghost copies?)
/*static*/ void *vmemmap_base;
/*static*/ void *vm_table_base;
/*static*/ void *hyp_pgt_base;
/*static*/ void *host_s2_pgt_base;
/*static*/ void *ffa_proxy_pages;
#else
static void *vmemmap_base;
static void *vm_table_base;
static void *hyp_pgt_base;
static void *host_s2_pgt_base;
static void *ffa_proxy_pages;
#endif /* CONFIG_NVHE_GHOST_SPEC */

static struct kvm_pgtable_mm_ops pkvm_pgtable_mm_ops;
#ifdef CONFIG_NVHE_GHOST_SPEC
/*static*/ struct hyp_pool hpool;
#else /* CONFIG_NVHE_GHOST_SPEC */
static struct hyp_pool hpool;
#endif

#ifdef CONFIG_NVHE_GHOST_SPEC
u64 ghost_vmemmap_size;
u64 ghost_vm_table_size;
u64 ghost_hyp_pgt_size;
u64 ghost_host_s2_pgt_size;

u64 ghost__pkvm_init_phys;
u64 ghost__pkvm_init_size;
u64 ghost__pkvm_init_virt;
#endif /* CONFIG_NVHE_GHOST_SPEC */

static int divide_memory_pool(void *virt, unsigned long size)
{
	unsigned long nr_pages;

	hyp_early_alloc_init(virt, size);

	nr_pages = hyp_vmemmap_pages(sizeof(struct hyp_page));
#ifdef CONFIG_NVHE_GHOST_SPEC
	ghost_vmemmap_size = nr_pages;
#endif /* CONFIG_NVHE_GHOST_SPEC */
	vmemmap_base = hyp_early_alloc_contig(nr_pages);
	if (!vmemmap_base)
		return -ENOMEM;

#if defined(__KVM_NVHE_HYPERVISOR__) && defined(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL)
	casemate_model_step_init(hyp_virt_to_phys(vmemmap_base), nr_pages);
#endif /* defined(__KVM_NVHE_HYPERVISOR__) && defined(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL) */

	nr_pages = hyp_vm_table_pages();
#ifdef CONFIG_NVHE_GHOST_SPEC
	ghost_vm_table_size = nr_pages;
#endif /* CONFIG_NVHE_GHOST_SPEC */
	vm_table_base = hyp_early_alloc_contig(nr_pages);
	if (!vm_table_base)
		return -ENOMEM;

#if defined(__KVM_NVHE_HYPERVISOR__) && defined(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL)
	casemate_model_step_init(hyp_virt_to_phys(vm_table_base), nr_pages);
#endif /* defined(__KVM_NVHE_HYPERVISOR__) && defined(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL) */

	nr_pages = hyp_s1_pgtable_pages();
#ifdef CONFIG_NVHE_GHOST_SPEC
	ghost_hyp_pgt_size = nr_pages;
#endif /* CONFIG_NVHE_GHOST_SPEC */
	hyp_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!hyp_pgt_base)
		return -ENOMEM;

#if defined(__KVM_NVHE_HYPERVISOR__) && defined(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL)
	casemate_model_step_init(hyp_virt_to_phys(hyp_pgt_base), nr_pages);
#endif /* defined(__KVM_NVHE_HYPERVISOR__) && defined(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL) */

	nr_pages = host_s2_pgtable_pages();
#ifdef CONFIG_NVHE_GHOST_SPEC
	ghost_host_s2_pgt_size = nr_pages;
#endif /* CONFIG_NVHE_GHOST_SPEC */
	host_s2_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!host_s2_pgt_base)
		return -ENOMEM;

#if defined(__KVM_NVHE_HYPERVISOR__) && defined(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL)
	casemate_model_step_init(hyp_virt_to_phys(host_s2_pgt_base), nr_pages);
#endif /* defined(__KVM_NVHE_HYPERVISOR__) && defined(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL) */

	nr_pages = hyp_ffa_proxy_pages();
	ffa_proxy_pages = hyp_early_alloc_contig(nr_pages);
	if (!ffa_proxy_pages)
		return -ENOMEM;

	return 0;
}

static int create_hyp_host_fp_mappings(void)
{
	void *start, *end;
	int ret, i;

	for (i = 0; i < hyp_nr_cpus; i++) {
		start = (void *)kern_hyp_va(kvm_arm_hyp_host_fp_state[i]);
		end = start + PAGE_ALIGN(pkvm_host_fp_state_size());
#ifdef CONFIG_NVHE_GHOST_SPEC
		ret = pkvm_create_mappings(start, end, PAGE_HYP, HYP_HOST_FP_STATE, DUMMY_CPU);
#else
		ret = pkvm_create_mappings(start, end, PAGE_HYP);
#endif /* CONFIG_NVHE_GHOST_SPEC */
		if (ret)
			return ret;
	}

	return 0;
}

static int recreate_hyp_mappings(phys_addr_t phys, unsigned long size,
				 unsigned long *per_cpu_base,
				 u32 hyp_va_bits)
{
	void *start, *end, *virt = hyp_phys_to_virt(phys);
	unsigned long pgt_size = hyp_s1_pgtable_pages() << PAGE_SHIFT;
	enum kvm_pgtable_prot prot;
	int ret, i;

	/* Recreate the hyp page-table using the early page allocator */
	hyp_early_alloc_init(hyp_pgt_base, pgt_size);
	ret = kvm_pgtable_hyp_init(&pkvm_pgtable, hyp_va_bits,
				   &hyp_early_alloc_mm_ops);
	if (ret)
		return ret;

	ret = hyp_create_idmap(hyp_va_bits);
	if (ret)
		return ret;

	ret = hyp_map_vectors();
	if (ret)
		return ret;

	ret = hyp_back_vmemmap(hyp_virt_to_phys(vmemmap_base));
	if (ret)
		return ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
	ret = pkvm_create_mappings(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC, HYP_TEXT, DUMMY_CPU);
#else
	ret = pkvm_create_mappings(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC);
#endif /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
	ret = pkvm_create_mappings(__hyp_data_start, __hyp_data_end, PAGE_HYP, HYP_DATA, DUMMY_CPU);
#else
	ret = pkvm_create_mappings(__hyp_data_start, __hyp_data_end, PAGE_HYP);
#endif /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
	ret = pkvm_create_mappings(__hyp_rodata_start, __hyp_rodata_end, PAGE_HYP_RO, HYP_RODATA, DUMMY_CPU);
#else
	ret = pkvm_create_mappings(__hyp_rodata_start, __hyp_rodata_end, PAGE_HYP_RO);
#endif /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
	ret = pkvm_create_mappings(__hyp_bss_start, __hyp_bss_end, PAGE_HYP, HYP_BSS, DUMMY_CPU);
#else
	ret = pkvm_create_mappings(__hyp_bss_start, __hyp_bss_end, PAGE_HYP);
#endif /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
	ret = pkvm_create_mappings(virt, virt + size, PAGE_HYP, HYP_WORKSPACE, DUMMY_CPU);
#else
	ret = pkvm_create_mappings(virt, virt + size, PAGE_HYP);
#endif /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;

	for (i = 0; i < hyp_nr_cpus; i++) {
		struct kvm_nvhe_init_params *params = per_cpu_ptr(&kvm_init_params, i);

		start = (void *)kern_hyp_va(per_cpu_base[i]);
		end = start + PAGE_ALIGN(hyp_percpu_size);
#ifdef CONFIG_NVHE_GHOST_SPEC
		ret = pkvm_create_mappings(start, end, PAGE_HYP, HYP_PERCPU, i);
#else
		ret = pkvm_create_mappings(start, end, PAGE_HYP);
#endif /* CONFIG_NVHE_GHOST_SPEC */
		if (ret)
			return ret;

		ret = pkvm_create_stack(params->stack_pa, &params->stack_hyp_va);
		if (ret)
			return ret;
	}

	create_hyp_host_fp_mappings();

	/*
	 * Map the pvmfw section RO in the hypervisor, but transfer the
	 * ownership from the host to the hypervisor itself to make sure that it
	 * can't be donated or shared with another entity.
	 *
	 * The ownership transition requires matching changes in the host
	 * stage-2. This will be done later (see finalize_host_mappings()) once
	 * the hyp_vmemmap is addressable.
	 */
	start = hyp_phys_to_virt(pvmfw_base);
	end = start + pvmfw_size;
	prot = pkvm_mkstate(PAGE_HYP_RO, PKVM_PAGE_OWNED);
#ifdef CONFIG_NVHE_GHOST_SPEC
	ret = pkvm_create_mappings(start, end, prot, HYP_PVMFW, DUMMY_CPU);
#else
	ret = pkvm_create_mappings(start, end, prot);
#endif /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;

	return 0;
}

static void update_nvhe_init_params(void)
{
	struct kvm_nvhe_init_params *params;
	unsigned long i;

	for (i = 0; i < hyp_nr_cpus; i++) {
		params = per_cpu_ptr(&kvm_init_params, i);
		params->pgd_pa = __hyp_pa(pkvm_pgtable.pgd);
		dcache_clean_inval_poc((unsigned long)params,
				    (unsigned long)params + sizeof(*params));
	}
}

static void *hyp_zalloc_hyp_page(void *arg)
{
	return hyp_alloc_pages(&hpool, 0);
}

static void hpool_get_page(void *addr)
{
	hyp_get_page(&hpool, addr);
}

static void hpool_put_page(void *addr)
{
	hyp_put_page(&hpool, addr);
}

static int fix_host_ownership_walker(const struct kvm_pgtable_visit_ctx *ctx,
				     enum kvm_pgtable_walk_flags visit)
{
	enum pkvm_page_state state;
	phys_addr_t phys;

	if (!kvm_pte_valid(ctx->old))
		return 0;

	if (ctx->level != (KVM_PGTABLE_MAX_LEVELS - 1))
		return -EINVAL;

	phys = kvm_pte_to_phys(ctx->old);
	if (!addr_is_memory(phys))
		return -EINVAL;

	/*
	 * Adjust the host stage-2 mappings to match the ownership attributes
	 * configured in the hypervisor stage-1.
	 */
	state = pkvm_getstate(kvm_pgtable_hyp_pte_prot(ctx->old));
	switch (state) {
	case PKVM_PAGE_OWNED:
		return host_stage2_set_owner_locked(phys, PAGE_SIZE, PKVM_ID_HYP);
	case PKVM_PAGE_SHARED_OWNED:
		hyp_phys_to_page(phys)->host_state = PKVM_PAGE_SHARED_BORROWED;
		break;
	case PKVM_PAGE_SHARED_BORROWED:
		hyp_phys_to_page(phys)->host_state = PKVM_PAGE_SHARED_OWNED;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int fix_hyp_pgtable_refcnt_walker(const struct kvm_pgtable_visit_ctx *ctx,
					 enum kvm_pgtable_walk_flags visit)
{
	/*
	 * Fix-up the refcount for the page-table pages as the early allocator
	 * was unable to access the hyp_vmemmap and so the buddy allocator has
	 * initialised the refcount to '1'.
	 */
	if (kvm_pte_valid(ctx->old))
		ctx->mm_ops->get_page(ctx->ptep);

	return 0;
}

static int pin_table_walker(const struct kvm_pgtable_visit_ctx *ctx,
			    enum kvm_pgtable_walk_flags visit)
{
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;
	kvm_pte_t pte = *(ctx->ptep);

	if (kvm_pte_valid(pte))
		mm_ops->get_page(kvm_pte_follow(pte, mm_ops));

	return 0;
}

static int pin_host_tables(void)
{
	struct kvm_pgtable_walker walker = {
		.cb	= pin_table_walker,
		.flags	= KVM_PGTABLE_WALK_TABLE_POST,
		.arg	= &host_mmu.mm_ops,
	};

	return kvm_pgtable_walk(&host_mmu.pgt, 0, BIT(host_mmu.pgt.ia_bits), &walker);
}

static int fix_host_ownership(void)
{
	struct kvm_pgtable_walker walker = {
		.cb	= fix_host_ownership_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF,
	};
	int i, ret;

	for (i = 0; i < hyp_memblock_nr; i++) {
		struct memblock_region *reg = &hyp_memory[i];
		u64 start = (u64)hyp_phys_to_virt(reg->base);

		ret = kvm_pgtable_walk(&pkvm_pgtable, start, reg->size, &walker);
		if (ret)
			return ret;
	}

	return 0;
}

static int fix_hyp_pgtable_refcnt(void)
{
	struct kvm_pgtable_walker walker = {
		.cb	= fix_hyp_pgtable_refcnt_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF | KVM_PGTABLE_WALK_TABLE_POST,
		.arg	= pkvm_pgtable.mm_ops,
	};

	return kvm_pgtable_walk(&pkvm_pgtable, 0, BIT(pkvm_pgtable.ia_bits),
				&walker);
}

static int unmap_protected_regions(void)
{
	struct pkvm_moveable_reg *reg;
	int i, ret;

	for (i = 0; i < pkvm_moveable_regs_nr; i++) {
		reg = &pkvm_moveable_regs[i];
		if (reg->type != PKVM_MREG_PROTECTED_RANGE)
			continue;

		ret = host_stage2_set_owner_locked(reg->start, reg->size,
						   PKVM_ID_PROTECTED);
		if (ret)
			return ret;
	}

	return 0;
}

void __noreturn __pkvm_init_finalise(void)
{
	struct kvm_host_data *host_data = this_cpu_ptr(&kvm_host_data);
	struct kvm_cpu_context *host_ctxt = &host_data->host_ctxt;
	unsigned long nr_pages, reserved_pages, pfn;
	int ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
	GHOST_LOG_CONTEXT_ENTER();

	if (ghost_print_on("setup")) {
		// dump some mappings
		ghost_dump_setup();
		//	if (static_branch_unlikely(&kvm_protected_mode_initialized)) {
		ghost_hyp_put_mapping_reqs();
		ghost_dump_pgtable(&pkvm_pgtable,"pkvm_pgtable", 0);
		ghost_check_hyp_mapping_reqs(&pkvm_pgtable,false /*noisy*/);
	}
#endif /* CONFIG_NVHE_GHOST_SPEC */

	/* Now that the vmemmap is backed, install the full-fledged allocator */
	pfn = hyp_virt_to_pfn(hyp_pgt_base);
	nr_pages = hyp_s1_pgtable_pages();
	reserved_pages = hyp_early_alloc_nr_used_pages();
	ret = hyp_pool_init(&hpool, pfn, nr_pages, reserved_pages);
	if (ret)
		goto out;

	ret = kvm_host_prepare_stage2(host_s2_pgt_base);
	if (ret)
		goto out;

	pkvm_pgtable_mm_ops = (struct kvm_pgtable_mm_ops) {
		.zalloc_page = hyp_zalloc_hyp_page,
		.phys_to_virt = hyp_phys_to_virt,
		.virt_to_phys = hyp_virt_to_phys,
		.get_page = hpool_get_page,
		.put_page = hpool_put_page,
		.page_count = hyp_page_count,
	};
	pkvm_pgtable.mm_ops = &pkvm_pgtable_mm_ops;

	ret = fix_hyp_pgtable_refcnt();
	if (ret)
		goto out;

	ret = hyp_create_fixmap();
	if (ret)
		goto out;

	ret = pkvm_timer_init();
	if (ret)
		goto out;

	ret = fix_host_ownership();
	if (ret)
		goto out;

	ret = unmap_protected_regions();
	if (ret)
		goto out;

	ret = pin_host_tables();
	if (ret)
		goto out;

	ret = hyp_ffa_init(ffa_proxy_pages);
	if (ret)
		goto out;

	pkvm_hyp_vm_table_init(vm_table_base);

#ifdef CONFIG_NVHE_GHOST_SPEC
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	ghost_initialise_sm(ghost__pkvm_init_phys, ghost__pkvm_init_size);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	init_abstraction_common();
	init_abstraction_thread_local();
	/* The call to record_abstraction_common() is delayed until the call to
	 * __pkvm_prot_finalize() so that it occurs after the initialisation of
	 * pKVM modules, as they affect the stage-1 mapping of pKVM.
	 */
	WRITE_ONCE(ghost_pkvm_init_finalized, true);
#endif /* CONFIG_NVHE_GHOST_SPEC */

out:

#ifdef CONFIG_NVHE_GHOST_SPEC
	GHOST_LOG_CONTEXT_EXIT(); // __pkvm_init_finalise
#endif /* CONFIG_NVHE_GHOST_SPEC */

	/*
	 * We tail-called to here from handle___pkvm_init() and will not return,
	 * so make sure to propagate the return value to the host.
	 */
	cpu_reg(host_ctxt, 1) = ret;

	__host_enter(host_ctxt);
}

int __pkvm_init(phys_addr_t phys, unsigned long size, unsigned long nr_cpus,
		unsigned long *per_cpu_base, u32 hyp_va_bits)
{
	struct kvm_nvhe_init_params *params;
	void *virt = hyp_phys_to_virt(phys);
	typeof(__pkvm_init_switch_pgd) *fn;
	int ret;

#ifdef CONFIG_NVHE_GHOST_SPEC
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	u64 sm_size = PAGE_ALIGN(2 * sizeof(struct casemate_model_state));
#endif

	GHOST_LOG_CONTEXT_ENTER();

	if (ghost_print_on("setup")) {
		ghost_printf(
			"\n"
			"__pkvm_init:\n"
			"    CPU:..................%d\n"
			"\n"
			"  arguments:\n"
			"    phys:.................%p\n"
			"    size:.................%lx\n"
			"    nr_cpus:..............%lu\n"
			"    per_cpu_base:.........%p\n"
			"    hyp_va_bits:..........%x\n"
			"\n"
			"  interesting globals:\n"
			"    hyp_physvirt_offset:..%llx\n"
			"\n"
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
			"  simplified model:\n"
			"    phys:.................%p\n"
			"    virt:.................%p\n"
			"    size:.................%llx\n"
			"\n"
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
			,
			hyp_smp_processor_id(), (void*)phys, size, nr_cpus,
			per_cpu_base, hyp_va_bits, hyp_physvirt_offset
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
			,
			(void*)(phys+size-sm_size),
			(void*)(virt+size-sm_size),
			sm_size
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
		);
	}
#endif /* CONFIG_NVHE_GHOST_SPEC */

	BUG_ON(kvm_check_pvm_sysreg_table());

#ifdef CONFIG_NVHE_GHOST_SPEC
	if (!PAGE_ALIGNED(phys) || !PAGE_ALIGNED(size)) {
		GHOST_LOG_CONTEXT_EXIT();
		return -EINVAL;
	}
#else /* CONFIG_NVHE_GHOST_SPEC */
	if (!PAGE_ALIGNED(phys) || !PAGE_ALIGNED(size))
		return -EINVAL;
#endif /* CONFIG_NVHE_GHOST_SPEC */

	hyp_spin_lock_init(&pkvm_pgd_lock);
	hyp_nr_cpus = nr_cpus;
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	ret = divide_memory_pool(virt, size - sm_size);
#else /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	ret = divide_memory_pool(virt, size);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ret) {
		GHOST_LOG_CONTEXT_EXIT();
		return ret;
	}
#else /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;
#endif /* CONFIG_NVHE_GHOST_SPEC */

#ifdef CONFIG_NVHE_GHOST_SPEC
	ghost__pkvm_init_phys = phys;
	ghost__pkvm_init_size = size;
	ghost__pkvm_init_virt = (u64)virt;
#endif /* CONFIG_NVHE_GHOST_SPEC */

	ret = recreate_hyp_mappings(phys, size, per_cpu_base, hyp_va_bits);
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ret) {
		GHOST_LOG_CONTEXT_EXIT();
		return ret;
	}
#else /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;
#endif /* CONFIG_NVHE_GHOST_SPEC */

	ret = hyp_alloc_init(SZ_128M);
#ifdef CONFIG_NVHE_GHOST_SPEC
	if (ret) {
		GHOST_LOG_CONTEXT_EXIT();
		return ret;
	}
#else /* CONFIG_NVHE_GHOST_SPEC */
	if (ret)
		return ret;
#endif /* CONFIG_NVHE_GHOST_SPEC */

	update_nvhe_init_params();

#ifdef CONFIG_NVHE_GHOST_SPEC
	//	hyp_putc('P');hyp_putc('S');hyp_putc('H');hyp_putc('A');hyp_putc('C');hyp_putc('k');hyp_putc('\n');
	GHOST_LOG_CONTEXT_EXIT();
	// because we will tail call here with no intention of returning,
	// pop the parents off as well.
	GHOST_LOG_CONTEXT_EXIT_FORCE("handle_host_hcall");
	GHOST_LOG_CONTEXT_EXIT_FORCE("handle_trap");
#endif /* CONFIG_NVHE_GHOST_SPEC */

	/* Jump in the idmap page to switch to the new page-tables */
	params = this_cpu_ptr(&kvm_init_params);
	fn = (typeof(fn))__hyp_pa(__pkvm_init_switch_pgd);
	fn(params->pgd_pa, params->stack_hyp_va, __pkvm_init_finalise);

	unreachable();
}
