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

#include <nvhe/early_alloc.h>
#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/trap_handler.h>


// GHOST
#include <../debug-pl011.h>
#include <../ghost_extra_debug-pl011.h>
#include <nvhe/ghost_mapping_reqs.h>
#include <nvhe/ghost_misc.h>
#include "./ghost_compute_abstraction.h"
#include <../ghost_pgtable.h>
#include "../ghost_control.h"
// /GHOST

unsigned long hyp_nr_cpus;

#define hyp_percpu_size ((unsigned long)__per_cpu_end - \
			 (unsigned long)__per_cpu_start)


#ifdef CONFIG_KVM_ARM_HYP_DEBUG_UART
unsigned long arm64_kvm_hyp_debug_uart_addr;
static int create_hyp_debug_uart_mapping(void)
{
	phys_addr_t base = CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR;

	return __pkvm_create_private_mapping_ghost(base, PAGE_SIZE, PAGE_HYP_DEVICE,
					           &arm64_kvm_hyp_debug_uart_addr, HYP_UART);
}
#else
static int create_hyp_debug_uart_mapping(void) { return 0; }
#endif

// GHOST
// Ghost: removed static (perhaps better to add explicit ghost copies?)
/*static*/ void *vmemmap_base;
/*static*/ void *vm_table_base;
/*static*/ void *hyp_pgt_base;
/*static*/ void *host_s2_pgt_base;
// /GHOST

static struct kvm_pgtable_mm_ops pkvm_pgtable_mm_ops;
static struct hyp_pool hpool;

// GHOST
u64 ghost_vmemmap_size;
u64 ghost_vm_table_size;
u64 ghost_hyp_pgt_size;
u64 ghost_host_s2_pgt_size;

u64 ghost__pkvm_init_phys;
u64 ghost__pkvm_init_size;
u64 ghost__pkvm_init_virt;
// /GHOST


static int divide_memory_pool(void *virt, unsigned long size)
{
	unsigned long nr_pages;

	hyp_early_alloc_init(virt, size);

	nr_pages = hyp_vmemmap_pages(sizeof(struct hyp_page));
	// GHOST
	ghost_vmemmap_size = nr_pages;
	// /GHOST
	vmemmap_base = hyp_early_alloc_contig(nr_pages);
	if (!vmemmap_base)
		return -ENOMEM;

	nr_pages = hyp_vm_table_pages();
	// GHOST
	ghost_vm_table_size = nr_pages;
	// /GHOST
	vm_table_base = hyp_early_alloc_contig(nr_pages);
	if (!vm_table_base)
		return -ENOMEM;

	nr_pages = hyp_s1_pgtable_pages();
	// GHOST
	ghost_hyp_pgt_size = nr_pages;
	// /GHOST
	hyp_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!hyp_pgt_base)
		return -ENOMEM;

	nr_pages = host_s2_pgtable_pages();
	// GHOST
	ghost_host_s2_pgt_size = nr_pages;
	// /GHOST
	host_s2_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!host_s2_pgt_base)
		return -ENOMEM;

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

	ret = pkvm_create_mappings_ghost(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC, HYP_TEXT, DUMMY_CPU);

	// PS HACK: in principle we should guard the extra ghost arguments with a preprocessor conditional, eg as below. But that's very ugly, so I'll skip for now, and use the _ghost function instead
	//
	//					ret = pkvm_create_mappings_ghost(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC
	//#ifdef GHOST
	//				, HYP_TEXT
	//#endif
	//);
	if (ret)
		return ret;

	ret = pkvm_create_mappings_ghost(__hyp_rodata_start, __hyp_rodata_end, PAGE_HYP_RO, HYP_RODATA, DUMMY_CPU);
	if (ret)
		return ret;

	ret = pkvm_create_mappings_ghost(__hyp_bss_start, __hyp_bss_end, PAGE_HYP, HYP_BSS, DUMMY_CPU);
	if (ret)
		return ret;

	ret = pkvm_create_mappings_ghost(virt, virt + size, PAGE_HYP, HYP_WORKSPACE, DUMMY_CPU);
	if (ret)
		return ret;

	for (i = 0; i < hyp_nr_cpus; i++) {
		struct kvm_nvhe_init_params *params = per_cpu_ptr(&kvm_init_params, i);
		unsigned long hyp_addr;

		start = (void *)kern_hyp_va(per_cpu_base[i]);
		end = start + PAGE_ALIGN(hyp_percpu_size);
		ret = pkvm_create_mappings_ghost(start, end, PAGE_HYP, HYP_PERCPU, i);
		if (ret)
			return ret;

		/*
		 * Allocate a contiguous HYP private VA range for the stack
		 * and guard page. The allocation is also aligned based on
		 * the order of its size.
		 */
		ret = pkvm_alloc_private_va_range(PAGE_SIZE + EL2_STACKSIZE, &hyp_addr);

		// GHOST
		// the stack instrumentation was
		//end = (void *)per_cpu_ptr(&kvm_init_params, i)->stack_hyp_va;
		//start = end - PAGE_SIZE;
		//ret = pkvm_create_mappings_ghost(start, end, PAGE_HYP, HYP_STACKS, i);
		// /GHOST

		if (ret)
			return ret;

		/*
		 * Since the stack grows downwards, map the stack to the page
		 * at the higher address and leave the lower guard page
		 * unbacked.
		 *
		 * Any valid stack address now has the PAGE_SHIFT bit as 1
		 * and addresses corresponding to the guard page have the
		 * PAGE_SHIFT bit as 0 - this is used for overflow detection.
		 */
		hyp_spin_lock(&pkvm_pgd_lock);
		ret = kvm_pgtable_hyp_map(&pkvm_pgtable, hyp_addr + PAGE_SIZE,
					EL2_STACKSIZE, params->stack_pa, PAGE_HYP);

		// GHOST XXX REVIEW RE: variable stack size!
		ghost_record_mapping_req(hyp_addr + PAGE_SIZE,
					EL2_STACKSIZE, params->stack_pa, PAGE_HYP, HYP_STACKS);
		// /GHOST

		hyp_spin_unlock(&pkvm_pgd_lock);
		if (ret)
			return ret;

		/* Update stack_hyp_va to end of the stack's private VA range */
		params->stack_hyp_va = hyp_addr + PAGE_SIZE + EL2_STACKSIZE;
	}

	/*
	 * Map the host sections RO in the hypervisor, but transfer the
	 * ownership from the host to the hypervisor itself to make sure they
	 * can't be donated or shared with another entity.
	 *
	 * The ownership transition requires matching changes in the host
	 * stage-2. This will be done later (see finalize_host_mappings()) once
	 * the hyp_vmemmap is addressable.
	 */
	prot = pkvm_mkstate(PAGE_HYP_RO, PKVM_PAGE_SHARED_OWNED);

	ret = pkvm_create_mappings_ghost(&kvm_vgic_global_state,
					&kvm_vgic_global_state + 1, prot, HYP_VGIC, DUMMY_CPU);
	if (ret)
		return ret;

	ret = create_hyp_debug_uart_mapping();
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
	enum kvm_pgtable_prot prot;
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
		prot = pkvm_mkstate(PKVM_HOST_MEM_PROT, PKVM_PAGE_SHARED_BORROWED);
		break;
	case PKVM_PAGE_SHARED_BORROWED:
		prot = pkvm_mkstate(PKVM_HOST_MEM_PROT, PKVM_PAGE_SHARED_OWNED);
		break;
	default:
		return -EINVAL;
	}

	return host_stage2_idmap_locked(phys, PAGE_SIZE, prot);
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

void __noreturn __pkvm_init_finalise(void)
{
	struct kvm_host_data *host_data = this_cpu_ptr(&kvm_host_data);
	struct kvm_cpu_context *host_ctxt = &host_data->host_ctxt;
	unsigned long nr_pages, reserved_pages, pfn;
	int ret;

	// GHOST
	int i;
	// mark all CPUs as not yet finished __pkvm_prot_finalize
	//hyp_spin_lock(ghost_prot_finalized_lock); // no need for this here
	for (i=0; i<NR_CPUS; i++)
		pkvm_prot_finalized_cpu[i]=false;
	//hyp_spin_unlock(ghost_prot_finalized_lock);
	// register the debug output
	ghost_extra_debug_initialised = true;
	// dump some mappings
	ghost_dump_setup();
	//	if (static_branch_unlikely(&kvm_protected_mode_initialized)) {
	ghost_hyp_put_mapping_reqs();
	ghost_dump_pgtable(&pkvm_pgtable,"pkvm_pgtable", 0);
	ghost_check_hyp_mapping_reqs(&pkvm_pgtable,false /*noisy*/);
	// /GHOST



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

	ret = fix_host_ownership();
	if (ret)
		goto out;

	ret = fix_hyp_pgtable_refcnt();
	if (ret)
		goto out;

	ret = hyp_create_pcpu_fixmap();
	if (ret)
		goto out;

	pkvm_hyp_vm_table_init(vm_table_base);

out:
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
	void (*fn)(phys_addr_t params_pa, void *finalize_fn_va);
	int ret;

	// GHOST
	init_ghost_control();

	hyp_puts("\n__pkvm_init:");
	hyp_puts("arguments:");
	hyp_putsxnl("phys", phys, 64);
	hyp_putsxnl("size", size, 32);
	hyp_putsxnl("nr_cpu", nr_cpus, 8);
	hyp_putsxnl("per_cpu_base", (u64)per_cpu_base, 64);
	hyp_putsxnl("hyp_va_bits", (u64)hyp_va_bits, 8);

	hyp_puts("\nInteresting globals:");
	hyp_putsxnl("hyp_physvirt_offset", hyp_physvirt_offset, 64);
	// /GHOST

	BUG_ON(kvm_check_pvm_sysreg_table());

	if (!PAGE_ALIGNED(phys) || !PAGE_ALIGNED(size))
		return -EINVAL;

	hyp_spin_lock_init(&pkvm_pgd_lock);
	hyp_nr_cpus = nr_cpus;

	ret = divide_memory_pool(virt, size);
	if (ret)
		return ret;

	// GHOST
	ghost__pkvm_init_phys = phys;
	ghost__pkvm_init_size = size;
	ghost__pkvm_init_virt = (u64)virt;
	// /GHOST

	ret = recreate_hyp_mappings(phys, size, per_cpu_base, hyp_va_bits);
	if (ret)
		return ret;

	update_nvhe_init_params();

	// GHOST
	//	hyp_putc('P');hyp_putc('S');hyp_putc('H');hyp_putc('A');hyp_putc('C');hyp_putc('k');hyp_putc('\n');
	// /GHOST


	/* Jump in the idmap page to switch to the new page-tables */
	params = this_cpu_ptr(&kvm_init_params);
	fn = (typeof(fn))__hyp_pa(__pkvm_init_switch_pgd);
	fn(__hyp_pa(params), __pkvm_init_finalise);

	unreachable();
}
