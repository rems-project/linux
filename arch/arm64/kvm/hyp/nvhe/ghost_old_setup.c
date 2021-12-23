// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>

#include <nvhe/early_alloc.h>
#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/trap_handler.h>

// PS HACK
#include <../debug-pl011.h>
#include <../check-debug-pl011.h>


// PS HACK
/*
#include <nvhe/check-pkvm-pgtables.h>
#include <asm/kvm_asm.h>
*/
#include <nvhe/check-pkvm-pgtables.h>
#include <nvhe/check-pkvm-asm.h>


struct hyp_pool hpool;
unsigned long hyp_nr_cpus;

#define hyp_percpu_size ((unsigned long)__per_cpu_end - \
			 (unsigned long)__per_cpu_start)

#ifdef CONFIG_KVM_ARM_HYP_DEBUG_UART
unsigned long arm64_kvm_hyp_debug_uart_addr;
static int create_hyp_debug_uart_mapping(void)
{
	phys_addr_t base = CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR;
	unsigned long haddr;

	haddr = __pkvm_create_private_mapping(base, PAGE_SIZE, PAGE_HYP_DEVICE);
	if (!haddr)
		return -1;

	arm64_kvm_hyp_debug_uart_addr = haddr;

	return 0;
}
#else
static int create_hyp_debug_uart_mapping(void) { return 0; }
#endif


/* JK HACK : replace them with the following ones
 static void *vmemmap_base;
 static void *hyp_pgt_base;
 static void *host_s2_pgt_base;
+*/

// PS HACK REMOVE static FROM BELOW TO MAKE VISIBLE IN check-pkvm-pgtables.c AND ADD size's
// JK HACK: It seems we do not need stacks_base and stacks_size any more in our
// new version. So I removed them. 
void *stacks_base;
void *vmemmap_base;
void *hyp_pgt_base;
void *host_s2_pgt_base;
static struct kvm_pgtable_mm_ops pkvm_pgtable_mm_ops;

void* early_remainder;

// JK: add the following lines to memorize size 
unsigned long stacks_size;
unsigned long vmemmap_size;
unsigned long hyp_pgt_size;
unsigned long host_s2_pgt_size;

static int divide_memory_pool(void *virt, unsigned long size)
{
	unsigned long vstart, vend, nr_pages;

	hyp_early_alloc_init(virt, size);

        // JK : added, but we need to check it later
        stacks_size = hyp_nr_cpus;
        stacks_base = hyp_early_alloc_contig(hyp_nr_cpus);
        if (!stacks_base)
                return -ENOMEM;

	hyp_vmemmap_range(__hyp_pa(virt), size, &vstart, &vend);
	nr_pages = (vend - vstart) >> PAGE_SHIFT;
        // JK HACK : save the size of vmemmap 
        vmemmap_size = nr_pages;
        hyp_putsxn("divide_memory_pool: vmemmap_size - ", vmemmap_size, 64);
        hyp_putsp("\n");
      
	vmemmap_base = hyp_early_alloc_contig(nr_pages);
	if (!vmemmap_base)
		return -ENOMEM;

	nr_pages = hyp_s1_pgtable_pages();
        // JK HACK : save the size of hyp_pgt_base
        hyp_pgt_size = nr_pages; // JK HACK : added
        hyp_putsxn("divide_memory_pool: hyp_pgt_size - ", hyp_pgt_size, 64);
        hyp_putsp("\n");
	
        hyp_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!hyp_pgt_base)
		return -ENOMEM;

	nr_pages = host_s2_pgtable_pages();
        // JK HACK : save the size of hyp_pgt_base
        host_s2_pgt_size = nr_pages; // JK HACK : added
        hyp_putsxn("divide_memory_pool: host_s2_mem_pgt_size - ", 
                   host_s2_pgt_size, 64);
        hyp_putsp("\n");

	host_s2_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!host_s2_pgt_base)
		return -ENOMEM;

        // PS HACK: record start of remainder
        early_remainder = (void*)hyp_early_alloc_cur();

	return 0;
}

static int recreate_hyp_mappings(phys_addr_t phys, unsigned long size,
				 unsigned long *per_cpu_base,
                                 u32 hyp_va_bits, unsigned long nr_cpus) // JK HACK: added
//                              u32 hyp_va_bits) // JK HACK : replaced with the
//                              above line 
{
        _Bool check;


	void *start, *end, *virt = hyp_phys_to_virt(phys);
	unsigned long pgt_size = hyp_s1_pgtable_pages() << PAGE_SHIFT;
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

	ret = hyp_back_vmemmap(phys, size, hyp_virt_to_phys(vmemmap_base));
	if (ret)
		return ret;

	ret = pkvm_create_mappings(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC);
	if (ret)
		return ret;

	ret = pkvm_create_mappings(__start_rodata, __end_rodata, PAGE_HYP_RO);
	if (ret)
		return ret;

	ret = pkvm_create_mappings(__hyp_rodata_start, __hyp_rodata_end, PAGE_HYP_RO);
	if (ret)
		return ret;

	ret = pkvm_create_mappings(__hyp_bss_start, __hyp_bss_end, PAGE_HYP);
	if (ret)
		return ret;

	ret = pkvm_create_mappings(__hyp_bss_end, __bss_stop, PAGE_HYP_RO);
	if (ret)
		return ret;

	ret = pkvm_create_mappings(virt, virt + size, PAGE_HYP);
	if (ret)
		return ret;

	for (i = 0; i < hyp_nr_cpus; i++) {
		start = (void *)kern_hyp_va(per_cpu_base[i]);
		end = start + PAGE_ALIGN(hyp_percpu_size);
		ret = pkvm_create_mappings(start, end, PAGE_HYP);
		if (ret)
			return ret;

		end = (void *)per_cpu_ptr(&kvm_init_params, i)->stack_hyp_va;
		start = end - PAGE_SIZE;
		ret = pkvm_create_mappings(start, end, PAGE_HYP);
		if (ret)
			return ret;
	}

        // PS HACK
        hyp_puts("PS HACK");
        dump_pgtable(pkvm_pgtable);

        // PS HACK
        // check sample property of the putative mapping
        record_hyp_mappings(phys, size, nr_cpus, per_cpu_base);
        check = check_hyp_mappings(pkvm_pgtable.pgd, CHECK_QUIET);



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

void __noreturn __pkvm_init_finalise(void)
{
	struct kvm_host_data *host_data = this_cpu_ptr(&kvm_host_data);
	struct kvm_cpu_context *host_ctxt = &host_data->host_ctxt;
	unsigned long nr_pages, reserved_pages, pfn;
	int ret;

        // JK HACK - added the following variable 
        unsigned long used_pages;

        
        // PS HACK - check the mappings again after the switch
        struct kvm_nvhe_init_params params_snapshot;
        hyp_puts("PS HACK AFTER SWITCH");
         ___kvm_get_sysregs(&params_snapshot);
        dump_kvm_nvhe_init_params(&params_snapshot);
        // the check fails at present just because the 
        // uart mapping isn't recorded
        check_hyp_mappings(pkvm_pgtable.pgd, CHECK_NOISY);


	/* Now that the vmemmap is backed, install the full-fledged allocator */
	pfn = hyp_virt_to_pfn(hyp_pgt_base);
	nr_pages = hyp_s1_pgtable_pages();
	reserved_pages = hyp_early_alloc_nr_used_pages();

        // JK HACK - add the following line to calculate used_pages
        used_pages = hyp_early_alloc_nr_used_pages();
	ret = hyp_pool_init(&hpool, pfn, nr_pages, reserved_pages, used_pages);
	// JK HACK - the following line is replaced with the above line
        // ret = hyp_pool_init(&hpool, pfn, nr_pages, reserved_pages);

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
	};
	pkvm_pgtable.mm_ops = &pkvm_pgtable_mm_ops;

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

	if (!PAGE_ALIGNED(phys) || !PAGE_ALIGNED(size))
		return -EINVAL;

	hyp_spin_lock_init(&pkvm_pgd_lock);
	hyp_nr_cpus = nr_cpus;

	ret = divide_memory_pool(virt, size);
	if (ret)
		return ret;

        // JK HACKED : replaced with the following line
       ret = recreate_hyp_mappings(phys, size, per_cpu_base, hyp_va_bits, (unsigned long)per_cpu_base);
       // ret = recreate_hyp_mappings(phys, size, per_cpu_base, hyp_va_bits);

	if (ret)
		return ret;

	update_nvhe_init_params();

       // PS HACK
       // check sample property of the putative mapping
       //
       // _Bool check = check_hyp_mappings(phys, size, nr_cpus, per_cpu_base);

       // PS HACK
       // hyp_putc('P');hyp_putc('S');hyp_putc('H');hyp_putc('A');hyp_putc('C');hyp_putc('k');hyp_putc('\n');

	/* Jump in the idmap page to switch to the new page-tables */
	params = this_cpu_ptr(&kvm_init_params);
	fn = (typeof(fn))__hyp_pa(__pkvm_init_switch_pgd);
	fn(__hyp_pa(params), __pkvm_init_finalise);

	unreachable();
}
