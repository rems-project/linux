#include <picovm/mem_protect.h>
#include <picovm/mm.h>
#include <picovm/memory.h>
#include <picovm/picovm.h>
#include <picovm/spinlock.h>

// NOTE: based on linux/arch/arm64/kvm/hyp/nvhe/setup.c
s64 __ro_after_init hyp_physvirt_offset;

unsigned long hyp_nr_cpus;

#define kern_hyp_va(v) v
#define hyp_percpu_size ((unsigned long)__per_cpu_end - \
			 (unsigned long)__per_cpu_start)


// NOTE: based on linux/arch/arm64/kvm/hyp/nvhe/
static unsigned long base;
static unsigned long end;
static unsigned long cur;

static void *vmemmap_base;
static void *vm_table_base;
static void *hyp_pgt_base;
static void *host_s2_pgt_base;

unsigned long hyp_early_alloc_nr_used_pages(void)
{
	return (cur - base) >> PAGE_SHIFT;
}

void *hyp_early_alloc_contig(unsigned int nr_pages)
{
	unsigned long size = (nr_pages << PAGE_SHIFT);
	void *ret = (void *)cur;

	if (!nr_pages)
		return NULL;

	if (end - cur < size)
		return NULL;

	cur += size;
	memset(ret, 0, size);

	return ret;
}

void *hyp_early_alloc_page(void *arg)
{
	return hyp_early_alloc_contig(1);
}

static void hyp_early_alloc_get_page(void *addr) { }
static void hyp_early_alloc_put_page(void *addr) { }

void hyp_early_alloc_init(void *virt, unsigned long size)
{
	base = cur = (unsigned long)virt;
	end = base + size;
}

static inline unsigned long __hyp_pgtable_total_pages(void)
{
	unsigned long res = 0, i;

	/* Cover all of memory with page-granularity */
	for (i = 0; i < hyp_memblock_nr; i++) {
		struct memblock_region *reg = &hyp_memory[i];
		res += __hyp_pgtable_max_pages(reg->size >> PAGE_SHIFT);
	}

	return res;
}

static inline unsigned long hyp_s1_pgtable_pages(void)
{
	unsigned long res;

	res = __hyp_pgtable_total_pages();

	/* Allow 1 GiB for private mappings */
	res += __hyp_pgtable_max_pages(SZ_1G >> PAGE_SHIFT);

	return res;
}

static inline unsigned long host_s2_pgtable_pages(void)
{
	unsigned long res;

	/*
	 * Include an extra 16 pages to safely upper-bound the worst case of
	 * concatenated pgds.
	 */
	res = __hyp_pgtable_total_pages() + 16;

	/* Allow 1 GiB for MMIO mappings */
	res += __hyp_pgtable_max_pages(SZ_1G >> PAGE_SHIFT);

	return res;
}

// from arch/arm64/kvm/hyp/nvhe/setup.c
static int divide_memory_pool(void *virt, unsigned long size)
{
	unsigned long nr_pages;
  base = cur = (unsigned long)virt;
	end = base + size;

	nr_pages = hyp_s1_pgtable_pages();
	hyp_pgt_base = hyp_early_alloc_contig(nr_pages);
	if (!hyp_pgt_base)
		return -ENOMEM;

	nr_pages = host_s2_pgtable_pages();
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
	enum picovm_pgtable_prot prot;
	int ret, i;

	/* Recreate the hyp page-table using the early page allocator */
	hyp_early_alloc_init(hyp_pgt_base, pgt_size);
	ret = picovm_pgtable_hyp_init(&picovm_pgtable, hyp_va_bits);
	if (ret)
		return ret;

  // TODO: uncomment when they are needed
	// ret = hyp_create_idmap(hyp_va_bits);
	// if (ret)
	// 	return ret;
	//
	// ret = hyp_map_vectors();
	// if (ret)
	// 	return ret;
	//
	// ret = hyp_back_vmemmap(hyp_virt_to_phys(vmemmap_base));
	// if (ret)
	// 	return ret;

	ret = picovm_create_mappings(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC);
	if (ret)
		return ret;

	ret = picovm_create_mappings(__hyp_rodata_start, __hyp_rodata_end, PAGE_HYP_RO);
	if (ret)
		return ret;

	ret = picovm_create_mappings(__hyp_bss_start, __hyp_bss_end, PAGE_HYP);
	if (ret)
		return ret;

	ret = picovm_create_mappings(virt, virt + size, PAGE_HYP);
	if (ret)
		return ret;

	for (i = 0; i < hyp_nr_cpus; i++) {
		struct picovm_nvhe_init_params *params = per_cpu_ptr(&picovm_init_params, i);
    unsigned long hyp_addr;

		start = (void *)kern_hyp_va(per_cpu_base[i]);
		end = start + PAGE_ALIGN(hyp_percpu_size);
		ret = picovm_create_mappings(start, end, PAGE_HYP);
		if (ret)
			return ret;

		/*
		 * Allocate a contiguous HYP private VA range for the stack
		 * and guard page. The allocation is also aligned based on
		 * the order of its size.
		 */
		ret = picovm_alloc_private_va_range(PAGE_SIZE + EL2_STACKSIZE, &hyp_addr);
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
		hyp_spin_lock(&picovm_pgd_lock);
		ret = picovm_pgtable_hyp_map(&picovm_pgtable, hyp_addr + PAGE_SIZE,
					EL2_STACKSIZE, params->stack_pa, PAGE_HYP);

		hyp_spin_unlock(&picovm_pgd_lock);
		if (ret)
			return ret;

		/* Update stack_hyp_va to end of the stack's private VA range */
		params->stack_hyp_va = hyp_addr + PAGE_SIZE + EL2_STACKSIZE;
	}

	return 0;
}

static void update_nvhe_init_params(void)
{
	struct kvm_nvhe_init_params *params;
	unsigned long i;

	for (i = 0; i < hyp_nr_cpus; i++) {
		params = per_cpu_ptr(&picovm_init_params, i);
		params->pgd_pa = __hyp_pa(picovm_pgtable.pgd);
		dcache_clean_inval_poc((unsigned long)params,
				    (unsigned long)params + sizeof(*params));
	}
}

void __noreturn __picovm_init_finalise(void)
{
  // TODO
	// struct kvm_host_data *host_data = this_cpu_ptr(&kvm_host_data);
	// struct kvm_cpu_context *host_ctxt = &host_data->host_ctxt;
	// unsigned long nr_pages, reserved_pages, pfn;
	// int ret;
	//
	// /* Now that the vmemmap is backed, install the full-fledged allocator */
	// pfn = hyp_virt_to_pfn(hyp_pgt_base);
	// nr_pages = hyp_s1_pgtable_pages();
	// reserved_pages = hyp_early_alloc_nr_used_pages();
	// ret = hyp_pool_init(&hpool, pfn, nr_pages, reserved_pages);
	// if (ret)
	// 	goto out;
	//
	// ret = kvm_host_prepare_stage2(host_s2_pgt_base);
	// if (ret)
	// 	goto out;
	//
	// pkvm_pgtable_mm_ops = (struct kvm_pgtable_mm_ops) {
	// 	.zalloc_page = hyp_zalloc_hyp_page,
	// 	.phys_to_virt = hyp_phys_to_virt,
	// 	.virt_to_phys = hyp_virt_to_phys,
	// 	.get_page = hpool_get_page,
	// 	.put_page = hpool_put_page,
	// 	.page_count = hyp_page_count,
	// };
	// pkvm_pgtable.mm_ops = &pkvm_pgtable_mm_ops;
	//
	// ret = fix_host_ownership();
	// if (ret)
	// 	goto out;
	//
	// ret = fix_hyp_pgtable_refcnt();
	// if (ret)
	// 	goto out;
	//
	// ret = hyp_create_pcpu_fixmap();
	// if (ret)
	// 	goto out;
	//
	// pkvm_hyp_vm_table_init(vm_table_base);

out:
	/*
	 * We tail-called to here from handle___pkvm_init() and will not return,
	 * so make sure to propagate the return value to the host.
	 */
	// cpu_reg(host_ctxt, 1) = ret;
	//
	// __host_enter(host_ctxt);
}


// from arch/arm64/kvm/hyp/nvhe/setup.c
int __picovm_init(phys_addr_t phys, unsigned long size, unsigned long nr_cpus,
		unsigned long *per_cpu_base, u32 hyp_va_bits)
{
	struct kvm_nvhe_init_params *params;
	void *virt = hyp_phys_to_virt(phys);
	void (*fn)(phys_addr_t params_pa, void *finalize_fn_va);
	int ret;

	if (!PAGE_ALIGNED(phys) || !PAGE_ALIGNED(size))
		return -EINVAL;

	hyp_spin_lock_init(&picovm_pgd_lock);
	hyp_nr_cpus = nr_cpus;
	ret = divide_memory_pool(virt, size);
	if (ret)
		return ret;

  ret = recreate_hyp_mappings(phys, size, per_cpu_base, hyp_va_bits);
	if (ret)
		return ret;

	update_nvhe_init_params();

	/* Jump in the idmap page to switch to the new page-tables */
	params = this_cpu_ptr(&picovm_init_params);
	fn = (typeof(fn))__hyp_pa(__picovm_init_switch_pgd);
	fn(__hyp_pa(params), __picovm_init_finalise);

	unreachable();
}
