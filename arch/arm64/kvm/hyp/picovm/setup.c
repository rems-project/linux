/*
 * Based on arch/arm64/kvm/hyp/nvhe/setup.c
 */
#include "picovm/pgtable.h"
#include <picovm/asm/errno-base.h>

#include <picovm/per-cpu.h>
#include <picovm/page.h>
#include <picovm/memory.h>

#include <picovm/config.h>
#include <picovm/kvm_hyp.h>
#include <picovm/kvm_picovm.h>

#include <picovm/early_alloc.h>
#include <picovm/spinlock.h>
#include <picovm/mem_protect.h>
#include <picovm/mm.h>
#include <picovm/trap_handler.h>

// DEFINED IN kvm_interface.c
extern s64 hyp_physvirt_offset;
extern struct memblock_region hyp_memory[];
extern unsigned int hyp_memblock_nr;

// DEFINED by linker script
extern char __per_cpu_start[];
extern char __per_cpu_end[];

// DEFINED IN cache.s
extern void dcache_clean_inval_poc(unsigned long start, unsigned long end);

unsigned long hyp_nr_cpus;

// Simplified from arch/arm64/include/asm/kvm_mmu.h and deps
// BEGIN **********************************************************************
#define ARM64_CB_SHIFT	15
#define ARM64_ALWAYS_SYSTEM                 	1 // TODO this is from a generated file
#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#define ALTINSTR_ENTRY_CB(feature, cb)					      \
	" .word 661b - .\n"				/* label           */ \
	" .word " __stringify(cb) "- .\n"		/* callback */	      \
	" .hword " __stringify(feature) "\n"		/* feature bit     */ \
	" .byte 662b-661b\n"				/* source len      */ \
	" .byte 664f-663f\n"				/* replacement len */

#define __ALTERNATIVE_CFG_CB(oldinstr, feature, cfg_enabled, cb)	\
	".if "__stringify(cfg_enabled)" == 1\n"				\
	"661:\n\t"							\
	oldinstr "\n"							\
	"662:\n"							\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY_CB(feature, cb)					\
	".popsection\n"							\
	"663:\n\t"							\
	"664:\n\t"							\
	".endif\n"

#define ALTERNATIVE_CB(oldinstr, feature, cb) \
	__ALTERNATIVE_CFG_CB(oldinstr, (1 << ARM64_CB_SHIFT) | (feature), 1, cb)

struct alt_instr {
	s32 orig_offset;	/* offset to original instruction */
	s32 alt_offset;		/* offset to replacement instruction */
	u16 cpufeature;		/* cpufeature bit set for replacement */
	u8  orig_len;		/* size of original instruction(s) */
	u8  alt_len;		/* size of new instruction(s), <= orig_len */
};
void kvm_update_va_mask(struct alt_instr *alt,
			u32 *origptr, u32 *updptr, int nr_inst);

#ifdef CONFIG_PICOVM_CLIGHTPLUS
extern __always_inline unsigned long __kern_hyp_va(unsigned long v);
#else
static __always_inline unsigned long __kern_hyp_va(unsigned long v)
{
#ifndef __KVM_VHE_HYPERVISOR__
	asm volatile(ALTERNATIVE_CB("and %0, %0, #1\n"
				    "ror %0, %0, #1\n"
				    "add %0, %0, #0\n"
				    "add %0, %0, #0, lsl 12\n"
				    "ror %0, %0, #63\n",
				    ARM64_ALWAYS_SYSTEM,
				    kvm_update_va_mask)
		     : "+r" (v));
#endif
	return v;
}
#endif

#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define kern_hyp_va(v) 	(u64)(__kern_hyp_va((unsigned long)(v)))
#else
#define kern_hyp_va(v) 	((typeof(v))(__kern_hyp_va((unsigned long)(v))))
#endif
// END ************************************************************************


#define hyp_percpu_size ((unsigned long)__per_cpu_end - \
			 (unsigned long)__per_cpu_start)

#define EL2_STACK_NR_PAGES (PICOVM_CONFIG_NVHE_EL2_STACKSIZE)
#define EL2_STACKSIZE (PAGE_SIZE * EL2_STACK_NR_PAGES)

unsigned long arm64_kvm_hyp_debug_uart_addr;
static int create_hyp_debug_uart_mapping(void)
{
	phys_addr_t base = CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR;

	return __picovm_create_private_mapping(base, PAGE_SIZE, PAGE_HYP_DEVICE,
						&arm64_kvm_hyp_debug_uart_addr);
}

static void *hyp_pgt_base;
static void *host_s2_pgt_base;

// from arch/arm64/kvm/hyp/nvhe/setup.c
static int divide_memory_pool(void *virt, unsigned long size)
{
	unsigned long nr_pages;
	hyp_early_alloc_init(virt, size);
  	
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
	int ret, i;

	/* Recreate the hyp page-table using the early page allocator */
	hyp_early_alloc_init(hyp_pgt_base, pgt_size);
	ret = picovm_pgtable_hyp_init(&picovm_pgtable, hyp_va_bits);
	if (ret)
		return ret;

	ret = hyp_create_idmap(hyp_va_bits);
	if (ret)
		return ret;

	ret = hyp_map_vectors();
	if (ret)
		return ret;

	ret = picovm_create_mappings(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC);
	if (ret)
		return ret;

	ret = picovm_create_mappings(__hyp_rodata_start, __hyp_rodata_end, PAGE_HYP_RO);
	if (ret)
		return ret;

	ret = picovm_create_mappings(__hyp_bss_start, __hyp_bss_end, PAGE_HYP);
	if (ret)
		return ret;

	#ifdef CONFIG_PICOVM_CLIGHTPLUS
	u64 start_u64 = (u64)virt;
	u64 end_u64 = start_u64 + size;
	ret = picovm_create_mappings((void *)start_u64, (void *)end_u64, PAGE_HYP);
	#else
	ret = picovm_create_mappings(virt, virt + size, PAGE_HYP);
	#endif
	if (ret)
		return ret;

	for (i = 0; i < hyp_nr_cpus; i++) {
		struct kvm_nvhe_init_params *params = per_cpu_ptr(&kvm_init_params, i);
		unsigned long hyp_addr;

		#ifdef CONFIG_PICOVM_CLIGHTPLUS
		u64 start_u64 = kern_hyp_va(per_cpu_base[i]);
		u64 end_u64 = start_u64 + PAGE_ALIGN(hyp_percpu_size);
		ret = picovm_create_mappings((void *)start_u64, (void *)end_u64, PAGE_HYP);
		#else
		start = (void *)kern_hyp_va(per_cpu_base[i]);
		end = start + PAGE_ALIGN(hyp_percpu_size);
		ret = picovm_create_mappings(start, end, PAGE_HYP);
		#endif
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
	
	create_hyp_debug_uart_mapping();
	return 0;
}

static void update_nvhe_init_params(void)
{
	struct kvm_nvhe_init_params *params;
	unsigned long i;

	for (i = 0; i < hyp_nr_cpus; i++) {
		params = per_cpu_ptr(&kvm_init_params, i);
		params->pgd_pa = __hyp_pa(picovm_pgtable.pgd);
		dcache_clean_inval_poc((unsigned long)params,
				    (unsigned long)params + sizeof(*params));
	}
}

static int fix_host_ownership_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
	#ifdef CONFIG_PICOVM_CLIGHTPLUS
	u64 prot;
	u64 state;
	#else
	enum picovm_pgtable_prot prot;
	enum picovm_page_state state;
	#endif
	phys_addr_t phys;

	if (!picovm_pte_valid(ctx->old))
		return 0;

	phys = picovm_pte_to_phys(ctx->old);
	if (!addr_is_memory(phys))
		return -EINVAL;

	/*
	 * Adjust the host stage-2 mappings to match the ownership attributes
	 * configured in the hypervisor stage-1.
	 */
	state = picovm_getstate(picovm_pgtable_hyp_pte_prot(ctx->old));
	switch (state) {
	case PICOVM_PAGE_OWNED:
		return host_stage2_set_owner_locked(phys, PAGE_SIZE, PICOVM_ID_HYP);
	case PICOVM_PAGE_SHARED_OWNED:
		prot = picovm_mkstate(PICOVM_HOST_MEM_PROT, PICOVM_PAGE_SHARED_BORROWED);
		break;
	case PICOVM_PAGE_SHARED_BORROWED:
		prot = picovm_mkstate(PICOVM_HOST_MEM_PROT, PICOVM_PAGE_SHARED_OWNED);
		break;
	default:
		return -EINVAL;
	}

	return host_stage2_idmap_locked(phys, PAGE_SIZE, prot);
}

static int fix_host_ownership(void)
{
	struct picovm_pgtable_walker walker = {
		.cb	= fix_host_ownership_walker,
	};
	int i, ret;

	for (i = 0; i < hyp_memblock_nr; i++) {
		struct memblock_region *reg = &hyp_memory[i];
		u64 start = (u64)hyp_phys_to_virt(reg->base);

		ret = picovm_pgtable_walk(&picovm_pgtable, start, reg->size, &walker);
		if (ret)
			return ret;
	}

	return 0;
}


void __noreturn __picovm_init_finalise(void)
{
	// NOTE: called in EL2 - (second half of the 1st init)
	struct kvm_host_data *host_data = this_cpu_ptr(&kvm_host_data);
	struct kvm_cpu_context *host_ctxt = &host_data->host_ctxt;
	int ret;

	ret = picovm_host_prepare_stage2(host_s2_pgt_base);
	if (ret)
		goto out;

	ret = fix_host_ownership();
	if (ret)
		goto out;

	ret = hyp_create_pcpu_fixmap();
	if (ret)
		goto out;

	/*picovm_hyp_vm_table_init(vm_table_base);*/

out:
	/*
	 * We tail-called to here from handle___pkvm_init() and will not return,
	 * so make sure to propagate the return value to the host.
	 */
	cpu_reg(host_ctxt, 1) = ret;

	__host_enter(host_ctxt);
}


// from arch/arm64/kvm/hyp/nvhe/setup.c
int __pkvm_init(phys_addr_t phys, unsigned long size, unsigned long nr_cpus,
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
	params = this_cpu_ptr(&kvm_init_params);
	#ifdef CONFIG_PICOVM_CLIGHTPLUS
	fn = (void (*)(phys_addr_t params_pa, void *finalize_fn_va))__hyp_pa(__pkvm_init_switch_pgd);
	#else
	fn = (typeof(fn))__hyp_pa(__pkvm_init_switch_pgd);
	#endif
	fn(__hyp_pa(params), __picovm_init_finalise);

	__builtin_unreachable();
}
