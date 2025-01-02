/* SPDX-License-Identifier: GPL-2.0-only */
/* 
 * Based on linux/arch/arm64/kvm/hyp/nvhe/mem_protect.c
 */
#include <picovm/asm/errno-base.h>

#include <picovm/linux/types.h>
#include <picovm/per-cpu.h>
#include <picovm/sysregs.h>
#include <picovm/linux/memblock.h>

#include <picovm/asm/bug.h>
#include <picovm/asm/tlbflush.h>

#include <picovm/spinlock.h>
#include <picovm/pgtable.h>
#include <picovm/memory.h>
#include <picovm/mmu.h>
#include <picovm/mm.h>
#include <picovm/mem_protect.h>

#include <picovm/kvm_hyp.h>
#include <picovm/kvm_picovm.h>

static inline u32 id_aa64mmfr0_parange_to_phys_shift(int parange)
{
	switch (parange) {
	case ID_AA64MMFR0_EL1_PARANGE_48: return 48;
	/*
	 * A future PE could use a value unknown to the kernel.
	 * However, by the "D10.1.4 Principles of the ID scheme
	 * for fields in ID registers", ARM DDI 0487C.a, any new
	 * value is guaranteed to be higher than what we know already.
	 * As a safe limit, we return the limit supported by the kernel.
	 */
	default: return CONFIG_ARM64_PA_BITS;
	}
}


// DEFINED IN kvm_interface.c
extern u64 id_aa64mmfr0_el1_sys_val;
extern u64 id_aa64mmfr1_el1_sys_val;

// DEFINED IN ../expection.c
enum exception_type {
	except_type_sync	= 0,
	except_type_irq		= 0x80,
	except_type_fiq		= 0x100,
	except_type_serror	= 0x180,
};
unsigned long get_except64_cpsr(unsigned long old, bool has_mte,
				unsigned long sctlr, unsigned long target_mode);
extern unsigned long get_except64_offset(unsigned long psr, unsigned long target_mode,
	enum exception_type type);


struct host_mmu {
	/* VTCR_EL2 value for the host */
	u64 vtcr;
	struct picovm_s2_mmu mmu;
	struct picovm_pgtable pgt;
	hyp_spinlock_t lock;
};

// the host Stage 2 page table
static struct host_mmu host_mmu;

// static DEFINE_PER_CPU(struct picovm_hyp_vm *, __current_vm);
// #define current_vm (*this_cpu_ptr(&__current_vm))

// static void guest_lock_component(struct picovm_hyp_vm *vm)
// {
// 	hyp_spin_lock(&vm->lock);
// 	current_vm = vm;
// }

// static void guest_unlock_component(struct picovm_hyp_vm *vm)
// {
// 	current_vm = NULL;
// 	hyp_spin_unlock(&vm->lock);
// } 

static void host_lock_component(void)
{
	hyp_spin_lock(&host_mmu.lock);
}

static void host_unlock_component(void)
{
	hyp_spin_unlock(&host_mmu.lock);
}

static inline void hyp_lock_component(void)
{
	hyp_spin_lock(&picovm_pgd_lock);
}

static inline void hyp_unlock_component(void)
{
	hyp_spin_unlock(&picovm_pgd_lock);
}

static void prepare_host_vtcr(void)
{
	u32 parange, phys_shift;

	/* The host stage 2 is id-mapped, so use parange for T0SZ */
	parange = picovm_get_parange(id_aa64mmfr0_el1_sys_val);
	phys_shift = id_aa64mmfr0_parange_to_phys_shift(parange);

	host_mmu.vtcr = picovm_get_vtcr(id_aa64mmfr0_el1_sys_val,
					id_aa64mmfr1_el1_sys_val, phys_shift);
}

int picovm_host_prepare_stage2(void *pgt_pool_base)
{
	struct picovm_s2_mmu *mmu = &host_mmu.mmu;
	int ret;

	prepare_host_vtcr();
	hyp_spin_lock_init(&host_mmu.lock);

	ret = picovm_pgtable_stage2_init(&host_mmu.pgt, mmu);
	if (ret)
		return ret;

	mmu->pgd_phys = __hyp_pa(host_mmu.pgt.pgd);
	// mmu->pgt = &host_mmu.pgt;
	atomic64_write(&mmu->vmid.id, 0);

	return 0;
}

int __pkvm_prot_finalize(void)
{
	struct picovm_s2_mmu *mmu = &host_mmu.mmu;
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);

	if (params->hcr_el2 & HCR_VM)
		return -EPERM;

	params->vttbr = picovm_get_vttbr(mmu);
	params->vtcr = host_mmu.vtcr;
	params->hcr_el2 |= HCR_VM;

	/*
	 * The CMO below not only cleans the updated params to the
	 * PoC, but also provides the DSB that ensures ongoing
	 * page-table walks that have started before we trapped to EL2
	 * have completed.
	 */
	picovm_flush_dcache_to_poc(params, sizeof(*params));

	write_sysreg(params->hcr_el2, hcr_el2);
	__load_stage2(&host_mmu.mmu, host_mmu.vtcr);

	/*
	 * Make sure to have an ISB before the TLB maintenance below but only
	 * when __load_stage2() doesn't include one already.
	 */
	isb();

	/* Invalidate stale HCR bits that may be cached in TLBs */
	__tlbi(vmalls12e1);
	dsb(nsh);
	isb();

	return 0;
}

struct picovm_mem_range {
	u64 start;
	u64 end;
};

// From include/vdso/limits.h
#define ULONG_MAX	(~0UL)

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

int host_stage2_idmap_locked(phys_addr_t addr, u64 size,
			     enum picovm_pgtable_prot prot)
{
	// TODO(doc) we don't do the host_stage2_try from actual pKVM
	return picovm_pgtable_stage2_map(&host_mmu.pgt, addr, size, addr,
					 prot /*, &host_s2_pool, 0 */);
}

int host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id)
{
	return picovm_pgtable_stage2_set_owner(&host_mmu.pgt, addr, size, owner_id);
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

static void host_inject_abort(struct kvm_cpu_context *host_ctxt)
{
	u64 spsr = read_sysreg(spsr_el2);
	u64 esr = read_sysreg(esr_el2);
	u64 ventry, ec;

	/* Repaint the ESR to report a same-level fault if taken from EL1 */
	if ((spsr & SPSR_ELn_M_MASK) != SPSR_ELn_M_EL0t) {
		ec = ESR_ELx_EC(esr);
		if (ec == ESR_ELx_EC_DABT_LOW)
			ec = ESR_ELx_EC_DABT_CUR;
		else if (ec == ESR_ELx_EC_IABT_LOW)
			ec = ESR_ELx_EC_IABT_CUR;
		else
			BUG_ON(1);
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

	write_sysreg(esr, esr_el1);
	write_sysreg(spsr, spsr_el1);
	write_sysreg(read_sysreg(elr_el2), elr_el1);
	write_sysreg(read_sysreg(far_el2), far_el1);

	ventry = read_sysreg(vbar_el1);
	ventry += get_except64_offset(spsr, SPSR_ELn_M_EL1h, except_type_sync);
	write_sysreg(ventry, elr_el2);

#ifdef CONFIG_ARM64_MTE
#error "picovm must be build with MTE disabled"
#endif
	spsr = get_except64_cpsr(spsr, false/*TODO: system_supports_mte()*/,
				 read_sysreg(sctlr_el1), SPSR_ELn_M_EL1h);
	write_sysreg(spsr, spsr_el2);
}



// this always include the fix for ARM64_WORKAROUND_1508412
#define read_sysreg_par() ({						\
	u64 par;							\
	asm("dmb sy");							\
	par = read_sysreg(par_el1);					\
	asm("dmb sy");							\
	par;								\
})

// Copied from arch/arm64/include/asm/kvm_arm.h
/* Hyp Prefetch Fault Address Register (HPFAR/HDFAR) */
#define HPFAR_MASK	(~UL(0xf))
/*
 * We have
 *	PAR	[PA_Shift - 1	: 12] = PA	[PA_Shift - 1 : 12]
 *	HPFAR	[PA_Shift - 9	: 4]  = FIPA	[PA_Shift - 1 : 12]
 *
 * Always assume 52 bit PA since at this point, we don't know how many PA bits
 * the page table has been set up for. This should be safe since unused address
 * bits in PAR are res0.
 */
#define PAR_TO_HPFAR(par)		\
	(((par) & GENMASK_ULL(52 - 1, 12)) >> 8)


// Copied from arch/arm64/include/asm/kvm_asm.h
#define __KVM_EXTABLE(from, to)						\
	"	.pushsection	__kvm_ex_table, \"a\"\n"		\
	"	.align		3\n"					\
	"	.long		(" #from " - .), (" #to " - .)\n"	\
	"	.popsection\n"


#define __kvm_at(at_op, addr)						\
( { 									\
	int __kvm_at_err = 0;						\
	u64 spsr, elr;							\
	asm volatile(							\
	"	mrs	%1, spsr_el2\n"					\
	"	mrs	%2, elr_el2\n"					\
	"1:	at	"at_op", %3\n"					\
	"	isb\n"							\
	"	b	9f\n"						\
	"2:	msr	spsr_el2, %1\n"					\
	"	msr	elr_el2, %2\n"					\
	"	mov	%w0, %4\n"					\
	"9:\n"								\
	__KVM_EXTABLE(1b, 2b)						\
	: "+r" (__kvm_at_err), "=&r" (spsr), "=&r" (elr)		\
	: "r" (addr), "i" (-EFAULT));					\
	__kvm_at_err;							\
} )

# define unlikely(x)	__builtin_expect(!!(x), 0)

// Copied from arch/arm64/kvm/hyp/include/hyp/fault.h
static inline bool __translate_far_to_hpfar(u64 far, u64 *hpfar)
{
	u64 par, tmp;

	/*
	 * Resolve the IPA the hard way using the guest VA.
	 *
	 * Stage-1 translation already validated the memory access
	 * rights. As such, we can use the EL1 translation regime, and
	 * don't have to distinguish between EL0 and EL1 access.
	 *
	 * We do need to save/restore PAR_EL1 though, as we haven't
	 * saved the guest context yet, and we may return early...
	 */
	par = read_sysreg_par();
	if (!__kvm_at("s1e1r", far))
		tmp = read_sysreg_par();
	else
		tmp = PAR_EL1_F; /* back to the guest */
	write_sysreg(par, par_el1);

	if (unlikely(tmp & PAR_EL1_F))
		return false; /* Translation failed, back to guest */

	/* Convert PAR to HPFAR format */
	*hpfar = PAR_TO_HPFAR(tmp);
	return true;
}

static inline bool __get_hpfar(u64 esr, u64 *hpfar_out)
{
	u64 hpfar, far;

	far = read_sysreg(far_el2);

	/*
	 * The HPFAR can be invalid if the stage 2 fault did not
	 * happen during a stage 1 page table walk (the ESR_EL2.S1PTW
	 * bit is clear) and one of the two following cases are true:
	 *   1. The fault was due to a permission fault
	 *   2. The processor carries errata 834220
	 *
	 * Therefore, for all non S1PTW faults where we either have a
	 * permission fault or the errata workaround is enabled, we
	 * resolve the IPA using the AT instruction.
	 */
	if (!(esr & ESR_ELx_S1PTW) &&
	    (/*TODO: cpus_have_final_cap(ARM64_WORKAROUND_834220) || */
	     (esr & ESR_ELx_FSC_TYPE) == ESR_ELx_FSC_PERM)) {
		if (!__translate_far_to_hpfar(far, &hpfar))
			return false;
	} else {
		hpfar = read_sysreg(hpfar_el2);
	}

	// fault->far_el2 = far;
	// fault->hpfar_el2 = hpfar;
	*hpfar_out = hpfar;
	return true;
}

void handle_host_mem_abort(struct kvm_cpu_context *host_ctxt)
{
	u64 hpfar_el2;
	u64 esr, addr;
	int ret = 0;

	esr = read_sysreg(esr_el2);
	BUG_ON(!__get_hpfar(esr, &hpfar_el2));

	addr = (hpfar_el2 & HPFAR_MASK) << 8;
	ret = host_stage2_idmap(addr);

	if (ret == -EPERM)
		host_inject_abort(host_ctxt);
	else
		BUG_ON(ret && ret != -EAGAIN);
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
int __pkvm_host_share_hyp(u64 pfn)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)hyp_phys_to_virt(host_addr);

	host_lock_component();
	hyp_lock_component();

	ret = __host_check_page_state_range(host_addr, PAGE_SIZE, PICOVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	ret = __hyp_check_page_state_range(hyp_addr, PAGE_SIZE, PICOVM_NOPAGE);
	if (ret)
		goto unlock;

//do_share:
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
	hyp_unlock_component();
	host_unlock_component();
	return ret;
}

int __pkvm_host_unshare_hyp(u64 pfn)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)hyp_phys_to_virt(host_addr);

	host_lock_component();
	hyp_lock_component();

	ret = __host_check_page_state_range(host_addr, PAGE_SIZE, PICOVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	ret = __hyp_check_page_state_range(hyp_addr, PAGE_SIZE, PICOVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

//do_unshare:
	// BEGIN WARN_ON()
	ret = __host_set_page_state_range(host_addr, PAGE_SIZE, PICOVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	{
		ret = picovm_pgtable_hyp_unmap(&picovm_pgtable, hyp_addr, PAGE_SIZE);
	}
	// END WARN_ON()
unlock:
	hyp_unlock_component();
	host_unlock_component();
	return ret;
}
