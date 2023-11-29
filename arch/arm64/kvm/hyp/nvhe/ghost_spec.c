#include <asm/kvm_mmu.h>
#include <hyp/ghost_extra_debug-pl011.h>
//#include <nvhe/ghost_check_pgtables.h>
#include <hyp/ghost_alloc.h>
#include <nvhe/ghost_misc.h>
#include <nvhe/ghost_pgtable.h>
#include <linux/arm-smccc.h>
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#include <nvhe/spinlock.h>
#include <nvhe/trap_handler.h>   // for DECLARE_REG
#include <nvhe/mem_protect.h>   // for DECLARE_REG
#include <asm/kvm_asm.h>    // for __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp etc
#include <asm/kvm_hyp.h> // for read_sysreg_el2
#include <asm/sysreg.h> // for SYS_ESR_EL2
#include <nvhe/ghost_asm_ids.h>
#include <nvhe/ghost_spec.h>
#include <nvhe/ghost_compute_abstraction.h>
#include <nvhe/ghost_kvm_pgtable.h>
#include <nvhe/ghost_control.h>


u64 ghost_read_gpr_explicit(struct ghost_registers *st, int n)
{
	ghost_assert(0 <= n && n < 31);
	ghost_spec_assert(st->gprs[n].status == GHOST_PRESENT); // TODO: check that we indeed want a spec-assert
	return st->gprs[n].value;
}

void ghost_write_gpr_explicit(struct ghost_registers *st, int n, u64 value)
{
	ghost_assert(0 <= n && n < 31);
	st->gprs[n].status = GHOST_PRESENT;
	st->gprs[n].value = value;
}

u64 ghost_read_sysreg_explicit(struct ghost_registers *st, enum ghost_sysreg n)
{
	ghost_assert(0 <= n && n < NR_GHOST_SYSREGS);
	ghost_spec_assert(st->sysregs[n].status == GHOST_PRESENT); // TODO: check that we indeed want a spec-assert
	return st->sysregs[n].value;
}

void ghost_write_sysreg_explicit(struct ghost_registers *st, enum ghost_sysreg n, u64 value)
{
	ghost_assert(0 <= n && n < NR_GHOST_SYSREGS);
	st->sysregs[n].status = GHOST_PRESENT;
	st->sysregs[n].value = value;
}

u64 ghost_read_el2_sysreg_explicit(struct ghost_registers *st, enum ghost_el2_sysreg n)
{
	ghost_assert(0 <= n && n < NR_GHOST_EL2_SYSREGS);
	if (st->el2_sysregs[n].status != GHOST_PRESENT)
		ghost_printf("TRYING TO READ EL2_SYSREG ==> %d\n", n);
	ghost_spec_assert(st->el2_sysregs[n].status == GHOST_PRESENT); // TODO: check that we indeed want a spec-assert
	return st->el2_sysregs[n].value;
}

void ghost_write_el2_sysreg_explicit(struct ghost_registers *st, enum ghost_el2_sysreg n, u64 value)
{
	ghost_assert(0 <= n && n < NR_GHOST_EL2_SYSREGS);
	st->el2_sysregs[n].status = GHOST_PRESENT;
	st->el2_sysregs[n].value = value;
}

/*
 * Init tracking
 */
bool ghost_pkvm_init_finalized;
DEFINE_HYP_SPINLOCK(ghost_prot_finalized_lock);
u64 ghost_prot_finalized_count;
bool ghost_prot_finalized_all;

DEFINE_PER_CPU(bool, ghost_check_this_hypercall);
DEFINE_PER_CPU(bool, ghost_checked_previous_hypercall);

DEFINE_PER_CPU(bool, ghost_print_this_hypercall);

bool ghost_exec_enabled(void)
{
	return GHOST_EXEC_SPEC && __this_cpu_read(ghost_check_this_hypercall);
}

bool ghost_checked_last_call(void)
{
	return __this_cpu_read(ghost_checked_previous_hypercall);
}

void ghost_enable_this_cpu(void)
{
	bool all_finalized;

	hyp_spin_lock(&ghost_prot_finalized_lock);
	all_finalized = ++ghost_prot_finalized_count == hyp_nr_cpus;
	hyp_spin_unlock(&ghost_prot_finalized_lock);

	if (all_finalized)
		WRITE_ONCE(ghost_prot_finalized_all, true);
}



struct ghost_state gs; // the "master" ghost state, shared but with its parts protected by the associated impl locks
DEFINE_PER_CPU(struct ghost_state, gs_recorded_pre);         // thread-local ghost state, of which only the relevant
DEFINE_PER_CPU(struct ghost_state, gs_recorded_post);        //  parts are used within each transition
DEFINE_PER_CPU(struct ghost_state, gs_computed_post);
DEFINE_PER_CPU(struct ghost_call_data, gs_call_data);  // thread-local implementation-seen values during call

void ghost_clear_call_data(void)
{
	struct ghost_call_data *call = this_cpu_ptr(&gs_call_data);
	call->return_value = 0;
	call->relaxed_reads.len = 0;
	call->memcache_donations.len = 0;
	call->at_translations.len = 0;
}



// adapted from memory.h to make it a pure function of the ghost state rather than depend on the impl global hyp_phys_virt_offset
#define ghost__hyp_va(g,phys)	((void *)((phys_addr_t)(phys) - g->globals.hyp_physvirt_offset))

// type of pKVM virtual addresses
typedef u64 hyp_va_t;
// Host kernel virtual address
typedef u64 host_va_t;
// Host intermediate physical address
typedef u64 host_ipa_t;
// guest intermediate physical address
typedef u64 guest_ipa_t;


// this function is only valid if @phys is within the address range to which
// the hyp_va linear mapped range is mapped too.
// THAT IS: memstart_addr <= phys && phys < memstart_addr + 2^tag_lsb
static inline hyp_va_t hyp_va_of_phys(const struct ghost_state *g, phys_addr_t phys)
{
	return phys - g->globals.hyp_physvirt_offset;
}

static inline phys_addr_t phys_of_hyp_va(const struct ghost_state *g, hyp_va_t hyp_va)
{
	return hyp_va + g->globals.hyp_physvirt_offset;
}

// the Host stage 2 mapping is the identity mapping
#define host_ipa_of_phys(PHYS) ((host_ipa_t)PHYS)
#define phys_of_host_ipa(HOST_IPA) ((phys_addr_t)HOST_IPA)

// We convert a host virtual address to a pKVM virtual address by zero-ing out
// the tag_val (which holds the hyp_va_msb and random tag for the kernel, which
// we do not know; and do not want to), and replace it with the pKVM tag_val
//
// NOTE: this function reproduces the calculation of converting a host virtual address
// from within its linear mapped region to a hypervisor virtual address; but, we cannot
// inspect the actual host virtual address space, and so any specification should not rely
// on this returning a mapping to the same physical location as the host would for that VA.
//
// I.E. do NOT expect: phys_of_hyp_va(hyp_va_of_host_va(ADDR)) == AArch64.TranslateAddress(ADDR) in EL1&0 Regime
static inline hyp_va_t hyp_va_of_host_va(const struct ghost_state *g, host_va_t host_va)
{
	u64 va_mask = GENMASK_ULL(g->globals.tag_lsb - 1, 0);
	return (host_va & va_mask) | (g->globals.tag_val << g->globals.tag_lsb);
}

// adapted from mem_protect.c to use the hyp_memory map
bool ghost_addr_is_memory(struct ghost_state *g, phys_addr_t phys)
{
	struct maplet_target t;
	if ( !mapping_lookup(phys, g->globals.hyp_memory, &t) ) {
		return false;
	}
	ghost_assert(t.kind == MAPLET_MEMBLOCK);
	return true;
}


// adapted from mem_protect.c to use the hyp_memory map
bool ghost_addr_is_allowed_memory(struct ghost_state *g, phys_addr_t phys)
{
	struct maplet_target t;
	if (!mapping_lookup(phys, g->globals.hyp_memory, &t))
		return false;
	ghost_assert(t.kind == MAPLET_MEMBLOCK);
	return !(t.memblock & MEMBLOCK_NOMAP);
}


enum ghost_host_or_hyp {
	GHOST_HOST,
	GHOST_HYP
};

static bool is_owned_exclusively_by(const struct ghost_state *g, enum ghost_host_or_hyp id, phys_addr_t addr)
{
	switch(id) {
	case GHOST_HOST: {
		host_ipa_t host_ipa = host_ipa_of_phys(addr);
		if (mapping_in_domain(host_ipa, g->host.host_abstract_pgtable_annot))
			return false;
		if (mapping_in_domain(host_ipa, g->host.host_abstract_pgtable_shared))
			return false;
		return true;
	}
	case GHOST_HYP: {
		hyp_va_t hyp_va = hyp_va_of_phys(g, addr);
		return mapping_in_domain(hyp_va, g->pkvm.pkvm_abstract_pgtable.mapping);
	}
	default:
		ghost_assert(false);
		unreachable();
	}
}

static bool is_owned_and_shared_by(const struct ghost_state *g, enum ghost_host_or_hyp id, phys_addr_t addr)
{
	struct maplet_target t;
	switch (id) {
	case GHOST_HOST: {
		host_ipa_t host_ipa = host_ipa_of_phys(addr);
		if (!mapping_lookup(host_ipa, g->host.host_abstract_pgtable_shared, &t))
			return false;
		break;
	}
	case GHOST_HYP: {
		hyp_va_t hyp_va = hyp_va_of_phys(g, addr);
		if (!mapping_lookup(hyp_va, g->pkvm.pkvm_abstract_pgtable.mapping, &t))
			return false;
		break;
	}
	default:
		ghost_assert(false);
		unreachable();
	}
	ghost_assert(t.kind == MAPLET_MAPPED);
	return t.map.attrs.provenance == MAPLET_PAGE_STATE_SHARED_OWNED;
}

// if id == GHOST_HOST, addr should be a host_ipa
// if id == GHOST_HYP,  addr should be a hyp_va
static bool is_borrowed_by(const struct ghost_state *g, enum ghost_host_or_hyp id, u64 addr)
{
	struct maplet_target t;
	switch (id) {
	case GHOST_HOST:
		if (!mapping_lookup(addr, g->host.host_abstract_pgtable_shared, &t))
			return false;
		break;
	case GHOST_HYP:
		if (!mapping_lookup(addr, g->pkvm.pkvm_abstract_pgtable.mapping, &t))
			return false;
		break;
	default:
		ghost_assert(false);
		unreachable();
	}
	ghost_assert(t.kind == MAPLET_MAPPED);
	return t.map.attrs.provenance == MAPLET_PAGE_STATE_SHARED_BORROWED;
}

static struct maplet_attributes ghost_memory_attributes(enum maplet_page_state page_state, enum maplet_permissions perms, enum maplet_memtype_attr memtype)
{
	struct maplet_attributes attrs;
	attrs.provenance = page_state;
	attrs.prot = perms;
	attrs.memtype = memtype;
	return attrs;
}

static struct maplet_attributes ghost_default_host_memory_attributes(bool is_memory, enum maplet_page_state page_state)
{
	enum maplet_permissions default_host_prot = is_memory ? MAPLET_PERM_RWX : MAPLET_PERM_RW;
	enum maplet_memtype_attr default_host_memtype = is_memory ? MAPLET_MEMTYPE_NORMAL_CACHEABLE : MAPLET_MEMTYPE_DEVICE;
	return ghost_memory_attributes(page_state, default_host_prot, default_host_memtype);
}

static struct maplet_attributes ghost_default_hyp_memory_attributes(bool is_memory, enum maplet_page_state page_state)
{
	enum maplet_permissions default_hyp_prot = MAPLET_PERM_RW;
	enum maplet_memtype_attr default_hyp_memtype = is_memory ? MAPLET_MEMTYPE_NORMAL_CACHEABLE : MAPLET_MEMTYPE_DEVICE;
	return ghost_memory_attributes(page_state, default_hyp_prot, default_hyp_memtype);
}

static struct maplet_attributes ghost_default_vm_memory_attributes(bool is_memory, enum maplet_page_state page_state)
{
	enum maplet_permissions default_vm_prot = is_memory ? MAPLET_PERM_RWX : MAPLET_PERM_RW;
	enum maplet_memtype_attr default_vm_memtype = is_memory ? MAPLET_MEMTYPE_NORMAL_CACHEABLE : MAPLET_MEMTYPE_DEVICE;
	return ghost_memory_attributes(page_state, default_vm_prot, default_vm_memtype);
}

/**
 * copy_registers_to_host() - Make the host's register context be the current local one.
 */
static void copy_registers_to_host(struct ghost_state *g)
{
	ghost_this_cpu_local_state(g)->host_regs.present = true;
	copy_abstraction_regs(&ghost_this_cpu_local_state(g)->host_regs.regs, &ghost_this_cpu_local_state(g)->regs);
}

/**
 * copy_registers_to_guest() - Make this guest vcpu's register context be the local one.
 */
static void copy_registers_to_guest(struct ghost_state *g, struct ghost_vcpu *vcpu)
{
	copy_abstraction_regs(&vcpu->regs, &ghost_this_cpu_local_state(g)->regs);
}

bool compute_new_abstract_state_handle___pkvm_host_share_hyp(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	u64 pfn = ghost_read_gpr(g0, 1);
	phys_addr_t phys = hyp_pfn_to_phys(pfn); // ((phys_addr_t)((pfn) << PAGE_SHIFT)) // pure
	host_ipa_t host_addr = host_ipa_of_phys(phys);
	hyp_va_t hyp_addr = hyp_va_of_phys(g0, phys);
	int ret = 0;

	/* TODO: do some more thinking and if needed fix the following THEN branch
	 * ----
	 * BS and KM now think that ENOMEM cannot actually be an outcome of the hypercall
	 * as a result the __host_set_page_state_range() function (update of the HOST mapping)
	 * because of what comment preceding `host_stage2_try()` says and its code (which unmaps
	 * MMIO stuff if needed and retry updating the HOST mapping).
	 * KM: however I don't see the same in the code of `pkvm_create_mappings_locked()`,
	 *     so I think that the attempt at adding a new entry to the pKVM page table can
	 *     still cause a ENOMEM.
	 * ----
	 * NOTE: the rest of this comment is older than the previous TODO and may now be slightly wrong
	 * ----
	 * when the hypercall is adding entries to the host and hyp page tables
	 * it may run out of memory.
	 * we model this as a nondeterministic error (with two flavours) */
	if (call->return_value == -ENOMEM) {
		ret = -ENOMEM;
		// TODO: it is not clear how to write the spec currently
		// because we 2 possible outcome:
		//   1. the error happened when attempting to add an entry
		//      to the host page table; then we don't copy anything to g1
		//   2. the error happened when attempting to add an entry
		//      to the pKVM page table; then we need to do
		//        copy_abstraction_host(g1, g0);
		goto out;
	}

	// the host pfn_set and the annot mapping are unchanged
	// but the host shared mapping and the pkvm mapping will be updated
	copy_abstraction_host(g1, g0);
	copy_abstraction_pkvm(g1, g0);

	// __host_check_page_state_range(addr, size, PKVM_PAGE_OWNED);
	if (!is_owned_exclusively_by(g0, GHOST_HOST, phys)) {
		ret = -EPERM;
		goto out;
	}
	// checked in the pKVM code:
	// do_share() -> check_share() -> hyp_ack_share() -> __hyp_check_page_state_range()
	if (mapping_in_domain(hyp_addr, g0->pkvm.pkvm_abstract_pgtable.mapping)) {
		ret = -EPERM;
		goto out;
	}

	bool is_memory = ghost_addr_is_allowed_memory(g0, phys);
	struct maplet_attributes host_attrs = ghost_default_host_memory_attributes(is_memory, MAPLET_PAGE_STATE_SHARED_OWNED);
	struct maplet_attributes hyp_attrs = ghost_default_hyp_memory_attributes(is_memory, MAPLET_PAGE_STATE_SHARED_BORROWED);

	/* the host annot mapping is unchanged (we have established that host_addr is NOT already in there)
	 * but, there is a new host shared mapping, PKVM_PAGE_SHARED_OWNED */
	mapping_update(
		&g1->host.host_abstract_pgtable_shared,
		g0->host.host_abstract_pgtable_shared,
		MAP_INSERT_PAGE, GHOST_STAGE2, host_addr, 1, maplet_target_mapped_attrs(phys, 1, host_attrs)
	);

	/* add a new hyp mapping, PKVM_PAGE_SHARED_BORROWED */
	mapping_update(
		&g1->pkvm.pkvm_abstract_pgtable.mapping,
		g0->pkvm.pkvm_abstract_pgtable.mapping,
		MAP_INSERT_PAGE, GHOST_STAGE1, hyp_addr, 1, maplet_target_mapped_attrs(phys, 1, hyp_attrs)
	);

out:
	ghost_write_gpr(g1, 1, ret);

	/* these registers now become the host's run context */
	copy_registers_to_host(g1);

	/* check this spec */
	return true;
}


/* pkvm_host_unshare_hyp(pfn) */
bool compute_new_abstract_state_handle___pkvm_host_unshare_hyp(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	u64 pfn = ghost_read_gpr(g0, 1);
	phys_addr_t phys = hyp_pfn_to_phys(pfn); // ((phys_addr_t)((pfn) << PAGE_SHIFT)) // pure
	host_ipa_t host_addr = host_ipa_of_phys(phys);
	hyp_va_t hyp_addr = hyp_va_of_phys(g0, phys);
	int ret = 0;

	copy_abstraction_host(g1, g0);
	copy_abstraction_pkvm(g1, g0);

	// __host_check_page_state_range(addr, size, PKVM_PAGE_SHARED_OWNED);
	if (!is_owned_and_shared_by(g0, GHOST_HOST, phys)) {
		ret = -EPERM;
		goto out;
	}

	// check that pKVM is not using the page (otherwise EBUSY)
	// we model this as a non-deterministic choice that is determined
	// by the return code of the pKVM implementation
	if (call->return_value == -EBUSY) {
		ret = -EBUSY;
		goto out;
	}

	// NOTE: we do not need a is_in_mapping_pkvm() corresponding to
	//   __hyp_check_page_state_range(hyp_addr, PAGE_SIZE, PKVM_PAGE_SHARED_BORROWED)
	// because this is a (possibly disabled) check that the host is not trying
	// to unshare a page it did NOT previously share with pKVM.
	// TODO BS: I don't understand why this is here. Re-read the pKVM code
	// more carefully and adapt or remove this comment accordingly

	/* remove 'host_addr' from the host shared finite map */
	// in pKVM code: __host_set_page_state_range(host_addr, PAGE_SIZE, PKVM_PAGE_OWNED);
	mapping_move(
		&g1->host.host_abstract_pgtable_shared,
		mapping_minus(g0->host.host_abstract_pgtable_shared, host_addr, 1)
	);

	// PKVM can non-deterministically fail to unmap the page in its page table
	// TODO: this may not be possible now that host_share_hyp cannot do a ENOMEM
	// TODO: check and remove this accordingly
	if (call->return_value == -EFAULT) {
		ret = -EFAULT;
		goto out;
	}
	mapping_move(
		&g1->pkvm.pkvm_abstract_pgtable.mapping,
		mapping_minus(g0->pkvm.pkvm_abstract_pgtable.mapping, hyp_addr, 1)
	);
out:
	ghost_write_gpr(g1, 1, ret);

	/* these registers now become the host's run context */
	copy_registers_to_host(g1);

	/* check this spec */
	return true;
}

bool compute_new_abstract_state_handle___pkvm_host_reclaim_page(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	int ret = 0;
	u64 pfn = ghost_read_gpr(g0, 1);
	phys_addr_t addr = hyp_pfn_to_phys(pfn);
	host_ipa_t host_ipa = host_ipa_of_phys(addr);

	// locking host (it looks like the .flags fields in the vmemmap are owned by the host lock)
	// TODO: do we really want that?
	ghost_spec_assert(g0->host.present); // TODO: not sure

	copy_abstraction_host(g1, g0);

	// get leaf for addr in the host s2 page table
	// IF this causes an error, return it
	// TODO: was does kvm_pgtable_get_leaf() return if not mapped ?

	// IF the page of addr is exclusively owned by host, then return 0
	if (is_owned_exclusively_by(g0, GHOST_HOST, addr)) {
		ret = 0;
		goto out;
	}

	// let page: hyp_page = hyp_hyps_to_page(addr);
	// if !page.pending_reclaim then return -EPERM
	// else if page.need_poisoning then TODO: hyp_zero_page(addr) (which can fail, and error is returned)
	//         and unset page.pending_reclaim

	if (!ghost_pfn_set_contains(&g0->host.reclaimable_pfn_sets, pfn)) {
		ret = -EPERM;
		goto out;
	}

	if (ghost_pfn_set_contains(&g0->host.need_poisoning_pfn_sets, pfn)) {
		// TODO: how to model the zeroing? Do we want to?
		ghost_pfn_set_remove_external(&g1->host.need_poisoning_pfn_sets, pfn);
	}

	/* BS: spec should never get into a state where a reclaimable pfn
	 * was shared with or given back to the host before it was reclaimed ?
	 */
	ghost_assert(!mapping_in_domain(host_ipa, g0->host.host_abstract_pgtable_shared));
	ghost_assert(mapping_in_domain(host_ipa, g0->host.host_abstract_pgtable_annot));

	/* was marked as owned by pKVM in annot, remove it. */
	mapping_update(
		&g1->host.host_abstract_pgtable_annot,
		g0->host.host_abstract_pgtable_annot,
		MAP_REMOVE_PAGE, GHOST_STAGE2, host_ipa, 1,  MAPLET_NONE
	);

	// unset page.pending_reclaim
	ghost_pfn_set_remove_external(&g1->host.reclaimable_pfn_sets, pfn);

	// success.
	ret = 0;

out:
	ghost_write_gpr(g1, 1, ret);

	/* check this spec */
	return true;
}

/**
 * compute the new abstract ghost_state from a struct ghost_call_data *call = pkvm_host_map_guest(host_pfn, guest_gfn)
 */
bool compute_new_abstract_state_handle___pkvm_host_map_guest(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call) {
	int ret;

	u64 pfn = ghost_read_gpr(g0, 1);
	u64 gfn = ghost_read_gpr(g0, 2);

	phys_addr_t phys = hyp_pfn_to_phys(pfn);
	host_ipa_t host_ipa = host_ipa_of_phys(phys);
	guest_ipa_t guest_ipa = (gfn << PAGE_SHIFT);

	struct ghost_loaded_vcpu *hyp_loaded_vcpu = this_cpu_ghost_loaded_vcpu(g0);
	ghost_assert(hyp_loaded_vcpu->present);

	// previous vcpu_load must have been done
	// `hyp_vcpu = pkvm_get_loaded_hyp_vcpu(); if (!hyp_vcpu) goto out;`
	if (!hyp_loaded_vcpu->loaded) {
		ret = -EINVAL;
		goto out;
	}

	ghost_assert(ghost_vms_is_valid_handle(&g0->vms, hyp_loaded_vcpu->vm_handle))

	struct ghost_vm *g0_vm = ghost_vms_get(&g0->vms, hyp_loaded_vcpu->vm_handle);
	struct ghost_vm *g1_vm = ghost_vms_alloc(&g1->vms, hyp_loaded_vcpu->vm_handle);
	ghost_assert(g0_vm != NULL);
	ghost_assert(g1_vm != NULL);

	if (! g0_vm->protected) {
		/* don't check this spec */
		GHOST_WARN("__pkvm_host_map_guest with non-protected VM");
		return false;
	}

	// The call to pkvm_refill_memcache() may non-deterministically
	// fail because we run out of memory. In this case the hypercall
	// ends with that host mapping left unchanged.
	//
	// The code of __pkvm_host_donate_guest() allows for a non-deterministic
	// run out of memory when updating the guest page table.
	// However, BS and KM think that pkvm_refill_memcache() is checking
	// that this cannot happens by donating the max number of pages
	// that may be needed from the host's memcache to pKVM's memcache used
	// for the guest.
	// TODO: there is still something we don't understand in the code
	// see the BS comment in arch/arm64/kvm/hyp/nvhe/mm.c
	// TODO2: we need to model the donation from the host of the pages used
	// in pKVM (guest) memcached.
	// This will require adding more state to ghost_pkvm
	if (call->return_value == -ENOMEM) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * Take a snapshot of the host/pkvm and vm states, which we will update.
	 *
	 * if a donation happens, then we will update the pkvm state,
	 * NOTE: we should be holding the pkvm pgd lock here, even if the underlying call didn't do a donation,
	 * so it's safe to copy.
	 */
	copy_abstraction_host(g1, g0);
	copy_abstraction_pkvm(g1, g0);
	ghost_vm_clone_into_partial(g1_vm, g0_vm, VMS_VM_OWNED);

	for (int d=0; d<call->memcache_donations.len; d++) {
		u64 pfn = call->memcache_donations.pages[d];
		phys_addr_t donated_phys = hyp_pfn_to_phys(pfn);
		host_ipa_t host_donated_page_ipa = host_ipa_of_phys(donated_phys);
		hyp_va_t hyp_donated_page_addr = (u64)ghost__hyp_va(g0, donated_phys);

		bool is_memory = ghost_addr_is_allowed_memory(g0, donated_phys);
		struct maplet_attributes hyp_attrs = ghost_default_hyp_memory_attributes(is_memory, MAPLET_PAGE_STATE_PRIVATE_OWNED);

		/* The memcache HEAD pointer is in a page that is shared with pKVM,
		 * but the pages of the linked list are actually owned exclusively by the host,
		 * and they are stolen by pKVM as needed.
		 */
		if (! is_owned_exclusively_by(g0, GHOST_HOST, host_donated_page_ipa))
			ghost_spec_assert(false);

		// Each memcache page that is donated must be put as owned in pKVM's tables,
		// removed from the host's mappings (i.e. added to annot) and marked as owned by the hypervisor in the annotations,
		// and WRITE_ONCE written back to the HEAD to say it's happened.

		mapping_update(
			&g1->pkvm.pkvm_abstract_pgtable.mapping,
			g1->pkvm.pkvm_abstract_pgtable.mapping,
			MAP_INSERT_PAGE, GHOST_STAGE1, hyp_donated_page_addr, 1, maplet_target_mapped_attrs(donated_phys, 1, hyp_attrs)
		);
		mapping_update(
			&g1->host.host_abstract_pgtable_annot,
			g1->host.host_abstract_pgtable_annot,
			MAP_INSERT_PAGE, GHOST_STAGE2, host_donated_page_ipa, 1, maplet_target_annot_ext(MAPLET_OWNER_ANNOT_OWNED_HYP)
		);
		// TODO: WRITE_ONCE()

		// finally, we mark that this page as one potentially used for a pagetable for this guest.
		ghost_pfn_set_insert(&g1_vm->vm_locked.vm_abstract_pgtable.table_pfns, pfn);
	}

	// TODO: non-protected VM/VCPUs?

	// if this page is not accessible by the host, fail with -EPERM
	if (!is_owned_exclusively_by(g0, GHOST_HOST, phys)) {
		ret = -EPERM;
		goto out;
	}
	// if the addr is already mapped in the guest mapping, fail with -EPERM
	if (mapping_in_domain(guest_ipa, g0_vm->vm_locked.vm_abstract_pgtable.mapping)) {
		ret = -EPERM;
		goto out;
	}

	// TODO: other error cases

	// Mark as owned by a VM as annotation in the host table
	mapping_update(
		&g1->host.host_abstract_pgtable_annot,
		g1->host.host_abstract_pgtable_annot,
		MAP_INSERT_PAGE, GHOST_STAGE2, host_ipa, 1, maplet_target_annot_ext(MAPLET_OWNER_ANNOT_OWNED_GUEST)
	);

	// Finally, add the mapping to the VM's pagetable.
	bool is_memory = ghost_addr_is_allowed_memory(g0, phys);
	struct maplet_attributes vm_attrs = ghost_default_vm_memory_attributes(is_memory, MAPLET_PAGE_STATE_PRIVATE_OWNED);
	mapping_update(
		&g1_vm->vm_locked.vm_abstract_pgtable.mapping,
		g1_vm->vm_locked.vm_abstract_pgtable.mapping,
		MAP_INSERT_PAGE, GHOST_STAGE2, guest_ipa, 1, maplet_target_mapped_attrs(phys, 1, vm_attrs)
	);

	// success.
	ret = 0;

out:
	ghost_write_gpr(g1, 1, ret);

	/* these registers now become the host's run context */
	copy_registers_to_host(g1);

	/* check this spec */
	return true;
}

bool compute_new_abstract_state_handle___pkvm_vcpu_load(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call) {
	pkvm_handle_t vm_handle = ghost_read_gpr(g0, 1);
	unsigned int vcpu_idx = ghost_read_gpr(g0, 2);

	ghost_assert(this_cpu_ghost_loaded_vcpu(g0)->present);

	// if another vcpu is already loaded on this CPU, then do nothing
	if (this_cpu_ghost_loaded_vcpu(g0)->loaded)
		goto out;

	struct ghost_vm *vm = ghost_vms_get(&g0->vms, vm_handle);

	// if the vm does not exist, do nothing.
	if (!vm)
		goto out;

	// if loading non-existent vcpu, do nothing.
	if (vcpu_idx >= vm->vm_table_locked.nr_vcpus)
		goto out;

	struct ghost_vcpu *vcpu = vm->vm_table_locked.vcpus[vcpu_idx];
	ghost_assert(vcpu_idx < KVM_MAX_VCPUS);
	ghost_assert(vcpu);

	// if the vcpu is already loaded (potentially in another CPU), then do nothing
	if (vcpu->loaded)
		goto out;

	// record in the ghost state of the vcpu 'vcpu_idx' that is has been loaded
	struct ghost_vm *vm1 = ghost_vms_alloc(&g1->vms, vm->pkvm_handle);
	ghost_vm_clone_into_partial(vm1, vm, VMS_VM_TABLE_OWNED);

	// this vm's vcpu is now marked as loaded
	ghost_assert(vm1->vm_table_locked.vcpus[vcpu_idx]);
	vm1->vm_table_locked.vcpus[vcpu_idx]->loaded = true;

	// and the table has the same number of vms as before.
	g1->vms.table_data.present = true;
	g1->vms.table_data.nr_vms = g0->vms.table_data.nr_vms;

	// and mark this cpu as having a loaded vcpu
	*this_cpu_ghost_loaded_vcpu(g1) = (struct ghost_loaded_vcpu){
		.present = true,
		.loaded = true,
		.vm_handle = vm_handle,
		.vcpu_index = vcpu_idx,
	};
out:

	/* NOTE: vcpu_load does not write back to any general purpose register other than the SMCCC errorno (X0) */
	copy_registers_to_host(g1);

	/* check this spec */
	return true;
}

bool compute_new_abstract_state_handle___pkvm_vcpu_put(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	struct ghost_loaded_vcpu *loaded_vcpu = this_cpu_ghost_loaded_vcpu(g0);
	ghost_assert(loaded_vcpu->present);

	// have to have done a previous vcpu_load
	if (!loaded_vcpu->loaded) {
		goto out;
	}

	pkvm_handle_t vm_handle = loaded_vcpu->vm_handle;
	u64 vcpu_idx = loaded_vcpu->vcpu_index;

	struct ghost_vm *vm0 = ghost_vms_get(&g0->vms, vm_handle);
	struct ghost_vm *vm1 = ghost_vms_alloc(&g1->vms, vm_handle);
	ghost_assert(vm0);
	ghost_assert(vm1);
	ghost_vm_clone_into_partial(vm1, vm0, VMS_VM_TABLE_OWNED);

	// the vm's vcpu is now marked as not loaded.
	ghost_assert(vm1->vm_table_locked.vcpus[vcpu_idx]);
	vm1->vm_table_locked.vcpus[vcpu_idx]->loaded = false;

	// and the table has the same number of vms as before.
	g1->vms.table_data.present = true;
	g1->vms.table_data.nr_vms = g0->vms.table_data.nr_vms;

out:
	*this_cpu_ghost_loaded_vcpu(g1) = (struct ghost_loaded_vcpu){
		.present = true,
		.loaded = false,
	};

	/* NOTE: vcpu_put does not write back to any general purpose register other than the SMCCC errorno (X0) */
	copy_registers_to_host(g1);

	/* check this spec */
	return true;
}

bool compute_new_abstract_state_handle___kvm_vcpu_run_begin(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	struct ghost_loaded_vcpu *loaded_vcpu = this_cpu_ghost_loaded_vcpu(g0);
	ghost_assert(loaded_vcpu->present);

	// have to have done a previous vcpu_load
	if (!loaded_vcpu->loaded) {
		goto out;
	}

	pkvm_handle_t vm_handle = loaded_vcpu->vm_handle;
	u64 vcpu_index = loaded_vcpu->vcpu_index;

	/* must have existed to be able to load it */
	struct ghost_vm *vm0 = ghost_vms_get(&g0->vms, vm_handle);
	ghost_assert(vm0);

	struct ghost_vcpu *vcpu0 = vm0->vm_table_locked.vcpus[vcpu_index];
	ghost_assert(vcpu0);

	/* save current register state into the host context */
	copy_abstraction_regs(&ghost_this_cpu_local_state(g1)->host_regs.regs, &ghost_this_cpu_local_state(g0)->regs);

	/* restore saved vcpu register state to the local regs */
	copy_abstraction_regs(&ghost_this_cpu_local_state(g1)->regs, &vcpu0->regs);

	/* mark as guest running */
	ghost_this_cpu_local_state(g1)->cpu_state = (struct ghost_running_state){
		.guest_running = true,
		.vm_handle = vm_handle,
		.vcpu_index = vcpu_index,
	};

out:
	return true;
}

bool compute_new_abstract_state_handle___kvm_vcpu_run_end(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	struct ghost_loaded_vcpu *loaded_vcpu = this_cpu_ghost_loaded_vcpu(g0);
	ghost_assert(loaded_vcpu->present);

	// have to have done a previous vcpu_load
	if (!loaded_vcpu->loaded) {
		goto out;
	}

	/* must have existed to be able to load it */
	pkvm_handle_t vm_handle = loaded_vcpu->vm_handle;
	u64 vcpu_index = loaded_vcpu->vcpu_index;

	struct ghost_vm *vm0 = ghost_vms_get(&g0->vms, vm_handle);
	struct ghost_vcpu *vcpu0 = vm0->vm_table_locked.vcpus[vcpu_index];

	/* must have existed in the vms table to have loaded it */
	struct ghost_vm *vm1 = ghost_vms_get(&g1->vms, vm_handle);
	ghost_assert(vm1);

	struct ghost_vcpu *vcpu1 = vm1->vm_table_locked.vcpus[vcpu_index];
	ghost_assert(vcpu1);

	/* save current register state into the vcpu context */
	copy_abstraction_regs(&vcpu0->regs, &ghost_this_cpu_local_state(g1)->regs);

	/* restore saved host register state to the local regs */
	copy_abstraction_regs(&ghost_this_cpu_local_state(g0)->regs, &ghost_this_cpu_local_state(g1)->host_regs.regs);

	/* mark as host running */
	ghost_this_cpu_local_state(g1)->cpu_state = (struct ghost_running_state){
		.guest_running = false,
	};

	/* TODO: vcpu_run return value */

out:
	return true;
}

//TODO: move somewhere else
#define phys_of_host_va(X) X// TODO
// performs the mapping checks of hyp_pin_shared_mem (from mem_protect.c)
// @from and @to are host_va
bool ghost_hyp_check_host_shared_mem(struct ghost_state *g, host_va_t from, host_va_t to)
{
	u64 start = ALIGN_DOWN((u64)from, PAGE_SIZE);
	u64 end = PAGE_ALIGN((u64)to);
	u64 size = end - start;
	for (host_va_t addr=start; addr < size * PAGE_SIZE; addr += PAGE_SIZE) {
		if (!is_owned_and_shared_by(g, GHOST_HOST, phys_of_host_va(addr)))
			return false;
		if (!is_borrowed_by(g, GHOST_HYP, phys_of_host_va(addr)))
			return false;
	}
	return true;
}


static bool ghost_map_donated_memory_checkonly(struct ghost_state *g, host_ipa_t host_ipa, size_t size_in_bytes)
{
	phys_addr_t phys_addr = phys_of_host_ipa(host_ipa);
	u64 hyp_virt = (u64)ghost__hyp_va(g, phys_addr);
	u64 nr_pages = PAGE_ALIGN((u64)size_in_bytes) >> PAGE_SHIFT;

	for (u64 addr=phys_addr; addr < nr_pages * PAGE_SIZE; addr += PAGE_SIZE) {
		if (!is_owned_exclusively_by(g, GHOST_HOST, addr))
			return false;

	}
	for (u64 addr=hyp_virt; addr < nr_pages * PAGE_SIZE; addr += PAGE_SIZE) {
		if (mapping_in_domain(hyp_virt, g->pkvm.pkvm_abstract_pgtable.mapping))
			return false;
	}
	return true;
}

static void ghost_map_donated_memory_nocheck(struct ghost_state *g, host_ipa_t host_ipa, size_t size_in_bytes)
{
	phys_addr_t phys_addr = phys_of_host_ipa(host_ipa);
	u64 hyp_virt = (u64)ghost__hyp_va(g, phys_addr);
	u64 nr_pages = PAGE_ALIGN((u64)size_in_bytes) >> PAGE_SHIFT;

	mapping_move(
		&g->host.host_abstract_pgtable_annot,
		mapping_plus(g->host.host_abstract_pgtable_annot,
			mapping_singleton(GHOST_STAGE2, host_ipa, nr_pages, maplet_target_annot_ext(MAPLET_OWNER_ANNOT_OWNED_HYP)))
	);

	bool is_memory = ghost_addr_is_allowed_memory(g, phys_addr);
	struct maplet_attributes hyp_attrs = ghost_default_hyp_memory_attributes(is_memory, MAPLET_PAGE_STATE_PRIVATE_OWNED);

	mapping_move(
		&g->pkvm.pkvm_abstract_pgtable.mapping,
		mapping_plus(g->pkvm.pkvm_abstract_pgtable.mapping,
			mapping_singleton(GHOST_STAGE1, hyp_virt, nr_pages,
				maplet_target_mapped_attrs(phys_addr, nr_pages, hyp_attrs)))
	);
}

// TODO: duplicating pkvm_get_hyp_vm_size() because it is static (in arch/arm64/kvm/hyp/nvhe/pkvm.c)
static size_t ghost_pkvm_get_hyp_vm_size(unsigned int nr_vcpus)
{
	return size_add(sizeof(struct pkvm_hyp_vm),
		  size_mul(sizeof(struct pkvm_hyp_vcpu *), nr_vcpus));
}

static size_t ghost_pkvm_get_last_ran_size(struct ghost_state *g)
{
	// TODO: this directly using the hyp_nr_cpus global from setup.c
	// we need to have a copy in the ghost_state instead
	return array_size(hyp_nr_cpus, sizeof(int));
}

bool compute_new_abstract_state_handle___pkvm_init_vm(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call) {
	int ret;
	size_t vm_size, pgd_size, last_ran_size;

	host_va_t host_kvm_hva = ghost_read_gpr(g0, 1);
	host_va_t vm_hva = ghost_read_gpr(g0, 2);
	host_va_t pgd_hva = ghost_read_gpr(g0, 3);
	host_va_t last_ran_hva = ghost_read_gpr(g0, 4);

	struct kvm *host_kvm_hyp_va = (struct kvm*)hyp_va_of_host_va(g0, host_kvm_hva);
	host_ipa_t vm_host_ipa = host_ipa_of_phys(phys_of_hyp_va(g0, hyp_va_of_host_va(g0, vm_hva)));
	phys_addr_t pgd_phys = phys_of_hyp_va(g0, hyp_va_of_host_va(g0, pgd_hva));
	host_ipa_t pgd_host_ipa = host_ipa_of_phys(pgd_phys);
	host_ipa_t last_ran_host_ipa = host_ipa_of_phys(phys_of_hyp_va(g0, hyp_va_of_host_va(g0, last_ran_hva)));

	copy_abstraction_host(g1, g0);
	copy_abstraction_pkvm(g1, g0);

	// checking that the pages underlying the host_kvm structure is owned by the host
	// and shared with pKVM
	if (!ghost_hyp_check_host_shared_mem(g0, host_kvm_hva, host_kvm_hva + sizeof(struct kvm))) {
		ret = -EPERM;
		goto out;
	}

	u64 handle = call->return_value;

	// In the implementation, insert_vm_table_entry() may return -EINVAL,
	// if during the init of pKVM vm_table could not allocated,
	// so these ghost compute functions are only valid if properly initialised
	ghost_assert(READ_ONCE(ghost_pkvm_init_finalized));

	// the implementation must have taken the vm_table lock
	ghost_spec_assert(g0->vms.present && g0->vms.table_data.present);

	// pKVM should not allocate the same handle to a previously existent VM
	ghost_spec_assert(ghost_vms_get(&g0->vms, handle) == NULL);

	// if we've already allocated KVM_MAX_PVMS VMs, then fail with -ENOMEM
	if (g0->vms.table_data.nr_vms == KVM_MAX_PVMS) {
		ret = -ENOMEM;
		goto out;
	}

	// otherwise, we have all the same vms as before, plus one more
	copy_abstraction_vms_partial(g1, g0, VMS_VM_TABLE_OWNED);
	struct ghost_vm *vm1 = ghost_vms_alloc(&g1->vms, handle);
	g1->vms.table_data.present = true; // TODO: we probably want to change copy_abstraction_vms_partial() instead to set g1.vms.present to true (check with Ben)
	g1->vms.table_data.nr_vms = g0->vms.table_data.nr_vms + 1;
	ghost_assert(vm1);

	// the calls to map_donated_memory() may run out of
	// memory when updating the pKVM page table
	// BS suspects there is an invariant preventing this from
	// actually happening.
	ghost_spec_assert(call->return_value != -ENOMEM);

	u64 nr_vcpus = GHOST_READ_ONCE(call, host_kvm_hyp_va->created_vcpus);
	if (nr_vcpus < 1) {
		ret = -EINVAL;
		goto out;
	}

	vm_size = ghost_pkvm_get_hyp_vm_size(nr_vcpus);
	last_ran_size = ghost_pkvm_get_last_ran_size(g0);
	pgd_size = kvm_pgtable_stage2_pgd_size(host_mmu.arch.vtcr);

	if (   !PAGE_ALIGNED(vm_host_ipa)
	    && !PAGE_ALIGNED(last_ran_host_ipa)
	    && !PAGE_ALIGNED(pgd_host_ipa)) {
		// if any of the calls to map_donated_memory()
		// are given a non-page aligned va, it returns NULL
		// which causes the hypercall to return -ENOMEM
		ret = -ENOMEM;
		goto out;
	}

	// NOTE: to avoid having to do the equivalent of any unmap_donated_memory() in
	// the spec, we group the checks and we then do the three mapping updates
	// only if all of their checks succeeded.
	if (!ghost_map_donated_memory_checkonly(g1, vm_host_ipa, vm_size)) {
		ret = -ENOMEM;
		goto out;
	}
	if (!ghost_map_donated_memory_checkonly(g1, last_ran_host_ipa, last_ran_size)) {
		ret = -ENOMEM;
		goto out;
	}
	if (!ghost_map_donated_memory_checkonly(g1, pgd_host_ipa, pgd_size)) {
		ret = -ENOMEM;
		goto out;
	}

	ghost_map_donated_memory_nocheck(g1, vm_host_ipa, vm_size);
	ghost_map_donated_memory_nocheck(g1, last_ran_host_ipa, last_ran_size);
	ghost_map_donated_memory_nocheck(g1, pgd_host_ipa, pgd_size);

	// Now set up the VM with the right initial state:
	// an empty mapping with the right pool,
	// and the first nr_vcpus un-initialised unloaded vcpus.
	vm1->vm_locked.present = true;

	// vm starts with empty pgtables, in the region given to vm_init as pgd_phys..+pgd_size
	vm1->vm_locked.vm_abstract_pgtable.mapping = mapping_empty_();
	ghost_pfn_set_init(&vm1->vm_locked.vm_abstract_pgtable.table_pfns, pgd_phys, pgd_phys + pgd_size);
	vm1->vm_locked.vm_abstract_pgtable.root = pgd_phys;

	vm1->vm_table_locked.present = true;
	vm1->vm_table_locked.nr_vcpus = nr_vcpus;
	vm1->vm_table_locked.nr_initialised_vcpus = 0;
	vm1->pkvm_handle = handle;
	vm1->protected = GHOST_READ_ONCE(call, host_kvm_hyp_va->arch.pkvm.enabled);
	for (int i = 0; i < nr_vcpus; i++) {
		vm1->vm_table_locked.vcpus[i] = malloc_or_die(sizeof(struct ghost_vcpu));
		vm1->vm_table_locked.vcpus[i]->vcpu_handle = i;
		vm1->vm_table_locked.vcpus[i]->loaded = false;
		vm1->vm_table_locked.vcpus[i]->initialised = false;
	}

	// in theory this is unsafe, as another thread could've swooped in between
	// the release of all the locks and this check,
	// and removed the VM.
	//
	// However, the chance of another thread removing this VV, before __pkvm_init_vm has even returned,
	// is so remotely small we don't care.
	vm1->lock = ghost_pointer_to_vm_lock(handle);
	ret = handle;
out:
	ghost_write_gpr(g1, 1, ret);

	/* these registers now become the host's run context */
	copy_registers_to_host(g1);

	/* check this spec*/
	return true;
}

/* Locking shape in the implementation:
 * 
 *  (1) [L_host L_hyp  host_donate_hyp(vcpu_hva) U_hyp U_host] 
        [L_vm_table
		(2) [L_host L_hyp  hyp_pin_shared_mem(host_vcpu) U_hyp U_host]
		(3) (optional) [L_host L_hyp  hyp_pin_shared_mem(sve_state) U_hyp U_host]
	U_vm_table]
 */
bool compute_new_abstract_state_handle___pkvm_init_vcpu(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	int ret = 0;
	int vcpu_idx;
	struct ghost_vcpu *vcpu;

	pkvm_handle_t vm_handle = ghost_read_gpr(g0, 1);
	host_va_t host_vcpu_hva = ghost_read_gpr(g0, 2);
	host_va_t vcpu_hva = ghost_read_gpr(g0, 3);
//	struct kvm_vcpu *host_vcpu_hyp_va = (struct kvm_vcpu *)hyp_va_of_host_va(g0, host_vcpu_hva);

	struct ghost_vm *vm0 = ghost_vms_get(&g0->vms, vm_handle);
	if (!vm0) {
		ret = -ENOENT;
		goto out;
	}
	struct ghost_vm *vm1 = ghost_vms_alloc(&g1->vms, vm_handle);
	ghost_assert(vm1);
	ghost_vm_clone_into_partial(vm1, vm0, VMS_VM_TABLE_OWNED);

	vcpu_idx = vm1->vm_table_locked.nr_initialised_vcpus;
	if (vcpu_idx >= vm1->vm_table_locked.nr_vcpus) {
		ret = -EINVAL;
		goto out;
	}
	ghost_spec_assert(vcpu_idx < KVM_MAX_VCPUS);
	vcpu = vm1->vm_table_locked.vcpus[vcpu_idx];
	ghost_assert(vcpu);

	copy_abstraction_host(g1, g0);
	copy_abstraction_pkvm(g1, g0);

	host_ipa_t vcpu_ipa = host_ipa_of_phys(phys_of_hyp_va(g0, hyp_va_of_host_va(g0, vcpu_hva)));
	if (!ghost_map_donated_memory_checkonly(g1, vcpu_ipa, sizeof(struct pkvm_hyp_vcpu))) {
		ret = -ENOMEM;
		goto out;
	}
	ghost_map_donated_memory_nocheck(g1, vcpu_ipa, sizeof(struct pkvm_hyp_vcpu));

	// TODO: if the vcpu is NOT protected the spec should not care about the sysregs stuff and skip


	// TODO ret = init_pkvm_hyp_vcpu(hyp_vcpu, hyp_vm, host_vcpu, idx);

	// TODO: this can't be in the spec at the moment because the load of host_vcpu->vcpu_idx is not READ_ONCE()
	// if (host_vcpu->vcpu_idx != vcpu_idx) {
	// 	ret = -EINVAL;
	// 	goto done;
	// }

	if (!ghost_hyp_check_host_shared_mem(g0, host_vcpu_hva, host_vcpu_hva + sizeof(struct kvm_vcpu))) {
		ret = -EBUSY;
		goto out;
	}


	// TODO -> hyp_pin_shared_mem(host_vcpu, host_vcpu + 1)
/*

	hyp_vcpu->vcpu.vcpu_id = READ_ONCE_GHOST_RECORD(host_vcpu->vcpu_id);
	hyp_vcpu->vcpu.vcpu_idx = vcpu_idx;

	hyp_vcpu->vcpu.arch.hw_mmu = &hyp_vm->kvm.arch.mmu;
	hyp_vcpu->vcpu.arch.cflags = READ_ONCE(host_vcpu->arch.cflags);
	hyp_vcpu->vcpu.arch.mp_state.mp_state = KVM_MP_STATE_STOPPED;

*/
// struct ghost_vcpu {
// 	struct ghost_registers regs;
// };

	// TODO if ret != 0 ==> goto out
	vcpu->vcpu_handle = vcpu_idx;
	vcpu->loaded = false;
	vcpu->initialised = true;

	vcpu->regs.present = true;
	for (int i=0; i<31; i++) {
		vcpu->regs.gprs[i].status = GHOST_PRESENT;
		vcpu->regs.gprs[i].value = 0;
	}
	for (int i=0; i<NR_GHOST_SYSREGS; i++) {
		ghost_write_sysreg_explicit(&vcpu->regs, i, 0);
		// vcpu->regs.el1_sysregs[i].status = GHOST_PRESENT;
		// vcpu->regs.el1_sysregs[i].value = 0;
	}
	for (int i=0; i<NR_GHOST_EL2_SYSREGS; i++) {
		ghost_write_el2_sysreg_explicit(&vcpu->regs, i, 0);
		// vcpu->regs.el2_sysregs[i].status = GHOST_PRESENT;
		// vcpu->regs.el2_sysregs[i].value = 0;
	}
	// TODO: if the vcpu is NOT protected ===> the vcpu it set to a ON_PENDING state and the reset values for x0 and pc are taken
	//	 from the host_vcpu struct
	// TOOD: for protected vcpu ===> x0 and pc (and everything else) is set to 0 (en the vcpu is set to OFF state)
	// TODO: in the implementation MPIDR_EL1 = 0x80000000 (this is RES1 bit) and SCTLR_EL1 = 0xc50078

	g1->vms.table_data.present = true; // TODO: check with Ben that we really need this here
	vm1->vm_table_locked.nr_initialised_vcpus++;
out:
	ghost_write_gpr(g1, 1, ret);

	/* these registers now become the host's run context */
	copy_registers_to_host(g1);

	/* check this spec*/
	return true;
}


bool compute_new_abstract_state_handle___pkvm_teardown_vm(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	int ret = 0;

	pkvm_handle_t vm_handle = ghost_read_gpr(g0, 1);
	struct ghost_vm *vm = ghost_vms_get(&g0->vms, vm_handle);
	if (!vm) {
		ret = -ENOENT;
		goto out;
	}

	// TODO(doc): we can have an ND EBUSY, because of hyp_page_count() > 0
	// TODO: this is if the vm has loaded vcpu
	// if (call->return_value == -EBUSY) {
	// 	ret = -EBUSY;
	// 	goto out;
	// }
	// TODO: more abstract version of the previous
	for (int i=0; i<KVM_MAX_VCPUS; i++) {
		if (vm->vm_table_locked.vcpus[i]->loaded) {
			ret = -EBUSY;
			goto out;
		}
	}

	// TODO: copy the pfs from vm->vm_abstract_pgtable.table_pfns;
	// into a some "reclaimable_pfn_sets" list in ghost_state
	// and mark them as "need_poisoning" or "pending_reclaim" depending on their state

	/* TODO: reclaim_guest_pages(hyp_vm, mc);
	 * this does:
	 *	1. mark all leaves of the page table as
			- HOST_PAGE_NEED_POISONING (if exclusively owned by guest)
			- HOST_PAGE_PENDING_RECLAIM (if shared borrowed/owned)
	 *	2. destroy the guest pgtable (free the tables and ???)
	 *	3. sets the guest stage 2 pgtable root phys_addr to 0 (the kvm mmu struct)
	 */

	// TODO: unpin_host_vcpus(hyp_vm->vcpus, hyp_vm->nr_vcpus);

	// TODO: for each vcpu, move pages from vcpu_memcache to hyp_memcast
	//	 AND unmap_donated_memory_noclear()
	//	 AND teardown_donated_memory(mc, hyp_vcpu, sizeof(*hyp_vcpu));

	// TODO: teardown_donated_memory() for last_vcpu_ran

	// TODO: teardown_donated_memory() for hyp_vm
	// TODO: hyp_unpin_shared_mem() from hyp_vm

	ghost_vms_free(&g0->vms, vm_handle);
out:
	ghost_write_gpr(g1, 1, ret);

	/* these registers now become the host's run context */
	copy_registers_to_host(g1);

	/* check this spec*/
	return true;
}

bool compute_new_abstract_state_handle_host_hcall(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	bool new_state_computed = false;
	GHOST_LOG_CONTEXT_ENTER();
	int smccc_ret = SMCCC_RET_SUCCESS;
	// // allow any hcall to fail with ENOMEM, with an otherwise-identity abstract state
	// if (call->return_value == -ENOMEM) {
	// 	ghost_write_gpr(g1, 1, -ENOMEM);
	// 	return false;
	// }

	unsigned long id = ghost_read_gpr(g0, 0) - KVM_HOST_SMCCC_ID(0);

	/* set X0 first, so the individual functions can overwrite it. */
	ghost_write_gpr(g1, 0, smccc_ret);

	switch (id) {
	case __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_host_share_hyp(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_host_unshare_hyp(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_host_reclaim_page(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_host_map_guest(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_vcpu_load(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_vcpu_put(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___kvm_vcpu_run:
		new_state_computed =  compute_new_abstract_state_handle___kvm_vcpu_run_begin(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___pkvm_init_vm:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_init_vm(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_init_vcpu(g1, g0, call);
		break;
	case __KVM_HOST_SMCCC_FUNC___pkvm_teardown_vm:
		new_state_computed =  compute_new_abstract_state_handle___pkvm_teardown_vm(g1, g0, call);
		break;
		// TODO: and their bodies, and all the other cases
	default:
		smccc_ret = SMCCC_RET_NOT_SUPPORTED;
		ghost_write_gpr(g1, 0, smccc_ret);
		break;
	}

	GHOST_LOG_CONTEXT_EXIT();
	return new_state_computed;
}

u64 ghost_esr_ec_low_to_cur(u64 esr)
{
	u64 ec = ESR_ELx_EC(esr);
	switch (ec) {
	case ESR_ELx_EC_DABT_LOW:
		ec = ESR_ELx_EC_DABT_CUR;
		break;
	case ESR_ELx_EC_IABT_LOW:
		ec = ESR_ELx_EC_IABT_CUR;
		break;
	default:
		// the implementation should panic
		ghost_assert(false);
	}
	esr &= ~ESR_ELx_EC_MASK;
	esr |= ec << ESR_ELx_EC_SHIFT;
	return esr;
}

// TODO: the spec is not great at the moment because it is just doing the same copies
// of the registers as the pKVM implementation.
// What we should instead do is (symbolically) run the ASL AArch64.DataAbort with the right arguments
// and collect the set of register writes it does and use that as a kind of spec.
void ghost_inject_abort(struct ghost_state *g1, struct ghost_state *g0)
{
	u64 spsr_el2 = ghost_read_el2_sysreg(g0, SPSR_EL2);
	u64 esr_el2 = ghost_read_el2_sysreg(g0, ESR_EL2);

	u64 esr_el1;

	// if SPSR_EL2.M[3:0] <> PSR_EL0
	if ((spsr_el2 & PSR_MODE_MASK) != PSR_MODE_EL0t)
		// change the exception class to be a same-level fault
		esr_el1 = ghost_esr_ec_low_to_cur(esr_el2);
	else
		esr_el1 = esr_el2;

	// the implementation uses this RES0 bit (which is architecturally guaranteed
	// to preserve software writes) to signal to the host that it is not dealing with a
	// userspace fault
	esr_el1 |= ESR_ELx_S1PTW;

	ghost_write_sysreg(g1, ESR_EL1, esr_el1);
	ghost_write_sysreg(g1, SPSR_EL1, spsr_el2);
	ghost_write_sysreg(g1, ELR_EL1, ghost_read_el2_sysreg(g0, ELR_EL2));
	ghost_write_sysreg(g1, FAR_EL1, ghost_read_el2_sysreg(g0, FAR_EL2));

	ghost_write_el2_sysreg(g1, ELR_EL2,
		ghost_read_sysreg(g0, VBAR_EL1) + get_except64_offset(spsr_el2, PSR_MODE_EL1h, except_type_sync));

	spsr_el2 = get_except64_cpsr(spsr_el2, false/*TODO: we hardcode that the cpus do not support MTE */,
				     ghost_read_sysreg(g0, SCTLR_EL1), PSR_MODE_EL1h);
	ghost_write_el2_sysreg(g1, SPSR_EL2, spsr_el2);
}


// TODO: move this somewhere more sensible
#define HPFAR_FIPA_SHIFT UL(4)

bool compute_new_abstract_state_handle_host_mem_abort(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	u64 esr = ghost_read_el2_sysreg(g0, ESR_EL2);
	u64 hpfar;
	host_ipa_t addr;

	if (!(esr & ESR_ELx_S1PTW) && (esr & ESR_ELx_FSC_TYPE) == ESR_ELx_FSC_PERM) {
		u64 far = ghost_read_el2_sysreg(g0, FAR_EL2);
		struct ghost_at_translation *at_status = ghost_at_translations_get(&call->at_translations, far);
		if (at_status->success)
			hpfar = at_status->ipa;
		else
			// this should not be accessible because the pKVM code will have panicked
			// in this situation
			ghost_spec_assert(false);
	} else {
		hpfar = ghost_read_el2_sysreg(g0, HPFAR_EL2);
	}

	// the bits [51:12] of the faulting IPA are in bits [47:4] of the HPFAR_EL2 register
	// (the mismatch of the upper bites offset is because the upper bits are FIPA are RES0)
	addr = (hpfar >> HPFAR_FIPA_SHIFT) << PAGE_SHIFT;

	// this is the third if in mem_protect.c::host_stage2_adjust_range()
	if (!is_owned_exclusively_by(g0, GHOST_HOST, addr))
		ghost_inject_abort(g1, g0);

	/* TODO: modelling of host_stage2_adjust_range()
		1. ==> non-deterministic -EGAIN (when the pte for addr is valid)
	*/

	/* check this spec */
	return true;
}

/* Guest API */

bool compute_new_abstract_state_pkvm_memshare(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	int ret = 0;

	// Get the VCPU loaded onto this physical core. It provides further indices.
	struct ghost_loaded_vcpu *loaded_vcpu = this_cpu_ghost_loaded_vcpu(g0);
	ghost_spec_assert(loaded_vcpu->present);
	ghost_spec_assert(loaded_vcpu->loaded);

	// Get the VM that this VCPU belongs to.
	struct ghost_vm *g0_vm = ghost_vms_get(&g0->vms, loaded_vcpu->vm_handle);
	ghost_spec_assert(g0_vm != NULL);
	ghost_spec_assert(g0_vm->vm_locked.present);
	ghost_spec_assert(g0_vm->vm_table_locked.present);

	// Get the rest of the VCPU. We need the registers.
	struct ghost_vcpu *vcpu0 = g0_vm->vm_table_locked.vcpus[loaded_vcpu->vcpu_index];
	ghost_assert(vcpu0->regs.present);

	// Pluck out the arguments.
	guest_ipa_t guest_ipa_page = ALIGN_DOWN(ghost_read_vcpu_gpr(vcpu0, 1), PAGE_SIZE);
	u64 arg2 = ghost_read_vcpu_gpr(vcpu0, 2);
	u64 arg3 = ghost_read_vcpu_gpr(vcpu0, 3);

	// Initialise computed host + VM state. We need post-VCPU to return to the guest.

	copy_abstraction_host(g1, g0);
	struct ghost_vm *g1_vm = ghost_vms_alloc(&g1->vms, loaded_vcpu->vm_handle);
	ghost_assert(g1_vm != NULL);
	ghost_vm_clone_into_partial(g1_vm, g0_vm, VMS_VM_OWNED);
	ghost_vm_clone_into_partial(g1_vm, g0_vm, VMS_VM_TABLE_OWNED);
	struct ghost_vcpu *vcpu1 = g1_vm->vm_table_locked.vcpus[loaded_vcpu->vcpu_index];
	*vcpu1 = *vcpu0;

	if (arg2 || arg3)
		goto out_guest_err;

	// checks in: do_share() -> check_share() -> guest_request_share

	struct maplet_target g0_vm_mapping;
	if (!mapping_lookup(guest_ipa_page, g0_vm->vm_locked.vm_abstract_pgtable.mapping, &g0_vm_mapping)) {
		ret = -EFAULT;
		goto out_host;
	}

	struct maplet_attributes g0_vm_page_attrs;
	if ( !maplet_target_get_mapped(&g0_vm_mapping, NULL, NULL, &g0_vm_page_attrs) ||
	     g0_vm_page_attrs.provenance != MAPLET_PAGE_STATE_PRIVATE_OWNED) {
		ret = -EPERM;
		goto out_guest_err;
	}

	phys_addr_t phys;

	mapping_oa(guest_ipa_page, g0_vm->vm_locked.vm_abstract_pgtable.mapping, &phys);

	if (!ghost_addr_is_allowed_memory(g0, phys)) {
		ret = -EINVAL;
		goto out_guest_err;
	}

	host_ipa_t host_ipa = host_ipa_of_phys(phys);

	// checks in: do_share() -> check_share() -> host_ack_share() -> __host_ack_transition()

	if (mapping_in_domain(host_ipa, g0->host.host_abstract_pgtable_shared)) {
		ret = -EPERM;
		goto out_guest_err;
	}

	// work in: do_share() -> __do_share()

	// Mark the guest page as PKVM_PAGE_SHARED_OWNED
	g1_vm->vm_locked.vm_abstract_pgtable.mapping =
		mapping_plus(g0_vm->vm_locked.vm_abstract_pgtable.mapping,
			mapping_singleton(GHOST_STAGE2, guest_ipa_page, 1, 
				maplet_target_mapped_ext(phys, 1, g0_vm_page_attrs.prot,
					MAPLET_PAGE_STATE_SHARED_OWNED, g0_vm_page_attrs.memtype)));

	// Flip the page from PKVM_NOPAGE to PKVM_PAGE_SHARED_BORROWED

	g1->host.host_abstract_pgtable_shared =
		mapping_plus(g0->host.host_abstract_pgtable_shared,
			mapping_singleton(GHOST_STAGE2, host_ipa, 1, 
				maplet_target_mapped_attrs(phys, 1,
					ghost_default_host_memory_attributes(true,
						MAPLET_PAGE_STATE_SHARED_BORROWED))));

	g1->host.host_abstract_pgtable_annot =
		mapping_minus(g0->host.host_abstract_pgtable_annot, host_ipa, 1);
	
out_host:

	if (ret == -EFAULT) {
		// XXX
	}

	// XXX HOW TO DENOTE RETURN TO HOST?
	return true;

out_guest_err:

	// Return in guest registers.
	ghost_write_vcpu_gpr(vcpu1, 0, SMCCC_RET_INVALID_PARAMETER);
	ghost_write_vcpu_gpr(vcpu1, 1, 0);
	ghost_write_vcpu_gpr(vcpu1, 2, 0);
	ghost_write_vcpu_gpr(vcpu1, 3, 0);

	// XXX HOW TO DENOTE RETURN TO GUEST?
	return true;
}

bool compute_new_abstract_state_pkvm_memunshare(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	int ret = 0;

	// Get the VCPU loaded onto this physical core. It provides further indices.
	struct ghost_loaded_vcpu *loaded_vcpu = this_cpu_ghost_loaded_vcpu(g0);
	ghost_spec_assert(loaded_vcpu->present);
	ghost_spec_assert(loaded_vcpu->loaded);

	// Get the VM that this VCPU belongs to.
	struct ghost_vm *g0_vm = ghost_vms_get(&g0->vms, loaded_vcpu->vm_handle);
	ghost_spec_assert(g0_vm != NULL);
	ghost_spec_assert(g0_vm->vm_locked.present);
	ghost_spec_assert(g0_vm->vm_table_locked.present);

	// Get the rest of the VCPU. We need the registers.
	struct ghost_vcpu *vcpu0 = g0_vm->vm_table_locked.vcpus[loaded_vcpu->vcpu_index];
	ghost_assert(vcpu0->regs.present);

	// Pluck out the arguments.
	guest_ipa_t guest_ipa_page = ALIGN_DOWN(ghost_read_vcpu_gpr(vcpu0, 1), PAGE_SIZE);
	u64 arg2 = ghost_read_vcpu_gpr(vcpu0, 2);
	u64 arg3 = ghost_read_vcpu_gpr(vcpu0, 3);

	// Initialise computed host + VM state. We need post-VCPU to return to the guest.

	copy_abstraction_host(g1, g0);
	struct ghost_vm *g1_vm = ghost_vms_alloc(&g1->vms, loaded_vcpu->vm_handle);
	ghost_assert(g1_vm != NULL);
	ghost_vm_clone_into_partial(g1_vm, g0_vm, VMS_VM_OWNED);
	ghost_vm_clone_into_partial(g1_vm, g0_vm, VMS_VM_TABLE_OWNED);
	struct ghost_vcpu *vcpu1 = g1_vm->vm_table_locked.vcpus[loaded_vcpu->vcpu_index];
	*vcpu1 = *vcpu0;

	if (arg2 || arg3)
		goto out_guest_err;

	// checks in: do_share() -> check_share() -> guest_request_share

	struct maplet_target g0_vm_mapping;
	if (!mapping_lookup(guest_ipa_page, g0_vm->vm_locked.vm_abstract_pgtable.mapping, &g0_vm_mapping)) {
		ret = -EFAULT;
		goto out_host;
	}

	struct maplet_attributes g0_vm_page_attrs;
	if ( !maplet_target_get_mapped(&g0_vm_mapping, NULL, NULL, &g0_vm_page_attrs) ||
	     g0_vm_page_attrs.provenance != MAPLET_PAGE_STATE_SHARED_OWNED) {
		ret = -EPERM;
		goto out_guest_err;
	}

	phys_addr_t phys;

	mapping_oa(guest_ipa_page, g0_vm->vm_locked.vm_abstract_pgtable.mapping, &phys);

	if (!ghost_addr_is_allowed_memory(g0, phys)) {
		ret = -EINVAL;
		goto out_guest_err;
	}

	host_ipa_t host_ipa = host_ipa_of_phys(phys);

	// checks in: do_share() -> check_share() -> host_ack_share() -> __host_ack_transition()

	if (!mapping_in_domain(host_ipa, g0->host.host_abstract_pgtable_shared)) {
		ret = -EPERM;
		goto out_guest_err;
	}
	// XXX Not only in domain -> check that it is PKVM_PAGE_SHARED_BORROWED

	// work in: do_share() -> __do_share()

	// Mark the guest page as PKVM_PAGE_OWNED
	g1_vm->vm_locked.vm_abstract_pgtable.mapping =
		mapping_plus(g0_vm->vm_locked.vm_abstract_pgtable.mapping,
			mapping_singleton(GHOST_STAGE2, guest_ipa_page, 1, 
				maplet_target_mapped_ext(phys, 1, g0_vm_page_attrs.prot,
					MAPLET_PAGE_STATE_PRIVATE_OWNED, g0_vm_page_attrs.memtype)));

	// Flip the page from PKVM_PAGE_SHARED_BORROWED to PKVM_NOPAGE

	g1->host.host_abstract_pgtable_shared =
		mapping_minus(g0->host.host_abstract_pgtable_shared, host_ipa, 1);

	g1->host.host_abstract_pgtable_annot =
		mapping_plus(g0->host.host_abstract_pgtable_shared,
			mapping_singleton(GHOST_STAGE2, host_ipa, 1,
				maplet_target_mapped_attrs(phys, 1,
					ghost_default_host_memory_attributes(true,
						MAPLET_PAGE_STATE_PRIVATE_OWNED))));
	
out_host:

	if (ret == -EFAULT) {
		// XXX
	}

	// XXX HOW TO DENOTE RETURN TO HOST?
	return true;

out_guest_err:

	// Return in guest registers.
	ghost_write_vcpu_gpr(vcpu1, 0, SMCCC_RET_INVALID_PARAMETER);
	ghost_write_vcpu_gpr(vcpu1, 1, 0);
	ghost_write_vcpu_gpr(vcpu1, 2, 0);
	ghost_write_vcpu_gpr(vcpu1, 3, 0);

	// XXX HOW TO DENOTE RETURN TO GUEST?
	return true;
}

bool compute_new_abstract_state_handle_guest_hcall(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	bool new_state_computed = false;
	GHOST_LOG_CONTEXT_ENTER();

	u64 hcall_id = ghost_read_gpr(g0, 0);

	switch (hcall_id) {
	case ARM_SMCCC_VENDOR_HYP_KVM_MEM_SHARE_FUNC_ID:
		new_state_computed = compute_new_abstract_state_pkvm_memshare(g1, g0, call);
		break;
	case ARM_SMCCC_VENDOR_HYP_KVM_MEM_UNSHARE_FUNC_ID:
		new_state_computed = compute_new_abstract_state_pkvm_memunshare(g1, g0, call);
		break;

	case ARM_SMCCC_VERSION_FUNC_ID:
		/* TODO */
		break;
	case ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID:
		/* TODO */
		break;
	case ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID:
		/* TODO */
		break;
	case ARM_SMCCC_VENDOR_HYP_KVM_HYP_MEMINFO_FUNC_ID:
		/* TODO */
		break;

	default:
		/* TODO */
		//new_state_computed = compute_new_abstract_state_pkvm_handle_psci(hyp_vcpu);
		break;
	}

	GHOST_LOG_CONTEXT_EXIT();
	return new_state_computed;
}


bool compute_new_abstract_state_handle_guest_mem_abort(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	/* guest mem abort = return back to, and then ERET from, vcpu_run */
	return compute_new_abstract_state_handle___kvm_vcpu_run_end(g1, g0, call);
}

/* Top-level EL2 exception handler spec */

bool compute_new_abstract_state_handle_trap(struct ghost_state *post, struct ghost_state *pre, struct ghost_call_data *call)
{
	bool new_state_computed = false;
	GHOST_LOG_CONTEXT_ENTER();

	// copy over the things that were supposed to be constant, and always present.
	copy_abstraction_constants(post, pre);

	// and all the thread-local state the cpu can always see
	copy_abstraction_local_state(ghost_this_cpu_local_state(post), ghost_this_cpu_local_state(pre));

	// figure out if coming from host or guest
	struct ghost_running_state *gr_pre_cpu = this_cpu_ghost_run_state(pre);
	bool ghost_thought_guest_was_running = gr_pre_cpu->guest_running;

	switch (ESR_ELx_EC(ghost_read_el2_sysreg(pre, ESR_EL2))) {
	case ESR_ELx_EC_HVC64:
		if (ghost_thought_guest_was_running)
			new_state_computed =  compute_new_abstract_state_handle_guest_hcall(post, pre, call);
		else
			new_state_computed =  compute_new_abstract_state_handle_host_hcall(post, pre, call);
		break;
	case ESR_ELx_EC_SMC64:
		//TODO compute_new_abstract_state_handle_host_smc(post,pre);
		break;
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		//TODO compute_new_abstract_state_fpsimd_host_restore(post,pre);
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		if (ghost_thought_guest_was_running)
			new_state_computed =  compute_new_abstract_state_handle_guest_mem_abort(post, pre, call);
		else
			new_state_computed =  compute_new_abstract_state_handle_host_mem_abort(post, pre, call);
		break;
	default:
		ghost_assert(false);
	}

	GHOST_LOG_CONTEXT_EXIT();
	return new_state_computed;
}


/* Pretty-printing headers */
struct ghost_trap_param {
	const char *fmt_code;
};

struct ghost_trap_data {
	bool valid;
	u64 ec;
	const char *name;
	const char *params[6];
};

#define __HCALL(EC, NAME, R0, R1, R2, R3, R4, R5) \
	(struct ghost_trap_data){.valid=true, .ec=EC, .name=NAME, .params={R0,R1,R2,R3,R4,R5}}

#define HOST_HCALL(FN, R0, R1, R2, R3, R4, R5) \
	__HCALL(__KVM_HOST_SMCCC_FUNC_##FN, #FN, R0, R1, R2, R3, R4, R5)

#define GUEST_HCALL(SMCCC_FN, R0, R1, R2, R3, R4, R5) \
	__HCALL(SMCCC_FN, #SMCCC_FN, R0, R1, R2, R3, R4, R5)

static struct ghost_trap_data host_hcalls[] = {
	HOST_HCALL(__kvm_get_mdcr_el2, "", "", "", "", "", ""),
	HOST_HCALL(__pkvm_init, "", "phys: %p", "size: %lx", "nr_cpus: %ld", "per_cpu_base: %p", "hyp_va_bits: %ld"),
	HOST_HCALL(__pkvm_create_private_mapping, "", "", "", "", "", ""),
	HOST_HCALL(__pkvm_cpu_set_vector, "", "slot", "", "", "", ""),
	HOST_HCALL(__kvm_enable_ssbs, "", "", "", "", "", ""),
	HOST_HCALL(__vgic_v3_init_lrs, "", "", "", "", "", ""),
	HOST_HCALL(__vgic_v3_get_gic_config, "", "", "", "", "", ""),
	HOST_HCALL(__kvm_flush_vm_context, "", "", "", "", "", ""),
	HOST_HCALL(__kvm_tlb_flush_vmid_ipa, "", "mmu: %p", "ipa: %p", "host_ctxt: %p", "", ""),
	HOST_HCALL(__kvm_tlb_flush_vmid, "", "mmu: %p", "", "", "", ""),
	HOST_HCALL(__kvm_flush_cpu_context, "", "mmu: %p", "", "", "", ""),
	HOST_HCALL(__pkvm_prot_finalize, "", "", "", "", "", ""),

	HOST_HCALL(__pkvm_host_share_hyp, "", "pfn: %lx", "", "", "", ""),
	HOST_HCALL(__pkvm_host_unshare_hyp, "", "pfn: %lx", "", "", "", ""),
	HOST_HCALL(__pkvm_host_reclaim_page, "", "pfn: %lx", "", "", "", ""),
	HOST_HCALL(__pkvm_host_map_guest, "", "pfn: %lx", "gfn: %lx", "", "", ""),
	HOST_HCALL(__kvm_adjust_pc, "", "", "", "", "", ""),
	HOST_HCALL(__kvm_vcpu_run, "", "", "", "", "", ""),
	HOST_HCALL(__kvm_timer_set_cntvoff, "", "", "", "", "", ""),
	HOST_HCALL(__vgic_v3_save_vmcr_aprs, "", "", "", "", "", ""),
	HOST_HCALL(__vgic_v3_restore_vmcr_aprs, "", "", "", "", "", ""),
	HOST_HCALL(__pkvm_init_vm, "", "host_kvm: %p", "vm_hva: %p", "pgd_hva: %p", "last_ran_hva: %p", ""),
	HOST_HCALL(__pkvm_init_vcpu, "", "handle: %lx", "host_vcpu: %p", "vcpu_hva: %p", "", ""),
	HOST_HCALL(__pkvm_teardown_vm, "", "handle: %lx", "", "", "", ""),
	HOST_HCALL(__pkvm_vcpu_load, "", "handle: %lx", "vcpu_index: %p", "hcr_el2: %lx", "", ""),
	HOST_HCALL(__pkvm_vcpu_put, "", "", "", "", "", ""),
	HOST_HCALL(__pkvm_vcpu_sync_state, "", "", "", "", "", ""),
};
#define NR_HOST_HCALLS (sizeof(host_hcalls)/sizeof(host_hcalls[0]))

static struct ghost_trap_data guest_hcalls[] = {
	GUEST_HCALL(ARM_SMCCC_VERSION_FUNC_ID, "", "", "", "", "", ""),
	GUEST_HCALL(ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID, "", "", "", "", "", ""),
	GUEST_HCALL(ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID, "", "", "", "", "", ""),
	GUEST_HCALL(ARM_SMCCC_VENDOR_HYP_KVM_HYP_MEMINFO_FUNC_ID, "", "", "", "", "", ""),
	GUEST_HCALL(ARM_SMCCC_VENDOR_HYP_KVM_MEM_SHARE_FUNC_ID, "", "ipa: %p", "", "", "", ""),
	GUEST_HCALL(ARM_SMCCC_VENDOR_HYP_KVM_MEM_UNSHARE_FUNC_ID, "", "", "", "", "", "")
};
#define NR_GUEST_HCALLS (sizeof(guest_hcalls)/sizeof(guest_hcalls[0]))

static struct ghost_trap_data unknown_trap_data = {
	.valid = true,
	.name = "<unknown>",
	.params = {0},
};

static struct ghost_trap_data __tag_hcall(struct kvm_cpu_context *ctxt, bool from_guest)
{
	u64 hcall_id = cpu_reg(ctxt, 0);

	if (from_guest) {
		for (int i = 0; i < NR_GUEST_HCALLS; i++)
			if (guest_hcalls[i].ec == hcall_id)
				return guest_hcalls[i];
	}
	else {
		hcall_id -= KVM_HOST_SMCCC_ID(0);

		for (int i = 0; i < NR_HOST_HCALLS; i++)
			if (host_hcalls[i].ec == hcall_id)
				return host_hcalls[i];
	}

	return unknown_trap_data;
}

static struct ghost_trap_data host_abort_trap_data = {
	.valid = true,
	.name = "handle_host_mem_abort"
};

static struct ghost_trap_data guest_abort_trap_data = {
	.valid = true,
	.name = "handle_guest_mem_abort"
};

static struct ghost_trap_data __tag_abt(struct kvm_cpu_context *ctxt, bool from_guest)
{
	if (from_guest)
		return guest_abort_trap_data;
	else
		return host_abort_trap_data;
}

static struct ghost_trap_data compute_trap_state(struct kvm_cpu_context *ctxt, bool from_guest)
{
	u64 esr = read_sysreg_el2(SYS_ESR);
	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_HVC64:
		return __tag_hcall(ctxt, from_guest);
	case ESR_ELx_EC_SMC64:
		return unknown_trap_data;
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		return unknown_trap_data;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		return __tag_abt(ctxt, from_guest);
	default:
		return unknown_trap_data;
	}
}

static void tag_exception_entry(struct kvm_cpu_context *ctxt)
{
	ghost_print_enter();

	// dispatch printing/checking on the implementation's understanding of the state
	// since we (currently) trust that more.
	struct ghost_running_state *cpu_run_state = this_cpu_ptr(&ghost_cpu_run_state);
	bool from_guest = cpu_run_state->guest_running;

	struct ghost_trap_data trap = compute_trap_state(ctxt, from_guest);

	__this_cpu_write(ghost_print_this_hypercall, ghost_print_on(trap.name));
	__this_cpu_write(ghost_check_this_hypercall, READ_ONCE(ghost_prot_finalized_all) && trap.valid && (!ghost_control_is_controlled(trap.name) || ghost_control_check_enabled(trap.name)));

	if (! ghost_print_on(trap.name))
		goto print_exit;

	ghost_printf(
		"\n"
		GHOST_WHITE_ON_BLUE "****** TRAP (from %s) *****************************************************" GHOST_NORMAL "\n"
		GHOST_WHITE_ON_BLUE "%s" GHOST_NORMAL "\n",
		from_guest ? "guest" : " host",
		trap.name
	);

	for (int i = 0; i < 6; i++) {
		if (trap.params[i] && *trap.params[i]) {
			ghost_printf("[r%d] ", i);
			ghost_printf(trap.params[i], ctxt->regs.regs[i]);
			ghost_printf("\n");
		}
	}

	if (!ghost_exec_enabled())
		ghost_printf(GHOST_WHITE_ON_YELLOW "skipping exec check" GHOST_NORMAL "\n");

print_exit:
	ghost_print_exit();
}


void ghost_record_pre(struct kvm_cpu_context *ctxt)
{
	tag_exception_entry(ctxt);

	GHOST_LOG_CONTEXT_ENTER();
	if (! GHOST_EXEC_SPEC)
		goto exit_context;

	if (__this_cpu_read(ghost_check_this_hypercall)) {
		clear_abstraction_thread_local();

		ghost_lock_maplets();
		record_abstraction_constants_pre();
		ghost_unlock_maplets();

		/* need vms lock because loaded_vcpu might need to create that vm */
		ghost_lock_vms();
		record_and_check_abstraction_local_state_pre(ctxt);
		ghost_unlock_vms();

		ghost_clear_call_data();
	}

exit_context:
	GHOST_LOG_CONTEXT_EXIT();
}

void ghost_post(struct kvm_cpu_context *ctxt)
{
	bool new_state_computed = false;

	struct ghost_state *gr_pre = this_cpu_ptr(&gs_recorded_pre);
	struct ghost_state *gr_post = this_cpu_ptr(&gs_recorded_post);
	struct ghost_state *gc_post = this_cpu_ptr(&gs_computed_post);
	struct ghost_call_data *call = this_cpu_ptr(&gs_call_data);

	GHOST_LOG_CONTEXT_ENTER();
	if (ghost_exec_enabled()) {
		// record the remaining parts of the new impl abstract state
		// (the pkvm, host, and vm components having been recorded at impl lock points)
		ghost_lock_maplets();
		record_abstraction_constants_post();
		ghost_lock_vms();
		record_and_copy_abstraction_local_state_post(ctxt);
		call->return_value = cpu_reg(ctxt, 1);

		// actually compute the new state
		new_state_computed = compute_new_abstract_state_handle_trap(gc_post, gr_pre, call);

		// and check the two are equal on relevant components
		if (new_state_computed) {
			if (__this_cpu_read(ghost_print_this_hypercall)) {
				ghost_printf("---\n");
				ghost_printf("ret:\n");
				ghost_printf("[r0] %lx\n", ctxt->regs.regs[0]);
				ghost_printf("[r1] %lx\n", ctxt->regs.regs[1]);
				ghost_printf(GHOST_WHITE_ON_BLUE "check abstraction" GHOST_NORMAL "\n");

#ifdef CONFIG_NVHE_GHOST_SPEC_DUMP_STATE
				ghost_printf("ghost recorded pre (full):\n");
				ghost_dump_state(gr_pre);
				ghost_printf("\n");
				ghost_printf("\n");
				ghost_printf("ghost recorded post (full):\n");
				ghost_dump_state(gr_post);
				ghost_printf("\n");
				ghost_printf("\n");
				ghost_printf("ghost computed post (full):\n");
				ghost_dump_state(gc_post);
				ghost_printf("\n");
#endif /* CONFIG_NVHE_GHOST_SPEC_DUMP_STATE */
			}
			check_abstraction_equals_all(gc_post, gr_post, gr_pre);
		} else {
			if (__this_cpu_read(ghost_print_this_hypercall)) {
				ghost_printf(GHOST_WHITE_ON_YELLOW "skipping spec check" GHOST_NORMAL "\n");
			}
		}

		ghost_unlock_vms();
		ghost_unlock_maplets();
	}

	__this_cpu_write(ghost_checked_previous_hypercall, __this_cpu_read(ghost_check_this_hypercall));
	GHOST_LOG_CONTEXT_EXIT();
}
