#include <asm/kvm_mmu.h>
#include <hyp/ghost_extra_debug-pl011.h>
//#include <nvhe/ghost_check_pgtables.h>
#include <hyp/ghost_alloc.h>
#include <nvhe/ghost_misc.h>
#include <nvhe/ghost_pgtable.h>
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



/*
 * Init tracking
 */
bool ghost_pkvm_init_finalized;
DEFINE_HYP_SPINLOCK(ghost_prot_finalized_lock);
u64 ghost_prot_finalized_count;
bool ghost_prot_finalized_all;
DEFINE_PER_CPU(bool, ghost_check_this_hypercall);

DEFINE_PER_CPU(bool, ghost_print_this_hypercall);

bool ghost_exec_enabled(void)
{
	return GHOST_EXEC_SPEC && __this_cpu_read(ghost_check_this_hypercall);
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
static bool is_borrowed_by(const struct ghost_state *g, enum ghost_host_or_hyp id, phys_addr_t addr)
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

void compute_new_abstract_state_handle___pkvm_host_share_hyp(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	u64 pfn = ghost_reg_gpr(g0, 1);
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
	ghost_reg_gpr(g1, 1) = ret;
}


/* pkvm_host_unshare_hyp(pfn) */
void compute_new_abstract_state_handle___pkvm_host_unshare_hyp(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	u64 pfn = ghost_reg_gpr(g0, 1);
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
	ghost_reg_gpr(g1, 1) = ret;
}

/**
 * compute the new abstract ghost_state from a struct ghost_call_data *call = pkvm_host_map_guest(host_pfn, guest_gfn)
 */
void compute_new_abstract_state_handle___pkvm_host_map_guest(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call) {
	int ret;

	u64 pfn = ghost_reg_gpr(g0, 1);
	u64 gfn = ghost_reg_gpr(g0, 2);

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
	// ghost_vm_clone_into_partial(g1_vm, g0_vm, VMS_VM_OWNED);

	for (int d=0; d<call->memcache_donations.len; d++) {
		u64 pfn = call->memcache_donations.pages[d];
		phys_addr_t donated_phys = hyp_pfn_to_phys(pfn);
		host_ipa_t host_page_ipa = host_ipa_of_phys(donated_phys);
		hyp_va_t hyp_page_addr = (u64)ghost__hyp_va(g0, donated_phys);

		bool is_memory = ghost_addr_is_allowed_memory(g0, donated_phys);
		struct maplet_attributes hyp_attrs = ghost_default_hyp_memory_attributes(is_memory, MAPLET_PAGE_STATE_PRIVATE_OWNED);

		// TODO: what if location was not shared with pKVM?
		if (!(is_owned_and_shared_by(g0, GHOST_HOST, host_page_ipa) && is_borrowed_by(g0, GHOST_HYP, hyp_page_addr)))
			ghost_spec_assert(false);

		// Each memcache page that is donated must be swapped from shared to owned in pKVM's tables,
		// removed from the host's shared mappings, and marked as owned by the hypervisor in the host's annotations.

		mapping_move(
			&g1->pkvm.pkvm_abstract_pgtable.mapping,
			mapping_plus(
				mapping_minus(g1->pkvm.pkvm_abstract_pgtable.mapping, hyp_page_addr, 1),
				mapping_singleton(GHOST_STAGE1, hyp_page_addr, 1, maplet_target_mapped_attrs(donated_phys, 1, hyp_attrs))
			)
		);

		mapping_move(
			&g1->host.host_abstract_pgtable_shared,
			mapping_minus(g1->host.host_abstract_pgtable_shared, host_page_ipa, 1)
		);

		mapping_move(
			&g1->host.host_abstract_pgtable_annot,
			mapping_plus(
				g1->host.host_abstract_pgtable_annot,
				mapping_singleton(GHOST_STAGE2, host_page_ipa, 1, maplet_target_annot_ext(MAPLET_OWNER_ANNOT_OWNED_HYP))
			)
		);

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
	mapping_move(
		&g1->host.host_abstract_pgtable_annot,
		mapping_plus(g1->host.host_abstract_pgtable_annot,
		             mapping_singleton(GHOST_STAGE2, host_ipa, 1, maplet_target_annot_ext(MAPLET_OWNER_ANNOT_OWNED_GUEST)))
	);

	// Finally, add the mapping to the VM's pagetable.
	bool is_memory = ghost_addr_is_allowed_memory(g0, phys);
	struct maplet_attributes vm_attrs = ghost_default_vm_memory_attributes(is_memory, MAPLET_PAGE_STATE_PRIVATE_OWNED);
	mapping_move(
		&g1_vm->vm_locked.vm_abstract_pgtable.mapping,
		mapping_plus(g0_vm->vm_locked.vm_abstract_pgtable.mapping,
			     mapping_singleton(GHOST_STAGE2, guest_ipa, 1, maplet_target_mapped_attrs(phys, 1, vm_attrs)))
	);

	// success.
	ret = 0;

out:
	ghost_reg_gpr(g1, 1) = ret;
}

void compute_new_abstract_state_handle___pkvm_vcpu_load(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call) {
	pkvm_handle_t vm_handle = ghost_reg_gpr(g0, 1);
	unsigned int vcpu_idx = ghost_reg_gpr(g0, 2);

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
	ghost_vm_clone_into(vm1, vm);

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
	/* NOTE: vcpu_load does not write back to any general purpose register */
	return;
}

void compute_new_abstract_state_handle___pkvm_vcpu_put(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
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
	ghost_vm_clone_into(vm1, vm0);

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
	/* NOTE: vcpu_put does not write back to any general purpose register */
	return;
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

void compute_new_abstract_state_handle___pkvm_init_vm(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call) {
	int ret;
	size_t vm_size, pgd_size, last_ran_size;

	GHOST_SPEC_DECLARE_REG(host_va_t, host_kvm_hva, g0, 1);
	GHOST_SPEC_DECLARE_REG(host_va_t, vm_hva, g0, 2);
	GHOST_SPEC_DECLARE_REG(host_va_t, pgd_hva, g0, 3);
	GHOST_SPEC_DECLARE_REG(host_va_t, last_ran_hva, g0, 4);

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

	// Now setup the VM with the right initial state:
	// an empty mapping with the right pool,
	// and the first nr_vcpus un-initialised unloaded vcpus.
	vm1->vm_locked.present = true;
	vm1->vm_locked.vm_abstract_pgtable.mapping = mapping_empty_();
	// NOTE: we expect the VM's page table to be place at the beginning
	// of the first page of the memory region donated by the host
	// for that purpose
	ghost_pfn_set_init(&vm1->vm_locked.vm_abstract_pgtable.table_pfns, pgd_phys, pgd_phys + pgd_size);
	vm1->vm_table_locked.present = true;
	vm1->vm_table_locked.nr_vcpus = nr_vcpus;
	vm1->vm_table_locked.nr_initialised_vcpus = 0;
	vm1->pkvm_handle = handle;
	for (int i = 0; i < nr_vcpus; i++) {
		vm1->vm_table_locked.vcpus[i] = malloc_or_die(sizeof(struct ghost_vcpu));
		vm1->vm_table_locked.vcpus[i]->vcpu_handle = i;
		vm1->vm_table_locked.vcpus[i]->loaded = false;
		vm1->vm_table_locked.vcpus[i]->initialised = false;
	}

	// in theory this is unsafe, as another thread could've swooped in between
	// the release of all the locks  and this check,
	// and removed the VM.
	//
	// However, the chance of another thread removing this VV, before __pkvm_init_vm has even returned,
	// is so remotely small we don't care.
	vm1->lock = ghost_pointer_to_vm_lock(handle);
	ret = handle;
out:
	ghost_reg_gpr(g1, 1) = ret;
}

/* Locking shape in the implementation:
 * 
 *  (1) [L_host L_hyp  host_donate_hyp(vcpu_hva) U_hyp U_host] 
        [L_vm_table
		(2) [L_host L_hyp  hyp_pin_shared_mem(host_vcpu) U_hyp U_host]
		(3) (optional) [L_host L_hyp  hyp_pin_shared_mem(sve_state) U_hyp U_host]
	U_vm_table]
 */
void compute_new_abstract_state_handle___pkvm_init_vcpu(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call)
{
	int ret = 0;
	int vcpu_idx;
	struct ghost_vcpu *vcpu;

	pkvm_handle_t vm_handle = ghost_reg_gpr(g0, 1);
	host_va_t host_vcpu_hva = ghost_reg_gpr(g0, 2);
	host_va_t vcpu_hva = ghost_reg_gpr(g0, 3);
//	struct kvm_vcpu *host_vcpu_hyp_va = (struct kvm_vcpu *)hyp_va_of_host_va(g0, host_vcpu_hva);

	struct ghost_vm *vm = ghost_vms_get(&g0->vms, vm_handle);
	if (!vm) {
		ret = -ENOENT;
		goto out;
	}

	vcpu_idx = vm->vm_table_locked.nr_initialised_vcpus;
	if (vcpu_idx >= vm->vm_table_locked.nr_vcpus) {
		ret = -EINVAL;
		goto out;
	}
	ghost_spec_assert(vcpu_idx < KVM_MAX_VCPUS);
	vcpu = vm->vm_table_locked.vcpus[vcpu_idx];
	ghost_assert(vcpu);

	copy_abstraction_host(g1, g0);
	copy_abstraction_pkvm(g1, g0);
	copy_abstraction_vms_partial(g1, g0, VMS_VM_TABLE_OWNED);

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
// 	struct ghost_register_state regs;
// };

	// TODO if ret != 0 ==> goto out
	vcpu->vcpu_handle = vcpu_idx;
	vcpu->loaded = false;
	vcpu->initialised = true;
	vm->vm_table_locked.nr_initialised_vcpus++;
out:
	ghost_reg_gpr(g1, 1) = ret;
}



void compute_new_abstract_state_handle_host_hcall(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call, bool *new_state_computed)
{
	GHOST_LOG_CONTEXT_ENTER();
	int smccc_ret = SMCCC_RET_SUCCESS;
	// allow any hcall to fail with ENOMEM, with an otherwise-identity abstract state
	if (call->return_value == -ENOMEM) {
		ghost_reg_gpr(g1, 1) = -ENOMEM;
		return;
	}

	unsigned long id = ghost_reg_gpr(g0, 0) - KVM_HOST_SMCCC_ID(0);
	switch (id) {
	case __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp:
		compute_new_abstract_state_handle___pkvm_host_share_hyp(g1, g0, call);
		*new_state_computed = true;
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp:
		compute_new_abstract_state_handle___pkvm_host_unshare_hyp(g1, g0, call);
		*new_state_computed = true;
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page:
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest:
		compute_new_abstract_state_handle___pkvm_host_map_guest(g1, g0, call);
		*new_state_computed = true;
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load:
		compute_new_abstract_state_handle___pkvm_vcpu_load(g1, g0, call);
		*new_state_computed = true;
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put:
		compute_new_abstract_state_handle___pkvm_vcpu_put(g1, g0, call);
		*new_state_computed = true;
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_init_vm:
		compute_new_abstract_state_handle___pkvm_init_vm(g1, g0, call);
		*new_state_computed = true;
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu:
		compute_new_abstract_state_handle___pkvm_init_vcpu(g1, g0, call);
		*new_state_computed = true;
		break;
		// TODO: and their bodies, and all the other cases
	default:
		smccc_ret = SMCCC_RET_NOT_SUPPORTED;
		break;
	}
	ghost_reg_gpr(g1, 0) = smccc_ret;
	GHOST_LOG_CONTEXT_EXIT();
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
	u64 spsr_el2 = ghost_reg_el2(g0, GHOST_SPSR_EL2);
	u64 esr_el2 = ghost_reg_el2(g0, GHOST_ESR_EL2);

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

	ghost_reg_el1(g1, ESR_EL1) = esr_el1;
	ghost_reg_el1(g1, SPSR_EL1) = spsr_el2;
	ghost_reg_el1(g1, ELR_EL1) = ghost_reg_el2(g0, GHOST_ELR_EL2);
	ghost_reg_el1(g1, FAR_EL1) = ghost_reg_el2(g0, GHOST_FAR_EL2);

	ghost_reg_el2(g1, GHOST_ELR_EL2) =
		ghost_reg_el1(g0, VBAR_EL1) + get_except64_offset(spsr_el2, PSR_MODE_EL1h, except_type_sync);

	spsr_el2 = get_except64_cpsr(spsr_el2, false/*TODO: we hardcode that the cpus do not support MTE */,
				     ghost_reg_el1(g0, SCTLR_EL1), PSR_MODE_EL1h);
	ghost_reg_el2(g1, GHOST_SPSR_EL2) = spsr_el2;
}


// TODO: move this somewhere more sensible
#define HPFAR_FIPA_SHIFT UL(4)

void compute_new_abstract_state_handle_host_mem_abort(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call, bool *new_state_computed)
{
	u64 esr = ghost_reg_el2(g0, GHOST_ESR_EL2);
	u64 hpfar;
	host_ipa_t addr;

	if (!(esr & ESR_ELx_S1PTW) && (esr & ESR_ELx_FSC_TYPE) == ESR_ELx_FSC_PERM) {
		u64 far = ghost_reg_el2(g0, GHOST_FAR_EL2);
		struct ghost_at_translation *at_status = ghost_at_translations_get(&call->at_translations, far);
		if (at_status->success)
			hpfar = at_status->ipa;
		else
			// this should not be accessible because the pKVM code will have panicked
			// in this situation
			ghost_spec_assert(false);
	} else {
		hpfar = ghost_reg_el2(g0, GHOST_HPFAR_EL2);
	}

	// the bits [51:12] of the faulting IPA are in bits [47:4] of the HPFAR_EL2 register
	// (the mismatch of the upper bites offset is because the upper bits are FIPA are RES0)
	addr = (hpfar >> HPFAR_FIPA_SHIFT) << PAGE_SHIFT;

	// this is the third if in mem_protect.c::host_stage2_adjust_range()
	if (!is_owned_exclusively_by(g0, GHOST_HOST, addr))
		ghost_inject_abort(g1, g0);

	*new_state_computed = true;
	/* TODO: modelling of host_stage2_adjust_range()
		1. ==> non-deterministic -EGAIN (when the pte for addr is valid)
	*/
}

void compute_new_abstract_state_handle_host_trap(struct ghost_state *post, struct ghost_state *pre, struct ghost_call_data *call, bool *new_state_computed)
{
	GHOST_LOG_CONTEXT_ENTER();

	// check *post was clear
	GHOST_LOG(post->pkvm.present, bool);
	GHOST_LOG(post->host.present, bool);
	GHOST_LOG(this_cpu_ghost_register_state(post)->present, bool);
	ghost_assert(!post->pkvm.present && !post->host.present && !this_cpu_ghost_register_state(post)->present);

	// copy over the things that were supposed to be constant, and always present.
	copy_abstraction_constants(post, pre);

	// and all the thread-local state the cpu can always see
	copy_abstraction_local_state(ghost_this_cpu_local_state(post), ghost_this_cpu_local_state(pre));

	switch (ESR_ELx_EC(ghost_reg_el2(pre,GHOST_ESR_EL2))) {
	case ESR_ELx_EC_HVC64:
		compute_new_abstract_state_handle_host_hcall(post,pre,call,new_state_computed);
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
		compute_new_abstract_state_handle_host_mem_abort(post,pre,call,new_state_computed);
		break;
	default:
		ghost_assert(false);
	}
	GHOST_LOG_CONTEXT_EXIT();
}

void compute_new_abstract_state_handle_guest_trap(struct ghost_state *post, struct ghost_state *pre, struct ghost_call_data *call, bool *new_state_computed)
{
	// TODO
}

#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
static void tag_hcall_args(struct kvm_cpu_context *ctxt, u64 hcall_id)
{
	switch (hcall_id) {
	case __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp:
		hyp_putsxnl("pfn", cpu_reg(ctxt, 1), 64);
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp:
		hyp_putsxnl("pfn", cpu_reg(ctxt, 1), 64);
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page:
		hyp_putsxnl("pfn", cpu_reg(ctxt, 1), 64);
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest:
		hyp_putsxnl("pfn", cpu_reg(ctxt, 1), 64);
		hyp_putsxnl("gfn", cpu_reg(ctxt, 2), 64);
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load:
		hyp_putsxnl("vm_handle", cpu_reg(ctxt, 1), 64);
		hyp_putsxnl("vcpu_index", cpu_reg(ctxt, 2), 64);
		hyp_putsxnl("hcr_el2", cpu_reg(ctxt, 3), 64);
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put:
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_init_vm:
		hyp_putsxnl("host_kvm", cpu_reg(ctxt, 1), 64);
		hyp_putsxnl("vm_hva", cpu_reg(ctxt, 2), 64);
		hyp_putsxnl("pgd_hva", cpu_reg(ctxt, 3), 64);
		hyp_putsxnl("last_ran_hva", cpu_reg(ctxt, 4), 64);
		break;

	case __KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu:
		hyp_putsxnl("handle", cpu_reg(ctxt, 1), 64);
		hyp_putsxnl("host_vcpu", cpu_reg(ctxt, 2), 64);
		hyp_putsxnl("vcpu_hva", cpu_reg(ctxt, 3), 64);
		break;

		// TODO: and their bodies, and all the other cases
	default:
		break;
	}
}
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */

static bool this_trap_check_controlled(struct kvm_cpu_context *ctxt)
{
	u64 esr = read_sysreg_el2(SYS_ESR);
	u64 ec = ESR_ELx_EC(esr);
	u64 hcall_id;
	char *name;
	switch (ec) {
	case ESR_ELx_EC_HVC64:
		hcall_id = cpu_reg(ctxt, 0);
		hcall_id -= KVM_HOST_SMCCC_ID(0);
		if (hcall_id <= __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_sync_state)
			name = (char *)ghost_host_hcall_names[hcall_id];
		else
			/* unknown HCALL */
			return false;
		break;
	case ESR_ELx_EC_SMC64:
		name = NULL;
		break;
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		name = NULL;
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		name = "handle_host_mem_abort";
		break;
	default:
		/* unknown or unhandled EC */
		return true;
	}

	if (name == NULL)
		return false;

	return !ghost_control_is_controlled(name) || ghost_control_check_enabled(name);
}

static bool this_trap_print_controlled(struct kvm_cpu_context *ctxt)
{
	struct ghost_running_state *cpu_run_state = this_cpu_ptr(&ghost_cpu_run_state);

	if (cpu_run_state->guest_running)
		return true; // TODO: dispatch trap print control on guest traps.

	u64 esr = read_sysreg_el2(SYS_ESR);
	u64 ec = ESR_ELx_EC(esr);
	u64 hcall_id;
	char *name;
	switch (ec) {
	case ESR_ELx_EC_HVC64:
		hcall_id = cpu_reg(ctxt, 0);
		hcall_id -= KVM_HOST_SMCCC_ID(0);
		if (hcall_id <= __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_sync_state)
			name = (char *)ghost_host_hcall_names[hcall_id];
		else
			/* unknown HCALL */
			return true;
		break;
	case ESR_ELx_EC_SMC64:
		name = NULL;
		break;
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		name = NULL;
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		name = "handle_host_mem_abort";
		break;
	default:
		BUG();
	}

	if (name == NULL)
		return false;

	return ghost_print_on(name);
}

static void tag_guest_exception_entry(struct kvm_cpu_context *ctxt)
{
	ghost_printf(
		GHOST_WHITE_ON_BLUE "guest entry" GHOST_NORMAL "\n"
	);
}

static void tag_host_exception_entry(struct kvm_cpu_context *ctxt)
{
	u64 esr = read_sysreg_el2(SYS_ESR);
	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_HVC64:
		GHOST_INFO("HVC64");
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
		u64 hcall_id;
		char *hcall_name;
		hcall_id = cpu_reg(ctxt, 0);
		hcall_id -= KVM_HOST_SMCCC_ID(0);
		if (hcall_id <= __KVM_HOST_SMCCC_FUNC___pkvm_vcpu_sync_state)
			hcall_name = (char *)ghost_host_hcall_names[hcall_id];
		else
			hcall_name = "<unknown>";

		GHOST_INFO(hcall_name);

		ghost_printf(
			GHOST_WHITE_ON_BLUE "handle_host_hcall %s" GHOST_NORMAL "\n",
			hcall_name
		);

		tag_hcall_args(ctxt, hcall_id);
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
		break;
	case ESR_ELx_EC_SMC64:
		GHOST_INFO("SMC64");
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
		ghost_printf(GHOST_WHITE_ON_BLUE "handle_host_smc" GHOST_NORMAL "\n");
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
		break;
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		GHOST_INFO("SVE");
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
		ghost_printf(GHOST_WHITE_ON_BLUE "fmsimd_host_restore" GHOST_NORMAL "\n");
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		GHOST_INFO("IABT/DABT");
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
		ghost_printf(GHOST_WHITE_ON_BLUE "handle_host_mem_abort" GHOST_NORMAL "\n");
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
		break;
	default:
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
		ghost_printf(GHOST_WHITE_ON_BLUE "<unknown: %ld>" GHOST_NORMAL "\n", ESR_ELx_EC(esr));
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
		break;
	}
}

static void tag_exception_entry(struct kvm_cpu_context *ctxt)
{
	bool print_enabled;
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
	ghost_print_enter();
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */

	// TODO: dispatch on ghost or cpu run state?
	// struct ghost_state *gr_pre = this_cpu_ptr(&gs_recorded_pre);
	// struct ghost_running_state *gr_pre_cpu = this_cpu_ghost_run_state(gr_pre);
	struct ghost_running_state *cpu_run_state = this_cpu_ptr(&ghost_cpu_run_state);

	print_enabled = this_trap_print_controlled(ctxt);
	__this_cpu_write(ghost_print_this_hypercall, print_enabled);
	if (! print_enabled)
		goto print_exit;

#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
	ghost_printf(
		"\n"
		GHOST_WHITE_ON_BLUE "****** TRAP ***************************************************************" GHOST_NORMAL "\n"
	);
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */

	if (cpu_run_state->guest_running)
		tag_guest_exception_entry(ctxt);
	else
		tag_host_exception_entry(ctxt);

	if (! ghost_exec_enabled())
		ghost_printf(GHOST_WHITE_ON_YELLOW "skipping exec check" GHOST_NORMAL "\n");
print_exit:
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
	ghost_print_exit();
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
}


void ghost_record_pre(struct kvm_cpu_context *ctxt)
{
	__this_cpu_write(ghost_check_this_hypercall, READ_ONCE(ghost_prot_finalized_all) && this_trap_check_controlled(ctxt));

	tag_exception_entry(ctxt);

	GHOST_LOG_CONTEXT_ENTER();
	if (! GHOST_EXEC_SPEC)
		goto exit_context;

	if (__this_cpu_read(ghost_check_this_hypercall)) {
		clear_abstraction_thread_local();

		ghost_lock_maplets();
		record_abstraction_constants_pre();
		ghost_unlock_maplets();
		record_and_check_abstraction_local_state_pre(ctxt);

		ghost_clear_call_data();
	}

exit_context:
	GHOST_LOG_CONTEXT_EXIT();
}

void ghost_post(struct kvm_cpu_context *ctxt)
{
	bool new_state_computed = false;

	struct ghost_state *gr_pre = this_cpu_ptr(&gs_recorded_pre);
	struct ghost_running_state *gr_pre_cpu = this_cpu_ghost_run_state(gr_pre);
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

		// compute the new spec abstract state
		// need to dispatch on the saved ghost pre
		// as might have swapped from guest<->host during the implementation of the trap.
		if (gr_pre_cpu->guest_running)
			compute_new_abstract_state_handle_guest_trap(gc_post, gr_pre, call, &new_state_computed);
		else
			compute_new_abstract_state_handle_host_trap(gc_post, gr_pre, call, &new_state_computed);

		// and check the two are equal on relevant components
		if (new_state_computed) {
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
			if (__this_cpu_read(ghost_print_this_hypercall)) {
				ghost_printf(GHOST_WHITE_ON_BLUE "check abstraction" GHOST_NORMAL "\n");
			}
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
#ifdef CONFIG_NVHE_GHOST_SPEC_DUMP_STATE
			if (this_trap_print_controlled(ctxt)) {
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
			}
#endif /* CONFIG_NVHE_GHOST_SPEC_DUMP_STATE */
			check_abstraction_equals_all(gc_post, gr_post, gr_pre);
		} else {
#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
			if (__this_cpu_read(ghost_print_this_hypercall)) {
				ghost_printf(GHOST_WHITE_ON_YELLOW "skipping spec check" GHOST_NORMAL "\n");
			}
#endif /* CONFIG_NVHE_GHOST_SPEC_NOISY */
		}

		ghost_unlock_vms();
		ghost_unlock_maplets();
	}
	GHOST_LOG_CONTEXT_EXIT();
}
