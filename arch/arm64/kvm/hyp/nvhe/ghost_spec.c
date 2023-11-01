#include <asm/kvm_mmu.h>
#include <hyp/ghost_extra_debug-pl011.h>
//#include <nvhe/ghost_check_pgtables.h>
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



_Bool pkvm_init_finalized=false;
DEFINE_HYP_SPINLOCK(ghost_prot_finalized_lock);


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
	return hyp_va - g->globals.hyp_physvirt_offset;
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
	if ( !mapping_lookup(phys, g->hyp_memory, &t) ) {
		return false;
	}
	ghost_assert(t.k == MEMBLOCK);
	return true;
}


// adapted from mem_protect.c to use the hyp_memory map
bool ghost_addr_is_allowed_memory(struct ghost_state *g, phys_addr_t phys)
{
	struct maplet_target t;
	if (!mapping_lookup(phys, g->hyp_memory, &t))
		return false;
	ghost_assert(t.k == MEMBLOCK);
	return !(t.u.b.flags & MEMBLOCK_NOMAP);
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
	ghost_assert(t.k == MAPPED);
	return t.u.m.page_state == PKVM_PAGE_SHARED_OWNED;
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
	ghost_assert(t.k == MAPPED);
	return t.u.m.page_state == PKVM_PAGE_SHARED_BORROWED;
}


// horrible hack: copied unchanged from mem_protect.c, just to get in scope
static enum kvm_pgtable_prot ghost_default_host_prot(bool is_memory)
{
	return is_memory ? PKVM_HOST_MEM_PROT : PKVM_HOST_MMIO_PROT;
}




/* adapted from pgtable.c:stage2_set_prot_attr() */
/* TODO: handle device prot */
u64 arch_prot_of_prot(enum kvm_pgtable_prot prot)
{
	u64 attr=0;
	if (!(prot & KVM_PGTABLE_PROT_X))
		attr |= KVM_PTE_LEAF_ATTR_HI_S2_XN;
	if (prot & KVM_PGTABLE_PROT_R)
		attr |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R;
	if (prot & KVM_PGTABLE_PROT_W)
		attr |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W;
	return attr;
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

	u64 host_arch_prot = arch_prot_of_prot(ghost_default_host_prot(ghost_addr_is_memory(g0, phys)));
	u64 hyp_arch_prot = host_arch_prot;

	/* the host annot mapping is unchanged (we have established that host_addr is NOT already in there)
	 * but, there is a new host shared mapping, PKVM_PAGE_SHARED_OWNED */
	mapping_move(
		&g1->host.host_abstract_pgtable_shared,
		mapping_plus(
			g0->host.host_abstract_pgtable_shared,
			mapping_singleton(host_addr, 1, maplet_target_mapped_ext(phys, PKVM_PAGE_SHARED_OWNED, host_arch_prot)))
	);
	
	/* add a new hyp mapping, PKVM_PAGE_SHARED_BORROWED */
	mapping_move(
		&g1->pkvm.pkvm_abstract_pgtable.mapping,
		mapping_plus(
			g0->pkvm.pkvm_abstract_pgtable.mapping,
			mapping_singleton(hyp_addr, 1, maplet_target_mapped_ext(phys, PKVM_PAGE_SHARED_BORROWED, hyp_arch_prot)))
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
	ghost_vm_clone_into(g1_vm, g0_vm);

	for (int d=0; d<call->memcache_donations.len; d++) {
		u64 pfn = call->memcache_donations.pages[d];
		phys_addr_t donated_phys = hyp_pfn_to_phys(pfn);
		host_ipa_t host_page_ipa = host_ipa_of_phys(donated_phys);
		hyp_va_t hyp_page_addr = (u64)ghost__hyp_va(g0, donated_phys);
		u64 hyp_arch_prot = arch_prot_of_prot(ghost_default_host_prot(ghost_addr_is_memory(g0, donated_phys)));

		// TODO: what if location was not shared with pKVM?
		if (!(is_owned_and_shared_by(g0, GHOST_HOST, donated_phys) && is_borrowed_by(g0, GHOST_HYP, donated_phys)))
			ghost_spec_assert(false);

		// Each memcache page that is donated must be swapped from shared to owned in pKVM's tables,
		// removed from the host's shared mappings, and marked as owned by the hypervisor in the host's annotations.

		mapping_move(
			&g1->pkvm.pkvm_abstract_pgtable.mapping,
			mapping_plus(
				mapping_minus(g1->pkvm.pkvm_abstract_pgtable.mapping, hyp_page_addr, 1),
				mapping_singleton(hyp_page_addr, 1, maplet_target_mapped_ext(donated_phys, PKVM_PAGE_OWNED, hyp_arch_prot))
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
				mapping_singleton(host_page_ipa, 1, maplet_target_annot_ext(PKVM_ID_HYP))
			)
		);

		// finally, we mark that this page as one potentially used for a pagetable for this guest.
		ghost_pfn_set_insert(&g1_vm->vm_abstract_pgtable.table_pfns, pfn);
	}

	// TODO: non-protected VM/VCPUs?

	// if this page is not accessible by the host, fail with -EPERM
	if (!is_owned_exclusively_by(g0, GHOST_HOST, phys)) {
		ret = -EPERM;
		goto out;
	}
	// if the addr is already mapped in the guest mapping, fail with -EPERM
	if (mapping_in_domain(guest_ipa, g0_vm->vm_abstract_pgtable.mapping)) {
		ret = -EPERM;
		goto out;
	}

	// TODO: other error cases

	// Mark as owned by a VM as annotation in the host table
	mapping_move(
		&g1->host.host_abstract_pgtable_annot,
		mapping_plus(g1->host.host_abstract_pgtable_annot,
		             mapping_singleton(host_ipa, 1, maplet_target_annot(PKVM_ID_GUEST)))
	);

	// Finally, add the mapping to the VM's pagetable.
	u64 guest_arch_prot = arch_prot_of_prot(ghost_default_host_prot(ghost_addr_is_memory(g0, phys)));
	mapping_move(
		&g1_vm->vm_abstract_pgtable.mapping,
		mapping_plus(g0_vm->vm_abstract_pgtable.mapping,
			     mapping_singleton(guest_ipa, 1, maplet_target_mapped_ext(phys, PKVM_PAGE_OWNED, guest_arch_prot)))
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
	if (vcpu_idx >= vm->nr_vcpus)
		goto out;

	struct ghost_vcpu *vcpu = vm->vcpus[vcpu_idx];
	ghost_assert(vcpu_idx < KVM_MAX_VCPUS);
	ghost_assert(vcpu);

	// if the vcpu is already loaded (potentially in another CPU), then do nothing
	if (vcpu->loaded)
		goto out;

	// record in the ghost state of the vcpu 'vcpu_idx' that is has been loaded
	struct ghost_vm *vm1 = ghost_vms_alloc(&g1->vms, vm->pkvm_handle);
	ghost_vm_clone_into(vm1, vm);
	ghost_assert(vm1->vcpus[vcpu_idx]);
	vm1->vcpus[vcpu_idx]->loaded = true;

	// record in the ghost state that the current CPU has loaded
	// the vcpu 'vcpu_idx' of vm 'vm_idx'
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
	bool loaded;

	struct ghost_loaded_vcpu *loaded_vcpu = this_cpu_ghost_loaded_vcpu(g0);
	ghost_assert(loaded_vcpu->present);

	// have to have done a previous vcpu_load
	if (!loaded_vcpu->loaded) {
		loaded = false;
		goto out;
	}

	pkvm_handle_t vm_handle = loaded_vcpu->vm_handle;
	u64 vcpu_idx = loaded_vcpu->vcpu_index;

	struct ghost_vm *vm0 = ghost_vms_get(&g0->vms, vm_handle);
	struct ghost_vm *vm1 = ghost_vms_alloc(&g1->vms, vm_handle);
	ghost_spec_assert(vm0); // must have existed to have loaded it.
	ghost_assert(vm1);

	ghost_vm_clone_into(vm1, vm0);

	ghost_assert(vm1->vcpus[vcpu_idx]);
	vm1->vcpus[vcpu_idx]->loaded = false;

	loaded = true;

out:
	*this_cpu_ghost_loaded_vcpu(g1) = (struct ghost_loaded_vcpu){
		.present = true,
		.loaded = loaded,
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
			mapping_singleton(host_ipa, nr_pages, maplet_target_annot(PKVM_ID_HYP)))
	);

	u64 host_arch_prot = arch_prot_of_prot(ghost_default_host_prot(ghost_addr_is_memory(g, phys_addr)));
	u64 hyp_arch_prot = host_arch_prot;

	mapping_move(
		&g->pkvm.pkvm_abstract_pgtable.mapping,
		mapping_plus(g->pkvm.pkvm_abstract_pgtable.mapping,
			mapping_singleton(hyp_virt, nr_pages,
				maplet_target_mapped_ext(phys_addr, PKVM_PAGE_OWNED, hyp_arch_prot)))
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
	ghost_assert(READ_ONCE(pkvm_init_finalized));
	
	// if we've already allocated KVM_MAX_PVMS VMs, then fail with -ENOMEM
	struct ghost_vm *vm1 = ghost_vms_alloc(&g1->vms, handle);
	if (!vm1) {
		ret = -ENOMEM;
		goto out;
	}

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

	g1->vms.present = true;

	// NOTE: we expect the VM's page table to be place at the beginning
	// of the first page of the memory region donated by the host
	// for that purpose
	ghost_pfn_set_init(&vm1->vm_abstract_pgtable.table_pfns, pgd_phys, pgd_phys + pgd_size);
	vm1->vm_abstract_pgtable.mapping = mapping_empty_();
	vm1->nr_vcpus = nr_vcpus;
	vm1->nr_initialised_vcpus = 0;
	// NOTE: this sets the .loaded fields of all the elements
	// of the array to false
	memset(vm1->vcpus, 0, sizeof(struct ghost_vcpu[KVM_MAX_VCPUS]));
	vm1->pkvm_handle = handle;
	
	ghost_assert_vms_table_locked();
	vm1->lock = ghost_pointer_to_vm_lock(handle);
	ret = handle;
out:
	ghost_reg_gpr(g1, 1) = ret;
}

void compute_new_abstract_state_handle_host_hcall(struct ghost_state *g1, struct ghost_state *g0, struct ghost_call_data *call, bool *new_state_computed)
{
	int smccc_ret = SMCCC_RET_SUCCESS;
	// allow any hcall to fail with ENOMEM, with an otherwise-identity abstract state
	if (call->return_value == -ENOMEM) {
		ghost_reg_gpr(g1, 1) = -ENOMEM;
		return;
	}

	unsigned long id = ghost_reg_gpr(g0, 0) - KVM_HOST_SMCCC_ID(0);
#pragma GCC diagnostic ignored "-Wunused-label" // not sure why the next lines trigger that
	switch (id) {
	__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp:
		compute_new_abstract_state_handle___pkvm_host_share_hyp(g1, g0, call);
		*new_state_computed = true;
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp:
		compute_new_abstract_state_handle___pkvm_host_unshare_hyp(g1, g0, call);
		*new_state_computed = true;
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page:
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest:
		compute_new_abstract_state_handle___pkvm_host_map_guest(g1, g0, call);
		*new_state_computed = true;
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load:
		compute_new_abstract_state_handle___pkvm_vcpu_load(g1, g0, call);
		*new_state_computed = true;
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put:
		compute_new_abstract_state_handle___pkvm_vcpu_put(g1, g0, call);
		*new_state_computed = true;
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_init_vm:
		compute_new_abstract_state_handle___pkvm_init_vm(g1, g0, call);
		*new_state_computed = true;
		break;

		// TODO: and their bodies, and all the other cases
	default:
		smccc_ret = SMCCC_RET_NOT_SUPPORTED;
		break;
	}
	ghost_reg_gpr(g1, 0) = smccc_ret;
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

	/* TODO: modelling of host_stage2_adjust_range()

		1. ==> non-deterministic -EGAIN (when the pte for addr is valid)

		2. ==> return -EPERM pte == 0, which means:
			* the page stage is PKVM_PAGE_OWNED (by host)

		3. ==> calculation of some range (which is going to be passed to the idmap function)
	*/
}




void compute_new_abstract_state_handle_trap(struct ghost_state *g1 /*new*/, struct ghost_state *g0 /*old*/, struct ghost_call_data *call, bool *new_state_computed)
	// pointer or struct arguments and results?  For more obvious correspondence to math, struct - but that may be too terrible for executability, and distracting for those used to idiomatic C.  Doesn't matter too much.
{

	// assumes *g1 has been cleared
	ghost_assert(!g1->pkvm.present && !g1->host.present && !this_cpu_ghost_register_state(g1)->present);

	// copy the g0 regs to g1; we'll update them to make the final g1
	copy_abstraction_regs(g1, g0);

	// hyp_memory is supposed to be constant, so just copy the old one
	copy_abstraction_hyp_memory(g1, g0);

	// the globals are supposed to be constant, so copy them over
	copy_abstraction_constants(g1, g0);

	switch (ESR_ELx_EC(ghost_reg_el2(g0,GHOST_ESR_EL2))) {
	case ESR_ELx_EC_HVC64:
		compute_new_abstract_state_handle_host_hcall(g1,g0,call,new_state_computed);
		break;
	case ESR_ELx_EC_SMC64:
		//TODO compute_new_abstract_state_handle_host_smc(g1,g0);
		break;
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		//TODO compute_new_abstract_state_fpsimd_host_restore(g1,g0);
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		compute_new_abstract_state_handle_host_mem_abort(g1,g0,call,new_state_computed);
		break;
	default:
		ghost_assert(false);
	}
}

void ghost_handle_trap_epilogue(struct kvm_cpu_context *host_ctxt, bool from_host)
{
	bool new_state_computed=false;

	// record the remaining parts of the new impl abstract state
	// (the pkvm, host, and vm components having been recorded at impl lock points)
	ghost_lock_maplets();
	record_abstraction_hyp_memory(this_cpu_ptr(&gs_recorded_post));
	record_abstraction_regs_post(host_ctxt);
	record_abstraction_constants_post();
	// compute the new spec abstract state
	this_cpu_ptr(&gs_call_data)->return_value = cpu_reg(host_ctxt, 1);
	compute_new_abstract_state_handle_trap(this_cpu_ptr(&gs_computed_post), this_cpu_ptr(&gs_recorded_pre), this_cpu_ptr(&gs_call_data), &new_state_computed);
	// and check the two are equal on relevant components
	if (new_state_computed)
		check_abstraction_equals_all(this_cpu_ptr(&gs_computed_post), this_cpu_ptr(&gs_recorded_post), this_cpu_ptr(&gs_recorded_pre));
	ghost_unlock_maplets();
}