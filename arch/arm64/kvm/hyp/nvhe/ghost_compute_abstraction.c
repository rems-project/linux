// computing the abstraction function from the pKVM concrete state to the abstract state



// these are the non-ghost headers from mem_protect.c - probably we only need some of them
#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>
#include <asm/stage2_pgtable.h>

#include <hyp/adjust_pc.h>
#include <hyp/fault.h>

#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/spinlock.h>
// end of mem_protect.c non-ghost headers


// and the ghost headers from mem_protect.c
#include <hyp/ghost_extra_debug-pl011.h>
#include <nvhe/ghost_pgtable.h>
#include <nvhe/ghost_spec.h>
#include <nvhe/ghost_asm.h>
#include <nvhe/ghost_asm_ids.h>

//horrible hack for ghost code in nvhe/iommu/s2mpu.c
// but in the default build # CONFIG_KVM_S2MPU is not set
// and (looking in the Makefile) it seems that file isn't even linked in
// void __kvm_nvhe_ghost_dump_s2mpus(u64 indent);

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wunused-variable"
// end of mem_protect.c ghost headers


#include <hyp/ghost_alloc.h>

#include <nvhe/ghost_spec.h>
#include <nvhe/ghost_compute_abstraction.h>

/* from nvhe/pkvm.c */
extern struct pkvm_hyp_vm **vm_table;

// for all these, one needs to be in ghost_(un)lock_maplets()
// and, unless we make the memory management more automatic, the context must carefully free any pre-existing mappings

/* abstraction functions should not create whole ghost structs on the stack
 * but, instead, read and write directly to an owned ghost object */

void compute_abstraction_pkvm(struct ghost_pkvm *dest);
void compute_abstraction_host(struct ghost_host *dest);
void compute_abstraction_vm(struct ghost_vm *dest, struct pkvm_hyp_vm *src_vm);
mapping compute_abstraction_hyp_memory(void);

void clear_abstract_pgtable(abstract_pgtable *ap);

// should these return abstract-state structs or update a ghost_state struct?  We really need the latter, but (looking towards the functional spec) nicer to factor via the former?

mapping compute_abstraction_hyp_memory(void)
{
	mapping m;
	int cur;
        m = mapping_empty_();
	for (cur=0; cur<hyp_memblock_nr; cur++)
		extend_mapping_coalesce(&m, hyp_memory[cur].base, hyp_memory[cur].size / PAGE_SIZE, maplet_target_memblock(hyp_memory[cur].flags));
	return m;
}

// should this read from the mapping, or from our ghost record of the mapping requests?  From the mapping, as this is to specify what EL2 Stage 1 translation does - correctness of the initialisation w.r.t. the requests is a different question
// should this be usable only from a freshly initialised state, or from an arbitrary point during pKVM execution?  From an arbitrary point during execution.  (Do we have to remove any annot parts here?  not sure)
// need to hold the pkvm lock
void compute_abstraction_pkvm(struct ghost_pkvm *dest)
{
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	u64 pool_range_start = (u64)hyp_virt_to_phys(hyp_pgt_base);
	u64 pool_range_end = pool_range_start + ghost_hyp_pgt_size * PAGE_SIZE;
	ghost_record_pgtable_ap(&dest->pkvm_abstract_pgtable, &pkvm_pgtable, pool_range_start, pool_range_end, "pkvm_pgtable", i);
	dest->present = true;
}

void compute_abstraction_host(struct ghost_host *dest)
{
	// this is for storing the 'exact' host page table, which is used to compute the subcomponent
	// the actually store in the ghost state.
	// making this static to avoid wasting stack space
	static abstract_pgtable tmp_ap;
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	u64 pool_range_start = (u64)hyp_virt_to_phys(host_s2_pgt_base);
	u64 pool_range_end = pool_range_start + ghost_host_s2_pgt_size * PAGE_SIZE;
	ghost_record_pgtable_ap(&tmp_ap, &host_mmu.pgt, pool_range_start, pool_range_end, "host_mmu.pgt", i);
	ghost_pfn_set_copy(&dest->host_pgtable_pages, &tmp_ap.table_pfns);
	dest->host_abstract_pgtable_annot = mapping_annot(tmp_ap.mapping);
	dest->host_abstract_pgtable_shared = mapping_shared(tmp_ap.mapping);
	dest->present = true;
	free_mapping(tmp_ap.mapping);
}


static struct ghost_vm_slot *__ghost_vm_or_free_slot_from_handle(struct ghost_vms *vms, pkvm_handle_t handle) {
	ghost_assert(vms->present);
	ghost_assert_vms_locked();

	struct ghost_vm_slot *free_slot = NULL;

	for (int i=0; i<KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *this = &vms->table[i];

		if (this->exists && this->handle == handle) {
			// sanity check: the included vm has the same handle as the slot marker
			// they should always match for slots that exist, but are technically owned by separate locks.
			ghost_assert(this->vm->pkvm_handle == this->handle);
			return this;
		} else if (!this->exists) {
			free_slot = this;
		}
	}

	return free_slot;
}

hyp_spinlock_t *ghost_pointer_to_vm_lock(pkvm_handle_t handle)
{
	// TODO: remove this unsafe operation.
	return &vm_table[handle - /*HANDLE_OFFSET*/ 0x1000]->lock;
}

struct ghost_vm *ghost_vms_get(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_locked();
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	if (slot->exists)
		return slot->vm;
	return NULL;
}

struct ghost_vm *ghost_vms_alloc(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_locked();
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	if (!slot->exists) {
		slot->vm = malloc_or_die(sizeof(struct ghost_vm));
		slot->exists = true;
		slot->handle = handle;
		return slot->vm;
	}

	return NULL;
}

static void ghost_vm_clear_slot(struct ghost_vm_slot *slot)
{
	ghost_assert_vms_locked();
	if (slot->exists) {
		slot->exists = false;
		clear_abstract_pgtable(&slot->vm->vm_abstract_pgtable);
		for (int i = 0; i < KVM_MAX_VCPUS; i++) {
			if (slot->vm->vcpus[i])
				free(slot->vm->vcpus[i]);
		}
		free(slot->vm);
	}
}

void ghost_vms_free(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_locked();
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	// can only free something that exists in the table
	ghost_assert(slot);
	ghost_vm_clear_slot(slot);
}

bool ghost_vms_is_valid_handle(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_locked();
	ghost_assert(vms->present);
	struct ghost_vm *vm = ghost_vms_get(vms, handle);
	return vm != NULL;
}

/// from a vm_table index compute the abstract ghost VM
void compute_abstraction_vm(struct ghost_vm *dest, struct pkvm_hyp_vm *vm) {
	int i;
	ghost_assert(vm);
	hyp_assert_lock_held(&vm->lock);
	dest->pkvm_handle = vm->kvm.arch.pkvm.handle;
	dest->nr_vcpus = vm->kvm.created_vcpus;
	dest->nr_initialised_vcpus = vm->nr_vcpus;
	for (i=0; i < KVM_MAX_VCPUS; i++) {
		if (i < vm->nr_vcpus) {
			dest->vcpus[i] = malloc_or_die(sizeof (struct ghost_vcpu));
			dest->vcpus[i]->vcpu_handle = i;
			dest->vcpus[i]->loaded = vm->vcpus[i]->loaded_hyp_vcpu ? true : false;
			dest->vcpus[i]->initialised = false; // TODO
			// TODO: regs
		} else {
			dest->vcpus[i] = NULL;
		}
	}
	ghost_record_pgtable_ap(&dest->vm_abstract_pgtable, &vm->pgt, vm->pool.range_start, vm->pool.range_end, "guest_mmu.pgt", 0);
	dest->lock = &vm->lock;
}

void check_abstract_pgtable_equal(abstract_pgtable *ap1, abstract_pgtable *ap2, char *cmp_name, char* ap1_name, char* ap2_name, u64 indent)
{
	GHOST_LOG_CONTEXT_ENTER();
	GHOST_LOG(cmp_name, str);
	GHOST_LOG(ap1_name, str);
	GHOST_LOG(ap2_name, str);
	ghost_pfn_set_assert_equal(&ap1->table_pfns, &ap2->table_pfns);
	check_mapping_equal(ap1->mapping, ap2->mapping);
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_hyp_memory(struct ghost_state *g1, struct ghost_state *g2)
{
	GHOST_LOG_CONTEXT_ENTER();
	check_mapping_equal(g1->hyp_memory, g2->hyp_memory);
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_reg(struct ghost_state *g1, struct ghost_state *g2)
{
	GHOST_LOG_CONTEXT_ENTER();
	u64 i;
	u64 ghost_el2_regs[] = (u64[])GHOST_EL2_REGS;
	for (i=0; i<=30; i++) {
		if (ghost_reg_gpr(g1,i) != ghost_reg_gpr(g2,i)) {
			GHOST_LOG(i, u64);
			GHOST_LOG(ghost_reg_gpr(g1,i), u64);
			GHOST_LOG(ghost_reg_gpr(g2,i), u64);
			GHOST_WARN("gpr register mismatch");
			ghost_spec_assert(false);
		}
	}
	for (i=0; i<sizeof(ghost_el2_regs)/sizeof(u64); i++) {
		if (ghost_reg_el2(g1,ghost_el2_regs[i]) != ghost_reg_el2(g2,ghost_el2_regs[i])) {
			GHOST_LOG(i, u64);
			GHOST_LOG(ghost_reg_el2(g1,i), u64);
			GHOST_LOG(ghost_reg_el2(g2,i), u64);
			GHOST_WARN("el2_sysreg register mismatch");
			ghost_spec_assert(false);
		}
	}
	// TODO other regs
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_pkvm(struct ghost_pkvm *gp1, struct ghost_pkvm *gp2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(gp1->present && gp2->present);
	check_abstract_pgtable_equal(&gp1->pkvm_abstract_pgtable, &gp2->pkvm_abstract_pgtable, "abstraction_equals_pkvm", "gp1.pkvm_mapping", "gp2.pkvm_mapping", 4);
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_host(struct ghost_host *gh1, struct ghost_host *gh2)
{
	GHOST_LOG_CONTEXT_ENTER();
	GHOST_LOG(gh1->present, bool);
	GHOST_LOG(gh2->present, bool);
	ghost_assert(gh1->present && gh2->present);
	ghost_pfn_set_assert_equal(&gh1->host_pgtable_pages, &gh2->host_pgtable_pages);
	ghost_spec_assert(mapping_equal(gh1->host_abstract_pgtable_annot, gh2->host_abstract_pgtable_annot, "abstraction_equals_host", "gh1.host_mapping_annot", "gh2.host_mapping_annot", 4));
	ghost_spec_assert(mapping_equal(gh1->host_abstract_pgtable_shared, gh2->host_abstract_pgtable_shared, "abstraction_equals_host", "gh1.host_mapping_shared", "gh2.host_mapping_shared", 4));
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_loaded_vcpu(struct ghost_loaded_vcpu *loaded_vcpu1, struct ghost_loaded_vcpu *loaded_vcpu2)
{
	GHOST_LOG_CONTEXT_ENTER();
	GHOST_LOG(loaded_vcpu1->present, bool);
	GHOST_LOG(loaded_vcpu2->present, bool);
	ghost_assert(loaded_vcpu1->present && loaded_vcpu2->present);

	GHOST_LOG(loaded_vcpu1->loaded, bool);
	GHOST_LOG(loaded_vcpu2->loaded, bool);
	ghost_spec_assert(loaded_vcpu1->loaded == loaded_vcpu2->loaded);

	if (loaded_vcpu1->loaded) {
		GHOST_LOG(loaded_vcpu1->vm_handle, u32);
		GHOST_LOG(loaded_vcpu2->vm_handle, u32);
		GHOST_LOG(loaded_vcpu1->vcpu_index, u64);
		GHOST_LOG(loaded_vcpu2->vcpu_index, u64);
		ghost_spec_assert(loaded_vcpu1->vm_handle == loaded_vcpu2->vm_handle);
		ghost_spec_assert(loaded_vcpu1->vcpu_index == loaded_vcpu2->vcpu_index);
	}
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_loaded_vcpus(struct ghost_state *g1, struct ghost_state *g2)
{
	GHOST_LOG_CONTEXT_ENTER();
	for (int i=0; i < g1->globals.hyp_nr_cpus; i++) {
		GHOST_LOG_CONTEXT_ENTER_INNER("loop vcpus");
		GHOST_LOG(i, u32);
		GHOST_LOG(g1->loaded_hyp_vcpu[i].present, bool);
		GHOST_LOG(g2->loaded_hyp_vcpu[i].present, bool);
		if (g1->loaded_hyp_vcpu[i].present && g2->loaded_hyp_vcpu[i].present) {
			check_abstraction_equals_loaded_vcpu(&g1->loaded_hyp_vcpu[i], &g2->loaded_hyp_vcpu[i]);
		} else if (g1->loaded_hyp_vcpu[i].present && !g2->loaded_hyp_vcpu[i].present) {
			ghost_assert(false);
		}
		GHOST_LOG_CONTEXT_EXIT();
	}
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_vcpu(struct ghost_vcpu *vcpu1, struct ghost_vcpu *vcpu2)
{
	GHOST_LOG_CONTEXT_ENTER();

	if (!vcpu1) {
		if (!vcpu2) {
			GHOST_SPEC_FAIL("vcpu2 did not exist.");
		}

		GHOST_LOG_CONTEXT_EXIT();
		return;
	} else if (!vcpu2) {
		if (!vcpu1) {
			GHOST_SPEC_FAIL("vcpu1 did not exist.");
		}

		GHOST_LOG_CONTEXT_EXIT();
		return;
	}

	ghost_assert(vcpu1);
	ghost_assert(vcpu2);

	GHOST_LOG(vcpu1->loaded, bool);
	GHOST_LOG(vcpu2->loaded, bool);
	GHOST_LOG(vcpu1->vcpu_handle, u64);
	GHOST_LOG(vcpu2->vcpu_handle, u64);
	ghost_spec_assert(vcpu1->loaded == vcpu2->loaded);
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_vm(struct ghost_vm *vm1, struct ghost_vm *vm2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_vm_locked(vm1);

	// if not for the same guest VM, then not equal
	// technically the handles are fields on the vm and protected by the vm
	// but if we hold the vm_table lock they can't change out from under us
	// and we don't want to lock vm2 if it's not the same guest as vm1
	GHOST_LOG(vm1->pkvm_handle, u32);
	GHOST_LOG(vm2->pkvm_handle, u32);
	ghost_spec_assert(vm1->pkvm_handle == vm2->pkvm_handle);
	ghost_assert(vm1->lock == vm2->lock);

	GHOST_LOG(vm1->nr_vcpus, u64);
	GHOST_LOG(vm2->nr_vcpus, u64);
	ghost_spec_assert(vm1->nr_vcpus == vm2->nr_vcpus);

	// GHOST_LOG(vm1->nr_initialised_vcpus, u64);
	// GHOST_LOG(vm2->nr_initialised_vcpus, u64);
	// ghost_spec_assert(vm1->nr_initialised_vcpus == vm2->nr_initialised_vcpus);
	
	for (int i=0; i < vm1->nr_vcpus; i++) {
		GHOST_LOG_CONTEXT_ENTER_INNER("loop vcpus");
		GHOST_LOG(i, u32);
		check_abstraction_equals_vcpu(vm1->vcpus[i], vm2->vcpus[i]);
		GHOST_LOG_CONTEXT_EXIT();
	}

	check_abstract_pgtable_equal(&vm1->vm_abstract_pgtable, &vm2->vm_abstract_pgtable, "abstraction_equals_vm", "vm1.vm_abstract_pgtable", "vm2.vm_abstract_pgtable", 4);
	GHOST_LOG_CONTEXT_EXIT();
}

/// Check that `vm` is found in `vms` and that the two ghost vms are equal
void check_abstraction_vm_in_vms_and_equal(pkvm_handle_t vm_handle, struct ghost_state *g, struct ghost_vms *vms) {
	int i;	
	GHOST_LOG_CONTEXT_ENTER();
	GHOST_LOG(vm_handle, u32);

	struct ghost_vm *g_vm = ghost_vms_get(&g->vms, vm_handle);
	struct ghost_vm *found_vm = ghost_vms_get(vms, vm_handle);

	ghost_assert(g_vm != NULL);
	ghost_spec_assert(found_vm);

	check_abstraction_equals_vm(g_vm, found_vm);
	GHOST_LOG_CONTEXT_EXIT();
}

void __check_abstraction_vm_contained_in(struct ghost_vm *vm, struct ghost_vms *vms) {
	struct ghost_vm *vm2 = ghost_vms_get(vms, vm->pkvm_handle);

	if (vm2) {
		check_abstraction_equals_vm(vm, vm2);
	} else {
		ghost_spec_assert(false);
	}
}

void __check_abstraction_vm_all_contained_in(struct ghost_vms *vms1, struct ghost_vms *vms2) {
	int i;
	// just iterate over the whole table of slots
	// and check, for each VM that exists in vms1 whether that vm can be found in vms2
	for (i=0; i<KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &vms1->table[i];
		if (slot->exists) {
			__check_abstraction_vm_contained_in(slot->vm, vms2);
		}
	}
}

void check_abstraction_equals_vms(struct ghost_vms *gc, struct ghost_vms *gr_post)
{
	ghost_assert(gc->present && gr_post->present);
	// the computed and recorded post states should have exactly the same set of touched VMs
	__check_abstraction_vm_all_contained_in(gc, gr_post);
	__check_abstraction_vm_all_contained_in(gr_post, gc);
}

void check_abstraction_equals_run_state(struct ghost_running_state *spec, struct ghost_running_state *recorded)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(spec->present);
	ghost_assert(recorded->present);

	GHOST_SPEC_ASSERT_VAR_EQ(spec->guest_running, recorded->guest_running, bool);

	if (spec->guest_running) {
		GHOST_SPEC_ASSERT_VAR_EQ(spec->vm_handle, recorded->vm_handle, u32);
		GHOST_SPEC_ASSERT_VAR_EQ(spec->vcpu_index, recorded->vcpu_index, u64);
	}
}

void check_abstraction_refined_run_state(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_running_state *gc_run = this_cpu_ghost_run_state(gc);
	struct ghost_running_state *gr_post_run = this_cpu_ghost_run_state(gr_post);
	struct ghost_running_state *gr_pre_run = this_cpu_ghost_run_state(gr_pre);
	GHOST_LOG(gc_run->present, bool);
	GHOST_LOG(gr_post_run->present, bool);


	if (gc_run->present && gr_post_run->present) {
		check_abstraction_equals_run_state(gc_run, gr_post_run);
	} else if (gc_run->present && !gr_post_run->present) {
		GHOST_SPEC_FAIL("recorded post has no cpu_run_state");
	} else if (!gc_run->present && gr_post_run->present) {
		check_abstraction_equals_run_state(gr_post_run, gr_pre_run);
	} else {
		ghost_spec_assert(true);
	}

	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_refined_pkvm(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();

	GHOST_LOG(gc->pkvm.present, bool);
	GHOST_LOG(gr_post->pkvm.present, bool);

	if (gc->pkvm.present && gr_post->pkvm.present) {
		check_abstraction_equals_pkvm(&gc->pkvm, &gr_post->pkvm);
	}
	else if (gc->pkvm.present && !gr_post->pkvm.present) {
		ghost_assert(false);
	}
	else if (!gc->pkvm.present && gr_post->pkvm.present) {
		ghost_assert(gr_pre->pkvm.present);
		check_abstraction_equals_pkvm(&gr_post->pkvm, &gr_pre->pkvm);
	}

	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_refined_host(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();

	GHOST_LOG(gc->host.present, bool);
	GHOST_LOG(gr_post->host.present, bool);

	if (gc->host.present && gr_post->host.present) {
		check_abstraction_equals_host(&gc->host, &gr_post->host);
	}
	else if (gc->host.present && !gr_post->host.present) {
		ghost_assert(false);
	}
	else if (!gc->host.present && gr_post->host.present) {
		ghost_assert(gr_pre->host.present);
		check_abstraction_equals_host(&gr_post->host, &gr_pre->host);
	}

	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_refined_vms(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();

	// TODO: ensure we actually own the locks of any VMs we touched in the hypercall before doing this...
	if (gc->vms.present && gr_post->vms.present) {
		check_abstraction_equals_vms(&gc->vms, &gr_post->vms);
	} else if (gc->vms.present && !gr_post->vms.present) {
		ghost_assert(false);
	} else if (!gc->vms.present && gr_post->vms.present) {
		ghost_assert(gr_pre->vms.present);
		check_abstraction_equals_vms(&gr_post->vms, &gr_pre->vms);
	}

	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_globals(struct ghost_state *gc, struct ghost_state *gr_post)
{
	GHOST_LOG_CONTEXT_ENTER();

	ghost_spec_assert(
		   gc->globals.hyp_nr_cpus == gr_post->globals.hyp_nr_cpus
		&& gc->globals.hyp_physvirt_offset == gr_post->globals.hyp_physvirt_offset
		&& gc->globals.tag_lsb == gr_post->globals.tag_lsb
		&& gc->globals.tag_val == gr_post->globals.tag_val
	);



	GHOST_LOG_CONTEXT_EXIT();
}


// do we want these for an arbitrary g or for the global gs ?


void check_abstraction_equals_all(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();

	// these things might not be present, in which case we check conditionally
	check_abstraction_refined_pkvm(gc, gr_post, gr_pre);
	check_abstraction_refined_host(gc, gr_post, gr_pre);
	check_abstraction_refined_vms(gc, gr_post, gr_pre);
	check_abstraction_refined_run_state(gc, gr_post, gr_pre);

	// these must always be present and therefore always checked
	check_abstraction_equals_hyp_memory(gc, gr_post);
	check_abstraction_equals_reg(gc, gr_post);
	check_abstraction_equals_globals(gc, gr_post);
	check_abstraction_equals_loaded_vcpus(gc, gr_post);

	GHOST_LOG_CONTEXT_EXIT();
}


void init_abstraction(struct ghost_state *g)
{
	g->pkvm.present = false;
	g->host.present = false;
	this_cpu_ghost_register_state(g)->present = false;
	g->vms.present = false;
	for (int cpu=0; cpu<NR_CPUS; cpu++) {
		g->loaded_hyp_vcpu[cpu].present = false;
	}
}

void init_abstraction_common(void)
{
	init_abstraction(&gs);
}

void init_abstraction_thread_local(void)
{
	init_abstraction(this_cpu_ptr(&gs_recorded_pre));
	init_abstraction(this_cpu_ptr(&gs_recorded_post));
	init_abstraction(this_cpu_ptr(&gs_computed_post));
}

void clear_abstract_pgtable(abstract_pgtable *ap)
{
	free_mapping(ap->mapping);
	ghost_pfn_set_clear(&ap->table_pfns);
}

void clear_abstraction_pkvm(struct ghost_state *g)
{
	if (g->pkvm.present) {
		clear_abstract_pgtable(&g->pkvm.pkvm_abstract_pgtable);
		g->pkvm.present = false;
	}
}

void clear_abstraction_host(struct ghost_state *g)
{
	if (g->host.present) {
		ghost_pfn_set_clear(&g->host.host_pgtable_pages);
		free_mapping(g->host.host_abstract_pgtable_annot);
		free_mapping(g->host.host_abstract_pgtable_shared);
		g->host.present = false;
	}
}

void clear_abstraction_regs(struct ghost_state *g)
{
	this_cpu_ghost_register_state(g)->present = false;
}

void clear_abstraction_vm(struct ghost_state *g, pkvm_handle_t handle)
{
	ghost_vms_free(&g->vms, handle);
}

void clear_abstraction_vms(struct ghost_state *g)
{
	int i;
	g->vms.present = false;
	for (i=0; i<KVM_MAX_PVMS; i++) {
		ghost_vm_clear_slot(&g->vms.table[i]);
	}
}

void clear_abstraction_all(struct ghost_state *g)
{
	clear_abstraction_pkvm(g);
	clear_abstraction_host(g);
	clear_abstraction_regs(g);
	clear_abstraction_vms(g);
	for (int i=0; i<NR_CPUS; i++) {
		g->loaded_hyp_vcpu[i].present = false;
	}
}

void clear_abstraction_thread_local(void)
{
	ghost_lock_maplets();
	ghost_lock_vms();
	clear_abstraction_all(this_cpu_ptr(&gs_recorded_pre));
	clear_abstraction_all(this_cpu_ptr(&gs_recorded_post));
	clear_abstraction_all(this_cpu_ptr(&gs_computed_post));
	ghost_unlock_vms();
	ghost_unlock_maplets();
}

void copy_abstraction_regs(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert(this_cpu_ghost_register_state(g_src)->present);
	ghost_assert(!this_cpu_ghost_register_state(g_tgt)->present);
	memcpy((void*) &(g_tgt->regs), (void*) &(g_src->regs), sizeof(struct ghost_register_state));
}

void copy_abstraction_constants(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	g_tgt->globals.hyp_nr_cpus = g_src->globals.hyp_nr_cpus;
	g_tgt->globals.hyp_physvirt_offset = g_src->globals.hyp_physvirt_offset;
	g_tgt->globals.tag_lsb = g_src->globals.tag_lsb;
	g_tgt->globals.tag_val = g_src->globals.tag_val;
}

void copy_abstraction_hyp_memory(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	g_tgt->hyp_memory = mapping_copy(g_src->hyp_memory);
}

void copy_abstraction_pkvm(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert_maplets_locked();
	ghost_assert(g_src->pkvm.present);
	clear_abstraction_pkvm(g_tgt);

	abstract_pgtable_copy(&g_tgt->pkvm.pkvm_abstract_pgtable, &g_src->pkvm.pkvm_abstract_pgtable);

	g_tgt->pkvm.present = g_src->pkvm.present;
}

void copy_abstraction_host(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert_maplets_locked();
	ghost_assert(g_src->host.present);
	clear_abstraction_host(g_tgt);

	g_tgt->host.host_abstract_pgtable_annot = mapping_copy(g_src->host.host_abstract_pgtable_annot);
	g_tgt->host.host_abstract_pgtable_shared = mapping_copy(g_src->host.host_abstract_pgtable_shared);
	ghost_pfn_set_copy(&g_tgt->host.host_pgtable_pages, &g_src->host.host_pgtable_pages);

	g_tgt->host.present = g_src->host.present;
}

void copy_abstraction_vms(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert_maplets_locked();
	ghost_assert(g_src->vms.present);

	clear_abstraction_vms(g_tgt);

	// since we just cleared the whole table in tgt, can just copy the src one over.
	for (int i=0; i<KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *src_slot = &g_src->vms.table[i];
		struct ghost_vm_slot *tgt_slot = &g_tgt->vms.table[i];
		bool exists = src_slot->exists;
		tgt_slot->exists = src_slot->exists;
		if (exists) {
			ghost_vm_clone_into(tgt_slot->vm, src_slot->vm);
		}
	}
}

void ghost_vm_clone_into_nomappings(struct ghost_vm *dest, struct ghost_vm *src)
{
	ghost_assert_vm_locked(src);

	dest->nr_vcpus = src->nr_vcpus;
	dest->nr_initialised_vcpus = src->nr_initialised_vcpus;
	ghost_assert(src->nr_vcpus <= KVM_MAX_VCPUS);
	for (int vcpu_idx=0; vcpu_idx<src->nr_vcpus; vcpu_idx++) {
		dest->vcpus[vcpu_idx] = src->vcpus[vcpu_idx];
	}
	dest->pkvm_handle = src->pkvm_handle;
	dest->lock = src->lock;
}

void ghost_vm_clone_into(struct ghost_vm *dest, struct ghost_vm *src)
{
	ghost_vm_clone_into_nomappings(dest, src);
	abstract_pgtable_copy(&dest->vm_abstract_pgtable, &src->vm_abstract_pgtable);
}

void copy_abstraction_vm(struct ghost_state *g_tgt, struct ghost_state *g_src, pkvm_handle_t handle)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_maplets_locked();

	struct ghost_vm *src_vm = ghost_vms_get(&g_src->vms, handle);
	ghost_assert(src_vm);

	ghost_assert_vm_locked(src_vm);

	clear_abstraction_vm(g_tgt, handle);
	struct ghost_vm *tgt_vm = ghost_vms_alloc(&g_tgt->vms, handle);
	ghost_assert(tgt_vm);

	ghost_vm_clone_into(tgt_vm, src_vm);
	GHOST_LOG_CONTEXT_EXIT();
}

void copy_abstraction_loaded_vcpus(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	for (int i=0; i < g_src->globals.hyp_nr_cpus; i++) {
		if (g_src->loaded_hyp_vcpu[i].present) {
			g_tgt->loaded_hyp_vcpu[i] = g_src->loaded_hyp_vcpu[i];
		}
	}
}

void record_abstraction_hyp_memory(struct ghost_state *g)
{
	g->hyp_memory = compute_abstraction_hyp_memory();
}

void record_abstraction_pkvm(struct ghost_state *g)
{
	ghost_assert(!g->pkvm.present);
	compute_abstraction_pkvm(&g->pkvm);
}

void record_abstraction_loaded_vcpu(struct ghost_state *g)
{
	GHOST_LOG_CONTEXT_ENTER();
	bool loaded = false;
	pkvm_handle_t vm_handle = 0;
	u64 vcpu_index = 0;
	struct pkvm_hyp_vcpu *loaded_vcpu = pkvm_get_loaded_hyp_vcpu();
	if (loaded_vcpu) {
		// Now we dereference the vcpu struct, even though we're not protected by a lock
		// this is somehow ok?
		vm_handle = loaded_vcpu->vcpu.kvm->arch.pkvm.handle;
		vcpu_index = loaded_vcpu->vcpu.vcpu_idx;
		loaded = true;
	}
	*this_cpu_ghost_loaded_vcpu(g) = (struct ghost_loaded_vcpu){
		.present = true,
		.loaded = loaded,
		.vm_handle = vm_handle,
		.vcpu_index = vcpu_index,
	};
	GHOST_LOG_CONTEXT_EXIT();
}

void record_abstraction_host(struct ghost_state *g)
{
	ghost_assert(!g->host.present);
	compute_abstraction_host(&g->host);
}

void record_abstraction_vm(struct ghost_state *g, struct pkvm_hyp_vm *vm)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_vms_locked();

	// if recording the first vm, make an empty dictionary.
	if (!g->vms.present) {
		// this creates an empty table of vm slots (where all .exists are false)
		for (int vm_index = 0; vm_index < KVM_MAX_PVMS; vm_index++) {
			g->vms.table[vm_index].exists = false;
		}
		g->vms.present = true;
	}

	// we really should only call record_abstraction_vm to record a vm that actually exists
	// and that we own
	ghost_assert(vm);
	hyp_assert_lock_held(&vm->lock);

	pkvm_handle_t handle = vm->kvm.arch.pkvm.handle;
	struct ghost_vm *slot = ghost_vms_get(&g->vms, handle);

	// get, and if it doesn't exist, create one
	if (!slot) {
		slot = ghost_vms_alloc(&g->vms, handle);
	}

	// if pKVM has space for a VM, the infrastructure should too.
	ghost_assert(slot);

	// write the vm directly into the slot
	compute_abstraction_vm(slot, vm);
	GHOST_LOG_CONTEXT_EXIT();
}

void record_abstraction_vms_and_check_none(struct ghost_state *g)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_vms_locked();
	ghost_assert_pkvm_vm_table_locked();

	// empty the dictionary first;
	clear_abstraction_vms(g);

	// set it to be present, but empty.
	g->vms.present = true;

	for (int vm_index = 0; vm_index < KVM_MAX_PVMS; vm_index++) {
		struct pkvm_hyp_vm *hyp_vm = vm_table[vm_index];
		if (hyp_vm) {
			// should be that there were no vms at this point.
			ghost_assert(false);
		}
	}
	GHOST_LOG_CONTEXT_EXIT();
}

void record_abstraction_regs(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	int i;
	this_cpu_ghost_register_state(g)->present = true;

	// copy GPR values from the ctxt saved by the exception vector
	for (i=0; i<=30; i++) {
		this_cpu_ghost_register_state(g)->ctxt.regs.regs[i] = ctxt->regs.regs[i];
	}
	// save EL2 registers
	ghost_get_sysregs(this_cpu_ghost_register_state(g)->el2_sysregs);
	// save EL1 registers comprising pKVM's view of the context
	// __sysreg_save_state_nvhe(ctxt);
}

void record_abstraction_hyp_memory_pre(void)
{
		ghost_lock_maplets();
		record_abstraction_hyp_memory(this_cpu_ptr(&gs_recorded_pre));
		ghost_unlock_maplets();
}

void record_abstraction_regs_pre(struct kvm_cpu_context *ctxt)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_regs(g, ctxt);
}

void record_abstraction_regs_post(struct kvm_cpu_context *ctxt)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_regs(g, ctxt);
}


void ghost_cpu_running_state_copy(struct ghost_running_state *run_tgt, struct ghost_running_state *g_src)
{
	run_tgt->present = g_src->present;
	run_tgt->guest_running = g_src->guest_running;
	run_tgt->vm_handle = g_src->vm_handle;
	run_tgt->vcpu_index = g_src->vcpu_index;
}


/**
 * these are here to make __kvm_nvhe_ versions of them that are accessible in both the nvhe and non-nvhe code
 * as they were static in va_layout.c but now we need to access them in the ghost spec.
 *
 * TODO: Ben will move these (or fix it or something)
 */
u8 tag_lsb;
u64 tag_val;

/* defined in setup.c */
extern unsigned long hyp_nr_cpus;

void record_abstraction_constants(struct ghost_state *g)
{
	g->globals.hyp_nr_cpus = hyp_nr_cpus;
	g->globals.hyp_physvirt_offset = hyp_physvirt_offset;
	g->globals.tag_lsb = tag_lsb;
	g->globals.tag_val = tag_val;
}

void record_abstraction_constants_pre(void)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_constants(g);
}

void record_abstraction_constants_post(void)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_constants(g);
}


void record_abstraction_all(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	GHOST_LOG_CONTEXT_ENTER();
	record_abstraction_hyp_memory(g);
	record_abstraction_pkvm(g);
	record_abstraction_host(g);
	record_abstraction_vms_and_check_none(g);
	if (ctxt) {
		record_abstraction_regs(g,ctxt);
	}
	record_abstraction_constants(g);
	GHOST_LOG_CONTEXT_EXIT();
}

void record_abstraction_common(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_lock_pkvm_vm_table();
	ghost_lock_maplets();
	ghost_lock_vms();
	record_abstraction_all(&gs, NULL);
	ghost_unlock_vms();
	ghost_unlock_maplets();
	ghost_unlock_pkvm_vm_table();
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_check_abstraction_pkvm_pre(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	// For pKVM and Host we believe there is no single synchronisation point during a hypercall
	// because the hypercalls may take and release the locks on these multiple times.
	//
	// For now we just record the pre for the very first lock, and assume no interference.
	// ... but later on we'll have to do some this-thread-diff/trajectory tracking instead
	if (!g->pkvm.present) {
		record_abstraction_pkvm(g);
		check_abstraction_equals_pkvm(&g->pkvm, &gs.pkvm);
	}
	ghost_unlock_maplets();
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_copy_abstraction_pkvm_post(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	// TODO: for pKVM and Host we believe there is no single synchronisation point
	// (see comment in record_and_check_abstraction_pkvm_pre)
	// so on the post we must clear if there was a previous recorded post
	if (g->pkvm.present)
		clear_abstraction_pkvm(g);
	record_abstraction_pkvm(g);
	copy_abstraction_pkvm(&gs, g);
	ghost_unlock_maplets();
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_check_abstraction_host_pre(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	// TODO: see comment in record_and_check_abstraction_pkvm_pre
	if (!g->host.present) {
		record_abstraction_host(g);
		check_abstraction_equals_host(&g->host, &gs.host);
	}
	ghost_unlock_maplets();
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_copy_abstraction_host_post(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	// TODO: for pKVM and Host we believe there is no single synchronisation point
	// (see comment in record_and_check_abstraction_pkvm_pre)
	// so on the post we must clear if there was a previous recorded post
	if (g->host.present)
		clear_abstraction_host(g);
	record_abstraction_host(g);
	copy_abstraction_host(&gs, g);
	ghost_unlock_maplets();
	GHOST_LOG_CONTEXT_EXIT();
}

void record_abstraction_loaded_vcpu_and_check_none(void)
{
	struct pkvm_hyp_vcpu *loaded_vcpu = pkvm_get_loaded_hyp_vcpu();
	// this cpu should have a loaded vcpu yet
	ghost_assert(!loaded_vcpu);
	this_cpu_ghost_loaded_vcpu(&gs)->present = true;
	this_cpu_ghost_loaded_vcpu(&gs)->loaded = false;
}

void record_and_check_abstraction_loaded_hyp_vcpu_pre(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_loaded_vcpu(g);
	check_abstraction_equals_loaded_vcpus(g, &gs);
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_copy_abstraction_loaded_hyp_vcpu_post(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_loaded_vcpu(g);
	copy_abstraction_loaded_vcpus(&gs, g);
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_check_abstraction_vm_pre(struct pkvm_hyp_vm *vm)
{
	GHOST_LOG_CONTEXT_ENTER();
	// TODO: (and for the others) maplets are already locked by the top-level hcall
	// but this isn't right (e.g. for vpu_run), and it should be at least this
	// (if not more!) fine-grained locking for maplets and the vms.vms table.
	ghost_lock_maplets();
	ghost_lock_vms();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	pkvm_handle_t handle = vm->kvm.arch.pkvm.handle;

	// Edge case: it might be that this is actually the very first time we take the vm lock
	// just after creating the vm, therefore it wont exist in gs.vms yet!
	// so only do the check if it was really there before we started.
	// NOTE: this is ok, because at the unlock we will put this vm in there,
	// so on future locks we will do the check.
	if (ghost_vms_is_valid_handle(&gs.vms, handle)) {
		record_abstraction_vm(g, vm);
		check_abstraction_vm_in_vms_and_equal(handle, g, &gs.vms);
	}

	ghost_unlock_vms();
	ghost_unlock_maplets();
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_copy_abstraction_vm_post(struct pkvm_hyp_vm *vm)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_lock_maplets();
	ghost_lock_vms();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_vm(g, vm);
	copy_abstraction_vm(&gs, g, vm->kvm.arch.pkvm.handle);
	ghost_unlock_vms();
	ghost_unlock_maplets();
	GHOST_LOG_CONTEXT_EXIT();
}


/****************************************/
// locking

DEFINE_HYP_SPINLOCK(ghost_vms_hyp_lock);

void ghost_lock_vms(void)
{
	hyp_spin_lock(&ghost_vms_hyp_lock);
}

void ghost_unlock_vms(void)
{
	hyp_spin_unlock(&ghost_vms_hyp_lock);
}


void ghost_lock_pkvm_vm_table(void)
{
	hyp_spin_lock(&vm_table_lock);
}

void ghost_unlock_pkvm_vm_table(void)
{
	hyp_spin_unlock(&vm_table_lock);
}

/****************************************/
// ghost_call_data helpers

void ghost_relaxed_reads_insert(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width, u64 value)
{
	// quick sanity check: non-overlapping with any that already exist in the list
	for (int i=0; i<rs->len; i++) {
		if ((u64)rs->read_slots[i].phys_addr <= phys_addr && phys_addr <= (u64)rs->read_slots[i].phys_addr + 8*rs->read_slots[i].width)
			ghost_assert(false); // new read inside an existing one
		if (phys_addr <= (u64)rs->read_slots[i].phys_addr && (u64)rs->read_slots[i].phys_addr <= phys_addr + 8*width)
			ghost_assert(false); // existing read inside this one
	}

	ghost_assert(rs->len < GHOST_MAX_RELAXED_READS);
	rs->read_slots[rs->len++] = (struct ghost_read){
		.phys_addr = phys_addr,
		.width = width,
		.value = value,
	};
}

u64 ghost_relaxed_reads_get(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width)
{
	int i;
	for (i=0; i<rs->len; i++) {
		struct ghost_read *r = &rs->read_slots[i];
		if (r->phys_addr == phys_addr && r->width == width)
			return r->value;
	}

	/* If the spec tries to read a relaxed read which wasn't read during the call
	 * then the spec is clearly incorrect. */
	ghost_spec_assert(false);
	unreachable();
}

void ghost_memcache_donations_insert(struct ghost_memcache_donations *ds, u64 pfn) {
	ghost_assert(ds->len < GHOST_MAX_MEMCACHE_DONATIONS);
	ds->pages[ds->len++] = pfn;
}

void ghost_at_translations_insert_fail(struct ghost_at_translations *ts, u64 va)
{
	ghost_assert(ts->len < GHOST_MAX_AT_TRANSLATIONS);
	ts->translations[ts->len++] = (struct ghost_at_translation){
		.va = va,
		.success = false,
	};
}

void ghost_at_translations_insert_success(struct ghost_at_translations *ts, u64 va, u64 ipa)
{
	ghost_assert(ts->len < GHOST_MAX_AT_TRANSLATIONS);
	ts->translations[ts->len++] = (struct ghost_at_translation){
		.va = va,
		.success = true,
		.ipa = ipa,
	};
}

struct ghost_at_translation *ghost_at_translations_get(struct ghost_at_translations *ts, u64 va)
{
	for (int i = 0; i < ts->len; i++) {
		struct ghost_at_translation *t = &ts->translations[i];
		if (t->va == va)
			return t;
	}

	return NULL;
}

/********************************************/
// ghost per-cpu state helpers

struct ghost_loaded_vcpu *this_cpu_ghost_loaded_vcpu(struct ghost_state *g)
{
	return &g->loaded_hyp_vcpu[hyp_smp_processor_id()];
}
struct ghost_register_state *this_cpu_ghost_register_state(struct ghost_state *g)
{
	return &g->regs[hyp_smp_processor_id()];
}
struct ghost_running_state *this_cpu_ghost_run_state(struct ghost_state *g)
{
	return &g->cpu_state[hyp_smp_processor_id()];
}
