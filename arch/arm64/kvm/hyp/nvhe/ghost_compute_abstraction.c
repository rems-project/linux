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

#ifdef CONFIG_NVHE_GHOST_DIFF
#include <nvhe/ghost_abstraction_diff.h>
#endif /* CONFIG_NVHE_GHOST_DIFF */


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

void clear_abstract_pgtable(abstract_pgtable *ap);

// should these return abstract-state structs or update a ghost_state struct?  We really need the latter, but (looking towards the functional spec) nicer to factor via the former?

mapping compute_abstraction_hyp_memory(void)
{
	mapping m;
	int cur;
	m = mapping_empty_();
	for (cur=0; cur<hyp_memblock_nr; cur++)
		extend_mapping_coalesce(&m, GHOST_STAGE_NONE, hyp_memory[cur].base, hyp_memory[cur].size / PAGE_SIZE, maplet_target_memblock(hyp_memory[cur].flags));
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
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	u64 pool_range_start = (u64)hyp_virt_to_phys(host_s2_pgt_base);
	u64 pool_range_end = pool_range_start + ghost_host_s2_pgt_size * PAGE_SIZE;
	ghost_record_pgtable_ap(&dest->host_concrete_pgtable, &host_mmu.pgt, pool_range_start, pool_range_end, "host_mmu.pgt", i);
	ghost_pfn_set_copy(&dest->host_pgtable_pages, &dest->host_concrete_pgtable.table_pfns);
	dest->host_abstract_pgtable_annot = mapping_annot(dest->host_concrete_pgtable.mapping);
	dest->host_abstract_pgtable_shared = mapping_shared(dest->host_concrete_pgtable.mapping);
	dest->present = true;
}

static void make_abstraction_vms(struct ghost_vms *vms)
{
	ghost_assert(!vms->present);

	// this creates an empty table of vm slots (where all .exists are false)
	for (int vm_index = 0; vm_index < KVM_MAX_PVMS; vm_index++) {
		vms->table[vm_index].exists = false;
	}

	vms->present = true;
	vms->table_data.present = false;
}

static struct ghost_vm_slot *__ghost_vm_or_free_slot_from_handle(struct ghost_vms *vms, pkvm_handle_t handle) {
	ghost_assert_vms_locked();

	if (!vms->present)
		make_abstraction_vms(vms);

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

	/* check for Out-of-Memory */
	if (!slot)
		return NULL;

	if (!slot->exists) {
		slot->vm = malloc_or_die(sizeof(struct ghost_vm));
		slot->exists = true;
		slot->handle = handle;

		/* just in case, make sure the two sides are marked not present */
		slot->vm->vm_locked.present = false;
		slot->vm->vm_table_locked.present = false;

		return slot->vm;
	} else {
		/* shouldn't try alloc() a new ghost vm if one already exists for that handle. */
		ghost_assert(false);
	}
}

static void ghost_vm_clear_slot(struct ghost_vm_slot *slot)
{
	ghost_assert_vms_locked();
	if (slot->exists) {
		// if the slot says it has a vm, then it must have one.
		ghost_assert(slot->vm);

		slot->exists = false;

		/* either side might be present, or both */

		if (slot->vm->vm_locked.present)
			clear_abstract_pgtable(&slot->vm->vm_locked.vm_abstract_pgtable);

		if (slot->vm->vm_table_locked.present) {
			for (int i = 0; i < KVM_MAX_VCPUS; i++) {
				if (slot->vm->vm_table_locked.vcpus[i])
					free(slot->vm->vm_table_locked.vcpus[i]);
			}
		}

		free(slot->vm);
	}
}

void ghost_vms_free(struct ghost_vms *vms, pkvm_handle_t handle)
{
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	ghost_assert(slot);
	ghost_assert(slot->exists);
	ghost_assert(slot->vm);

	ghost_assert(!slot->vm->vm_locked.present);
	ghost_assert(!slot->vm->vm_table_locked.present);
	free(slot->vm);

	slot->exists = false;
}

bool ghost_vms_is_valid_handle(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_locked();
	ghost_assert(vms->present);
	struct ghost_vm *vm = ghost_vms_get(vms, handle);
	return vm != NULL;
}

/// from a vm_table index compute the abstract ghost VM
void compute_abstraction_vm_partial(struct ghost_vm *dest, struct pkvm_hyp_vm *hyp_vm, enum vm_field_owner owner) {
	ghost_assert(hyp_vm);

	dest->protected = hyp_vm->kvm.arch.pkvm.enabled;
	dest->pkvm_handle = hyp_vm->kvm.arch.pkvm.handle;
	dest->lock = &hyp_vm->lock;

	if (owner & VMS_VM_OWNED) {
		/* really do need to hold this lock */
		hyp_assert_lock_held(&hyp_vm->lock);
		dest->vm_locked.present = true;
		ghost_record_pgtable_ap(&dest->vm_locked.vm_abstract_pgtable, &hyp_vm->pgt, hyp_vm->pool.range_start, hyp_vm->pool.range_end, "guest_mmu.pgt", 0);
	}


	if (owner & VMS_VM_TABLE_OWNED) {
		/* can't assert the lock held, as it might be that we're in a loaded vcpu
		 * so don't need the lock at all. */
		dest->vm_table_locked.present = true;
		dest->vm_table_locked.nr_vcpus = hyp_vm->kvm.created_vcpus;
		dest->vm_table_locked.nr_initialised_vcpus = hyp_vm->nr_vcpus;

		/* the pKVM hyp_vm .vcpus field is only defined up to created_vcpus */
		for (int vcpu_idx=0; vcpu_idx < KVM_MAX_PVMS; vcpu_idx++) {
			dest->vm_table_locked.vcpus[vcpu_idx] = NULL;
			if (vcpu_idx < hyp_vm->kvm.created_vcpus) {
				struct pkvm_hyp_vcpu *vcpu = hyp_vm->vcpus[vcpu_idx];
				struct ghost_vcpu *g_vcpu = malloc_or_die(sizeof (struct ghost_vcpu));
				g_vcpu->vcpu_handle = vcpu_idx;
				g_vcpu->initialised = vcpu_idx < hyp_vm->nr_vcpus;
				// vcpu_idx < hyp_vm->nr_vcpus --> vcpu is not NULL
				ghost_spec_assert(!g_vcpu->initialised || vcpu);
				if (vcpu) {
					g_vcpu->loaded = vcpu->loaded_hyp_vcpu ? true : false;
					// TODO: regs
				}
				dest->vm_table_locked.vcpus[vcpu_idx] = g_vcpu;
			}
		}
	}
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

void check_abstraction_equals_reg(struct ghost_register_state *r1, struct ghost_register_state *r2, bool check_sysregs)
{
	GHOST_LOG_CONTEXT_ENTER();
	u64 i;
	u64 ghost_el2_regs[] = (u64[])GHOST_EL2_REGS;
	for (i=0; i<=30; i++) {
		if (GHOST_GPR(r1, i) != GHOST_GPR(r2, i)) {
			GHOST_LOG(i, u64);
			GHOST_LOG(GHOST_GPR(r1, i), u64);
			GHOST_LOG(GHOST_GPR(r2, i), u64);
			GHOST_WARN("gpr register mismatch");
			ghost_spec_assert(false);
		}
	}
	if (check_sysregs) {
		for (i=0; i<NR_SYS_REGS; i++) {
			if (GHOST_SYSREG_EL1(r1, i) != GHOST_SYSREG_EL1(r2, i)) {
				const char *name = GHOST_VCPU_SYSREG_NAMES[i];
				GHOST_LOG(i, u64);
				GHOST_LOG(name, str);
				GHOST_LOG(GHOST_SYSREG_EL1(r1, i), u64);
				GHOST_LOG(GHOST_SYSREG_EL1(r2, i), u64);
				GHOST_WARN("EL1 sysreg register mismatch");
				ghost_spec_assert(false);
			}
		}
		for (i=0; i<sizeof(ghost_el2_regs)/sizeof(u64); i++) {
			u64 r = ghost_el2_regs[i];
			if (GHOST_SYSREG_EL2(r1, r) != GHOST_SYSREG_EL2(r2, r)) {
				const char *name = GHOST_EL2_REG_NAMES[r];
				GHOST_LOG(r, u64);
				GHOST_LOG(name, str);
				GHOST_LOG(GHOST_SYSREG_EL2(r1, r), u64);
				GHOST_LOG(GHOST_SYSREG_EL2(r2, r), u64);
				GHOST_WARN("el2_sysreg register mismatch");
				ghost_spec_assert(false);
			}
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

	GHOST_LOG(loaded_vcpu1->loaded, bool); GHOST_LOG(loaded_vcpu2->loaded, bool);
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

void check_abstraction_equals_run_state(struct ghost_running_state *spec, struct ghost_running_state *recorded)
{
	GHOST_LOG_CONTEXT_ENTER();

	GHOST_SPEC_ASSERT_VAR_EQ(spec->guest_running, recorded->guest_running, bool);

	if (spec->guest_running) {
		GHOST_SPEC_ASSERT_VAR_EQ(spec->vm_handle, recorded->vm_handle, u32);
		GHOST_SPEC_ASSERT_VAR_EQ(spec->vcpu_index, recorded->vcpu_index, u64);
	}

	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_refined_run_state(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_running_state *gc_run = this_cpu_ghost_run_state(gc);
	struct ghost_running_state *gr_post_run = this_cpu_ghost_run_state(gr_post);

	check_abstraction_equals_run_state(gc_run, gr_post_run);

	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_host_regs(struct ghost_host_regs *r1, struct ghost_host_regs *r2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(r1->present == r2->present);
	if (r1->present && r2->present)
		check_abstraction_equals_reg(&r1->regs, &r2->regs, false);
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_local_state(struct ghost_state *g1, struct ghost_state *g2)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_local_state *l1 = ghost_this_cpu_local_state(g1);
	struct ghost_local_state *l2 = ghost_this_cpu_local_state(g2);

	check_abstraction_equals_run_state(&l1->cpu_state, &l2->cpu_state);
	check_abstraction_equals_loaded_vcpu(&l1->loaded_hyp_vcpu, &l2->loaded_hyp_vcpu);
	/* regs not checked */
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_refined_local_state(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_local_state *gc_local = ghost_this_cpu_local_state(gc);
	struct ghost_local_state *gr_pre_local = ghost_this_cpu_local_state(gr_pre);
	struct ghost_local_state *gr_post_local = ghost_this_cpu_local_state(gr_post);


	if (gc_local->loaded_hyp_vcpu.present && gr_post_local->loaded_hyp_vcpu.present) {
		GHOST_INFO("loaded_vcpu1->gc");
		GHOST_INFO("loaded_vcpu2->gr_post");
		check_abstraction_equals_loaded_vcpu(&gc_local->loaded_hyp_vcpu, &gr_post_local->loaded_hyp_vcpu);
	}
	else if (gc_local->loaded_hyp_vcpu.present && !gr_post_local->loaded_hyp_vcpu.present) {
		ghost_assert(false);
	}
	else if (!gc_local->loaded_hyp_vcpu.present && gr_post_local->loaded_hyp_vcpu.present) {
		GHOST_INFO("loaded_vcpu1->gr_post");
		GHOST_INFO("loaded_vcpu2->gr_pre");
		ghost_assert(gr_pre_local->loaded_hyp_vcpu.present);
		check_abstraction_equals_loaded_vcpu(&gr_post_local->loaded_hyp_vcpu, &gr_pre_local->loaded_hyp_vcpu);
	}

	if (gc_local->host_regs.present && gr_post_local->host_regs.present) {
		GHOST_INFO("r1->gc");
		GHOST_INFO("r2->gr_post");
		check_abstraction_equals_host_regs(&gc_local->host_regs, &gr_post_local->host_regs);
	}
	else if (gc_local->host_regs.present && !gr_post_local->host_regs.present) {
		ghost_assert(false);
	}
	else if (!gc_local->host_regs.present && gr_post_local->host_regs.present) {
		GHOST_INFO("r1->gr_post");
		GHOST_INFO("r2->gr_pre");
		ghost_assert(gr_pre_local->host_regs.present);
		check_abstraction_equals_host_regs(&gr_post_local->host_regs, &gr_pre_local->host_regs);
	}
	GHOST_LOG_CONTEXT_EXIT();
}

void check_abstraction_equals_vcpu(struct ghost_vcpu *vcpu1, struct ghost_vcpu *vcpu2)
{
	GHOST_LOG_CONTEXT_ENTER();

	ghost_spec_assert(vcpu1);
	ghost_spec_assert(vcpu2);

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
	// NOTE: we can't have this check on the lock here because some calls
	// of the current function compare the thread-local pre/post states in
	// which case we don't hold the lock.
	//
	// ghost_assert_vm_locked(vm1);

	// if not for the same guest VM, then not equal

	/* these fields are protected by the ghost_vms_lock and duplicated on the VM struct for ease of access */
	GHOST_LOG(vm1->pkvm_handle, u32);
	GHOST_LOG(vm2->pkvm_handle, u32);
	ghost_spec_assert(vm1->pkvm_handle == vm2->pkvm_handle);
	ghost_safety_check(vm1->lock == vm2->lock);

	if (vm1->vm_table_locked.present) {
		if (!vm2->vm_table_locked.present)
			GHOST_SPEC_FAIL("vm2->vm_table_locked missing");

		GHOST_LOG(vm1->vm_table_locked.nr_vcpus, u64);
		GHOST_LOG(vm2->vm_table_locked.nr_vcpus, u64);
		ghost_spec_assert(vm1->vm_table_locked.nr_vcpus == vm2->vm_table_locked.nr_vcpus);


		// GHOST_LOG(vm1->vm_table_locked.nr_initialised_vcpus, u64);
		// GHOST_LOG(vm2->vm_table_locked.nr_initialised_vcpus, u64);
		// ghost_spec_assert(vm1->vm_table_locked.nr_initialised_vcpus == vm2->vm_table_locked.nr_initialised_vcpus);

		for (int i=0; i < vm1->vm_table_locked.nr_vcpus; i++) {
			GHOST_LOG_CONTEXT_ENTER_INNER("loop vcpus");
			GHOST_LOG_INNER("loop vcpus", i, u32);
			check_abstraction_equals_vcpu(vm1->vm_table_locked.vcpus[i], vm2->vm_table_locked.vcpus[i]);
			GHOST_LOG_CONTEXT_EXIT_INNER("loop vcpus");
		}
	}

	if (vm1->vm_locked.present) {
		if (!vm2->vm_locked.present)
			GHOST_SPEC_FAIL("vm2->vm_locked missing");

		check_abstract_pgtable_equal(&vm1->vm_locked.vm_abstract_pgtable, &vm2->vm_locked.vm_abstract_pgtable, "abstraction_equals_vm", "vm1.vm_abstract_pgtable", "vm2.vm_abstract_pgtable", 4);
	}

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

void check_abstraction_vms_subseteq(struct ghost_vms *gc, struct ghost_vms *gr_post)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(gc->present && gr_post->present);

	if (gc->table_data.present) {
		if (!gr_post->table_data.present)
			GHOST_SPEC_FAIL("gr_post->table_data was missing");

		GHOST_LOG(gc->table_data.nr_vms, u64);
		GHOST_LOG(gr_post->table_data.nr_vms, u64);
		ghost_spec_assert(gc->table_data.nr_vms == gr_post->table_data.nr_vms);
	}

	/* it might be that we recorded more of the state than was touched by the spec,
	 * in that case there may be VMs (e.g. whose locks were spuriously taken by the implementation)
	 * which are in the recorded post, but not mentioned by the spec.
	 *
	 * So we need to only check that `VMS(spec) subseteq VMS(recorded)`
	 */
	__check_abstraction_vm_all_contained_in(gc, gr_post);
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
		check_abstraction_vms_subseteq(&gc->vms, &gr_post->vms);
	} else if (gc->vms.present && !gr_post->vms.present) {
		ghost_assert(false);
	} else if (!gc->vms.present && gr_post->vms.present) {
		ghost_assert(gr_pre->vms.present);
		check_abstraction_vms_subseteq(&gr_post->vms, &gr_pre->vms);
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

	check_mapping_equal(gc->globals.hyp_memory, gr_post->globals.hyp_memory);

	GHOST_LOG_CONTEXT_EXIT();
}


// do we want these for an arbitrary g or for the global gs ?


#ifdef CONFIG_NVHE_GHOST_DIFF
/*
 * Print the diff between the recorded pre concrete host pgtable state and recorded post pgtable state
 */
static void ghost_post_dump_recorded_concrete_host_pgtable_diff(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	struct ghost_diff *diff;
	if (! ghost_print_on(__func__))
		return;

	if (gr_pre->host.present && gr_post->host.present) {
		ghost_printf("\n");
		ghost_printf("recorded post host pgtable diff from recorded pre: ");
		ghost_diff_and_print_pgtable(&gr_pre->host.host_concrete_pgtable, &gr_post->host.host_concrete_pgtable);
		ghost_printf("\n");
	}
}

/*
 * Print the diff between the recorded pre ghost state and recorded post ghost state
 */
static void ghost_post_dump_recorded_ghost_diff(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	struct ghost_diff *diff;
	if (! ghost_print_on(__func__))
		return;

	ghost_printf("\n");
	ghost_printf("recorded post ghost state diff from recorded pre: ");
	ghost_diff_and_print_state(gr_pre, gr_post);
	ghost_printf("\n");
}

/*
 * Print the diff between the recorded post and computed (spec) post.
 */
static void ghost_post_dump_computed_ghost_diff(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	struct ghost_diff *diff;
	if (! ghost_print_on(__func__))
		return;

	ghost_printf("\n");
	ghost_printf("computed ghost spec diff from recorded post: ");
	ghost_diff_and_print_state(gr_post, gc);
	ghost_printf("\n");
}

static void post_dump_diff(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	ghost_post_dump_recorded_concrete_host_pgtable_diff(gc, gr_post, gr_pre);
	ghost_post_dump_recorded_ghost_diff(gc, gr_post, gr_pre);
	ghost_post_dump_computed_ghost_diff(gc, gr_post, gr_pre);
}
#endif /* CONFIG_NVHE_GHOST_SPEC_DIFF */

void check_abstraction_equals_all(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();

#ifdef CONFIG_NVHE_GHOST_DIFF
	if (__this_cpu_read(ghost_print_this_hypercall))
		post_dump_diff(gc, gr_post, gr_pre);
#endif /* CONFIG_NVHE_GHOST_DIFF */


	// these things might not be present, in which case we check conditionally
	check_abstraction_refined_pkvm(gc, gr_post, gr_pre);
	check_abstraction_refined_host(gc, gr_post, gr_pre);
	check_abstraction_refined_vms(gc, gr_post, gr_pre);
	check_abstraction_refined_run_state(gc, gr_post, gr_pre);
	check_abstraction_refined_local_state(gc, gr_post, gr_pre);

	// these must always be present and therefore always checked
	check_abstraction_equals_globals(gc, gr_post);

	GHOST_LOG_CONTEXT_EXIT();
}

void init_abstraction(struct ghost_state *g)
{
	g->pkvm.present = false;
	g->host.present = false;
	g->vms.present = false;
	ghost_this_cpu_local_state(g)->present = false;
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
		clear_abstract_pgtable(&g->host.host_concrete_pgtable);
		g->host.present = false;
	}
}

void clear_abstraction_regs(struct ghost_state *g)
{
	this_cpu_ghost_register_state(g)->present = false;
}

static void ghost_vms_partial_vm_try_free_slot(struct ghost_state *g, struct ghost_vm *vm)
{
	ghost_assert(vm);

	/* if the VM struct is merely partial, can't free it yet. */
	if (vm->vm_locked.present || vm->vm_table_locked.present)
		return;

	ghost_vms_free(&g->vms, vm->pkvm_handle);
}

void clear_abstraction_vm_partial(struct ghost_state *g, pkvm_handle_t handle, enum vm_field_owner owner)
{
	ghost_assert_vms_locked();
	struct ghost_vm *vm = ghost_vms_get(&g->vms, handle);

	/* if not there, nothing to do */
	if (!vm)
		return;

	if (owner & VMS_VM_OWNED) {
		if (vm->vm_locked.present)
			clear_abstract_pgtable(&vm->vm_locked.vm_abstract_pgtable);


		vm->vm_locked.present = false;
	}

	if (owner & VMS_VM_TABLE_OWNED)
		vm->vm_table_locked.present = false;

	ghost_vms_partial_vm_try_free_slot(g, vm);
}

void clear_abstraction_vms_partial(struct ghost_state *g, enum vm_field_owner owner)
{
	if (!g->vms.present)
		return;

	for (int i=0; i < KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &g->vms.table[i];
		clear_abstraction_vm_partial(g, slot->handle, owner);
	}
}

void clear_abstraction_vms(struct ghost_state *g)
{
	int i;
	g->vms.present = false;
	g->vms.table_data.present = false;
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
	ghost_this_cpu_local_state(g)->present = false;
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

void copy_abstraction_regs(struct ghost_register_state *g_tgt, struct ghost_register_state *g_src)
{
	ghost_assert(g_tgt->present);
	ghost_assert(g_src->present);
	memcpy(g_tgt, g_src, sizeof(struct ghost_register_state));
}

void copy_abstraction_constants(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	g_tgt->globals.hyp_nr_cpus = g_src->globals.hyp_nr_cpus;
	g_tgt->globals.hyp_physvirt_offset = g_src->globals.hyp_physvirt_offset;
	g_tgt->globals.tag_lsb = g_src->globals.tag_lsb;
	g_tgt->globals.tag_val = g_src->globals.tag_val;
	g_tgt->globals.hyp_memory = mapping_copy(g_src->globals.hyp_memory);
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

	g_tgt->host.host_concrete_pgtable.mapping = mapping_copy(g_src->host.host_concrete_pgtable.mapping);

	g_tgt->host.present = g_src->host.present;
}

void ghost_vm_clone_into_partial(struct ghost_vm *dest, struct ghost_vm *src, enum vm_field_owner owner)
{
	dest->protected = src->protected;
	dest->pkvm_handle = src->pkvm_handle;
	dest->lock = src->lock;

	/* no need to check we actually own any locks
	 * as we're only copying between ghost objects. */

	if (owner & VMS_VM_TABLE_OWNED) {
		dest->vm_table_locked.present = true;
		dest->vm_table_locked.nr_vcpus = src->vm_table_locked.nr_vcpus;
		dest->vm_table_locked.nr_initialised_vcpus = src->vm_table_locked.nr_initialised_vcpus;
		ghost_assert(src->vm_table_locked.nr_vcpus <= KVM_MAX_VCPUS);
		int copied_vcpu = 0;
		for (int vcpu_idx=0; vcpu_idx<KVM_MAX_VCPUS; vcpu_idx++) {
			if (vcpu_idx<src->vm_table_locked.nr_vcpus && src->vm_table_locked.vcpus[vcpu_idx]) {
				copied_vcpu++;
				dest->vm_table_locked.vcpus[vcpu_idx] = malloc_or_die(sizeof(struct ghost_vcpu));
				*dest->vm_table_locked.vcpus[vcpu_idx] = *src->vm_table_locked.vcpus[vcpu_idx];
			} else {
				dest->vm_table_locked.vcpus[vcpu_idx] = NULL;
			}
		}
		ghost_assert(copied_vcpu == dest->vm_table_locked.nr_vcpus);
	}

	if (owner & VMS_VM_OWNED) {
		ghost_assert_maplets_locked();
		dest->vm_locked.present = true;
		abstract_pgtable_copy(&dest->vm_locked.vm_abstract_pgtable, &src->vm_locked.vm_abstract_pgtable);
	}

}

void copy_abstraction_vm_partial(struct ghost_state *g_tgt, struct ghost_state *g_src, pkvm_handle_t handle, enum vm_field_owner owner)
{
	GHOST_LOG_CONTEXT_ENTER();

	/* if the vms table isn't present in the target
	 * which might be if it had been previously cleared
	 * re-create a new one */
	if (!g_tgt->vms.present)
		make_abstraction_vms(&g_tgt->vms);

	struct ghost_vm *src_vm = ghost_vms_get(&g_src->vms, handle);
	ghost_assert(src_vm);

	clear_abstraction_vm_partial(g_tgt, handle, owner);

	struct ghost_vm *tgt_vm = ghost_vms_get(&g_tgt->vms, handle);
	if (!tgt_vm) {
		tgt_vm = ghost_vms_alloc(&g_tgt->vms, handle);
		ghost_assert(tgt_vm);
	}

	ghost_vm_clone_into_partial(tgt_vm, src_vm, owner);
	GHOST_LOG_CONTEXT_EXIT();
}

void copy_abstraction_vms_partial(struct ghost_state *g_tgt, struct ghost_state *g_src, enum vm_field_owner owner)
{
	ghost_assert_vms_locked();
	ghost_assert(g_src->vms.present);

	clear_abstraction_vms_partial(g_tgt, owner);

	// for each VM, copy it.
	for (int i=0; i<KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *src_slot = &g_src->vms.table[i];

		if (src_slot->exists) {
			copy_abstraction_vm_partial(g_tgt, g_src, src_slot->handle, owner);
		}
	}

	if (owner & VMS_VM_TABLE_OWNED)
		g_tgt->vms.table_data = g_src->vms.table_data;
}

void copy_abstraction_vms(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	copy_abstraction_vms_partial(g_tgt, g_src, VMS_VM_TABLE_OWNED | VMS_VM_OWNED);
}

void copy_abstraction_loaded_vcpu(struct ghost_loaded_vcpu *tgt, struct ghost_loaded_vcpu *src)
{
	memcpy(tgt, src, sizeof(*src));
}

void copy_abstraction_local_state(struct ghost_local_state *l_tgt, struct ghost_local_state *l_src)
{
	memcpy(l_tgt, l_src, sizeof(*l_src));
}

void record_abstraction_pkvm(struct ghost_state *g)
{
	ghost_assert(!g->pkvm.present);
	compute_abstraction_pkvm(&g->pkvm);
}

void record_abstraction_vm_partial(struct ghost_state *g, struct pkvm_hyp_vm *hyp_vm, enum vm_field_owner owner)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_vms_locked();

	pkvm_handle_t handle = hyp_vm->kvm.arch.pkvm.handle;

	// if recording the first vm, make an empty dictionary.
	if (!g->vms.present)
		make_abstraction_vms(&g->vms);

	/*
	* It may be that we're taking or releasing a vm_table_lock
	* when a VM lock was already taken
	* so it might already exist
	*/
	struct ghost_vm *vm = ghost_vms_get(&g->vms, handle);
	if (!vm) {
		/* if not: safe to just create one as we hold all the locks */
		vm = ghost_vms_alloc(&g->vms, handle);
		ghost_assert(vm);
	}

	compute_abstraction_vm_partial(vm, hyp_vm, owner);
	GHOST_LOG_CONTEXT_EXIT();
}

void record_abstraction_vms_partial(struct ghost_state *g, enum vm_field_owner owner)
{
	GHOST_LOG_CONTEXT_ENTER();

	/* Make empty table if not already there */
	if (!g->vms.present) {
		make_abstraction_vms(&g->vms);
	}

	if (owner & VMS_VM_TABLE_OWNED) {
		g->vms.table_data.present = true;
		g->vms.table_data.nr_vms = 0;
	}

	for (int idx=0; idx<KVM_MAX_PVMS; idx++) {
		struct pkvm_hyp_vm *hyp_vm = vm_table[idx];
		/* If we only have the table lock, not the entire vm lock
		 * then can't record the pgtable right now,
		 * so only take a partial view of it.
		 */
		if (hyp_vm) {
			record_abstraction_vm_partial(g, hyp_vm, owner);

			if (owner & VMS_VM_TABLE_OWNED)
				g->vms.table_data.nr_vms++;
		}
	}
	GHOST_LOG_CONTEXT_EXIT();
}

void record_abstraction_loaded_vcpu(struct ghost_state *g, struct pkvm_hyp_vcpu *loaded_vcpu)
{
	GHOST_LOG_CONTEXT_ENTER();
	bool loaded = false;
	pkvm_handle_t vm_handle = 0;
	u64 vcpu_index = 0;
	if (loaded_vcpu) {
		// Now we dereference the vcpu struct, even though we're not protected by a lock
		// this is somehow ok?
		vm_handle = loaded_vcpu->vcpu.kvm->arch.pkvm.handle;
		vcpu_index = loaded_vcpu->vcpu.vcpu_idx;
		loaded = true;

		/* The vm_table lock is still protecting us, ensuring the vcpu is only on one core
		 * it's just that we 'forgot' about that on the hypercall
		 * so just re-compute the vm-table-owned data. */
		record_abstraction_vm_partial(g, pkvm_hyp_vcpu_to_hyp_vm(loaded_vcpu), VMS_VM_TABLE_OWNED);
	}

	ghost_assert(ghost_this_cpu_local_state(g)->present);
	ghost_this_cpu_local_state(g)->loaded_hyp_vcpu = (struct ghost_loaded_vcpu){
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


void record_abstraction_vms_and_check_none(struct ghost_state *g)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_vms_locked();
	ghost_assert_pkvm_vm_table_locked();

	// empty the dictionary first;
	// then set it to be present, but empty.
	clear_abstraction_vms(g);
	make_abstraction_vms(&g->vms);

	// make there be a vm_table_data but make it empty.
	g->vms.table_data.present = true;
	g->vms.table_data.nr_vms = 0;

	for (int vm_index = 0; vm_index < KVM_MAX_PVMS; vm_index++) {
		struct pkvm_hyp_vm *hyp_vm = vm_table[vm_index];
		if (hyp_vm) {
			// should be that there were no vms at this point.
			ghost_assert(false);
		}
	}

	GHOST_LOG_CONTEXT_EXIT();
}

void record_abstraction_regs(struct ghost_register_state *gr, struct kvm_cpu_context *ctxt)
{
	int i;
	gr->present = true;

	// copy GPR values from the ctxt saved by the exception vector
	for (i=0; i<=30; i++) {
		GHOST_GPR(gr, i) = ctxt->regs.regs[i];
	}

	// save EL2 registers
	ghost_get_sysregs(gr->el2_sysregs);

	// save EL1 registers comprising pKVM's view of the context
	__sysreg_save_state_nvhe(&gr->ctxt);
}

void ghost_cpu_running_state_copy(struct ghost_running_state *run_tgt, struct ghost_running_state *g_src)
{
	run_tgt->guest_running = g_src->guest_running;
	run_tgt->vm_handle = g_src->vm_handle;
	run_tgt->vcpu_index = g_src->vcpu_index;
}

DECLARE_PER_CPU(struct pkvm_hyp_vcpu *, loaded_hyp_vcpu);
void record_abstraction_local_state(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	struct ghost_local_state *local = ghost_this_cpu_local_state(g);
	struct ghost_running_state *cpu_run_state = this_cpu_ptr(&ghost_cpu_run_state);

	if (ctxt)
		record_abstraction_regs(&local->regs, ctxt);

	ghost_cpu_running_state_copy(&local->cpu_state, cpu_run_state);

	local->host_regs.present = true;
	record_abstraction_regs(&local->host_regs.regs, &this_cpu_ptr(&kvm_host_data)->host_ctxt);

	local->present = true;

	/* no loaded_vcpu state, as that is read separately */
	struct pkvm_hyp_vcpu *loaded_vcpu = *this_cpu_ptr(&loaded_hyp_vcpu);
	record_abstraction_loaded_vcpu(g, loaded_vcpu);
}

void record_and_check_abstraction_local_state_pre(struct kvm_cpu_context *ctxt)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	GHOST_LOG_CONTEXT_ENTER();
	record_abstraction_local_state(g, ctxt);

	if (ghost_checked_last_call() && this_cpu_ghost_register_state(&gs)->present) {
		GHOST_TRACE("g1->gr_pre");
		GHOST_TRACE("g2->gs");
		check_abstraction_equals_local_state(g, &gs);
	}
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_copy_abstraction_local_state_post(struct kvm_cpu_context *ctxt)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_local_state(g, ctxt);
	copy_abstraction_local_state(ghost_this_cpu_local_state(&gs), ghost_this_cpu_local_state(g));
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
	g->globals.hyp_memory = compute_abstraction_hyp_memory();
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
	record_abstraction_pkvm(g);
	record_abstraction_host(g);
	record_abstraction_vms_and_check_none(g);
	/* dont record local state right at start,
	 * as the registers and other CPU local state aren't valid until
	 * the start of the first real hypercall after __pkvm_prot_finalize */
	// record_abstraction_local_state(g, ctxt);
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

		if (ghost_checked_last_call()) {
			check_abstraction_equals_pkvm(&g->pkvm, &gs.pkvm);
		}
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
		if (ghost_checked_last_call()) {
			check_abstraction_equals_host(&g->host, &gs.host);
		}
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
	ghost_spec_assert(!loaded_vcpu);
	this_cpu_ghost_loaded_vcpu(&gs)->present = true;
	this_cpu_ghost_loaded_vcpu(&gs)->loaded = false;
}

void record_and_check_abstraction_vms_pre(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	ghost_lock_vms();
	record_abstraction_vms_partial(g, VMS_VM_TABLE_OWNED);
	if (ghost_checked_last_call()) {
		check_abstraction_vms_subseteq(&g->vms, &gs.vms);
	}
	ghost_unlock_vms();
	GHOST_LOG_CONTEXT_EXIT();
}

void record_and_copy_abstraction_vms_post(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	ghost_lock_vms();
	record_abstraction_vms_partial(g, VMS_VM_TABLE_OWNED);
	copy_abstraction_vms_partial(&gs, g, VMS_VM_TABLE_OWNED);
	ghost_unlock_vms();
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
		record_abstraction_vm_partial(g, vm, VMS_VM_OWNED);
		if (ghost_checked_last_call()) {
			check_abstraction_vm_in_vms_and_equal(handle, g, &gs.vms);
		}
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
	record_abstraction_vm_partial(g, vm, VMS_VM_OWNED);
	copy_abstraction_vm_partial(&gs, g, vm->kvm.arch.pkvm.handle, VMS_VM_OWNED);
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
struct ghost_local_state *ghost_this_cpu_local_state(struct ghost_state *g)
{
	return &g->cpu_local_state[hyp_smp_processor_id()];
}

struct ghost_loaded_vcpu *this_cpu_ghost_loaded_vcpu(struct ghost_state *g)
{
	return &ghost_this_cpu_local_state(g)->loaded_hyp_vcpu;
}
struct ghost_register_state *this_cpu_ghost_register_state(struct ghost_state *g)
{
	return &ghost_this_cpu_local_state(g)->regs;
}
struct ghost_running_state *this_cpu_ghost_run_state(struct ghost_state *g)
{
	return &ghost_this_cpu_local_state(g)->cpu_state;
}

/*****************************************/
// Dumper

#define GHOST_MISSING_FIELD "<not recorded>"

static void ghost_dump_pkvm(struct ghost_pkvm *pkvm)
{
	ghost_printf("pkvm: ");

	if (!pkvm->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	} else {
		ghost_printf(
			"\n"
			"%I%gI(pgtable)\n",
			2, &pkvm->pkvm_abstract_pgtable, 2
		);
	}
}

static void ghost_dump_host(struct ghost_host *host)
{
	ghost_printf("host: ");

	if (!host->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
		return;
	}

	ghost_printf(
		"\n"
		"  annot:\n"
		"%I%gI(mapping)\n"
		"  shared:\n"
		"%I%gI(mapping)\n"
		"  pfns:\n"
		"%I%g(pfn_set)\n",
		4, &host->host_abstract_pgtable_annot, 4,
		4, &host->host_abstract_pgtable_shared, 4,
		4, &host->host_pgtable_pages
	);
}

static void ghost_dump_vm(struct ghost_vm *vm, u64 i)
{
	if (!vm)
		return;

	ghost_printf("%Ivm %x:\n", i, vm->pkvm_handle);

	ghost_printf("%Ivm_locked: ", i+4);
	if (vm->vm_locked.present) {
		ghost_printf(
			"\n"
			"%I%gI(pgtable)\n",
			i+8,
			&vm->vm_locked.vm_abstract_pgtable, i+8
		);
	} else {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	}

	ghost_printf("%Ivm_table_locked: ", i+4);
	if (!vm->vm_table_locked.present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
		return;
	}

	ghost_printf("\n");
	ghost_printf("%Inr_vcpus:%ld\n", i+8, vm->vm_table_locked.nr_vcpus);
	ghost_printf("%Inr_initialised_vcpus:%ld\n", i+8, vm->vm_table_locked.nr_initialised_vcpus);

	ghost_printf("%Ivcpus:\n", i+8);
	for (int vcpu_indx = 0; vcpu_indx < vm->vm_table_locked.nr_vcpus; vcpu_indx++) {
		struct ghost_vcpu *vcpu = vm->vm_table_locked.vcpus[vcpu_indx];
		ghost_printf("%Ivcpu %ld ", i+12, vcpu_indx);

		if (vcpu->initialised)
			ghost_printf("(initialised)");
		else
			ghost_printf("             ");

		ghost_printf(" ");

		if (vcpu->loaded)
			ghost_printf("(loaded)");
		else
			ghost_printf("        ");

		ghost_printf("\n");
	}
}

static void ghost_dump_vms(struct ghost_vms *vms)
{
	ghost_printf("vms: ");

	if (!vms->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
		return;
	}

	ghost_printf("\n");

	ghost_printf("    vm_table_data: ");
	if (vms->table_data.present) {
		ghost_printf("\n");
		ghost_printf("        nr_vms:%lx\n", vms->table_data.nr_vms);

	} else {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	}

	ghost_printf("    vm_table:\n", vms->table_data.nr_vms);
	for (int i = 0; i < KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &vms->table[i];
		if (slot->exists) {
			ghost_dump_vm(slot->vm, 4+4);
		}
	}
}

static void ghost_dump_globals(struct ghost_constant_globals *globals)
{
	ghost_printf(
		"globals:\n"
		"  hyp_nr_cpus:%lx\n"
		"  hyp_physvirt_offset:%lx\n"
		"  tag_lsb:%lx\n"
		"  tag_val:%lx\n",
		globals->hyp_nr_cpus,
		globals->hyp_physvirt_offset,
		globals->tag_lsb,
		globals->tag_val
	);
	/* TODO: dump hyp memory */
}

static void ghost_dump_regs(struct ghost_register_state *regs, u64 i)
{
	ghost_printf("%Iregs[cpu:%d]:<TODO>\n", i, hyp_smp_processor_id());
}

static void ghost_dump_loaded_vcpu(struct ghost_loaded_vcpu *vcpu, u64 i)
{
	ghost_printf("%Iloaded_vcpu[cpu:%d]: ", i, hyp_smp_processor_id());

	if (!vcpu->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	} else if (!vcpu->loaded) {
		ghost_printf("<unloaded>\n");
	} else {
		ghost_printf("<loaded vm_handle:%x vcpu_index:%ld>\n", vcpu->vm_handle, vcpu->vcpu_index);
	}
}

static void ghost_dump_running_state(struct ghost_running_state *run, u64 i)
{
	ghost_printf("%Irun_state[cpu:%d]: ", i, hyp_smp_processor_id());

	if (!run->guest_running) {
		ghost_printf("<host running>\n");
	} else {
		ghost_printf("<VM running, vm_handle:%x vcpu_index:ld>\n", run->vm_handle, run->vcpu_index);
	}
}

void ghost_dump_host_regs(struct ghost_host_regs *host_regs, u64 i)
{
	ghost_printf("%Ihost regs: ", i);

	if (!host_regs->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	} else {
		ghost_printf("<TODO>\n");
	}
}

void ghost_dump_thread_local(struct ghost_local_state *local)
{
	ghost_printf("locals[%ld]: ", hyp_smp_processor_id());
	if (!local->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	} else {
		ghost_printf("\n");
		ghost_dump_regs(&local->regs, 4);
		ghost_dump_loaded_vcpu(&local->loaded_hyp_vcpu, 4);
		ghost_dump_running_state(&local->cpu_state, 4);
		ghost_dump_host_regs(&local->host_regs, 4);
	}
}

void ghost_dump_state(struct ghost_state *g)
{
	ghost_dump_pkvm(&g->pkvm);
	ghost_dump_host(&g->host);
	ghost_dump_vms(&g->vms);
	ghost_dump_globals(&g->globals);
	ghost_dump_thread_local(ghost_this_cpu_local_state(g));
}