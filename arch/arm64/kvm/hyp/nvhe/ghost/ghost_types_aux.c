#include <hyp/ghost/ghost_alloc.h>
#include <hyp/ghost/ghost_extra_debug-pl011.h>
#include <nvhe/ghost/ghost_misc.h>

#include <nvhe/ghost/ghost_control.h>
#include <nvhe/ghost/ghost_state.h>
#include <nvhe/ghost/ghost_types_aux.h>
#include <nvhe/ghost/ghost_spec.h>

#ifdef CONFIG_NVHE_GHOST_DIFF
#include <nvhe/ghost/ghost_abstraction_diff.h>
#endif /* CONFIG_NVHE_GHOST_DIFF */

#include <nvhe/ghost/ghost_tracing.h>

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

/* from nvhe/pkvm.c */
extern struct pkvm_hyp_vm **vm_table;

hyp_spinlock_t *ghost_pointer_to_vm_lock(pkvm_handle_t handle)
{
	// TODO: remove this unsafe operation.
	return &vm_table[handle - /*HANDLE_OFFSET*/ 0x1000]->lock;
}

/*
 * Constructors and initialisers
 */
// EXPORTED ghost_types_aux.h
void make_abstraction_vms(struct ghost_vms *vms)
{
	ghost_assert(!vms->present);

	// this creates an empty table of vm slots (where all .exists are false)
	for (int vm_index = 0; vm_index < KVM_MAX_PVMS; vm_index++) {
		vms->table[vm_index].exists = false;
	}

	vms->present = true;
	vms->table_data.present = false;
}

static struct ghost_vm_slot *__ghost_vm_or_free_slot_from_handle(struct ghost_vms *vms, pkvm_handle_t handle)
{
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

// EXPORTED ghost_state.h
struct ghost_vm *ghost_vms_get(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_locked();
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	if (slot->exists)
		return slot->vm;
	return NULL;
}

// EXPORTED ghost_types_aux.h
struct ghost_vm *ghost_vms_alloc(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_locked();

	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);

	/* check for Out-of-Memory */
	if (!slot)
		return NULL;

	if (!slot->exists) {
		slot->vm = malloc_or_die(ALLOC_VM, sizeof(struct ghost_vm));
		slot->exists = true;
		slot->handle = handle;

		/* just in case, make sure the two sides are marked not present */
		slot->vm->vm_locked.present = false;
		slot->vm->vm_table_locked.present = false;

		memset(&slot->vm->vm_teardown_data, 0, sizeof(struct ghost_vm_teardown_data));
		return slot->vm;
	} else {
		/* shouldn't try alloc() a new ghost vm if one already exists for that handle. */
		ghost_assert(false);
	}
}

// EXPORTED ghost_state.h
bool ghost_vms_is_valid_handle(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_locked();
	ghost_assert(vms->present);
	struct ghost_vm *vm = ghost_vms_get(vms, handle);
	return vm != NULL;
}


// EXPORTED ghost_types_aux.h
void clear_abstract_pgtable(abstract_pgtable *ap)
{
	free_mapping(ap->mapping);
	ghost_pfn_set_clear(&ap->table_pfns);
}

// EXPORTED ghost_types_aux.h
void clear_abstraction_pkvm(struct ghost_state *g)
{
	if (g->pkvm.present) {
		clear_abstract_pgtable(&g->pkvm.pkvm_abstract_pgtable);
		g->pkvm.present = false;
	}
}

// EXPORTED ghost_types_aux.h
void clear_abstraction_host(struct ghost_state *g)
{
	if (g->host.present) {
		free_mapping(g->host.host_abstract_pgtable_annot);
		free_mapping(g->host.host_abstract_pgtable_shared);
		clear_abstract_pgtable(&g->host.host_concrete_pgtable);
		ghost_pfn_set_clear(&g->host.reclaimable_pfn_set);
		ghost_pfn_set_clear(&g->host.need_poisoning_pfn_set);
		g->host.present = false;
	}
}

// EXPORTED ghost_types_aux.h
void clear_abstraction_regs(struct ghost_state *g)
{
	this_cpu_ghost_registers(g)->present = false;
}

/**
 * ghost_vms_free() - Remove a previously emptied VM from the table
 *
 * @vms: ghost vm table
 * @handle: opaque pkvm-defined handle for the VM to remove
 *
 * Marks any slot (if it exists) for that VM as empty.
 *
 * Must own the ghost vms lock
 */
static void ghost_vms_free(struct ghost_vms *vms, pkvm_handle_t handle)
{
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	ghost_assert(slot);
	ghost_assert(slot->exists);
	ghost_assert(slot->vm);

	ghost_assert(!slot->vm->vm_locked.present);
	ghost_assert(!slot->vm->vm_table_locked.present);
	free(ALLOC_VM, slot->vm);
	slot->vm = NULL;

	slot->exists = false;
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
				if (slot->vm->vm_table_locked.vcpu_refs[i].vcpu) {
					free(ALLOC_VCPU, slot->vm->vm_table_locked.vcpu_refs[i].vcpu);
					slot->vm->vm_table_locked.vcpu_refs[i].vcpu = NULL;
				}
			}
		}

		free(ALLOC_VM, slot->vm);
		slot->vm = NULL;
	}
}

static void ghost_vms_partial_vm_try_free_slot(struct ghost_state *g, struct ghost_vm *vm)
{
	ghost_assert(vm);

	/* if the VM struct is merely partial, can't free it yet. */
	if (vm->vm_locked.present || vm->vm_table_locked.present)
		return;

	ghost_vms_free(&g->vms, vm->pkvm_handle);
}

// EXPORTED ghost_types_aux.h
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

	if (owner & VMS_VM_TABLE_OWNED) {
		vm->vm_table_locked.present = false;
		for (int i = 0; i < KVM_MAX_VCPUS; i++) {
			if (vm->vm_table_locked.vcpu_refs[i].vcpu) {
				free(ALLOC_VCPU, vm->vm_table_locked.vcpu_refs[i].vcpu);
				vm->vm_table_locked.vcpu_refs[i].vcpu = NULL;
			}
		}
	}

	ghost_vms_partial_vm_try_free_slot(g, vm);
}

// EXPORTED ghost_types_aux.h
void clear_abstraction_vms_partial(struct ghost_state *g, enum vm_field_owner owner)
{
	if (!g->vms.present)
		return;

	for (int i=0; i < KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &g->vms.table[i];
		clear_abstraction_vm_partial(g, slot->handle, owner);
	}
}

// EXPORTED ghost_types_aux.h
void clear_abstraction_vms(struct ghost_state *g)
{
	int i;
	g->vms.present = false;
	g->vms.table_data.present = false;
	for (i=0; i<KVM_MAX_PVMS; i++) {
		ghost_vm_clear_slot(&g->vms.table[i]);
	}
}

static void clear_abstraction_constant_globals(struct ghost_state *g)
{
	free_mapping(g->globals.hyp_memory);
	g->globals.hyp_memory = mapping_empty_();
}

// EXPORTED ghost_types_aux.h
void clear_abstraction_this_thread_local_state(struct ghost_state *g)
{
	clear_abstraction_pkvm(g);
	clear_abstraction_host(g);
	clear_abstraction_regs(g);
	clear_abstraction_vms(g);
	clear_abstraction_constant_globals(g);
	ghost_assert(ghost_this_cpu_local_state(g) != NULL);
	ghost_this_cpu_local_state(g)->present = false;
}

// EXPORTED ghost_types_aux.h
void clear_abstraction_this_thread_local_states(void)
{
	ghost_lock_maplets();
	ghost_lock_vms();
	clear_abstraction_this_thread_local_state(this_cpu_ptr(&gs_recorded_pre));
	clear_abstraction_this_thread_local_state(this_cpu_ptr(&gs_recorded_post));
	clear_abstraction_this_thread_local_state(this_cpu_ptr(&gs_computed_post));
	ghost_unlock_vms();
	ghost_unlock_maplets();
}


/*
 * Copying
 */
// EXPORTED ghost_types_aux.h
void copy_abstraction_regs(struct ghost_registers *g_tgt, struct ghost_registers *g_src)
{
	ghost_assert(g_tgt->present);
	ghost_assert(g_src->present);
	memcpy(g_tgt, g_src, sizeof(struct ghost_registers));
}

// EXPORTED ghost_types_aux.h
void copy_abstraction_constants(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	g_tgt->globals.hyp_nr_cpus = g_src->globals.hyp_nr_cpus;
	g_tgt->globals.hyp_physvirt_offset = g_src->globals.hyp_physvirt_offset;
	g_tgt->globals.tag_lsb = g_src->globals.tag_lsb;
	g_tgt->globals.tag_val = g_src->globals.tag_val;
	g_tgt->globals.hyp_memory = mapping_copy(g_src->globals.hyp_memory);
}

// EXPORTED ghost_types_aux.h
void copy_abstraction_host(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert_maplets_locked();
	ghost_assert(g_src->host.present);
	clear_abstraction_host(g_tgt);

	g_tgt->host.host_abstract_pgtable_annot = mapping_copy(g_src->host.host_abstract_pgtable_annot);
	g_tgt->host.host_abstract_pgtable_shared = mapping_copy(g_src->host.host_abstract_pgtable_shared);
	ghost_pfn_set_copy(&g_tgt->host.reclaimable_pfn_set, &g_src->host.reclaimable_pfn_set);
	ghost_pfn_set_copy(&g_tgt->host.need_poisoning_pfn_set, &g_src->host.need_poisoning_pfn_set);
	abstract_pgtable_copy(&g_tgt->host.host_concrete_pgtable, &g_src->host.host_concrete_pgtable);

	g_tgt->host.present = g_src->host.present;
}

// EXPORTED ghost_types_aux.h
void copy_abstraction_pkvm(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert_maplets_locked();
	ghost_assert(g_src->pkvm.present);
	clear_abstraction_pkvm(g_tgt);

	abstract_pgtable_copy(&g_tgt->pkvm.pkvm_abstract_pgtable, &g_src->pkvm.pkvm_abstract_pgtable);

	g_tgt->pkvm.present = g_src->pkvm.present;
}

// EXPORTED ghost_types_aux.h
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

// EXPORTED ghost_types_aux.h
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

// EXPORTED ghost_types_aux.h
void ghost_vcpu_clone_into(struct ghost_vcpu *dest, struct ghost_vcpu *src)
{
	ghost_assert(src);
	ghost_assert(dest);
	dest->vcpu_index = src->vcpu_index;
	dest->regs = src->regs;
	ghost_pfn_set_copy(&dest->recorded_memcache_pfn_set, &src->recorded_memcache_pfn_set);
}

// EXPORTED ghost_types_aux.h
void copy_abstraction_loaded_vcpu_status(struct ghost_loaded_vcpu_status *tgt, struct ghost_loaded_vcpu_status *src)
{
	tgt->loaded = src->loaded;
	tgt->vm_handle = src->vm_handle;
	ghost_vcpu_clone_into(tgt->loaded_vcpu, src->loaded_vcpu);
}

// EXPORTED ghost_types_aux.h
void copy_abstraction_local_state(struct ghost_local_state *l_tgt, struct ghost_local_state *l_src)
{
	ghost_assert(l_src->present);
	l_tgt->present = true;
	memcpy(&l_tgt->regs, &l_src->regs, sizeof(struct ghost_registers));
	copy_abstraction_loaded_vcpu_status(&l_tgt->loaded_vcpu_status, &l_src->loaded_vcpu_status);
	memcpy(&l_tgt->cpu_state, &l_src->cpu_state, sizeof(struct ghost_running_state));
	memcpy(&l_tgt->host_regs, &l_src->host_regs, sizeof(struct ghost_host_regs));
}


// EXPORTED ghost_types_aux.h
void ghost_vm_clone_into_partial(struct ghost_vm *dest, struct ghost_vm *src, enum vm_field_owner owner)
{
	dest->protected = src->protected;
	dest->pkvm_handle = src->pkvm_handle;
	dest->vm_teardown_data.host_mc = src->vm_teardown_data.host_mc;
	dest->vm_teardown_data.hyp_vm_struct_addr = src->vm_teardown_data.hyp_vm_struct_addr;
	dest->vm_teardown_data.last_ran_addr = src->vm_teardown_data.last_ran_addr;
	dest->lock = src->lock;

	/* no need to check we actually own any locks
	 * as we're only copying between ghost objects. */

	if (owner & VMS_VM_TABLE_OWNED) {
		dest->vm_table_locked.present = true;
		dest->vm_table_locked.nr_vcpus = src->vm_table_locked.nr_vcpus;
		dest->vm_table_locked.nr_initialised_vcpus = src->vm_table_locked.nr_initialised_vcpus;
		ghost_assert(src->vm_table_locked.nr_vcpus <= KVM_MAX_VCPUS);
		int copied_vcpu = 0;
		int found_loaded = 0;
		for (int vcpu_idx=0; vcpu_idx<KVM_MAX_VCPUS; vcpu_idx++) {
			struct ghost_vcpu_reference *src_vcpu_ref = &src->vm_table_locked.vcpu_refs[vcpu_idx];
			struct ghost_vcpu_reference *dest_vcpu_ref = &dest->vm_table_locked.vcpu_refs[vcpu_idx];

			dest_vcpu_ref->initialised = src_vcpu_ref->initialised;
			dest_vcpu_ref->loaded_somewhere = src_vcpu_ref->loaded_somewhere;
			if (vcpu_idx<src->vm_table_locked.nr_vcpus) {
				if (src_vcpu_ref->initialised) {
					if (src_vcpu_ref->loaded_somewhere){
						found_loaded++;
						ghost_assert(src_vcpu_ref->vcpu == NULL);
						dest->vm_table_locked.vcpu_refs[vcpu_idx].vcpu = NULL;
					} else {
						copied_vcpu++;
						ghost_assert(src_vcpu_ref->vcpu);
						ghost_assert(dest_vcpu_ref->vcpu == NULL);
						dest_vcpu_ref->vcpu = malloc_or_die(ALLOC_VCPU, sizeof(struct ghost_vcpu));
						ghost_vcpu_clone_into(dest_vcpu_ref->vcpu, src_vcpu_ref->vcpu);
					}
				} else {
					ghost_assert(src_vcpu_ref->vcpu == NULL);
					dest->vm_table_locked.vcpu_refs[vcpu_idx].vcpu = NULL;
				}
			}
		}
		for (int vcpu_idx=0; vcpu_idx<src->vm_table_locked.nr_initialised_vcpus; vcpu_idx++) {
			dest->vm_table_locked.vm_teardown_vcpu_addrs[vcpu_idx] =
				src->vm_table_locked.vm_teardown_vcpu_addrs[vcpu_idx];
		}
		// TODO: ghost_assert(copied_vcpu + found_loaded == dest->vm_table_locked.nr_vcpus);
	}

	if (owner & VMS_VM_OWNED) {
		ghost_assert_maplets_locked();
		dest->vm_locked.present = true;
		abstract_pgtable_copy(&dest->vm_locked.vm_abstract_pgtable, &src->vm_locked.vm_abstract_pgtable);
	}

}


/*
 * Equality checks over ghost objects
 */
// EXPORTED ghost_types_aux.h
bool check_abstraction_equals_register(struct ghost_register *r1, struct ghost_register *r2, bool todo_warnonly)
{
	bool ret = true;
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(r1->status == GHOST_PRESENT && r2->status == GHOST_PRESENT);
	if (todo_warnonly) {
		if (r1->value != r2->value)
			ret = false;
	} else {
		ghost_spec_assert(r1->value == r2->value);
	}
	GHOST_LOG_CONTEXT_EXIT();
	return ret;
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_reg(struct ghost_registers *r1, struct ghost_registers *r2, bool check_sysregs)
{
	GHOST_LOG_CONTEXT_ENTER();
	for (int i=0; i<31; i++) {
		u64 value1 = r1->gprs[i].value;
		u64 value2 = r2->gprs[i].value;
		if (r1->gprs[i].status != r2->gprs[i].status || value1 != value2) {
			GHOST_LOG(i, u64);
			GHOST_LOG(value1, u64);
			GHOST_LOG(value2, u64);
			GHOST_WARN("gpr register mismatch");
			ghost_spec_assert(false);
		}
	}
	if (check_sysregs) {
		for (int i=0; i<NR_GHOST_SYSREGS; i++) {
			u64 value1 = r1->sysregs[i].value;
			u64 value2 = r2->sysregs[i].value;
			if (r1->sysregs[i].status != r2->sysregs[i].status || value1 != value2) {
				GHOST_LOG(i, u64);
				GHOST_LOG(GHOST_SYSREGS_NAMES[i], str);
				GHOST_LOG(value1, u64);
				GHOST_LOG(value2, u64);
				GHOST_WARN("EL0/1 sysreg register mismatch");
				ghost_spec_assert(false);
			}
		}
		for (int i=0; i<NR_GHOST_EL2_SYSREGS; i++) {
			u64 value1 = r1->sysregs[i].value;
			u64 value2 = r2->sysregs[i].value;
			if (r1->sysregs[i].status != r2->sysregs[i].status || value1 != value2) {
				GHOST_LOG(i, u64);
				GHOST_LOG(GHOST_EL2_SYSREGS_NAMES[i], str);
				GHOST_LOG(value1, u64);
				GHOST_LOG(value2, u64);
				GHOST_WARN("EL2 sysreg register mismatch");
				ghost_spec_assert(false);
			}
		}
	}
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_vcpu(struct ghost_vcpu *vcpu1, struct ghost_vcpu *vcpu2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(vcpu1);
	ghost_assert(vcpu2);

	GHOST_SPEC_ASSERT_VAR_EQ(vcpu1->vcpu_index, vcpu2->vcpu_index, u64);
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_vcpu_reference(struct ghost_vcpu_reference *vcpu_ref1, struct ghost_vcpu_reference *vcpu_ref2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(vcpu_ref1);
	ghost_assert(vcpu_ref2);

	GHOST_SPEC_ASSERT_VAR_EQ(vcpu_ref1->initialised, vcpu_ref2->initialised, bool);
	if (vcpu_ref1->initialised && vcpu_ref2->initialised) {
		GHOST_SPEC_ASSERT_VAR_EQ(vcpu_ref1->loaded_somewhere, vcpu_ref2->loaded_somewhere, bool);
		GHOST_LOG(vcpu_ref1->vcpu, u64);
		GHOST_LOG(vcpu_ref2->vcpu, u64);
		if (vcpu_ref1->vcpu && vcpu_ref2->vcpu)
			check_abstraction_equals_vcpu(vcpu_ref1->vcpu, vcpu_ref2->vcpu);
	}
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_host_regs(struct ghost_host_regs *r1, struct ghost_host_regs *r2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(r1->present == r2->present);
	if (r1->present && r2->present)
		check_abstraction_equals_reg(&r1->regs, &r2->regs, false);
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_host(struct ghost_host *gh1, struct ghost_host *gh2)
{
	GHOST_LOG_CONTEXT_ENTER();
	GHOST_LOG(gh1->present, bool);
	GHOST_LOG(gh2->present, bool);
	ghost_assert(gh1->present && gh2->present);

	// equivalence of spec states
	ghost_spec_assert(mapping_equal(gh1->host_abstract_pgtable_annot, gh2->host_abstract_pgtable_annot, "abstraction_equals_host", "gh1.host_mapping_annot", "gh2.host_mapping_annot", 4));
	ghost_spec_assert(mapping_equal(gh1->host_abstract_pgtable_shared, gh2->host_abstract_pgtable_shared, "abstraction_equals_host", "gh1.host_mapping_shared", "gh2.host_mapping_shared", 4));

	ghost_pfn_set_assert_equal(&gh1->reclaimable_pfn_set, &gh2->reclaimable_pfn_set);
	ghost_pfn_set_assert_equal(&gh1->need_poisoning_pfn_set, &gh2->need_poisoning_pfn_set);

	// refinement of implementation
	ghost_pfn_set_assert_equal(&gh1->host_concrete_pgtable.table_pfns, &gh2->host_concrete_pgtable.table_pfns);
	ghost_spec_assert(gh1->host_concrete_pgtable.root == gh2->host_concrete_pgtable.root);

	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_pkvm(struct ghost_pkvm *gp1, struct ghost_pkvm *gp2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(gp1->present && gp2->present);
	check_abstract_pgtable_equal(&gp1->pkvm_abstract_pgtable, &gp2->pkvm_abstract_pgtable, "abstraction_equals_pkvm", "gp1.pkvm_mapping", "gp2.pkvm_mapping", 4);
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_run_state(struct ghost_running_state *expected, struct ghost_running_state *impl)
{
	GHOST_LOG_CONTEXT_ENTER();

	GHOST_SPEC_ASSERT_VAR_EQ(expected->guest_running, impl->guest_running, bool);

	if (expected->guest_running) {
		GHOST_SPEC_ASSERT_VAR_EQ(expected->vm_handle, impl->vm_handle, u32);
		GHOST_SPEC_ASSERT_VAR_EQ(expected->vcpu_index, impl->vcpu_index, u64);
	}

	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_local_state(struct ghost_state *g_expected, struct ghost_state *g_impl)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_local_state *local_expected = ghost_this_cpu_local_state(g_expected);
	struct ghost_local_state *local_impl = ghost_this_cpu_local_state(g_impl);

	check_abstraction_equals_run_state(&local_expected->cpu_state, &local_impl->cpu_state);
	check_abstraction_equals_loaded_vcpu_status(&local_expected->loaded_vcpu_status, &local_impl->loaded_vcpu_status);
	/* regs not checked */
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_equals_loaded_vcpu_status(struct ghost_loaded_vcpu_status *loaded_vcpu_status1, struct ghost_loaded_vcpu_status *loaded_vcpu_status2)
{
	GHOST_LOG_CONTEXT_ENTER();
	GHOST_LOG(loaded_vcpu_status1->loaded, bool); GHOST_LOG(loaded_vcpu_status2->loaded, bool);
	ghost_spec_assert(loaded_vcpu_status1->loaded == loaded_vcpu_status2->loaded);

	if (loaded_vcpu_status1->loaded) {
		GHOST_LOG(loaded_vcpu_status1->vm_handle, u32);
		GHOST_LOG(loaded_vcpu_status2->vm_handle, u32);
		ghost_spec_assert(loaded_vcpu_status1->vm_handle == loaded_vcpu_status2->vm_handle);
		check_abstraction_equals_vcpu(loaded_vcpu_status1->loaded_vcpu, loaded_vcpu_status2->loaded_vcpu);
	}
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
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

static void __check_abstraction_vm_contained_in(struct ghost_vm *vm, struct ghost_vms *vms, enum vm_field_owner owner) {
	struct ghost_vm *vm2 = ghost_vms_get(vms, vm->pkvm_handle);

	if (vm2) {
		check_abstraction_refined_vm(vm, vm2, owner);
	} else {
		ghost_spec_assert(false);
	}
}

static void __check_abstraction_vm_all_contained_in(struct ghost_vms *vms_spec, struct ghost_vms *vms_impl) {
	int i;
	// just iterate over the whole table of slots
	// and check, for each VM that exists in vms1 whether that vm can be found in vms2
	for (i=0; i<KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &vms_spec->table[i];
		if (slot->exists) {
			__check_abstraction_vm_contained_in(slot->vm, vms_impl, VMS_VM_TABLE_OWNED | VMS_VM_OWNED);
		}
	}
}

// EXPORTED ghost_types_aux.h
void check_abstraction_vms_subseteq(struct ghost_vms *g_spec, struct ghost_vms *g_impl)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(g_spec->present && g_impl->present);

	if (g_spec->table_data.present) {
		if (!g_impl->table_data.present)
			GHOST_SPEC_FAIL("g_impl->table_data was missing");

		GHOST_LOG(g_spec->table_data.nr_vms, u64);
		GHOST_LOG(g_impl->table_data.nr_vms, u64);
		ghost_spec_assert(g_spec->table_data.nr_vms == g_impl->table_data.nr_vms);
	}

	/* it might be that we recorded more of the state than was touched by the spec,
	 * in that case there may be VMs (e.g. whose locks were spuriously taken by the implementation)
	 * which are in the recorded post, but not mentioned by the spec.
	 *
	 * So we need to only check that `VMS(spec) subseteq VMS(recorded)`
	 */
	__check_abstraction_vm_all_contained_in(g_spec, g_impl);
	GHOST_LOG_CONTEXT_EXIT();
}

#ifndef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_LOG_ONLY
static void post_dump_diff(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_LOG_ONLY */
// EXPORTED ghost_types_aux.h
void check_abstraction_equals_all(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();
	trace_ghost_enter(GHOST_TRACE_POST_CHECK);

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

	trace_ghost_exit(GHOST_TRACE_POST_CHECK);
	GHOST_LOG_CONTEXT_EXIT();
}

//EXPORTED ghost_types_aux.h
/// Check that `vm` is found in `vms` and that the two ghost vms are equal
void check_abstraction_vm_in_vms_and_equal(pkvm_handle_t vm_handle, struct ghost_state *g, struct ghost_vms *vms, enum vm_field_owner owner) {
	GHOST_LOG_CONTEXT_ENTER();
	GHOST_LOG(vm_handle, u32);

	struct ghost_vm *g_vm = ghost_vms_get(&g->vms, vm_handle);
	struct ghost_vm *found_vm = ghost_vms_get(vms, vm_handle);

	ghost_assert(g_vm != NULL);
	ghost_spec_assert(found_vm);

	check_abstraction_refined_vm(g_vm, found_vm, owner);
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstract_pgtable_equal(abstract_pgtable *ap1, abstract_pgtable *ap2, char *cmp_name, char* ap1_name, char* ap2_name, u64 indent)
{
	GHOST_LOG_CONTEXT_ENTER();
	GHOST_LOG(cmp_name, str);
	GHOST_LOG(ap1_name, str);
	GHOST_LOG(ap2_name, str);

	// assert mathematical spec equivalence
	check_mapping_equal(ap1->mapping, ap2->mapping);

	// implementation refinement check
	ghost_pfn_set_assert_equal(&ap1->table_pfns, &ap2->table_pfns);
	ghost_assert(ap1->root == ap2->root);

	GHOST_LOG_CONTEXT_EXIT();
}


/*
 * Refinement checks over ghost objects
 */
// EXPORTED ghost_types_aux.h
void check_abstraction_refined_pgtable(abstract_pgtable *ap_spec, abstract_pgtable *ap_impl)
{
	GHOST_LOG_CONTEXT_ENTER();
	check_mapping_equal(ap_spec->mapping, ap_impl->mapping);
	ghost_pfn_set_assert_subseteq(&ap_impl->table_pfns, &ap_spec->table_pfns);
	ghost_assert(ap_spec->root == ap_impl->root);
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_refined_register(int idx, struct ghost_register *gc_reg, struct ghost_register *gr_post_reg, struct ghost_register *gr_pre_reg)
{
	GHOST_LOG_CONTEXT_ENTER();

	//TODO: GHOST_LOG(gc_reg->status, enum ghost_status);
	//TODO: GHOST_LOG(gr_post_reg->status, enum ghost_status);

	if (gr_post_reg->status == GHOST_PRESENT && gc_reg->status == GHOST_PRESENT) {
		GHOST_LOG(idx, u32);
		GHOST_INFO("gc_reg");
		GHOST_INFO("gr_post_pre");
		if(!check_abstraction_equals_register(gc_reg, gr_post_reg, /*TODO*/true))
			ghost_printf("\x1b[30;41mWARNING register X%d mismatch ==> computed: %lx -- post: %lx\x1b[0m\n", idx, gc_reg->value, gr_post_reg->value);
	}
	else if (gr_post_reg->status == GHOST_ABSENT && gc_reg->status == GHOST_PRESENT) {
		ghost_assert(false);
	}
	else if (gr_post_reg->status == GHOST_PRESENT && gc_reg->status == GHOST_ABSENT) {
		GHOST_LOG(idx, u32);
		GHOST_INFO("gr_pre_reg");
		GHOST_INFO("gr_post_reg");
		ghost_assert(gr_pre_reg->status == GHOST_PRESENT);
		check_abstraction_equals_register(gr_pre_reg, gr_post_reg, false);
	}

	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_refined_registers(struct ghost_registers *gc_regs, struct ghost_registers *gr_post_regs, struct ghost_registers *gr_pre_regs)
{
	GHOST_LOG_CONTEXT_ENTER();

	GHOST_INFO("gprs");
	for (int i=0; i<31; i++) {
		check_abstraction_refined_register(i, &gc_regs->gprs[i], &gr_post_regs->gprs[i], &gr_pre_regs->gprs[i]);
	}

	// TODO EL0/1 and EL2 sysregs

	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_refined_run_state(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_running_state *gc_run = this_cpu_ghost_run_state(gc);
	struct ghost_running_state *gr_post_run = this_cpu_ghost_run_state(gr_post);

	check_abstraction_equals_run_state(gc_run, gr_post_run);

	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
void check_abstraction_refined_local_state(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct ghost_local_state *gc_local = ghost_this_cpu_local_state(gc);
	struct ghost_local_state *gr_pre_local = ghost_this_cpu_local_state(gr_pre);
	struct ghost_local_state *gr_post_local = ghost_this_cpu_local_state(gr_post);

	/* computed post and recorded post run and register states must be exactly equal (modulo status) */
	check_abstraction_refined_registers(&gc_local->regs, &gr_post_local->regs, &gr_pre_local->regs);
	check_abstraction_equals_run_state(&gc_local->cpu_state, &gr_post_local->cpu_state);
	check_abstraction_equals_loaded_vcpu_status(&gc_local->loaded_vcpu_status, &gr_post_local->loaded_vcpu_status);

	/* the others (loaded_vcpu_status and host_regs) may be not present on the computed state
	 * in which case we check they didn't change if they were recorded in the pre. */
	if (gc_local->host_regs.present && gr_post_local->host_regs.present) {
		GHOST_INFO("r1->gc");
		GHOST_INFO("r2->gr_post");
		check_abstraction_refined_registers(&gc_local->host_regs.regs, &gr_post_local->host_regs.regs, &gr_pre_local->host_regs.regs);
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

// EXPORTED ghost_types_aux.h
void check_abstraction_refined_vm(struct ghost_vm *vm_spec, struct ghost_vm *vm_impl, enum vm_field_owner owner)
{
	GHOST_LOG_CONTEXT_ENTER();
	// NOTE: we can't have this check on the lock here because some calls
	// of the current function compare the thread-local pre/post states in
	// which case we don't hold the lock.
	//
	// ghost_assert_vm_locked(vm1);

	// if not for the same guest VM, then not equal

	/* these fields are protected by the ghost_vms_lock and duplicated on the VM struct for ease of access */
	GHOST_SPEC_ASSERT_VAR_EQ(vm_spec->pkvm_handle, vm_impl->pkvm_handle, u32);
	GHOST_SPEC_ASSERT_VAR_EQ(vm_spec->vm_teardown_data.host_mc, vm_impl->vm_teardown_data.host_mc, u64);
	GHOST_SPEC_ASSERT_VAR_EQ(vm_spec->vm_teardown_data.hyp_vm_struct_addr, vm_impl->vm_teardown_data.hyp_vm_struct_addr, u64);
	GHOST_SPEC_ASSERT_VAR_EQ(vm_spec->vm_teardown_data.last_ran_addr, vm_impl->vm_teardown_data.last_ran_addr, u64);

	ghost_safety_check(vm_spec->lock == vm_impl->lock);

	if ((owner & VMS_VM_TABLE_OWNED) && vm_spec->vm_table_locked.present) {
		if (!vm_impl->vm_table_locked.present)
			GHOST_SPEC_FAIL("vm_impl->vm_table_locked missing");

		GHOST_LOG(vm_spec->vm_table_locked.nr_vcpus, u64);
		GHOST_LOG(vm_impl->vm_table_locked.nr_vcpus, u64);
		ghost_spec_assert(vm_spec->vm_table_locked.nr_vcpus == vm_impl->vm_table_locked.nr_vcpus);

		GHOST_LOG(vm_spec->vm_table_locked.nr_initialised_vcpus, u64);
		GHOST_LOG(vm_impl->vm_table_locked.nr_initialised_vcpus, u64);
		ghost_spec_assert(vm_spec->vm_table_locked.nr_initialised_vcpus == vm_impl->vm_table_locked.nr_initialised_vcpus);

		for (int i=0; i < vm_spec->vm_table_locked.nr_vcpus; i++) {
			GHOST_LOG_CONTEXT_ENTER_INNER("loop vcpu_refs");
			GHOST_LOG_INNER("loop vcpu_refs", i, u32);
			check_abstraction_equals_vcpu_reference(&vm_spec->vm_table_locked.vcpu_refs[i], &vm_impl->vm_table_locked.vcpu_refs[i]);
			GHOST_LOG_CONTEXT_EXIT_INNER("loop vcpu_refs");
		}

		for (int i=0; i < vm_spec->vm_table_locked.nr_initialised_vcpus; i++) {
			GHOST_LOG_CONTEXT_ENTER_INNER("loop vcpu_addrs");
			GHOST_LOG_INNER("loop vcpu_addrs", i, u32);
			GHOST_LOG_CONTEXT_ENTER(); // TODO: improve
			GHOST_SPEC_ASSERT_VAR_EQ(vm_spec->vm_table_locked.vm_teardown_vcpu_addrs[i], vm_impl->vm_table_locked.vm_teardown_vcpu_addrs[i], u64);
			GHOST_LOG_CONTEXT_EXIT();
			GHOST_LOG_CONTEXT_EXIT_INNER("loop vcpu_addrs");
		}
	}

	if ((owner & VMS_VM_OWNED) && vm_spec->vm_locked.present) {
		if (!vm_impl->vm_locked.present)
			GHOST_SPEC_FAIL("vm_impl->vm_locked missing");

		check_abstraction_refined_pgtable(&vm_spec->vm_locked.vm_abstract_pgtable, &vm_impl->vm_locked.vm_abstract_pgtable);
	}

	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_types_aux.h
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

// EXPORTED ghost_types_aux.h
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

// EXPORTED ghost_types_aux.h
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


/*
 * Dumping and diffing
 */
#define GHOST_MISSING_FIELD "<not recorded>"
// EXPORTED ghost_types_aux.h
void ghost_dump_pkvm(struct ghost_pkvm *pkvm)
{
	ghost_printf("pkvm: ");

	if (!pkvm->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	} else {
		ghost_printf_ext(
			"\n"
			"%I%gI(pgtable)\n",
			2, &pkvm->pkvm_abstract_pgtable, 2
		);
	}
}

// EXPORTED ghost_types_aux.h
void ghost_dump_host(struct ghost_host *host)
{
	ghost_printf("host: ");

	if (!host->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
		return;
	}

	ghost_printf_ext(
		"\n"
		"  annot:\n"
		"%I%gI(mapping)\n"
		"  shared:\n"
		"%I%gI(mapping)\n"
		"  pfns:\n"
		"%I%g(pfn_set)\n",
		4, &host->host_abstract_pgtable_annot, 4,
		4, &host->host_abstract_pgtable_shared, 4,
		4, &host->host_concrete_pgtable.table_pfns
	);
}

// EXPORTED ghost_types_aux.h
void ghost_dump_vm(struct ghost_vm *vm, u64 i)
{
	if (!vm)
		return;

	ghost_printf_ext("%Ivm %x:\n", i, vm->pkvm_handle);

	ghost_printf_ext("%Ivm_locked: ", i+4);
	if (vm->vm_locked.present) {
		ghost_printf_ext(
			"\n"
			"%I%gI(pgtable)\n",
			i+8,
			&vm->vm_locked.vm_abstract_pgtable, i+8
		);
	} else {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	}

	ghost_printf_ext("%Ivm_table_locked: ", i+4);
	if (!vm->vm_table_locked.present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
		return;
	}

	ghost_printf("\n");
	ghost_printf_ext("%Inr_vcpus:%lu\n", i+8, vm->vm_table_locked.nr_vcpus);
	ghost_printf_ext("%Inr_initialised_vcpus:%lu\n", i+8, vm->vm_table_locked.nr_initialised_vcpus);

	ghost_printf_ext("%Ivcpus:\n", i+8);
	for (int vcpu_indx = 0; vcpu_indx < vm->vm_table_locked.nr_vcpus; vcpu_indx++) {
		struct ghost_vcpu_reference *vcpu_ref = &vm->vm_table_locked.vcpu_refs[vcpu_indx];
		ghost_printf_ext("%Ivcpu %d ", i+12, vcpu_indx);

		if (vcpu_ref->initialised)
			ghost_printf("(initialised)");
		else
			ghost_printf("             ");

		ghost_printf(" ");

		if (vcpu_ref->loaded_somewhere)
			ghost_printf("(loaded_somewhere)");
		else
			ghost_printf("                  ");

		ghost_printf("\n");
	}

	ghost_printf_ext("%Ivcpu_addrs:\n", i+4);
	if (vm->vm_table_locked.present) {
		for (int idx=0; idx<vm->vm_table_locked.nr_initialised_vcpus; idx++) {
			ghost_printf_ext("%I[%d]: %p\n", i+8, idx, vm->vm_table_locked.vm_teardown_vcpu_addrs[idx]);
		}
	} else {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	}
}

// EXPORTED ghost_types_aux.h
void ghost_dump_vms(struct ghost_vms *vms)
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

	ghost_printf("    vm_table:\n");
	for (int i = 0; i < KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &vms->table[i];
		if (slot->exists) {
			ghost_dump_vm(slot->vm, 4+4);
		}
	}
}

// EXPORTED ghost_types_aux.h
void ghost_dump_globals(struct ghost_constant_globals *globals)
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

// EXPORTED ghost_types_aux.h
void ghost_dump_regs(struct ghost_registers *regs, u64 i)
{
	ghost_printf_ext("%Iregs[cpu:%d]:<TODO>\n", i, hyp_smp_processor_id());
}

// EXPORTED ghost_types_aux.h
void ghost_dump_loaded_vcpu_status(struct ghost_loaded_vcpu_status *loaded_vcpu_status, u64 i)
{
	ghost_printf_ext("%Iloaded_vcpu_status[cpu:%d]: ", i, hyp_smp_processor_id());

	if (!loaded_vcpu_status->loaded) {
		ghost_printf("<no loaded vCPU>\n");
	} else {
		ghost_printf("<loaded vm_handle:%x vcpu_index:%lu>\n", loaded_vcpu_status->vm_handle, loaded_vcpu_status->loaded_vcpu->vcpu_index);
	}
}

// EXPORTED ghost_types_aux.h
void ghost_dump_running_state(struct ghost_running_state *run, u64 i)
{
	ghost_printf_ext("%Irun_state[cpu:%d]: ", i, hyp_smp_processor_id());

	if (!run->guest_running) {
		ghost_printf("<host running>\n");
	} else {
		ghost_printf("<VM running, vm_handle:%x vcpu_index:%lu exit_code:%lu>\n", run->vm_handle, run->vcpu_index, run->guest_exit_code);
	}
}

// EXPORTED ghost_types_aux.h
void ghost_dump_host_regs(struct ghost_host_regs *host_regs, u64 i)
{
	ghost_printf_ext("%Ihost regs: ", i);

	if (!host_regs->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	} else {
		ghost_printf("<TODO>\n");
	}
}

// EXPORTED ghost_types_aux.h
void ghost_dump_thread_local(struct ghost_local_state *local)
{
	ghost_printf("locals[%d]: ", hyp_smp_processor_id());
	if (!local->present) {
		ghost_printf(GHOST_MISSING_FIELD "\n");
	} else {
		ghost_printf("\n");
		ghost_dump_regs(&local->regs, 4);
		ghost_dump_loaded_vcpu_status(&local->loaded_vcpu_status, 4);
		ghost_dump_running_state(&local->cpu_state, 4);
		ghost_dump_host_regs(&local->host_regs, 4);
	}
}

// EXPORTED ghost_types_aux.h
void ghost_dump_state(struct ghost_state *g)
{
	ghost_dump_pkvm(&g->pkvm);
	ghost_dump_host(&g->host);
	ghost_dump_vms(&g->vms);
	ghost_dump_globals(&g->globals);
	ghost_dump_thread_local(ghost_this_cpu_local_state(g));
}


#ifdef CONFIG_NVHE_GHOST_DIFF
/*
 * Print the diff between the recorded pre concrete host pgtable state and recorded post pgtable state
 */
static void ghost_post_dump_recorded_concrete_host_pgtable_diff(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
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
