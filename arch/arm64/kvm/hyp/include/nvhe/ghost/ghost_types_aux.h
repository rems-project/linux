#ifndef _GHOST_TYPES_H
#define _GHOST_TYPES_H

#include <nvhe/ghost/ghost_state.h>

hyp_spinlock_t *ghost_pointer_to_vm_lock(pkvm_handle_t handle);


/*
 * Constructors and initialisers
 */

/**
 * make_abstraction_vms() - Initialises an uninitialised ghost_vms to be empty.
 */
void make_abstraction_vms(struct ghost_vms *vms);

/**
 * ghost_vms_alloc() - Get a reference to a fresh (empty) ghost_vm in the table
 *
 * @vms: ghost vm table
 * @handle: the opaque pkvm-assigned handle for the VM we will put in this slot (for safety checks)
 *
 * A VM with that handle must not already exist in the vms table.
 *
 * Return:
 *  A reference to an empty vm slot that can be used.
 *  is marked non-empty on return
 *
 * Context: Must own the ghost vms lock, panics if all slots were used up.
 */
struct ghost_vm *ghost_vms_alloc(struct ghost_vms *vms, pkvm_handle_t );

/*
 * Destructors
 */
void clear_abstract_pgtable(abstract_pgtable *ap);
void clear_abstraction_pkvm(struct ghost_state *g);
void clear_abstraction_host(struct ghost_state *g);
void clear_abstraction_regs(struct ghost_state *g);
void clear_abstraction_vm_partial(struct ghost_state *g, pkvm_handle_t handle, enum vm_field_owner owner);
void clear_abstraction_vms_partial(struct ghost_state *g, enum vm_field_owner owner);
void clear_abstraction_vms(struct ghost_state *g);
void clear_abstraction_this_thread_local_state(struct ghost_state *g);
void clear_abstraction_this_thread_local_states(void);

/*
 * Functions to copy bits of ghost state from one ghost_* struct into another.
 * typically for a copy_ghost_XYZ(target, source), it:
 *  - assumes target's XYZ is not present
 *  - assumes source's XYZ is present
 */
void copy_abstraction_regs(struct ghost_registers *g_tgt, struct ghost_registers *g_src);
void copy_abstraction_constants(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_host(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_pkvm(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_vm_partial(struct ghost_state *g_tgt, struct ghost_state *g_src, pkvm_handle_t handle, enum vm_field_owner owner);
void copy_abstraction_vms_partial(struct ghost_state *g_tgt, struct ghost_state *g_src, enum vm_field_owner owner);
void copy_abstraction_local_state(struct ghost_local_state *l_tgt, struct ghost_local_state *l_src);
void copy_abstraction_loaded_vcpu_status(struct ghost_loaded_vcpu_status *tgt, struct ghost_loaded_vcpu_status *src);
void ghost_vcpu_clone_into(struct ghost_vcpu *dest, struct ghost_vcpu *src);

/**
 * ghost_vm_clone_into_partial() - Copies all the fields (including mappings) from one VM slot to another
 *
 * Must own the vm_table table lock, *and* both VMs locks
 */
void ghost_vm_clone_into_partial(struct ghost_vm *dest, struct ghost_vm *src, enum vm_field_owner owner);

/*
 * Equality checks over ghost objects
 */

void check_abstraction_equals_all(
	struct ghost_state *gc,
	struct ghost_state *gr_post,
	struct ghost_state *gr_pre
);
void check_abstraction_equals_pkvm(struct ghost_pkvm *gp1, struct ghost_pkvm *gp2);
void check_abstraction_equals_host(struct ghost_host *gh1, struct ghost_host *gh2);
void check_abstraction_equals_local_state(struct ghost_state *g_expected, struct ghost_state *g_impl);
void check_abstraction_equals_globals(struct ghost_state *gc, struct ghost_state *gr_post);
void check_abstraction_vms_subseteq(struct ghost_vms *g_spec, struct ghost_vms *g_impl);

bool check_abstraction_equals_register(struct ghost_register *r1, struct ghost_register *r2, bool todo_warnonly);
void check_abstraction_equals_reg(struct ghost_registers *r1, struct ghost_registers *r2, bool check_sysregs);
void check_abstraction_equals_vcpu(struct ghost_vcpu *vcpu1, struct ghost_vcpu *vcpu2);
void check_abstraction_equals_run_state(struct ghost_running_state *expected, struct ghost_running_state *impl);
void check_abstraction_equals_host_regs(struct ghost_host_regs *r1, struct ghost_host_regs *r2);
void check_abstraction_equals_loaded_vcpu_status(struct ghost_loaded_vcpu_status *loaded_vcpu_status1, struct ghost_loaded_vcpu_status *loaded_vcpu_status2);
void check_abstraction_equals_vcpu_reference(struct ghost_vcpu_reference *vcpu_ref1, struct ghost_vcpu_reference *vcpu_ref2);
void check_abstraction_vm_in_vms_and_equal(pkvm_handle_t vm_handle, struct ghost_state *g, struct ghost_vms *vms, enum vm_field_owner owner);
void check_abstract_pgtable_equal(
	abstract_pgtable *pgt1,
	abstract_pgtable *pgt2,
	char* cmp_name,
	char* pgt1_name,
	char* pgt2_name,
	u64 indent
);

void check_abstraction_refined_pgtable(
	abstract_pgtable *pgt_spec,
	abstract_pgtable *pgt_impl
);
void check_abstraction_refined_register(int idx, struct ghost_register *gc_reg, struct ghost_register *gr_post_reg, struct ghost_register *gr_pre_reg);
void check_abstraction_refined_registers(struct ghost_registers *gc_regs, struct ghost_registers *gr_post_regs, struct ghost_registers *gr_pre_regs);
void check_abstraction_refined_run_state(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre);
void check_abstraction_refined_local_state(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre);
void check_abstraction_refined_vm(struct ghost_vm *vm_spec, struct ghost_vm *vm_impl, enum vm_field_owner owner);
void check_abstraction_refined_pkvm(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre);
void check_abstraction_refined_host(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre);
void check_abstraction_refined_vms(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre);

/*
 * Printers
 */

void ghost_dump_state(struct ghost_state *g);
void ghost_dump_pkvm(struct ghost_pkvm *pkvm);
void ghost_dump_host(struct ghost_host *host);
void ghost_dump_vms(struct ghost_vms *vms);
void ghost_dump_vm(struct ghost_vm *vm, u64 i);
void ghost_dump_thread_local(struct ghost_local_state *local);
void ghost_dump_host_regs(struct ghost_host_regs *host_regs, u64 i);
void ghost_dump_running_state(struct ghost_running_state *run, u64 i);
void ghost_dump_globals(struct ghost_constant_globals *globals);
void ghost_dump_regs(struct ghost_registers *regs, u64 i);

#endif // _GHOST_TYPES_H