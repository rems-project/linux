#ifndef _GHOST_TYPES_H
#define _GHOST_TYPES_H

#include <nvhe/ghost/ghost_state.h>

/**
 * ghost_vms_get() - Get a reference to the ghost_vm in the table
 *
 * @vms: ghost vm table
 * @handle: the pkvm-defined opaque VM handle
 *
 * Return:
 *  - Reference to the ghost_vm* if it exists in the table
 *  - NULL if there is no VM with that handle in the table
 *
 * Context: Must own the ghost vms lock
 */
struct ghost_vm *ghost_vms_get(struct ghost_vms *vms, pkvm_handle_t handle);
hyp_spinlock_t *ghost_pointer_to_vm_lock(pkvm_handle_t handle);


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
//void ghost_vms_free(struct ghost_vms *vms, pkvm_handle_t handle);

/**
 * ghost_vms_is_valid_handle() - Checks that the guest associated with an opaque pkvm-assigned handle exists in the vm table
 *
 * Must own the ghost vms lock
 */
bool ghost_vms_is_valid_handle(struct ghost_vms *vms, pkvm_handle_t handle);

/**
 * ghost_vm_clone_into_partial() - Copies all the fields (including mappings) from one VM slot to another
 *
 * Must own the vm_table table lock, *and* both VMs locks
 */
void ghost_vm_clone_into_partial(struct ghost_vm *dest, struct ghost_vm *src, enum vm_field_owner owner);

void ghost_dump_state(struct ghost_state *g);

#endif // _GHOST_TYPES_H