#ifndef _GHOST_STATE_H
#define _GHOST_STATE_H

#include <linux/types.h>

#include <nvhe/ghost/ghost_status.h>
#include <nvhe/ghost/ghost_registers.h>
#include <nvhe/ghost/ghost_pgtable.h>

#include <nvhe/ghost/ghost_call_data.h>


/**
 * struct ghost_loaded_vcpu - Whether the current physical CPU has a loaded vCPU, and if there is one, a pointer to its state.
 *
 * @loaded: whether this physical CPU has a loaded vCPU.
 * @vm_handle: if loaded, the opaque pkvm-assigned handle for the vCPU's parent vm.
 * @loaded_vcpu: if loaded, a pointer to the vCPU state
 *
 * Context: Thread-local, so does not need to be protected by a lock.
 *          However, the underlying vm and its vcpus are protected by that guest vm's lock.
 *
 * Invariant: loaded_vcpu != NULL
 */
struct ghost_loaded_vcpu {
	bool loaded;
	pkvm_handle_t vm_handle;
	struct ghost_vcpu *loaded_vcpu;
};

/**
 * struct ghost_registers - register state
 *
 * @status: whether the parent ghost (v)CPU state has a value for this register
 * @pc: if present, the value of the register
 */
struct ghost_register {
	enum ghost_status status;
	u64 value;
};

/**
 * struct ghost_registers - (v)CPU registers state
 *
 * @present: whether the parent ghost state has some ghost registers state for this (v)CPU
 * @pc: if present, ghost copy of the program counter
 * @gprs: if present, ghost copy of the general-purpose registers
 * @sysregs: if present, ghost copy of the current value of the EL0/EL1 system registers
 * @el2_sysregs: if present, ghost copy of the current value of the EL2 system registers.
 *
 * Not all the register values are present, and are marked accordingly (see struct ghost_register).
 *
 * Context: thread-local, so not protected by any lock.
 */
struct ghost_registers {
	bool present;
	struct ghost_register pc;
	struct ghost_register gprs[31];
	struct ghost_register sysregs[NR_GHOST_SYSREGS];
	struct ghost_register el2_sysregs[NR_GHOST_EL2_SYSREGS];
};

/**
 * struct ghost_vcpu - A single vCPU within a VM
 *
 * @vcpu_index: the index of this vCPU in the VM.
 * @regs: the saved register state of this vCPU.
 * @recorded_memcache_pfn_set:
 *
 * Context: This is either protected by the vm_table lock (when the vCPU is not loaded
 	    on a physical CPU), or thread-local.
 */
struct ghost_vcpu {
	u64 vcpu_index;
	struct ghost_registers regs;
	struct pfn_set recorded_memcache_pfn_set;
};

/**
 * struct ghost_vcpu_reference - A reference to a single vCPU held by the vm_table locked part of a VM state
 *
 * @initialised: whether this vcpu has been initialised by __pkvm_init_vcpu.
 * @loaded_somewhere: if initialised, whether this vcpu is currently loaded on a physical CPU.
 * @vcpu: if initialised, a pointer to the actual state of the vCPU. This is NULL if the vCPU is not owned by the vm table (because it is loaded somewhere).
 *
 * Context: Protected by the vm_table lock, including the object pointed to by vcpu if not NULL.
 *
 * Invariant: loaded_somewhere == true <==> vcpu == NULL
 */
struct ghost_vcpu_reference {
	bool initialised;
	bool loaded_somewhere;
	struct ghost_vcpu *vcpu;
};

/**
 * enum vm_field_owner - Lock which owns a particular field.
 * @VMS_VM_TABLE_OWNED: for fields owned by pKVM's own vm_table_lock
 * @VMS_VM_OWNED: for fields owned/protected by the VM's own pgtable lock (so, the pgtable itself).
 */
enum vm_field_owner {
	VMS_VM_TABLE_OWNED = BIT(0),
	VMS_VM_OWNED = BIT(1),
};

/**
 * struct ghost_vm_locked_by_vm_lock - A guest VM (part protected by the internal VM lock)
 *
 * @present: whether this portion of the VM is present in the ghost state.
 * @vm_abstract_pgtable: an abstract mapping of the concrete guest pagetable.
 *
 * Context: Protected by the internal VM's lock,
 */
struct ghost_vm_locked_by_vm_lock {
	bool present;
	abstract_pgtable vm_abstract_pgtable;
};

/**
 * struct ghost_vm_locked_by_vm_table - A guest VM (part protected by the VM table lock)
 *
 * @present: whether this portion of the VM is present in the ghost state.
 * @nr_vcpus: if present, the number of vCPUs this VM was created with.
 * @nr_initialised_vcpus: if present, the number vCPUs that have been initialised so far by __pkvm_init_vcpu.
 * @vcpu_refs: if present, the actual table of ghost_vcpu_reference objects, valid up to nr_vcpus.
 * @vm_teardown_vcpu_addrs: if present, locations of the `pkvm_hyp_vcpu` structures, donated during __pkvm_init_vcpu calls.

 *
 * Context: Protected by the VM table lock,
 *          the `lock` field should not be used to take the lock, only to check it for sanity checking of the spec machinery
 *
 * NOTE: in `.vm_teardown_vcpu_addrs`, there are only `.nr_initialised_vcpus`
 * The remaining elements of the array should be zero.
 */
struct ghost_vm_locked_by_vm_table {
	bool present;
	u64 nr_vcpus;
	u64 nr_initialised_vcpus;
	struct ghost_vcpu_reference vcpu_refs[KVM_MAX_VCPUS];
	phys_addr_t vm_teardown_vcpu_addrs[KVM_MAX_VCPUS];
};

/**
 * struct ghost_vm_teardown_data - Memory taken to hold VM metadata
 * @host_mc: location of shared host memcache.
 * @hyp_vm_struct_addr: location of the `pkvm_hyp_vm` struct itself, donated during __pkvm_init_vm.
 * @last_ran_addr: location of the last_vcpu_ran array, donated during __pkvm_init_vm.
 *
 * NOTE: number of donated pages not saved here, but computed as part of spec.
 */
struct ghost_vm_teardown_data {
	phys_addr_t host_mc;
	phys_addr_t hyp_vm_struct_addr;
	phys_addr_t last_ran_addr;
};

/**
 * struct ghost_vm - A guest VM
 * @protected: whether this is a Protected VM.
 * @pkvm_handle: the opaque pKVM-defined handle for this VM.
 * @lock: (for ghost machinery checks) a reference to the underlying spinlock of the real hyp VM, for instrumentation purposes.
 * @vm_locked: fields owned by the internal VM lock
 * @vm_table_locked: fields protected by the pKVM vm_table lock
 * @vm_teardown_data: pages donated to pKVM for holding VM metadata, to be given back on teardown.
 *
 * The VM is split into two parts: the pgtable (owned by the VM's own internal lock)
 * and the other metadata which is collectively owned by the VM struct itself,
 * which is protected by the pKVM vm_table lock.
 *
 * We split the struct into two sub-structs for the parts protected by separate locks,
 * and these can be filled separately leading to partially initialised ghost VM structs.
 */
struct ghost_vm {
	bool protected;
	pkvm_handle_t pkvm_handle;
	hyp_spinlock_t *lock;
	struct ghost_vm_locked_by_vm_lock vm_locked;
	struct ghost_vm_locked_by_vm_table vm_table_locked;
	struct ghost_vm_teardown_data vm_teardown_data;
};

/**
 * struct ghost_host_regs - The host register bank.
 * @present: whether the parent ghost_state has recorded the ghost registers.
 * @regs: if present, the set of host registers (general-purpose, el1 and el2 sysregs).
 */
struct ghost_host_regs {
	bool present;
	struct ghost_registers regs;
};

/**
 * struct ghost_host - The host android/linux mapping
 *
 * @present: whether the parent ghost_state has some ghost host data
 * @host_abstract_pgtable_annot: if present, the annotated (invalid) parts of the host pgt with owner_id!=PKVM_ID_HOST
 * @host_abstract_pgtable_shared: if present, the valid parts of the host pgt with page state either PKVM_PAGE_SHARED_OWNED or PKVM_PAGE_SHARED_BORROWED
 * @host_concrete_pgtable: (for implementation refinement checks) if present, the full concrete host pagetable.
 *
 * The host (intermediate-physical, although idmapped) address space is represented in two parts:
 *  - The annot mapping, which are all unmapped in the host, includes all parts of hyp_memory (all the non-device memory the kernel knows about) which are owned by pkvm or the guests and not shared with the host (all shared locations will always be mapped)
 *  - The shared mapping, which are accessible by the host, but either shared with another (i.e marked PKVM_PAGE_SHARED_OWNED) or shared by someone else with the host (marked PKVM_PAGE_SHARED_BORROWED)
 *
 * Context: Protected by the host's hyp lock.
 */
struct ghost_host {
	bool present;

	mapping host_abstract_pgtable_annot;
	mapping host_abstract_pgtable_shared;
	struct pfn_set reclaimable_pfn_set;
	struct pfn_set need_poisoning_pfn_set;

	abstract_pgtable host_concrete_pgtable;
};

/**
 * struct ghost_pkvm - hypervisor-specific EL2 stage1 pagetable
 *
 * @present: whether the parent ghost state has some ghost pkvm EL2 data
 * @pkvm_abstract_pgtable: if present, abstract mapping containing the concrete EL2 Stage1 translation
 *
 * Context: Protected by the global pKVM hypervisor lock.
 */
struct ghost_pkvm {
	bool present;
	abstract_pgtable pkvm_abstract_pgtable;
};


/**
 * struct ghost_vm_slot - A slot in the VMS table
 *
 * @exists: whether this VM in the parent vm table slot contains a valid VM.
 * @handle: if exists, the pKVM-assigned VM handle this slot is for (the key).
 * @vm: if exists, the actual VM in this slot.
 *
 * Context: the fields are protected by the ghost vms lock,
 *          but the memory pointed to `vm` is owned by separate locks (see ghost_vm).
 */
struct ghost_vm_slot {
	bool exists;
	pkvm_handle_t handle;
	struct ghost_vm *vm;
};

/**
 * strcut ghost_vms_table_data - pKVM-owned data about the whole vm table state
 *
 * @present: whether the ghost state table of VMs has the pKVM vm_table data in it.
 * @nr_vms: if present, the current number of VMs that pKVM has.
 *
 * Context: owned by pKVM's vm_table_lock.
 */
struct ghost_vms_table_data {
	bool present;
	u64 nr_vms;
};

/**
 * struct ghost_vms - Ghost VM table
 *
 * @present: whether this part of the ghost state is set
 * @table_data: if present, metadata (e.g. nr_vms) of the vms.
 * @table: if present, a dictionary of ```VM handle -> VM```, implemented as a table of slots.
 *
 * Code should not access .table directly, but through the abstract ghost_vms_* functions below.
 * Context: the table itself is protected by the ghost_vms_lock
 *          but the table_data is owned by pKVM's own vm_table lock
 *          and each of the internal VMs are split with parts owned by different locks (see ghost_vm).
 */
struct ghost_vms {
	bool present;
	struct ghost_vms_table_data table_data;
	struct ghost_vm_slot table[KVM_MAX_PVMS];
};

/**
 * ghost_vms_is_valid_handle() - Checks that the guest associated with an opaque pkvm-assigned handle exists in the vm table
 *
 * Must own the ghost vms lock
 */
bool ghost_vms_is_valid_handle(struct ghost_vms *vms, pkvm_handle_t handle);

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

/**
 * struct ghost_constant_globals - Copy of the hypervisor read-only globals
 * @hyp_memory: abstract mapping interpretation of the hyp_memory array.
 * @hyp_nr_cpus: the actual count of the number of CPUs there are.
 * @hyp_physvirt_offset: the global physical offset of physical memory within the hyp VA space.
 * @tag_lsb: the pKVM VA tag (NOT the one of the Host kernel).
 * @tag_val: the pKVM VA tag value (the random offset and the bit indicating whether we are
 *           in the top or bottom of the virtual address space).
 *           (again this is NOT the one of the Host kernel)
 *
 * Context: not protected by any lock, as should be read-only globals.
 */
struct ghost_constant_globals {
	mapping hyp_memory;
	u64 hyp_nr_cpus;
	s64 hyp_physvirt_offset;
	u64 tag_lsb;
	u64 tag_val;
};

/**
 * struct ghost_local_state - Physical CPU-local ghost state.
 * @present: whether the ghost state has local state recorded for this CPU.
 * @regs: if present, physical register banks (general purpose, el2 system, el1 system) registers.
 * @loaded_hyp_vcpu: if present, ghost copies of the state of the currently loaded vcpu.
 * @cpu_state: if present, what is currently running on this CPU.
 * @host_regs: (optionally) if present, the host registers, for this physical CPU.
 */
struct ghost_local_state {
	bool present;
	struct ghost_registers regs;
	struct ghost_loaded_vcpu loaded_hyp_vcpu;
	struct ghost_running_state cpu_state;
	struct ghost_host_regs host_regs;
};

/**
 * struct ghost_state - Ghost copy of the whole EL2 state
 *
 * @pkvm: ghost EL2 hypervisor state, including EL2 Stage1 pagetables, protected by the pkvm hyp lock.
 * @host: ghost host pagetable state, protected by the host pgtable lock.
 * @vms: vm table, protected by the pKVM vm_table table lock, with each inner vm protected by that vm's own lock.
 * @globals: a copy of the set of hypervisor constant globals.
 * @cpu_local_state: per-CPU array of thread-local state for each physical CPU.
 *
 * A ghost state may be partial, and only have some of the above fields present.
 * In that case, the ghost state is valid for those parts that are present,
 * and should match the real physical state for those parts.
 */
struct ghost_state {
	struct ghost_pkvm pkvm;
	struct ghost_host host;
	struct ghost_vms vms;
	struct ghost_constant_globals globals;
	struct ghost_local_state* cpu_local_state[NR_CPUS];
};

#endif // _GHOST_STATEs_H