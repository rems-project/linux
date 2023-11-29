#ifndef _GHOST_SPEC_H
#define _GHOST_SPEC_H

#include <hyp/ghost_extra_debug-pl011.h>
//#include <nvhe/ghost_check_pgtables.h>
#include <nvhe/ghost_asm_ids.h>
#include <nvhe/ghost_misc.h>
#include <nvhe/ghost_pgtable.h>
#include <nvhe/spinlock.h>
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#include <nvhe/trap_handler.h>   // for DECLARE_REG
#include <asm/kvm_asm.h>    // for __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp etc
#include <asm/kvm_pkvm.h> // for KVM_MAX_PVMS

#include <nvhe/ghost_asserts.h>
#include <nvhe/ghost_pfn_set.h>
#include <nvhe/ghost_call_data.h>
#include <nvhe/ghost_control.h>
#include <nvhe/ghost_status.h>
#include <nvhe/ghost_registers.h>

// top-level spec types


/*
 * Initialisation:
 *
 * We track when __pkvm_init has succeeded with `ghost_pkvm_init_finalized`.
 *
 * However, up until all the cores have switched over to use the new pgtables,
 * pKVM is not yet guaranteeing isolation.
 *
 * So we track up until all cores have finishes __pkvm_prot_finalize
 * (with the `ghost_prot_finalized_count` counter, up to `hyp_nr_cpus`)
 * and once they have, we trip the global switch
 * (`ghost_prot_finalized_all`)
 *
 * It may be that a hypercall on another thread is midway execution during this,
 * this hypercall does not guarantee isolation as it started before the last CPU's __pkvm_prot_finalize
 * so we have a per-CPU hypercall check (`ghost_check_this_hypercall`) which is set a the start of a trap
 * iff ghost_prot_finalized_all
 */
extern bool ghost_pkvm_init_finalized;
extern u64 ghost_prot_finalized_count;
extern bool ghost_prot_finalized_all;
DECLARE_PER_CPU(bool, ghost_check_this_hypercall);

/**
 * ghost_this_trap - The name of the current trap.
 */
DECLARE_PER_CPU(const char *, ghost_this_trap);

/*
 * We shouldn't try check the recorded state against the previously recorded state on the start of a trap
 * if the previous hypercall on this CPU wasn't checked.
 *
 * TODO: we may still want to run the machinery to collect states and make sure they haven't changed _between_ hypercalls...
 */
DECLARE_PER_CPU(bool, ghost_checked_previous_hypercall);
bool ghost_checked_last_call(void);

/*
 * The noisy printing is controlled separately,
 * A call can be checked but silently,
 * or printed noisly with diffs but not checked.
 */
DECLARE_PER_CPU(bool, ghost_print_this_hypercall);

/**
 * ghost_exec_enabled() - Whether executable checking is currently enabled on this CPU.
 */
bool ghost_exec_enabled(void);

/**
 * ghost_enable_this_cpu() - Enable ghost machinery on this CPU.
 *
 * NOTE: This doesn't immediately start ghost speccing, see the above 'Initialisation' comment.
 */
void ghost_enable_this_cpu(void);

/**
 * struct ghost_loaded_vcpu - The identity of the currently loaded vcpu, if there is one.
 *
 * @present: whether the parent ghost_state has a ghost loaded_vcpu (for this cpu).
 * @loaded: if present, whether this physical CPU has a loaded vCPU.
 * @vm_handle: if present and loaded, the opaque pkvm-assigned handle for the vcpu's parent vm.
 * @vcpu_index: if present and loaded, the index in the guest vm's vcpu table of the loaded vcpu.
 *
 * Context: Thread-local, so does not need to be protected by a lock.
 *          However, the underlying vm and its vcpus are protected by that guest vm's lock.
 */
struct ghost_loaded_vcpu {
	bool present;
	bool loaded;
	pkvm_handle_t vm_handle;
	u64 vcpu_index;
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
 * struct ghost_vcpu - A single vcpu within a VM
 *
 * @vcpu_handle: the 'handle' (or, really, index) of this vcpu in the VM.
 * @initialised: whether this vcpu has been initialised by __pkvm_init_vcpu.
 * @loaded: if initialised, whether this vcpu is currently loaded on a physical CPU.
 * @regs: if initialised, the saved register state of this vcpu.
 *
 * Context: Protected by the vm_table lock.
 */
struct ghost_vcpu {
	u64 vcpu_handle; // really the index
	bool loaded;
	bool initialised;
	struct ghost_registers regs;
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
 * @vcpus: if present, the actual table of ghost_vcpu objects, valid up to nr_vcpus.
 *
 * Context: Protected by the VM table lock,
 *          the `lock` field should not be used to take the lock, only to check it for sanity checking of the spec machinery
 */
struct ghost_vm_locked_by_vm_table {
	bool present;
	u64 nr_vcpus;
	u64 nr_initialised_vcpus;
	struct ghost_vcpu *vcpus[KVM_MAX_VCPUS];
};

/**
 * struct ghost_vm - A guest VM
 * @protected: whether this is a Protected VM.
 * @pkvm_handle: the opaque pKVM-defined handle for this VM.
 * @lock: (for ghost machinery checks) a reference to the underlying spinlock of the real hyp VM, for instrumentation purposes.
 * @vm_locked: fields owned by the internal VM lock
 * @vm_table_locked: fields protected by the pKVM vm_table lock
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
	struct pfn_set reclaimable_pfn_sets;
	struct pfn_set need_poisoning_pfn_sets;

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
 * ghost_vms_free() - Remove a VM from the table
 *
 * @vms: ghost vm table
 * @handle: opaque pkvm-defined handle for the VM to remove
 *
 * Marks any slot (if it exists) for that VM as empty.
 *
 * Must own the ghost vms lock
 */
void ghost_vms_free(struct ghost_vms *vms, pkvm_handle_t handle);

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

/*
 * Lock order (in order to be taken): pKVM vm_table -> Host pgtable -> pKVM pgtable -> VM lock -> maplets -> ghost_vms
 *
 * Because the pKVM locks might be taken and inside the locked region some ghost machinery is done,
 * the inner ghost machinery should never itself try take a pKVM lock.
 */
extern hyp_spinlock_t ghost_vms_hyp_lock; /* defined in ghost_compute_abstraction.c */
extern hyp_spinlock_t vm_table_lock; /* defined in nvhe/pkvm.c */

void ghost_lock_vms(void);
void ghost_unlock_vms(void);

void ghost_lock_pkvm_vm_table(void);
void ghost_unlock_pkvm_vm_table(void);

static inline void ghost_assert_vm_locked(struct ghost_vm *vm)
{
	hyp_assert_lock_held(vm->lock);
}

static inline void ghost_assert_vms_locked(void)
{
	hyp_assert_lock_held(&ghost_vms_hyp_lock);
}

static inline void ghost_assert_pkvm_vm_table_locked(void)
{
	hyp_assert_lock_held(&vm_table_lock);
}


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
 * struct ghost_running_state - Track who was running before entering pKVM
 * @guest_running: whether the current exception was from a guest, otherwise was from host.
 * @vm_handle: if guest_running, the opaque pKVM handle of the VM that was running.
 * @vcpu_index: if guest_running, the index of the vcpu in the VM with vm_handle which was running.
 */
struct ghost_running_state {
	bool guest_running;
	pkvm_handle_t vm_handle;
	u64 vcpu_index;
};

void ghost_cpu_running_state_copy(struct ghost_running_state *run_tgt, struct ghost_running_state *g_src);

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

void ghost_dump_state(struct ghost_state *g);

struct ghost_local_state *ghost_this_cpu_local_state(struct ghost_state *g);
/**
 * this_cpu_read_ghost_loaded_vcpu() - Get the loaded_hyp_vcpu for this CPU
 */
struct ghost_loaded_vcpu *this_cpu_ghost_loaded_vcpu(struct ghost_state *g);
struct ghost_registers *this_cpu_ghost_registers(struct ghost_state *g);
struct ghost_running_state *this_cpu_ghost_run_state(struct ghost_state *g);

//
// struct args_host_hvc_pkvm_host_share_hyp {
// 	u64 pfn;
// };
//
// // TODO lots more
//
// union args {
// 	struct args_host_hvc_pkvm_host_share_hyp host_hvc_pkvm_host_share_hyp;
// 	// TODO lots more
// };
//
// struct ghost_host_transition_label {
// 	enum __kvm_host_smccc_func kind;
// 	union args args;
// };


// (1) would be the most obvious thing in a paper-math spec, but here perhaps (2) is cleaner.  There could be a hybrid with a C type common across hcalls that have the same shape, i.e. involve 0, 1, or 2 guests, and 0 or 1 hosts

struct ghost_transition {
	enum __kvm_host_smccc_func kind;    // TODO: need the guest calls too
	//	struct ghost_state initial, final;
};

// with the initial and final abstract states, and exception return stuff, in that same type, or separated out?   Dunno; say with.

// we use the struct kvm_cpu_context host_ctxt; for register values on entry and exit to the C part of exception handler.  This struct might not be exactly what we want - maybe we don't have all it's parts all the time - but it's roughly right.   Is the host_ctxt left unchanged from the start of handle_trap to whenever we need to record the state?   I guess so.

// then we have have thread-local state that records the transition, at the right point within the locks - presumably that matches the idiomatic separation-logic spec, too.


// from the top: how should we be mixing computing the final state vs checking the final state?

// - we'll have thread-local storage struct ghost_host_transition tran   for each thread
// - at the start of handle_trap(), we'll write (thread-local storage) initial_state_captured = false
// - if we ever reach a take-pkvm/host/guest-locks point, we'll compute the abstract state (both the "real" abstract state and the recordings of the current stage 2's) with abstraction(&tran.initial), and write initial_stage_captured = true
// - ...and at the unlock point, recompute the abstract stage with abstraction(&tran.final)
// - back in handle_trap (and also at any other exit point, if they exist), if initial_stage_captured == false we'll compute the abstract state now
// - ...and compute the intended abstract state (without the "recordings" part), as a function of the initial abstract state and the host_ctxt
// - ...and check (a) equality between the non-recordings part of the captured and intended abstract states, and (b) the above check on the recordings part w.r.t. the non-recordings part of those (now known to be equal) two

// hmm, there's some writing of sysregs (directly, not in the host_ctxt) after unlocking the shared data, eg in host_inject_abort (called by handle_host_mem_abort).  So we need to record those after, not when we record the shared data.


// top-level spec ghost state

// the "master" common ghost state, shared but with its parts protected by the associated impl locks
extern struct ghost_state gs;

// thread-local ghost state, of which only the relevant parts are used within each transition
DECLARE_PER_CPU(struct ghost_state, gs_recorded_pre);
DECLARE_PER_CPU(struct ghost_state, gs_recorded_post);
DECLARE_PER_CPU(struct ghost_state, gs_computed_post);

DECLARE_PER_CPU(struct ghost_running_state, ghost_cpu_run_state);

// __this_cpu_read(g_initial)
// __this_cpu_ptr(&g_initial)


//struct ghost_state spec_handle_trap(struct ghost_state *g);

/**
 * ghost_record_pre() - Record the state on entry to pKVM
 * @ctxt: the context (saved registers) on entry to pKVM.
 */
void ghost_record_pre(struct kvm_cpu_context *ctxt);

/**
 * ghost_post() - Record and check the state just prior to the exception return
 * @ctxt: the context (saved registers) on exit from pKVM.
 */
void ghost_post(struct kvm_cpu_context *ctxt);

#define HANDLE_FUNC_STRING(x)	[__KVM_HOST_SMCCC_FUNC_##x] = #x
static const char *ghost_host_hcall_names[] = {
	/* ___kvm_hyp_init */
	HANDLE_FUNC_STRING(__kvm_get_mdcr_el2),
	HANDLE_FUNC_STRING(__pkvm_init),
	HANDLE_FUNC_STRING(__pkvm_create_private_mapping),
	HANDLE_FUNC_STRING(__pkvm_cpu_set_vector),
	HANDLE_FUNC_STRING(__kvm_enable_ssbs),
	HANDLE_FUNC_STRING(__vgic_v3_init_lrs),
	HANDLE_FUNC_STRING(__vgic_v3_get_gic_config),
	HANDLE_FUNC_STRING(__kvm_flush_vm_context),
	HANDLE_FUNC_STRING(__kvm_tlb_flush_vmid_ipa),
	HANDLE_FUNC_STRING(__kvm_tlb_flush_vmid),
	HANDLE_FUNC_STRING(__kvm_flush_cpu_context),
	HANDLE_FUNC_STRING(__pkvm_prot_finalize),

	HANDLE_FUNC_STRING(__pkvm_host_share_hyp),
	HANDLE_FUNC_STRING(__pkvm_host_unshare_hyp),
	HANDLE_FUNC_STRING(__pkvm_host_reclaim_page),
	HANDLE_FUNC_STRING(__pkvm_host_map_guest),
	HANDLE_FUNC_STRING(__kvm_adjust_pc),
	HANDLE_FUNC_STRING(__kvm_vcpu_run),
	HANDLE_FUNC_STRING(__kvm_timer_set_cntvoff),
	HANDLE_FUNC_STRING(__vgic_v3_save_vmcr_aprs),
	HANDLE_FUNC_STRING(__vgic_v3_restore_vmcr_aprs),
	HANDLE_FUNC_STRING(__pkvm_init_vm),
	HANDLE_FUNC_STRING(__pkvm_init_vcpu),
	HANDLE_FUNC_STRING(__pkvm_teardown_vm),
	HANDLE_FUNC_STRING(__pkvm_vcpu_load),
	HANDLE_FUNC_STRING(__pkvm_vcpu_put),
	HANDLE_FUNC_STRING(__pkvm_vcpu_sync_state),
};

#endif // _GHOST_SPEC_H


