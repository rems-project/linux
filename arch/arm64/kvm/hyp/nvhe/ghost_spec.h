#ifndef _GHOST_SPEC_H
#define _GHOST_SPEC_H

#include <../debug-pl011.h>
#include <../ghost_extra_debug-pl011.h>
//#include <nvhe/ghost_check_pgtables.h>
#include <nvhe/ghost_asm_ids.h>
#include <nvhe/ghost_misc.h>
#include <../ghost_pgtable.h>
#include <nvhe/spinlock.h>
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#include <nvhe/trap_handler.h>   // for DECLARE_REG
#include <asm/kvm_asm.h>    // for __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp etc
#include <asm/kvm_pkvm.h> // for KVM_MAX_PVMS

// assertion to check invariants of the ghost instrumentation, which should never fail
#define ghost_assert(c) BUG_ON(!(c));

// assertion to check the spec
#define ghost_spec_assert(c) BUG_ON(!(c));
// from nvhe/pkvm.c
// the vm handles are vm table indexes + HANDLE_OFFSET
#define HANDLE_OFFSET 0x1000

// top-level spec types
struct ghost_loaded_vcpu {
	bool present;
	bool loaded;  // if there is a currently loaded vcpu
	pkvm_handle_t vm_handle; // if loaded, the VM handle
	u64 vcpu_index; // if loaded, the vcpu index within the VM
};

struct ghost_vcpu {
	bool exists; // the vm.vcpus table is up to KVM_MAX_VCPUS but only the first nr_vcpus are present
	bool loaded;  // if currently loaded on some physical CPU
};


/**
 * struct ghost_vm - Ghost copy of a guest VMs state
 *
 * @exists: whether this VM in the parent vm table slot contains a valid VM
 * @vm_abstract_pgtable: an abstract mapping of the concrete guest pagetable
 * @nr_vcpus: the number of VCPUs this VM has
 * @vcpus: the table of ghost_vcpu objects, valid up to nr_vcpus
 * @pkvm_handle: the opaque pkvm-assigned handle corresponding to this guest
 * @lock: a reference to the internal VM lock in pkvm.
 *
 * Protected by the VM's lock
 * the `lock` field should not be used to take the lock, only to check it
 */
struct ghost_vm {
	bool exists; // the vm is referenced in the vm_table[] array
	abstract_pgtable vm_abstract_pgtable;                  // the interpretation of the current concrete mapping
	u64 nr_vcpus;
	struct ghost_vcpu vcpus[KVM_MAX_VCPUS];     // table of vcpus, only `present` up to nr_vcpus, NOTE: ordered same as real pkvm vm.hyp_vcpu table
	pkvm_handle_t pkvm_handle; // pKVM-assigned handle
	hyp_spinlock_t *lock;
};

/**
 * struct ghost_host - Ghost copy of the host android/linux state
 * @present: whether the parent ghost_state has some ghost host data
 * @host_abstract_pgtable_annot: the annotated (invalid) parts of the host pgt with owner_id!=HOST
 * @host_abstract_pgtable_shared: the valid parts of the host pgt with page state either SHARED_OWNED or SHARED_BORROWED
 * @host_abstract_pgtable_nonannot: for debugging, the concrete parts of the table that are actually mapped right now.
 *
 * The host (intermediate-physical, although idmapped) address space is represented in two parts:
 *  - The annot mapping, which are all parts of physical space, which are owned by pkvm or the guests, and not shared with the host
 *  - The shared mapping, which are accessible by the host, but either shared with another (i.e marked SHARED_OWNED) or shared by someone else with the host (marked SHARED_BORROWED)
 */
struct ghost_host {                          // abstraction of state protected by the host lock
	bool present;
	abstract_pgtable host_abstract_pgtable_annot;           // the first two are the real host part of the abstract state
	abstract_pgtable host_abstract_pgtable_shared;          // 
	abstract_pgtable host_abstract_pgtable_nonannot;        // this isn't really in the host part of the abstract state (it's not computed by the next-abstract-state function); it's just so we can do an approximation to the check of host Stage 2 translations that the "real spec" will do};
};

struct ghost_pkvm {                          // abstraction of state protected by the pkvm lock
	bool present;
	abstract_pgtable pkvm_abstract_pgtable;                // the interpretation of the current concrete mapping
};

struct ghost_register_state {
	bool present;
	struct kvm_cpu_context ctxt;         // EL0/1 register values on entry or exit to the C part of exception handler (NB: not all elements are live)
	u64 el2_sysregs[GHOST_NR_SYSREGS];   // EL2 register values (NB: not all elements are live)
};

/**
 * struct ghost_vms - Ghost VM table
 *
 * @present: whether this part of the ghost state is set
 * @table: the underlying (unordered) table of VMs, unordered, and each protected by the corresponding pkvm vm lock
 *
 * Code should not access .table directly, but through the abstract ghost_vms_* functions.
 */
struct ghost_vms {
	bool present;
	struct ghost_vm table[KVM_MAX_PVMS];
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
 * Must own the ghost vms lock
 */
struct ghost_vm *ghost_vms_get(struct ghost_vms *vms, pkvm_handle_t handle);

/**
 * ghost_vms_alloc() - Get a reference to a fresh (empty) ghost_vm in the table
 *
 * @vms: ghost vm table
 *
 * Return:
 *  A reference to an empty vm slot that can be used.
 *  is marked non-empty on return
 *
 * Must own the ghost vms lock
 */
struct ghost_vm *ghost_vms_alloc(struct ghost_vms *vms);

/**
 * ghost_vms_get_default() - Get a reference to the ghost_vm in the table, creating one if it doesn't exist
 *
 * @vms: ghost vm table
 * @handle: the pkvm-defined opaque VM handle
 *
 * Return:
 *  - Reference to the existing-or-newly-created ghost_vm*
 *
 * Must own the ghost vms lock
 */
struct ghost_vm *ghost_vms_get_default(struct ghost_vms *vms, pkvm_handle_t handle);

/**
 * ghost_vm_clear() - Clears a VM slot back to default state
 *
 * @vm: the vm to clean
 *
 * Marks the slot empty.
 *
 * Must own the VM lock
 */
void ghost_vm_clear(struct ghost_vm *vm);

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
 * ghost_vm_clone_into_nomappings() - Copies all the fields (not mappings) from one VM slot to another
 *
 * Must own the ghost vms lock, *and* both VMs locks
 */
void ghost_vm_clone_into_nomappings(struct ghost_vm *dest, struct ghost_vm *src);

/**
 * ghost_vm_clone_into() - Copies all the fields (including mappings) from one VM slot to another
 *
 * Must own the ghost vms lock, *and* both VMs locks
 */
void ghost_vm_clone_into(struct ghost_vm *dest, struct ghost_vm *src);

void ghost_lock_vms(void);
void ghost_unlock_vms(void);
void ghost_assert_vms_locked(void);

struct ghost_state {
	mapping hyp_memory;                    // constant after initialisation - the interpretation of hyp_memory[]
	struct ghost_pkvm pkvm;                // protected by the pkvm lock
	struct ghost_host host;                // protected by the host lock
	struct ghost_register_state regs;      // register bank
	struct ghost_vms vms;                  // protected by the vm_table lock
	s64 hyp_physvirt_offset;               // constant after initialisation - the value of hyp_physvirt_offset
	struct ghost_loaded_vcpu loaded_hyp_vcpu[NR_CPUS];  // loaded vcpu, as a VM+VCPU index pair
};

/**
 * max number of recorded READ_ONCEs
 */
#define GHOST_MAX_RELAXED_READS 512

/**
 * struct ghost_read - A single relaxed read
 *
 * @phys_addr: the physical address read from
 * @value: the actual value that was read
 * @width: the size of the read, in bytes
 */
struct ghost_read {
	u64 phys_addr;
	u64 value;
	u8 width;
};

/**
 * struct ghost_relaxed_reads - List of previously seen relaxed reads
 *
 * @len: count of stored relaxed reads
 * @read_slots: the underlying buffer of ghost reads
 *
 * read_slots contains an array of non-overlapping ghost_read objects, up to index len
 * then ghost_relaxed_reads_insert appends to this, and ghost_reads_get gets the corresponding read value
 */
struct ghost_relaxed_reads {
	size_t len;
	struct ghost_read read_slots[GHOST_MAX_RELAXED_READS];
};

void ghost_relaxed_reads_insert(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width, u64 value);
u64 ghost_relaxed_reads_get(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width);

/**
 * struct ghost_call_data - Ghost copies of values from implementation
 *
 * To manage non-determinism in the implementation when writing the spec,
 * we collect various non-deterministically decided values
 * picked by the implementation
 *
 * @return_value: The final errno returned by the real implementation
 * @relaxed_reads: The list of relaxed READ_ONCE()s performed by the implementation.
 */
struct ghost_call_data {
	u64 return_value;
	struct ghost_relaxed_reads relaxed_reads;
};


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

// whether each CPU has finished its __pkvm_prot_finalize
extern hyp_spinlock_t ghost_prot_finalized_lock;
extern _Bool pkvm_prot_finalized_cpu[NR_CPUS];
extern _Bool pkvm_prot_finalized_all;
// TODO: do we need more synchronisation for accesses to the last of those?


// the "master" common ghost state, shared but with its parts protected by the associated impl locks
extern struct ghost_state gs;

// thread-local ghost state, of which only the relevant parts are used within each transition
DECLARE_PER_CPU(struct ghost_state, gs_recorded_pre);
DECLARE_PER_CPU(struct ghost_state, gs_recorded_post);
DECLARE_PER_CPU(struct ghost_state, gs_computed_post);

/**
 * gs_call_data - per-thread storage of data collected during the hypercall
 */
DECLARE_PER_CPU(struct ghost_call_data, gs_call_data);

/**
 * ghost_clear_call_data - Resets this CPU's recorded hypercall data back to empty
 */
void ghost_clear_call_data(void);

// __this_cpu_read(g_initial)
// __this_cpu_ptr(&g_initial)


//struct ghost_state spec_handle_trap(struct ghost_state *g);

// macros to make ghost register accesses more uniform
#define ghost_reg_gpr(g,r) g->regs.ctxt.regs.regs[r]
#define ghost_reg_el2(g,r) g->regs.el2_sysregs[r]
//#define ghost_reg_ctxt(g,r)


void compute_new_abstract_state_handle_trap(struct ghost_state *g1 /*new*/, struct ghost_state *g0 /*old*/, struct ghost_call_data *call, bool *new_state_computed);

/**
 * READ_ONCE_GHOST_RECORD(ptr) - Perform a READ_ONCE(ptr) but remember the address and value in the ghost state.
 */
#define READ_ONCE_GHOST_RECORD(x) \
	({ \
		typeof(x) v = READ_ONCE(x); \
		ghost_relaxed_reads_insert( \
			&this_cpu_ptr(&gs_call_data)->relaxed_reads, \
			(u64)&x, \
			sizeof(typeof(x)), \
			v \
		); \
		v; \
	})

/**
 * GHOST_READ_ONCE(x) - Behaves like READ_ONCE(x) but recalls the previously read value from the ghost state
 */
#define GHOST_READ_ONCE(gcd, x) \
	({ \
		ghost_relaxed_reads_get(&gcd->relaxed_reads, (u64)&x, sizeof(typeof(x))); \
	})


/**
 * GHOST_SPEC_DECLARE_REG()
 */
#define GHOST_SPEC_DECLARE_REG(type, name, ctxt, reg)	\
				type name = (type)ghost_reg_gpr(ctxt, (reg))

#endif // _GHOST_SPEC_H


