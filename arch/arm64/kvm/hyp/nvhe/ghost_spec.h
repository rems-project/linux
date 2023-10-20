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

// top-level spec types

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
 * struct ghost_vcpu - A single vcpu within a VM
 *
 * @loaded: whether this vcpu is currently loaded on a physical CPU
 *
 * the loaded field is redundant wrt the total set of (thread-local) loaded vcpus, but this matches pKVM's own data structures.
 * TODO: eventually this will also contain the register bank, if not running, which will be used by vcpu_run etc.
 *
 * Context: Protected by the parent VM's lock.
 */
struct ghost_vcpu {
	bool loaded;
};


/**
 * struct ghost_vm - A guest VM
 *
 * @vm_abstract_pgtable: an abstract mapping of the concrete guest pagetable
 * @nr_vcpus: the number of VCPUs this VM has
 * @vcpus: the table of ghost_vcpu objects, valid up to nr_vcpus
 * @pkvm_handle: the opaque pkvm-assigned handle corresponding to this guest
 * @lock: a reference to the internal VM lock in pkvm.
 *
 * Context: Protected by the VM's lock,
 *          the `lock` field should not be used to take the lock, only to check it for sanity checking of the spec machinery
 */
struct ghost_vm {
	abstract_pgtable vm_abstract_pgtable;
	u64 nr_vcpus;
	struct ghost_vcpu vcpus[KVM_MAX_VCPUS];
	pkvm_handle_t pkvm_handle;
	hyp_spinlock_t *lock;
};

/**
 * struct ghost_host - The host android/linux mapping
 *
 * @present: whether the parent ghost_state has some ghost host data
 * @host_abstract_pgtable_annot: if present, the annotated (invalid) parts of the host pgt with owner_id!=PKVM_ID_HOST
 * @host_abstract_pgtable_shared: if present, the valid parts of the host pgt with page state either PKVM_PAGE_SHARED_OWNED or PKVM_PAGE_SHARED_BORROWED
 * @host_abstract_pgtable_nonannot: if present, for debugging, the concrete parts of the table that are actually mapped right now.
 *
 * The host (intermediate-physical, although idmapped) address space is represented in two parts:
 *  - The annot mapping, which are all unmapped in the host, includes all parts of hyp_memory (all the non-device memory the kernel knows about) which are owned by pkvm or the guests and not shared with the host (all shared locations will always be mapped)
 *  - The shared mapping, which are accessible by the host, but either shared with another (i.e marked PKVM_PAGE_SHARED_OWNED) or shared by someone else with the host (marked PKVM_PAGE_SHARED_BORROWED)
 *
 * The nonannot isn't really in the host part of the abstract state (it's not computed by the next-abstract-state function);
 * it's just so we can do an approximation to the check of host Stage 2 translations that the "real spec" will do
 *
 * Context: Protected by the host's hyp lock.
 */
struct ghost_host {
	bool present;
	abstract_pgtable host_abstract_pgtable_annot;
	abstract_pgtable host_abstract_pgtable_shared;
	abstract_pgtable host_abstract_pgtable_nonannot;
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
 * struct ghost_register_state - per-CPU register state
 *
 * @present: whether the parent ghost state has some ghost register state for this CPU.
 * @ctxt: if present, the EL0/1 register values on entry/exit to the C.
 * @el2_sysregs: if present, ghost copy of the current value of the EL2 system registers.
 *
 * Not all the register values are present, but it's not explicitly marked which are,
 * although which are present should be constant for all present register states.
 *
 * Context: thread-local, so not protected by any lock.
 */
struct ghost_register_state {
	bool present;
	struct kvm_cpu_context ctxt;
	u64 el2_sysregs[GHOST_NR_SYSREGS];
};

/**
 * struct ghost_vm_slot - A slot in the VMS table
 *
 * @exists: whether this VM in the parent vm table slot contains a valid VM.
 * @handle: if exists, the pKVM-assigned VM handle this slot is for (the key).
 * @vm: if exists, the actual VM in this slot.
 *
 * Context: exists and handle are protected by the ghost vms table lock,
 *          the ghost vm itself is protected by that VM's lock.
 */
struct ghost_vm_slot {
	bool exists;
	pkvm_handle_t handle;
	struct ghost_vm vm;
};

/**
 * struct ghost_vms - Ghost VM table
 *
 * @present: whether this part of the ghost state is set
 * @table: if present, a dictionary of ```VM handle -> VM```, implemented as a table of slots.
 *
 * Code should not access .table directly, but through the abstract ghost_vms_* functions below.
 */
struct ghost_vms {
	bool present;
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
 * Must own the ghost vms table lock
 */
struct ghost_vm *ghost_vms_get(struct ghost_vms *vms, pkvm_handle_t handle);

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
 * Context: Must own the ghost vms table lock, panics if all slots were used up.
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
 * Must own the ghost vms table lock
 */
void ghost_vms_free(struct ghost_vms *vms, pkvm_handle_t handle);

/**
 * ghost_vms_is_valid_handle() - Checks that the guest associated with an opaque pkvm-assigned handle exists in the vm table
 *
 * Must own the ghost vms table lock
 */
bool ghost_vms_is_valid_handle(struct ghost_vms *vms, pkvm_handle_t handle);

/**
 * ghost_vm_clone_into_nomappings() - Copies all the fields (not mappings) from one VM slot to another
 *
 * Must own the ghost vms table lock, *and* both VMs locks
 */
void ghost_vm_clone_into_nomappings(struct ghost_vm *dest, struct ghost_vm *src);

/**
 * ghost_vm_clone_into() - Copies all the fields (including mappings) from one VM slot to another
 *
 * Must own the ghost vms table lock, *and* both VMs locks
 */
void ghost_vm_clone_into(struct ghost_vm *dest, struct ghost_vm *src);

void ghost_lock_vms_table(void);

void ghost_unlock_vms_table(void);

void ghost_assert_vms_table_locked(void);

/**
 * struct ghost_state - Ghost copy of the whole EL2 state
 *
 * @hyp_memory: abstract mapping interpretation of the hyp_memory array.
 * @pkvm: ghost EL2 hypervisor state, including EL2 Stage1 pagetables, protected by the pkvm hyp lock.
 * @host: ghost host pagetable state, protected by the host pgtable lock.
 * @regs: ghost copies of initial general-purpose and current system registers.
 * @vms: vm table, protected by the ghost vms table lock, with each inner vm protected by that vm's own lock.
 * @hyp_physvirt_offset: ghost copy of the global physical offset of physical memory within the hyp VA space.
 * @tag_lsb: ghost copy of the pKVM VA tag (NOT the one of the Host kernel).
 * @tag_val: ghost copy of the pKVM VA tag value (the random offset and the bit indicating whether we are
 *           in the top or bottom of the virtual address space).
 *           (again this is NOT the one of the Host kernel)
 * @loaded_hyp_vcpu: per-physical-cpu ghost copies of the state of the currently loaded vcpu.
 *
 * A ghost state may be partial, and only have some of the above fields present.
 * In that case, the ghost state is valid for those parts that are present,
 * and should match the real physical state for those parts.
 */
struct ghost_state {
	mapping hyp_memory;
	struct ghost_pkvm pkvm;
	struct ghost_host host;
	struct ghost_register_state regs; // TODO: make per-cpu
	struct ghost_vms vms;
	s64 hyp_physvirt_offset;
	u64 tag_lsb;
	u64 tag_val;
	struct ghost_loaded_vcpu loaded_hyp_vcpu[NR_CPUS];
};

/**
 * this_cpu_read_ghost_loaded_vcpu() - Get the loaded_hyp_vcpu for this CPU
 */
struct ghost_loaded_vcpu *this_cpu_ghost_loaded_vcpu(struct ghost_state *g);

/**
 * max number of recorded READ_ONCEs
 */
#define GHOST_MAX_RELAXED_READS 512

/**
 * struct ghost_read - A single relaxed read
 *
 * @phys_addr: the physical address read from.
 * @value: the actual value that was read.
 * @width: the size of the read, in bytes.
 */
struct ghost_read {
	u64 phys_addr;
	u64 value;
	u8 width;
};

/**
 * struct ghost_relaxed_reads - List of previously seen relaxed reads
 *
 * @len: count of stored relaxed reads.
 * @read_slots: the underlying buffer of ghost reads.
 *
 * The read_slots field contains an array of non-overlapping ghost_read objects, up to index len.
 * ghost_relaxed_reads_insert appends to this, and ghost_reads_get gets the corresponding read value
 */
struct ghost_relaxed_reads {
	size_t len;
	struct ghost_read read_slots[GHOST_MAX_RELAXED_READS];
};

void ghost_relaxed_reads_insert(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width, u64 value);
u64 ghost_relaxed_reads_get(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width);

#define GHOST_MAX_MEMCACHE_DONATIONS 16

/**
 * struct ghost_memcache_donations - List of memcache pages donated to hypervisor during call
 *
 * @len: count of donations
 * @pages: the underlying buffer of donated addresses.
 *
 * The slots field contains an array of donated pfns, up to index len.
 * ghost_memcache_donations_insert appends to this
 */
struct ghost_memcache_donations {
	size_t len;
	u64 pages[GHOST_MAX_MEMCACHE_DONATIONS];
};

void ghost_memcache_donations_insert(struct ghost_memcache_donations *ds, u64 pfn);

/**
 * struct ghost_call_data - Ghost copies of values seen by implementation
 *
 * @return_value: The final value (usually an errno) returned by the real implementation.
 * @relaxed_reads: The list of relaxed READ_ONCE()s performed by the implementation.
 * @memcache_donations: list of donated addresses
 *
 * To manage non-determinism in the spec,
 * we collect various non-deterministically decided values used by the implementation,
 * which can be dispatched on in the spec to resolve non-deterministic choices.
 */
struct ghost_call_data {
	u64 return_value;
	struct ghost_relaxed_reads relaxed_reads;
	struct ghost_memcache_donations memcache_donations;
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


#define GHOST_RECORD_MEMCACHE_DONATION(pfn) \
	ghost_memcache_donations_insert(&this_cpu_ptr(&gs_call_data)->memcache_donations, (u64)pfn)

#endif // _GHOST_SPEC_H


