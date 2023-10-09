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

// an opaque pKVM VM handle
typedef u64 pkvm_vm_handle_t;

// from nvhe/pkvm.c
// the vm handles are vm table indexes + HANDLE_OFFSET
#define HANDLE_OFFSET 0x1000

// top-level spec types
struct ghost_loaded_vcpu {
	bool present;
	bool loaded;  // if there is a currently loaded vcpu
	u64 vm_index; // if loaded, the VM index (in the ghost_state.vms table)
	u64 vcpu_index; // if loaded, the vcpu index within the VM
};

struct ghost_vcpu {
	bool exists; // the vm.vcpus table is up to KVM_MAX_VCPUS but only the first nr_vcpus are present
	bool loaded;  // if currently loaded on some physical CPU
};


struct ghost_vm {                            // abstraction of state protected by each VM lock
	bool present;
	bool exists; // the vm is referenced in the vm_table[] array
	abstract_pgtable vm_abstract_pgtable;                  // the interpretation of the current concrete mapping
	u64 nr_vcpus;
	struct ghost_vcpu vcpus[KVM_MAX_VCPUS];     // table of vcpus, only `present` up to nr_vcpus, NOTE: ordered same as real pkvm vm.hyp_vcpu table
	pkvm_vm_handle_t pkvm_handle; // pKVM-assigned handle
};

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

/// The table of VMs
/// technically not owed by the pkvm lock(!)
struct ghost_vms {
	bool present;
	struct ghost_vm vms[KVM_MAX_PVMS];     // protected by each VM lock, NOTE: ordered the same as pkvm's own vm_table.
};

struct ghost_state {
	mapping hyp_memory;                    // constant after initialisation - the interpretation of hyp_memory[]
	struct ghost_pkvm pkvm;                // protected by the pkvm lock
	struct ghost_host host;                // protected by the host lock
	struct ghost_register_state regs;      // register bank
	struct ghost_vms vms;                  // protected by the vm_table lock
	u64 vm_handle_offset;                  // vm handles are defined as index into vms.vms table + this offset
	s64 hyp_physvirt_offset;               // constant after initialisation - the value of hyp_physvirt_offset
	struct ghost_loaded_vcpu loaded_hyp_vcpu[NR_CPUS];  // loaded vcpu, as a VM+VCPU index pair
};


// some helper functions

/// Get the ghost vm from the pkvm-supplied vm handle
struct ghost_vm *ghost_vm_from_handle(struct ghost_state *g, pkvm_vm_handle_t handle);

/// Get the ghost vcpu from the pkvm-supplied vm handle and vcpu index within that vm
struct ghost_vcpu *ghost_vcpu_from_handle(struct ghost_state *g, pkvm_vm_handle_t handle, u64 vcpu_index);


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





// __this_cpu_read(g_initial)
// __this_cpu_ptr(&g_initial)


//struct ghost_state spec_handle_trap(struct ghost_state *g);

// macros to make ghost register accesses more uniform
#define ghost_reg_gpr(g,r) g->regs.ctxt.regs.regs[r]
#define ghost_reg_el2(g,r) g->regs.el2_sysregs[r]
//#define ghost_reg_ctxt(g,r)


void compute_new_abstract_state_handle_trap(struct ghost_state *g1 /*new*/, struct ghost_state *g0 /*old*/, u64 impl_return_value, bool *new_state_computed);


#endif // _GHOST_SPEC_H


