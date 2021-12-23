#ifndef _GHOST_SPEC_H
#define _GHOST_SPEC_H

#include <../debug-pl011.h>
#include <../ghost_extra_debug-pl011.h>
//#include <nvhe/ghost_check_pgtables.h>
#include <nvhe/ghost_asm_ids.h>
#include <nvhe/ghost_misc.h>
#include <../ghost_pgtable.h>
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"


#include <nvhe/trap_handler.h>   // for DECLARE_REG
#include <asm/kvm_asm.h>    // for __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp etc
#include <asm/kvm_pkvm.h> // for KVM_MAX_PVMS

// top-level spec

// Should we have all the ghost state in one struct, or threaded around the implementation state? For local specifications (as in the earlier executable spec experiments), the latter is better, but for the top-level spec the former seems better.

// Should the abstract state be protected by the corresponding implementation spinlocks, or by new ones?  Say the former for now - it's in principle slightly ugly to conflate protection for the concrete and abstract states, but I think preferable not to have to think about how two sets of locks relate.  And I increasingly believe the abstract state should follow the locking granularity of the concrete state, otherwise instrumentation is difficult and complex.

// If it's true that each HVC and other exceptions can "almost" be regarded as a single atomic transition, from exception entry to ERET, then we can record and check each such, as a pair of top-level ghost_state values and the additional data of the exception "arguments" and return values.   The "almost" has to cover intermediate page-table contents during page-table manipulation, for which we want to just describe the safe envelopes of mappings.

// What exactly is the serialisation order of these transitions?  Do we need to angst about (e.g.) the ghost state for one VM being out of step, as it's separately modified by a parallel HVC?  We can only compute the entire ghost state from the concrete state when we hold _all_ the locks, which the unmodified implementation never does. The ghost state should be cleanly partitioned into the pieces protected by each implementation lock (or, really, each _combination_ of implementation locks?).

// Should we record the separate primitive parts of mappings (with no annotation etc data), or something closer to the implementation?   Previously I thought the former, in which these mappings are mathematically just partial finite maps from page addresses to permissions, e.g.
//
//	mapping pkvm_mapping_shared_by_host;
//	mapping pkvm_mapping_donated_by_host;
//	mapping host_mapping_core;
//
// but switching to an abstract state following the concrete-state granularity suggests instead we should just have a
//
//	mapping host_mapping;
//
// that includes an abstract view of both the mapped and annotation parts of the concrete state.

// Roughly speaking, we think of the pKVM implementation of handle_trap() (the pKVM C code) as defining a transition relation  c --> c'  where c and c' range over the concrete state of the pKVM part of the machine, at some serialisation points   (this ignores interation via parts of that state shared with the host or guests, which we do have to deal with, but lets suppose for now that that can all be viewed as interleaved with atomic transitions of handle_trap())

// then in general the spec could be an arbitrary predicate P(c,c')

// but expressing it directly as such would be awkward, as (1) it would involve a lot of finickety detail about the concrete representation embodied in c and c', and (2) checking it would require one to copy the entire implementation state (which we _could_ do, and it'd be amusingly outrageous, but I don't see that it'd be a good idea)

// so instead we express the spec in terms of some abstract states a, with a transition relation a --> a' and an abstraction relation  c R a, so that a concrete transition c --> c' is allowed if there are a,a' such that
//     a --> a'
//     R     R
//     c --> c'

// Should the abstract state include enough information to _determine_ the Stage 2 translation functions, with the abstract transition relation loose enough, or just the loose constraints on those functions?  In a sense the former would be bogus, as during page-table mutations we only have the bounds in any case...

// Thinking about the abstraction relation, does the abstract state need to maintain information which is not determined by the concrete state?   For example, one might want to express the spec in terms of parts which are separately definable in terms of the history of API interactions, but are glommed together in the concrete state.   For pKVM, I don't think it has to, as the concrete state records donation, sharing, etc. - but in general it'd be ok if it did.  If so, one would change the above to require some initial-state a0 R c0 and then transitions from there, rather than locally existentially quantified

// A different possible reason would be if one wants to work up to some equivalence on abstract states.  I don't see why (at least for the math version of abstract states).

// So the abstraction relation can really be a function a = F(c), that we can compute (reified as C code)

//     a --> a'
//     F     F
//     c --> c'

// Thinking about the abstract transition relation, do the API calls have deterministic behaviour on the abstract state?   Where they do, we can express the abstract transition relation as a function (also reified as C code) that computes _the_ new intended abstract state from the old abstract state (and the host_ctxt inputs), and test the above holds of the implementation by computing the new actual abstract state from the new concrete state (with the abstraction function) and then comparing equality of those abstract states.  Where they don't, we have to model with C code that computes a (boolean) property of the old abstract state and the result of the abstraction function on the new concrete state (and then use that result as the starting point for the next step)  (which also means we have to be able to run the abstraction function for arbitrary reachable-during-execution concrete states, not just the initial state).   All this might differ for different parts of the abstract state.   The second (checking) scheme is more general, and I think we have no big reason to make the abstract model executable in itself - but OTOH where we can express the construction of the new abstract state functionally, that's probably clearer.  Still not really sure which.

// off the top of my head, I see two ways in which we have to be loose:
// (1) the concrete host memory mapping after a host memory abort step has (we believe) to be allowed to be any submapping of the intended upper bound.  For this, the abstract state could record just the upper bound, and the postcondition check check inclusion, not identity.  But we have to record the abstraction of the concrete mapping at the same right point as we compute the other abstract state.
// (2) not sure about the host device mapping - the concrete result can depend on allocation failures - but I guess we can and should just be loose in the same way as the host memory mapping

// I don't think there's any other implementation looseness or nondeterministic choice that leaks into the abstract state. Perhaps memory allocation failures for device mappings, but that could be absorbed into the same looseness as above. If there were, we'd have to make the resulting abstract state of a transition depend on it.

// So the ghost_host shouldn't include a "host_mapping_core" component?  But then (this is an amusing fine point in the spec design) should the spec's host stage2 be stable inbetween hypervisor invocations?  Maybe it doesn't matter much, but I guess nicer to be stable - then the ghost_host should include a host_mapping_all, which is just the interpretation of the concrete state, and we just assert it's a submapping of the upper bound.   Or we only maintain the upper bound, and let each occurrence of a host stage2 fault, separately nondeterministically.

// The abstract host/guest/pkvm stage 2 mappings are what the spec should use in place of the ASL stage 2 - though that doesn't appear in the C reasoning.

// So the abstract state should be partitioned into two parts:
// (1) part that can be functionally computed from the previous abstract state and host_ctxt arguments
// (2) part that's just the interpretation of the concrete stage 2 mappings


// if the calls are serialisable and simply locked, we can compute and save the abstract state in the main-body code at the lock/unlock points, and then check them in the postcondition - the saving _has_ to be intertwined with the code, but the checking function definition can be standalone.  If they're not, we have to do something more complex (perhaps partitioning up the concrete and abstract states in corresponding ways?) - but I don't know what, and it doesn't seem useful to think about it right now.

// presumably some calls will (on failure paths) never get to those lock-taking points.  Do we need to preemptively compute and record the state on entry to handle_trap, and then do it again (overwriting) if-and-when we get to those points?  I guess so.


struct ghost_vcpu {
	bool present;
};

struct ghost_vm {
	bool present;
	mapping vm_mapping; // the interpretation of the current concrete mapping
	struct ghost_vcpu vcpus[KVM_MAX_VCPUS];
};

struct ghost_host {
	mapping host_mapping_upper_bound;
	mapping host_mapping; // the interpretation of the current concrete mapping
};

struct ghost_state {
	struct kvm_cpu_context host_ctxt;    // register values on entry or exit to the C part of exception handler
	u64 sysregs[GHOST_NR_SYSREGS];       // overlap with the above?  but the above is mostly EL0/1 regs. We don't need all these sysregs, either
	mapping hyp_memory;                  // constant after initialisation - the interpretation of hyp_memory[]
	mapping pkvm_mapping;                // the interpretation of the current concrete mapping, protected by the pkvm lock
	struct ghost_host host;              // protected by the host lock
	struct ghost_vm vms[KVM_MAX_PVMS];   // protected by each VM lock
};


// TP: do we want to build into the shape of the ghost state that much of this is per system not per cpu?  PS: The recording has to be per-CPU, into thread-local variables - but the abstract state should be per-system, and we do need to check that the last state of one transition is equal to the initial state of the serialisation-order next

// should we factor the interpretations of the current concrete mappings (pkvm_mapping, host->host_mapping, and vms[_].vm_mapping) out into some separate struct, so that the function that computes the other parts of a new abstract state from the old abstract state can have a precise C type?  Not sure - it'd be morally cleaner to factor them out, but maybe gratuitously noisy.  For now, have that function compute a ghost state with each of the _recorded members empty.

// do we want the spec checking to check the recorded mappings against the individual components of the abstract-state mappings, or just the whole things?   More discriminating to do the former.


// transitions

// do we want an internal representation of the various transitions?  I guess so, so that we can record a transition explicitly at the relevant point in the implementation code.

// But then how should that relate to a "from the top" top-level spec, that will have to duplicate the dispatching of the implementation?  That duplication of dispatch seems inevitable - unless we can set up a scheme in which both "essentially spec" leaf functions can be automatically viewed as specs, as we've discussed before, _and_ "essentially spec" _program context_ can be automatically viewed as specs. Hmm... there's something semantically interesting going on there, no...?  But for now maybe we should just punt, duplicating that code as necessary, to make a clean standalone top-level spec. There's not that much dispatch code down to the distinct transitions, after all.


// should we be indexing transitions by a new enum, glomming the host and guest transitions together?  On each h/w thread (except when running pKVM) it's either the host or a specific guest running; pKVM knows which, and switches exception handlers. No - rather than our own enum(s), better to reuse the C enum, arch/arm64/include/asm/kvm_asm.h:enum __kvm_host_smccc_func, and the #define'd include/linux/arm-smccc.h:ARM_SMCC_KVM_FUNC_MEM_SHARE etc. for the guest.


// do we want (1) a C type of the arguments of each hypercall, or (2) just to use the (arch/arm64/include/asm/kvm_host.h) struct kvm_cpu_context *host_ctxt that contains all the host register values on entry to handle_hcall ?   For the former, it's a bit ugly in the C type system; we'd need something like this:
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
	struct ghost_state initial, final;
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



DECLARE_PER_CPU(struct ghost_state, g_recorded_backstop);
DECLARE_PER_CPU(struct ghost_state, g_recorded_pre);
DECLARE_PER_CPU(struct ghost_state, g_recorded_post);
DECLARE_PER_CPU(bool, g_recorded_pre_present);

// __this_cpu_read(g_initial)
// __this_cpu_ptr(&g_initial)


struct ghost_state spec_handle_trap(struct ghost_state *g);




#endif // _GHOST_SPEC_H


https://github.com/rems-project/riscv-isa-manual/blob/sail/release/riscv-spec-sail-draft.pdf
