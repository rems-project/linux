#ifndef _GHOST_RECORD_H
#define _GHOST_RECORD_H

#include <nvhe/pkvm.h> // struct pkvm_hyp_vm
#include <nvhe/ghost/ghost_state.h> // struct ghost_state, enum vm_field_owner

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
 * THIS_HCALL_IS(X) - Macro evaluating to 1 iff the name of current hcall is equal to the string X
 */
#define THIS_HCALL_IS(X) (0 == strcmp(__this_cpu_read(ghost_this_trap), (X)))

/*
 * The noisy printing is controlled separately,
 * A call can be checked but silently,
 * or printed noisly with diffs but not checked.
 */
DECLARE_PER_CPU(bool, ghost_print_this_hypercall);


void init_abstraction_common(void);
void init_abstraction_thread_local(void);
void record_abstraction_common(void);

//#ifdef IS_GHOST_SOURCE
void clear_abstraction_thread_local(void);
void clear_abstraction_vm_partial(struct ghost_state *g, pkvm_handle_t handle, enum vm_field_owner owner);
void record_and_check_abstraction_local_state_pre(struct kvm_cpu_context *ctxt);
void record_and_copy_abstraction_local_state_post(struct kvm_cpu_context *ctxt);
void record_abstraction_constants_pre(void);
void record_abstraction_constants_post(void);
void record_and_check_abstraction_pkvm_pre(void);
void record_and_check_abstraction_host_pre(void);
void record_abstraction_loaded_vcpu_and_check_none(void);
//#endif

void record_and_check_abstraction_vm_pre(struct pkvm_hyp_vm *vm);
void record_and_copy_abstraction_vm_post(struct pkvm_hyp_vm *vm);

void record_and_check_abstraction_vms_pre(void);
void record_and_copy_abstraction_vms_post(void);

void record_and_copy_abstraction_pkvm_post(void);
void record_and_copy_abstraction_host_post(void);

/**
 * ghost_machinery_enabled() - Whether we can start recording/checking the ghost_state (because pKVM has finished initialising).
 */
bool ghost_machinery_enabled(void);

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
 * ghost_record_pre() - Record the state on entry to pKVM
 * @ctxt: the context (saved registers) on entry to pKVM.
 * @guest_exit_code: if from a guest, the pKVM-computed guest exit code.
 *                   if not from a guest, must be 0.
 *
 * NOTE: Theoretically, this should be a snapshot of the state on exception entry,
 *       including the full saved register context, system registers, and vector offset.
 *       However, we insert this call into more convenient-to-edit places, and reconstruct
 *       that data from the pKVM-saved cpu context and exit code.
 */
// void ghost_record_pre(struct kvm_cpu_context *ctxt, u64 guest_exit_code);

/**
 * ghost_post() - Record and check the state just prior to the exception return
 * @ctxt: the context (saved registers) on exit from pKVM.
 */
// void ghost_post(struct kvm_cpu_context *ctxt);

#endif // _GHOST_RECORD_H
