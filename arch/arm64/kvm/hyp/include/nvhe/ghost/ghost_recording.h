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

void init_abstraction_common(void);
void init_abstraction_thread_local(void);
void record_abstraction_common(void);

void record_and_check_abstraction_pkvm_pre(void);
void record_and_copy_abstraction_pkvm_post(void);

void record_and_check_abstraction_host_pre(void);
void record_and_copy_abstraction_host_post(void);

void record_abstraction_constants_pre(void);
void record_abstraction_constants_post(void);

void record_and_check_abstraction_vm_pre(struct pkvm_hyp_vm *vm);
void record_and_copy_abstraction_vm_post(struct pkvm_hyp_vm *vm);

void record_and_check_abstraction_vms_pre(void);
void record_and_copy_abstraction_vms_post(void);

void record_and_check_abstraction_local_state_pre(struct kvm_cpu_context *ctxt);
void record_and_copy_abstraction_local_state_post(struct kvm_cpu_context *ctxt);

void record_abstraction_loaded_vcpu_and_check_none(void);


/**
 * ghost_machinery_enabled() - Whether we can start recording/checking the ghost_state (because pKVM has finished initialising).
 */
bool ghost_machinery_enabled(void);

#endif // _GHOST_RECORD_H
