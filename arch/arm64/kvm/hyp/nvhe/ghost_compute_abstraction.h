#ifndef _GHOST_COMPUTE_ABSTRACTION_H
#define _GHOST_COMPUTE_ABSTRACTION_H


#include "./ghost_spec.h"
// OLD
void record_abstraction(struct ghost_state *g);
void record_abstraction_shared_state(struct ghost_state *g);

// NEW
// functions exposed to non-ghost files
void init_abstraction_common(void);
void record_abstraction_common(void);
void clear_abstraction_thread_local(void);
void record_abstraction_regs_pre(struct kvm_cpu_context *ctxt);
void record_abstraction_regs_post(struct kvm_cpu_context *ctxt);
void record_abstraction_constants_pre(void);
void record_abstraction_constants_post(void);
void record_and_check_abstraction_pkvm_pre(void);
void record_and_check_abstraction_host_pre(void);
void record_and_check_abstraction_loaded_hyp_vcpu_pre(void);
void record_and_check_abstraction_vm_pre(struct pkvm_hyp_vm *vm);
void record_and_copy_abstraction_pkvm_post(void);
void record_and_copy_abstraction_host_post(void);
void record_and_copy_abstraction_loaded_hyp_vcpu_post(void);
void record_and_copy_abstraction_vm_post(struct pkvm_hyp_vm *vm);

// additional functions used only in ghost files
bool abstraction_equals_hyp_memory(struct ghost_state *g1, struct ghost_state *g2);
void copy_abstraction_regs(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_constants(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_hyp_memory(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_host(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_pkvm(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_vm(struct ghost_state *g_tgt, struct ghost_state *g_src, pkvm_handle_t handle);
void copy_abstraction_vms(struct ghost_state *g_tgt, struct ghost_state *g_src);


void record_abstraction_hyp_memory(struct ghost_state *g);
bool abstraction_equals_all(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre);

#endif // _GHOST_COMPUTE_ABSTRACTION_H

