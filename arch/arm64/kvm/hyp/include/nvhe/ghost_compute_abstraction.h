#ifndef _GHOST_COMPUTE_ABSTRACTION_H
#define _GHOST_COMPUTE_ABSTRACTION_H


#include <nvhe/ghost_spec.h>

// OLD
void record_abstraction(struct ghost_state *g);
void record_abstraction_shared_state(struct ghost_state *g);

// NEW
// functions exposed to non-ghost files
void init_abstraction_common(void);
void record_abstraction_common(void);
void clear_abstraction_thread_local(void);
void record_and_check_abstraction_local_state_pre(struct kvm_cpu_context *ctxt);
void record_and_copy_abstraction_local_state_post(struct kvm_cpu_context *ctxt);
void record_abstraction_constants_pre(void);
void record_abstraction_constants_post(void);
void record_and_check_abstraction_pkvm_pre(void);
void record_and_check_abstraction_host_pre(void);
void record_abstraction_loaded_vcpu_and_check_none(void);
void record_and_check_abstraction_loaded_hyp_vcpu_pre(void);
void record_and_check_abstraction_vms_pre(void);
void record_and_check_abstraction_vm_pre(struct pkvm_hyp_vm *vm);
void record_and_copy_abstraction_pkvm_post(void);
void record_and_copy_abstraction_host_post(void);
void record_and_copy_abstraction_loaded_hyp_vcpu_post(struct pkvm_hyp_vcpu *vcpu);
void record_and_copy_abstraction_vms_post(void);
void record_and_copy_abstraction_vm_post(struct pkvm_hyp_vm *vm);

// additional functions used only in ghost files
void copy_abstraction_regs(struct ghost_register_state *g_tgt, struct ghost_register_state *g_src);
void copy_abstraction_constants(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_host(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_pkvm(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_vms(struct ghost_state *g_tgt, struct ghost_state *g_src);
void copy_abstraction_vms_partial(struct ghost_state *g_tgt, struct ghost_state *g_src, enum vm_field_owner owner);
void copy_abstraction_vm_partial(struct ghost_state *g_tgt, struct ghost_state *g_src, pkvm_handle_t handle, enum vm_field_owner owner);
void copy_abstraction_local_state(struct ghost_local_state *l_tgt, struct ghost_local_state *l_src);

void check_abstraction_equals_all(
	struct ghost_state *gc,
	struct ghost_state *gr_post,
	struct ghost_state *gr_pre
);

void check_abstraction_pkvm_equals(
	struct ghost_pkvm *lhs,
	struct ghost_pkvm *rhs
);

void check_abstraction_equals_reg(struct ghost_register_state *r1, struct ghost_register_state *r2, bool check_sysregs);
void check_abstraction_equals_pkvm(struct ghost_pkvm *gp1, struct ghost_pkvm *gp2);
void check_abstraction_equals_host(struct ghost_host *gh1, struct ghost_host *gh2);
void check_abstraction_equals_loaded_vcpu(struct ghost_loaded_vcpu *loaded_vcpu1, struct ghost_loaded_vcpu *loaded_vcpu2);
void check_abstraction_equals_loaded_vcpus(struct ghost_state *g1, struct ghost_state *g2);
void check_abstraction_equals_vcpu(struct ghost_vcpu *vcpu1, struct ghost_vcpu *vcpu2);
void check_abstraction_equals_vm(struct ghost_vm *vm1, struct ghost_vm *vm2);
void check_abstraction_vms_subseteq(struct ghost_vms *gc, struct ghost_vms *gr_post);
void check_abstract_pgtable_equal(
	abstract_pgtable *pgt1,
	abstract_pgtable *pgt2,
	char* cmp_name,
	char* pgt1_name,
	char* pgt2_name,
	u64 indent
);


#endif // _GHOST_COMPUTE_ABSTRACTION_H

