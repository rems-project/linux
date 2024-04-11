#ifndef _GHOST_SPEC_H
#define _GHOST_SPEC_H

#include <asm/kvm_asm.h> // for __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp etc

#include <nvhe/ghost/ghost_state.h>


/**
 * ghost_check_this_hypercall - Per-CPU check of whether to check the current hypercall
 * (SEE comment in ghost_recording.h)
 */
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


struct ghost_local_state *ghost_this_cpu_local_state(struct ghost_state *g);
/**
 * this_cpu_read_ghost_loaded_vcpu() - Get the loaded_hyp_vcpu for this CPU
 */
struct ghost_loaded_vcpu *this_cpu_ghost_loaded_vcpu(struct ghost_state *g);
struct ghost_registers *this_cpu_ghost_registers(struct ghost_state *g);
struct ghost_running_state *this_cpu_ghost_run_state(struct ghost_state *g);

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

// top-level spec ghost state

// the gs and gs_recorded_* are the ghost_state actually written to by the ghost_recording.h functions

// the "master" common ghost state, shared but with its parts protected by the associated impl locks
extern struct ghost_state gs;

// thread-local ghost state, of which only the relevant parts are used within each transition
DECLARE_PER_CPU(struct ghost_state, gs_recorded_pre);
DECLARE_PER_CPU(struct ghost_state, gs_recorded_post);
DECLARE_PER_CPU(struct ghost_state, gs_computed_post);

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
void ghost_record_pre(struct kvm_cpu_context *ctxt, u64 guest_exit_code);

/**
 * ghost_post() - Record and check the state just prior to the exception return
 * @ctxt: the context (saved registers) on exit from pKVM.
 */
void ghost_post(struct kvm_cpu_context *ctxt);

#endif // _GHOST_SPEC_H
