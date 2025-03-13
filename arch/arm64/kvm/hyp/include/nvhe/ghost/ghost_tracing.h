#ifndef GHOST_TRACING_H
#define GHOST_TRACING_H

#include <asm/kvm_asm.h>

#define DECL_GHOST_HCALL_TEVENT(NAME)	GHOST_TRACE_##NAME = __KVM_HOST_SMCCC_FUNC_##NAME
enum ghost_trace_event {
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_share_hyp),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_unshare_hyp),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_map_guest),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_unmap_guest),
	DECL_GHOST_HCALL_TEVENT(__pkvm_relax_perms),
	DECL_GHOST_HCALL_TEVENT(__pkvm_wrprotect),
	DECL_GHOST_HCALL_TEVENT(__pkvm_dirty_log),
	DECL_GHOST_HCALL_TEVENT(__pkvm_tlb_flush_vmid),
	DECL_GHOST_HCALL_TEVENT(__kvm_adjust_pc),
	DECL_GHOST_HCALL_TEVENT(__kvm_vcpu_run),
	DECL_GHOST_HCALL_TEVENT(__kvm_timer_set_cntvoff),
	DECL_GHOST_HCALL_TEVENT(__vgic_v3_save_vmcr_aprs),
	DECL_GHOST_HCALL_TEVENT(__vgic_v3_restore_vmcr_aprs),
	DECL_GHOST_HCALL_TEVENT(__pkvm_init_vm),
	DECL_GHOST_HCALL_TEVENT(__pkvm_init_vcpu),
	DECL_GHOST_HCALL_TEVENT(__pkvm_start_teardown_vm),
	DECL_GHOST_HCALL_TEVENT(__pkvm_finalize_teardown_vm),
	DECL_GHOST_HCALL_TEVENT(__pkvm_reclaim_dying_guest_page),
	DECL_GHOST_HCALL_TEVENT(__pkvm_vcpu_load),
	DECL_GHOST_HCALL_TEVENT(__pkvm_vcpu_put),
	DECL_GHOST_HCALL_TEVENT(__pkvm_vcpu_sync_state),
	DECL_GHOST_HCALL_TEVENT(__pkvm_load_tracing),
	DECL_GHOST_HCALL_TEVENT(__pkvm_teardown_tracing),
	DECL_GHOST_HCALL_TEVENT(__pkvm_enable_tracing),
	DECL_GHOST_HCALL_TEVENT(__pkvm_swap_reader_tracing),
	DECL_GHOST_HCALL_TEVENT(__pkvm_enable_event),
	DECL_GHOST_HCALL_TEVENT(__pkvm_hyp_alloc_mgt_refill),
	DECL_GHOST_HCALL_TEVENT(__pkvm_hyp_alloc_mgt_reclaimable),
	DECL_GHOST_HCALL_TEVENT(__pkvm_hyp_alloc_mgt_reclaim),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_iommu_alloc_domain),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_iommu_free_domain),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_iommu_attach_dev),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_iommu_detach_dev),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_iommu_map_pages),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_iommu_unmap_pages),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_iommu_iova_to_phys),
	DECL_GHOST_HCALL_TEVENT(__pkvm_host_hvc_pd),
	DECL_GHOST_HCALL_TEVENT(__pkvm_stage2_snapshot),

	GHOST_TRACE_host_mem_abort,

	GHOST_TRACE_PRE,
	GHOST_TRACE_POST,
	GHOST_TRACE_POST_COMPUTE,
	GHOST_TRACE_POST_CHECK,

	/* top-level functions */
	GHOST_TRACE_record_and_check_abstraction_pkvm_pre,
	GHOST_TRACE_record_and_copy_abstraction_pkvm_post,
	GHOST_TRACE_record_and_check_abstraction_host_pre,
	GHOST_TRACE_record_and_copy_abstraction_host_post,
	GHOST_TRACE_record_abstraction_constants_pre,
	GHOST_TRACE_record_abstraction_constants_post,
	GHOST_TRACE_record_and_check_abstraction_vm_pre,
	GHOST_TRACE_record_and_copy_abstraction_vm_post,
	GHOST_TRACE_record_and_check_abstraction_vms_pre,
	GHOST_TRACE_record_and_copy_abstraction_vms_post,
	GHOST_TRACE_record_and_check_abstraction_local_state_pre,
	GHOST_TRACE_record_and_copy_abstraction_local_state_post,
	GHOST_TRACE_record_abstraction_loaded_vcpu_and_check_none,
};

static inline enum ghost_trace_event ghost_hcall_event(unsigned id, bool *is_valid)
{
	if (__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp <= id &&
	    id <= __KVM_HOST_SMCCC_FUNC___pkvm_stage2_snapshot)
	    *is_valid = true;
	return id;
}

static inline bool ghost_trace_event_is_enabled(enum ghost_trace_event event)
{
	switch (event) {
	case GHOST_TRACE___pkvm_relax_perms:
	case GHOST_TRACE___pkvm_wrprotect:
	case GHOST_TRACE___pkvm_dirty_log:
	case GHOST_TRACE___pkvm_tlb_flush_vmid:
	case GHOST_TRACE___kvm_adjust_pc:
	case GHOST_TRACE___kvm_timer_set_cntvoff:
	case GHOST_TRACE___vgic_v3_save_vmcr_aprs:
	case GHOST_TRACE___vgic_v3_restore_vmcr_aprs:
	case GHOST_TRACE___pkvm_host_iommu_alloc_domain:
	case GHOST_TRACE___pkvm_host_iommu_free_domain:
	case GHOST_TRACE___pkvm_host_iommu_attach_dev:
	case GHOST_TRACE___pkvm_host_iommu_detach_dev:
	case GHOST_TRACE___pkvm_host_iommu_map_pages:
	case GHOST_TRACE___pkvm_host_iommu_unmap_pages:
	case GHOST_TRACE___pkvm_host_iommu_iova_to_phys:
	case GHOST_TRACE___pkvm_host_hvc_pd:
	case GHOST_TRACE___pkvm_stage2_snapshot:
		return false;
	default:
		return true;
	}
}

/*
 * enter/exit of externally-called top-level ghost functions
 *
 * TODO: BS: replace this with for-upstream/pkvm-tracing machinery.
 */

void trace_ghost_enter(enum ghost_trace_event event);
void trace_ghost_exit(enum ghost_trace_event event);

#define GHOST_TRACE_STRING(x)	[GHOST_TRACE_##x] = #x
static const char *ghost_trace_event_names[] = {
	GHOST_TRACE_STRING(__pkvm_host_share_hyp),
	GHOST_TRACE_STRING(__pkvm_host_unshare_hyp),
	GHOST_TRACE_STRING(__pkvm_host_map_guest),
	GHOST_TRACE_STRING(__pkvm_host_unmap_guest),
	GHOST_TRACE_STRING(__pkvm_init_vm),
	GHOST_TRACE_STRING(__pkvm_init_vcpu),
	GHOST_TRACE_STRING(__pkvm_start_teardown_vm),
	GHOST_TRACE_STRING(__pkvm_finalize_teardown_vm),
	GHOST_TRACE_STRING(__pkvm_reclaim_dying_guest_page),
	GHOST_TRACE_STRING(__pkvm_vcpu_load),
	GHOST_TRACE_STRING(__pkvm_vcpu_put),
	GHOST_TRACE_STRING(__kvm_vcpu_run),
	GHOST_TRACE_STRING(__pkvm_hyp_alloc_mgt_refill),
	GHOST_TRACE_STRING(__pkvm_hyp_alloc_mgt_reclaimable),
	GHOST_TRACE_STRING(__pkvm_hyp_alloc_mgt_reclaim),
	GHOST_TRACE_STRING(host_mem_abort),
	GHOST_TRACE_STRING(PRE),
	GHOST_TRACE_STRING(POST),
	GHOST_TRACE_STRING(POST_COMPUTE),
	GHOST_TRACE_STRING(POST_CHECK),
	GHOST_TRACE_STRING(record_and_check_abstraction_pkvm_pre),
	GHOST_TRACE_STRING(record_and_copy_abstraction_pkvm_post),
	GHOST_TRACE_STRING(record_and_check_abstraction_host_pre),
	GHOST_TRACE_STRING(record_and_copy_abstraction_host_post),
	GHOST_TRACE_STRING(record_abstraction_constants_pre),
	GHOST_TRACE_STRING(record_abstraction_constants_post),
	GHOST_TRACE_STRING(record_and_check_abstraction_vm_pre),
	GHOST_TRACE_STRING(record_and_copy_abstraction_vm_post),
	GHOST_TRACE_STRING(record_and_check_abstraction_vms_pre),
	GHOST_TRACE_STRING(record_and_copy_abstraction_vms_post),
	GHOST_TRACE_STRING(record_and_check_abstraction_local_state_pre),
	GHOST_TRACE_STRING(record_and_copy_abstraction_local_state_post),
	GHOST_TRACE_STRING(record_abstraction_loaded_vcpu_and_check_none),
};

#endif /* GHOST_TRACING_H */