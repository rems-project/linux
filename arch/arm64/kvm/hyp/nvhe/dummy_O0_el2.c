// Dummy definitions to produce a fully linked EL2 binary for analysis.
#define KVM_NVHE_ALIAS(sym)	unsigned long sym
#define KVM_NVHE_ALIAS_HYP(x,y)	unsigned long __kvm_nvhe_##y
// XXX: Following imported directly from image-vars.h
///////////////////////////////////////////////////////

/*
 * KVM nVHE code has its own symbol namespace prefixed with __kvm_nvhe_, to
 * separate it from the kernel proper. The following symbols are legally
 * accessed by it, therefore provide aliases to make them linkable.
 * Do not include symbols which may not be safely accessed under hypervisor
 * memory mappings.
 */

/* Alternative callbacks for init-time patching of nVHE hyp code. */
KVM_NVHE_ALIAS(kvm_patch_vector_branch);
KVM_NVHE_ALIAS(kvm_update_va_mask);
KVM_NVHE_ALIAS(kvm_get_kimage_voffset);
KVM_NVHE_ALIAS(kvm_compute_final_ctr_el0);
KVM_NVHE_ALIAS(spectre_bhb_patch_loop_iter);
KVM_NVHE_ALIAS(spectre_bhb_patch_loop_mitigation_enable);
KVM_NVHE_ALIAS(spectre_bhb_patch_wa3);
KVM_NVHE_ALIAS(spectre_bhb_patch_clearbhb);
KVM_NVHE_ALIAS(alt_cb_patch_nops);

/* Global kernel state accessed by nVHE hyp code. */
KVM_NVHE_ALIAS(kvm_vgic_global_state);

/* Kernel symbols used to call panic() from nVHE hyp code (via ERET). */
KVM_NVHE_ALIAS(nvhe_hyp_panic_handler);

/* Vectors installed by hyp-init on reset HVC. */
KVM_NVHE_ALIAS(__hyp_stub_vectors);

/* Static keys which are set if a vGIC trap should be handled in hyp. */
KVM_NVHE_ALIAS(vgic_v2_cpuif_trap);
KVM_NVHE_ALIAS(vgic_v3_cpuif_trap);

#if defined(CONFIG_ARM64_PSEUDO_NMI) || defined(CONFIG_NVHE_EL2_O0)
/* Static key checked in GIC_PRIO_IRQOFF. */
KVM_NVHE_ALIAS(gic_nonsecure_priorities);
#endif

/* EL2 exception handling */
KVM_NVHE_ALIAS(__start___kvm_ex_table);
KVM_NVHE_ALIAS(__stop___kvm_ex_table);

/* PMU available static key */
#ifdef CONFIG_HW_PERF_EVENTS
KVM_NVHE_ALIAS(kvm_arm_pmu_available);
#endif

/* Position-independent library routines */
KVM_NVHE_ALIAS_HYP(clear_page, __pi_clear_page);
KVM_NVHE_ALIAS_HYP(copy_page, __pi_copy_page);
KVM_NVHE_ALIAS_HYP(memcpy, __pi_memcpy);
KVM_NVHE_ALIAS_HYP(memset, __pi_memset);

#ifdef CONFIG_KASAN
KVM_NVHE_ALIAS_HYP(__memcpy, __pi_memcpy);
KVM_NVHE_ALIAS_HYP(__memset, __pi_memset);
#endif

/* Hyp memory sections */
KVM_NVHE_ALIAS(__hyp_idmap_text_start);
KVM_NVHE_ALIAS(__hyp_idmap_text_end);
KVM_NVHE_ALIAS(__hyp_text_start);
KVM_NVHE_ALIAS(__hyp_text_end);
KVM_NVHE_ALIAS(__hyp_bss_start);
KVM_NVHE_ALIAS(__hyp_bss_end);
KVM_NVHE_ALIAS(__hyp_data_start);
KVM_NVHE_ALIAS(__hyp_data_end);
KVM_NVHE_ALIAS(__hyp_rodata_start);
KVM_NVHE_ALIAS(__hyp_rodata_end);
#ifdef CONFIG_TRACING
KVM_NVHE_ALIAS(__hyp_event_ids_start);
KVM_NVHE_ALIAS(__hyp_event_ids_end);
KVM_NVHE_ALIAS(__hyp_printk_fmts_start);
#endif

/* pKVM static key */
KVM_NVHE_ALIAS(kvm_protected_mode_initialized);

#ifdef CONFIG_NVHE_EL2_O0
KVM_NVHE_ALIAS(system_cpucaps);
#endif /* CONFIG_NVHE_EL2_O0 */

