#ifndef __KVM_HYP_GHOST_MISC_H
#define __KVM_HYP_GHOST_MISC_H

void dump_kvm_nvhe_init_params(struct kvm_nvhe_init_params *params);
void ghost_dump_shadow_table(void);
void ghost_dump_sysregs(void);

// for setup.c
void ghost_dump_setup(void);
extern void *vmemmap_base;
extern void *hyp_pgt_base;
extern void *host_s2_pgt_base;
extern u64 ghost_vmemmap_size;
extern u64 ghost_shadow_table_size;
extern u64 ghost_hyp_pgt_size;
extern u64 ghost_host_s2_pgt_size;
extern u64 ghost__pkvm_init_phys;
extern u64 ghost__pkvm_init_size;
extern u64 ghost__pkvm_init_virt;

#endif /* __KVM_HYP_GHOST_MISC_H */
