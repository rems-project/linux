#ifndef __KVM_HYP_GHOST_MAPPING_REQS_H
#define __KVM_HYP_GHOST_MAPPING_REQS_H

#include <asm/kvm_asm.h>
//#include "../../ghost_pgtable.h"


#define GHOST

enum mapping_req_kind {
        HYP_NULL,
        HYP_TEXT,
        HYP_DATA,
        HYP_RODATA,
        HYP_BSS,
        HYP_VGIC,
        HYP_IDMAP,
        HYP_STACKS,
        HYP_VMEMMAP,
        HYP_S1_PGTABLE,
        HYP_S2_PGTABLE,
        HYP_WORKSPACE,
        HYP_VMEMMAP_MAP,
        HYP_UART,
	HYP_PVMFW,
	HYP_BP_HARDEN_HYP_VECS,
        HYP_PERCPU,
	HYP_MODULE,
	HYP_HCALL,
	HYP_DEVICE,
        HYP_HOST_RODATA,
        HYP_HOST_BSS,
        HYP_MAPPING_REQ_KIND_NUMBER=HYP_PERCPU
};

#define MAX_MAPPING_REQS HYP_MAPPING_REQ_KIND_NUMBER -1 + NR_CPUS

#define DUMMY_CPU 0


void ghost_record_mapping_req_virt(void *from, void *to, enum kvm_pgtable_prot prot, enum mapping_req_kind kind, u64 cpu);
void ghost_record_mapping_req(unsigned long start, unsigned long size,
			unsigned long phys, enum kvm_pgtable_prot prot, enum mapping_req_kind kind);
void ghost_hyp_put_mapping_reqs(void);
//void ghost_newer_dump_pgtable(struct kvm_pgtable *pg, char *doc);
//void ghost_newer_record_pgtable(struct list_head *maplets_list_pre, struct kvm_pgtable *pg, char *doc);
//void ghost_newer_dump_pgtable_diff(struct list_head *maplets_list_pre, struct kvm_pgtable *pg, char *doc);
void ghost_dump_hyp_memory(u64 i);

//void ghost_newer_record_pgtable_2(struct list_head *maplets_list, kvm_pte_t *pgtable, u64 level, u64 va_partial, char *doc);

void record_hyp_mapping_reqs(phys_addr_t phys, uint64_t size, uint64_t nr_cpus, unsigned long *per_cpu_base);
#define CHECK_QUIET false
#define CHECK_NOISY true
void ghost_check_hyp_mapping_reqs(struct kvm_pgtable *pg, bool noisy);
void dump_pgtable(struct kvm_pgtable pg);





#endif /* __KVM_HYP_GHOST_MAPPING_REQS_H */
