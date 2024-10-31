/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Derived from arch/arm/include/asm/kvm_host.h:
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 */
#ifndef __PICOVM_HOST_H__
#define __PICOVM_HOST_H__

#include <picovm/prelude.h>

struct picovm_hyp_memcache {
	phys_addr_t head;
	unsigned long nr_pages;
};

struct picovm_vcpu_fault_info {
	u64 esr_el2;		/* Hyp Syndrom Register */
	u64 far_el2;		/* Hyp Fault Address Register */
	u64 hpfar_el2;		/* Hyp IPA Fault Address Register */
	u64 disr_el1;		/* Deferred [SError] Status Register */
};

static inline void push_hyp_memcache(struct picovm_hyp_memcache *mc,
				     phys_addr_t *p,
				     phys_addr_t (*to_pa)(void *virt))
{
	*p = mc->head;
	mc->head = to_pa(p);
	mc->nr_pages++;
}

static inline void *pop_hyp_memcache(struct picovm_hyp_memcache *mc,
				     void *(*to_va)(phys_addr_t phys))
{
	phys_addr_t *p = to_va(mc->head);

	if (!mc->nr_pages)
		return NULL;

	mc->head = *p;
	mc->nr_pages--;

	return p;
}

static inline int __topup_hyp_memcache(struct picovm_hyp_memcache *mc,
				       unsigned long min_pages,
				       void *(*alloc_fn)(void *arg),
				       phys_addr_t (*to_pa)(void *virt),
				       void *arg)
{
	while (mc->nr_pages < min_pages) {
		phys_addr_t *p = alloc_fn(arg);

		if (!p)
			return -ENOMEM;
		push_hyp_memcache(mc, p, to_pa);
	}

	return 0;
}

static inline void __free_hyp_memcache(struct picovm_hyp_memcache *mc,
				       void (*free_fn)(void *virt, void *arg),
				       void *(*to_va)(phys_addr_t phys),
				       void *arg)
{
	while (mc->nr_pages)
		free_fn(pop_hyp_memcache(mc, to_va), arg);
}

void free_hyp_memcache(struct picovm_hyp_memcache *mc);
int topup_hyp_memcache(struct picovm_hyp_memcache *mc, unsigned long min_pages);


struct picovm_vmid {
	atomic64_t id;
};

struct picovm_s2_mmu {
	struct picovm_vmid vmid;

	/*
	 * stage2 entry level table
	 *
	 * Two picovm_s2_mmu structures in the same VM can point to the same
	 * pgd here.  This happens when running a guest using a
	 * translation regime that isn't affected by its own stage-2
	 * translation, such as a non-VHE hypervisor running at vEL2, or
	 * for vEL1/EL0 with vHCR_EL2.VM == 0.  In that case, we use the
	 * canonical stage-2 page tables.
	 */
	phys_addr_t	pgd_phys;
	struct picovm_pgtable *pgt;

	/* The last vcpu id that ran on each physical CPU */
	int __percpu *last_vcpu_ran;

	struct picovm_arch *arch;
};

struct picovm_arch_memory_slot {
};

/**
 * struct picovm_smccc_features: Descriptor of the hypercall services exposed to the guests
 *
 * @std_bmap: Bitmap of standard secure service calls
 * @std_hyp_bmap: Bitmap of standard hypervisor service calls
 * @vendor_hyp_bmap: Bitmap of vendor specific hypervisor service calls
 */
struct picovm_smccc_features {
	unsigned long std_bmap;
	unsigned long std_hyp_bmap;
	unsigned long vendor_hyp_bmap;
};

struct picovm_pinned_page {
	struct list_head	link;
	struct page		*page;
};

typedef unsigned int ppicovm_handle_t;

struct picovm_protected_vm {
	ppicovm_handle_t handle;
	struct picovm_hyp_memcache teardown_mc;
	struct list_head pinned_pages;
	bool enabled;
};

struct picovm_arch {
	struct picovm_s2_mmu mmu;

	/* VTCR_EL2 value for this VM */
	u64    vtcr;
	/*
	 * For an untrusted host VM, 'pkvm.handle' is used to lookup
	 * the associated pKVM instance in the hypervisor.
	 */
	struct picovm_protected_vm pkvm;
};

extern unsigned int __ro_after_init picovm_arm_vmid_bits;

#endif /* __PICOVM_HOST_H__ */
