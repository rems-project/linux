/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Derived from arch/arm/include/asm/picovm_host.h:
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 */
#ifndef __PICOVM_HOST_H__
#define __PICOVM_HOST_H__

#include <picovm/prelude.h>

struct picovm_vmid {
	u64 id; // TODO: into atomic64_t?
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

	struct picovm_arch *arch;
};

struct picovm_arch {
	struct picovm_s2_mmu mmu;

	/* VTCR_EL2 value for this VM */
	u64    vtcr;
};

#endif /* __PICOVM_HOST_H__ */
