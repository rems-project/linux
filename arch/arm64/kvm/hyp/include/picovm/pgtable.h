/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	arch/arm64/include/asm/kvm_pgtable.h
 *	arch/arm64/include/asm/stage2_pgtable.h
 */

#ifndef __PICOVM_PGTABLE_H
#define __PICOVM_PGTABLE_H

#include <picovm/linux/types.h>
#include <picovm/linux/bits.h>
#include <picovm/asm/cpufeature.h>
#include <picovm/page.h>
#include <picovm/sysregs.h>


#define PICOVM_PGTABLE_MAX_LEVELS	4U

static inline u64 picovm_get_parange(u64 mmfr0)
{
	u64 parange = cpuid_feature_extract_unsigned_field(mmfr0,
				ID_AA64MMFR0_EL1_PARANGE_SHIFT);
	if (parange > ID_AA64MMFR0_EL1_PARANGE_MAX)
		parange = ID_AA64MMFR0_EL1_PARANGE_MAX;

	return parange;
}



typedef u64 picovm_pte_t;
typedef picovm_pte_t *picovm_pteref_t;

#define PICOVM_PTE_VALID 		BIT(0)

#define PICOVM_PTE_ADDR_MASK		GENMASK(47, PAGE_SHIFT)
// #define PICOVM_PTE_ADDR_51_48		GENMASK(15, 12)

#define PICOVM_PHYS_INVALID		(-1ULL)


static inline bool picovm_pte_valid(picovm_pte_t pte)
{
	return pte & PICOVM_PTE_VALID;
}

static inline u64 picovm_pte_to_phys(picovm_pte_t pte)
{
	u64 pa = pte & PICOVM_PTE_ADDR_MASK;

#if PAGE_SHIFT != 12
#error "picovm requiest 4K pages"
#endif
	// if (PAGE_SHIFT == 16)
	// 	pa |= FIELD_GET(KVM_PTE_ADDR_51_48, pte) << 48;

	return pa;
}

static inline picovm_pte_t kvm_phys_to_pte(u64 pa)
{
	picovm_pte_t pte = pa & PICOVM_PTE_ADDR_MASK;

#if PAGE_SHIFT != 12
#error "picovm requiest 4K pages"
#endif
	// if (PAGE_SHIFT == 16) {
	// 	pa &= GENMASK(51, 48);
	// 	pte |= FIELD_PREP(KVM_PTE_ADDR_51_48, pa >> 48);
	// }

	return pte;
}


enum picovm_pgtable_prot {
	PICOVM_PGTABLE_PROT_X = BIT(0),
	PICOVM_PGTABLE_PROT_W = BIT(1),
	PICOVM_PGTABLE_PROT_R = BIT(2),

	PICOVM_PGTABLE_PROT_DEVICE = BIT(3),

	PICOVM_PGTABLE_PROT_SW0 = BIT(55),
	PICOVM_PGTABLE_PROT_SW1 = BIT(56),
	PICOVM_PGTABLE_PROT_SW2 = BIT(57),
	PICOVM_PGTABLE_PROT_SW3 = BIT(58),
};

#define PICOVM_PGTABLE_PROT_RW (PICOVM_PGTABLE_PROT_R | PICOVM_PGTABLE_PROT_W)
#define PICOVM_PGTABLE_PROT_RWX (PICOVM_PGTABLE_PROT_RW | PICOVM_PGTABLE_PROT_X)

#define PICOVM_HOST_MEM_PROT PICOVM_PGTABLE_PROT_RWX
#define PICOVM_HOST_MMIO_PROT PICOVM_PGTABLE_PROT_RW

#define PAGE_HYP		PICOVM_PGTABLE_PROT_RW
#define PAGE_HYP_EXEC		(PICOVM_PGTABLE_PROT_R | PICOVM_PGTABLE_PROT_X)
#define PAGE_HYP_RO		(PICOVM_PGTABLE_PROT_R)
// #define PAGE_HYP_DEVICE		(PAGE_HYP | PICOVM_PGTABLE_PROT_DEVICE)


struct picovm_pgtable_visit_ctx {
	picovm_pte_t *ptep;
	picovm_pte_t old;
	void *arg;
	u64 addr;
	u64 ofs;
};

typedef int (*picovm_pgtable_visitor_fn_t)(
	const struct picovm_pgtable_visit_ctx *ctx);

struct picovm_pgtable_walker {
	const picovm_pgtable_visitor_fn_t cb;
	void *const arg;
};

struct picovm_pgtable {
	u32 ia_bits;
	u32 start_level;
	picovm_pte_t *pgd;

	/* Stage-2 only */
	struct picovm_s2_mmu *mmu;
};


/*
 * INTERFACE of picovm/pgtable.c
 */
int picovm_pgtable_hyp_init(struct picovm_pgtable *pgt, u32 va_bits);
int picovm_pgtable_stage2_init(struct picovm_pgtable *pgt, struct picovm_s2_mmu *mmu);

int picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 addr, u64 size,
			struct picovm_pgtable_walker *walker);

int picovm_pgtable_stage2_map(struct picovm_pgtable *pgt, u64 addr, u64 size,
			      u64 phys, enum picovm_pgtable_prot prot);
int picovm_pgtable_stage2_set_owner(struct picovm_pgtable *pgt, u64 addr, u64 size,
				    u8 owner_id);
int picovm_pgtable_hyp_map(struct picovm_pgtable *pgt, u64 addr, u64 size,
			   u64 phys, enum picovm_pgtable_prot prot);

int picovm_pgtable_hyp_unmap(struct picovm_pgtable *pgt, u64 addr, u64 size);

enum picovm_pgtable_prot picovm_pgtable_hyp_pte_prot(picovm_pte_t pte);
enum picovm_pgtable_prot picovm_pgtable_stage2_pte_prot(picovm_pte_t pte);

u64 picovm_get_vtcr(u64 mmfr0, u64 mmfr1, u32 phys_shift);

#endif /* __PICOV_PGTABLE_H */
