#ifndef __PICOVM_PGTABLE_H
#define __PICOVM_PGTABLE_H

#include <picovm/prelude.h>
#include <picovm/memory.h>

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h
#define PICOVM_PGTABLE_MAX_LEVELS		4U

// align to the NEXT page boundary
#define PAGE_ALIGN(addr)	ALIGN(addr, PAGE_SIZE)

// align to the PREVIOUS page boundary
#define PAGE_ALIGN_DOWN(addr) 	ALIGN_DOWN(addr, PAGE_SIZE)

// test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE
#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n) ((PAGE_SHIFT - 3) * (4 - (n)) + 3)

typedef u64 picovm_pte_t;
// TODO: __rcu ?
typedef picovm_pte_t *picovm_pteref_t;

#define PICOVM_PTE_VALID BIT(0)

#define PICOVM_PTE_ADDR_MASK GENMASK(47, PAGE_SHIFT)
#define PICOVM_PHYS_INVALID (-1ULL)

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h::static inline bool kvm_pte_valid
static inline bool picovm_pte_valid(picovm_pte_t pte)
{
	return pte & PICOVM_PTE_VALID;
}

// TODO(note):based on linux/arch/arm64/include/asm/kvm_pgtable.h::static inline u64 kvm_pte_to_phys
static inline phys_addr_t picovm_pte_to_phys(picovm_pte_t pte)
{
	phys_addr_t pa = pte & PICOVM_PTE_ADDR_MASK;
	return pa;
}

// TODO(note):based on linux/arch/arm64/include/asm/kvm_pgtable.h::static inline u64 kvm_phys_to_pte
static inline picovm_pte_t picovm_phys_to_pte(u64 pa)
{
	picovm_pte_t pte = pa & PICOVM_PTE_ADDR_MASK;
	return pte;
}

// TODO(note):based on linux/arch/arm64/include/asm/kvm_pgtable.h::struct kvm_pgtable
static inline u64 picovm_granule_shift(u32 level)
{
	/* Assumes PICOVM_PGTABLE_MAX_LEVELS is 4 */
	return ARM64_HW_PGTABLE_LEVEL_SHIFT(level);
}

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h::enum kvm_pgtable_prot
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

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h
#define PICOVM_PGTABLE_PROT_RW (PICOVM_PGTABLE_PROT_R | PICOVM_PGTABLE_PROT_W)
#define PICOVM_PGTABLE_PROT_RWX (PICOVM_PGTABLE_PROT_RW | PICOVM_PGTABLE_PROT_X)
#define PICOVM_HOST_MEM_PROT PICOVM_PGTABLE_PROT_RWX
#define PAGE_HYP PICOVM_PGTABLE_PROT_RW
#define PAGE_HYP_EXEC		(PICOVM_PGTABLE_PROT_R | PICOVM_PGTABLE_PROT_X)
#define PAGE_HYP_RO		(PICOVM_PGTABLE_PROT_R)

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable:typedef bool (*kvm_pgtable_force_pte_cb_t)(u64 addr, u64 end,
//					   enum kvm_pgtable_prot prot);
typedef bool (*picovm_pgtable_force_pte_cb_t)(u64 addr, u64 end,
					   enum picovm_pgtable_prot prot);

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h::struct kvm_pgtable_visit_ctx
struct picovm_pgtable_visit_ctx {
	picovm_pte_t *ptep;
  picovm_pte_t old;
	void *arg;
  u64 addr;
	u64 ofs;
};

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h::typedef int (*kvm_pgtable_visitor_fn_t)
typedef int (*picovm_pgtable_visitor_fn_t)(
	const struct picovm_pgtable_visit_ctx *ctx);

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h::struct kvm_pgtable_walker
struct picovm_pgtable_walker {
	const picovm_pgtable_visitor_fn_t cb;
	void *const arg;
};

// TODO(note):based on linux/arch/arm64/include/asm/kvm_pgtable.h::struct kvm_pgtable
struct picovm_pgtable {
	u32 ia_bits;
	u32 start_level;
	picovm_pte_t *pgd;

  /* Stage-2 only */
	struct picovm_s2_mmu			*mmu;
};

int picovm_pgtable_hyp_init(struct picovm_pgtable *pgt, u32 va_bits);

int picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 addr, u64 size,
		     struct picovm_pgtable_walker *walker);

int picovm_pgtable_stage2_map(struct picovm_pgtable *pgt, u64 addr, u64 size,
			      u64 phys, enum picovm_pgtable_prot prot);

int picovm_pgtable_hyp_map(struct picovm_pgtable *pgt, u64 addr, u64 size,
			   u64 phys, enum picovm_pgtable_prot prot);

int picovm_pgtable_hyp_unmap(struct picovm_pgtable *pgt, u64 addr, u64 size);

enum picovm_pgtable_prot picovm_pgtable_stage2_pte_prot(picovm_pte_t pte);


#endif /* __PICOV_PGTABLE_H */
