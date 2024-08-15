#ifndef __PICOVM_PGTABLE_H
#define __PICOVM_PGTABLE_H

#include <picovm/prelude.h>

typedef u64 pte_t;


struct picovm_pgtable {
	int TODO;
};

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h::enum kvm_pgtable_prot
enum picovm_pgtable_prot {
	PICOVM_PGTABLE_PROT_X			= BIT(0),
	PICOVM_PGTABLE_PROT_W			= BIT(1),
	PICOVM_PGTABLE_PROT_R			= BIT(2),

	PICOVM_PGTABLE_PROT_DEVICE		= BIT(3),

	PICOVM_PGTABLE_PROT_SW0			= BIT(55),
	PICOVM_PGTABLE_PROT_SW1			= BIT(56),
	PICOVM_PGTABLE_PROT_SW2			= BIT(57),
	PICOVM_PGTABLE_PROT_SW3			= BIT(58),
};

// TODO(note): based on linux/arch/arm64/include/asm/kvm_pgtable.h
#define PICOVM_PGTABLE_PROT_RW		(PICOVM_PGTABLE_PROT_R | PICOVM_PGTABLE_PROT_W)
#define PICOVM_PGTABLE_PROT_RWX		(PICOVM_PGTABLE_PROT_RW | PICOVM_PGTABLE_PROT_X)
#define PICOVM_HOST_MEM_PROT		PICOVM_PGTABLE_PROT_RWX
#define PAGE_HYP			PICOVM_PGTABLE_PROT_RW

int picovm_pgtable_stage2_map(struct picovm_pgtable *pgt, u64 addr, u64 size,
			      u64 phys, enum picovm_pgtable_prot prot);

int picovm_pgtable_hyp_map(struct picovm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			enum picovm_pgtable_prot prot);


#endif /* __PICOV_PGTABLE_H */
