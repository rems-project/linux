/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm64/kvm/hyp/pgtable.c 
 */
#include "picovm/kvm_picovm.h"
#include "picovm/mem_protect.h"
#include "picovm/mmu.h"
#include <picovm/asm/errno-base.h>

#include <picovm/asm/bug.h>
#include <picovm/asm/rwonce.h>
#include <picovm/asm/barrier.h>
#include <picovm/asm/tlbflush.h>

#include <picovm/config.h>
#include <picovm/page.h>
#include <picovm/bitfield.h>
#include <picovm/sysregs.h>
#include <picovm/memory.h>

#include <picovm/early_alloc.h>
#include <picovm/pgtable.h>



// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c
#define PICOVM_PTE_TYPE				BIT(1)
#define PICOVM_PTE_TYPE_BLOCK			0	
#define PICOVM_PTE_TYPE_PAGE			1
#define PICOVM_PTE_TYPE_TABLE			1

#define PICOVM_PTE_LEAF_ATTR_LO			GENMASK(11, 2)

#define PICOVM_PTE_LEAF_ATTR_LO_S1_AP		GENMASK(7, 6)
#define PICOVM_PTE_LEAF_ATTR_LO_S1_AP_RO	3
#define PICOVM_PTE_LEAF_ATTR_LO_S1_AP_RW	1
#define PICOVM_PTE_LEAF_ATTR_LO_S1_SH		GENMASK(9, 8)
#define PICOVM_PTE_LEAF_ATTR_LO_S1_SH_IS	3
#define PICOVM_PTE_LEAF_ATTR_LO_S1_AF		BIT(10)

#define PICOVM_PTE_LEAF_ATTR_LO_S1_ATTRIDX	GENMASK(4, 2)
#define MT_DEVICE_nGnRE 			4
#define MT_NORMAL				0

#define PICOVM_PTE_LEAF_ATTR_LO_S2_MEMATTR	GENMASK(5, 2)
#define PICOVM_PTE_LEAF_ATTR_LO_S2_S2AP_R	BIT(6)
#define PICOVM_PTE_LEAF_ATTR_LO_S2_S2AP_W	BIT(7)
#define PICOVM_PTE_LEAF_ATTR_LO_S2_SH		GENMASK(9, 8)
#define PICOVM_PTE_LEAF_ATTR_LO_S2_SH_IS	3
#define PICOVM_PTE_LEAF_ATTR_LO_S2_AF		BIT(10)

#define PICOVM_PTE_LEAF_ATTR_HI			GENMASK(63, 51)
#define PICOVM_PTE_LEAF_ATTR_HI_SW		GENMASK(58, 55)
#define PICOVM_PTE_LEAF_ATTR_HI_S1_XN		BIT(54)
#define PICOVM_PTE_LEAF_ATTR_HI_S2_XN		BIT(54)

#define PICOVM_INVALID_PTE_OWNER_MASK	GENMASK(9, 2)
#define PICOVM_MAX_OWNER_ID		FIELD_MAX(PICOVM_INVALID_PTE_OWNER_MASK)

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::struct kvm_stage2_map_data
struct picovm_stage2_map_data {
	const u64 phys;
	enum picovm_pgtable_prot prot;
	u8 owner_id;
};


// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::struct kvm_hyp_map_data
struct picovm_hyp_map_data {
	const u64 phys;
	enum picovm_pgtable_prot prot;
};

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::struct kvm_pgtable_walk_data
struct picovm_pgtable_walk_data {
	struct picovm_pgtable_walker	*walker;
	const u64			start;
	u64				addr;
	const u64			end;
};

static bool picovm_phys_is_valid(u64 phys)
{
	// BIT(id_aa64mmfr0_parange_to_phys_shift(ID_AA64MMFR0_EL1_PARANGE_MAX))
	return phys < BIT(48);
}

static bool inline picovm_pte_block(picovm_pte_t pte)
{
	return FIELD_GET(PICOVM_PTE_TYPE, pte) == PICOVM_PTE_TYPE_BLOCK;
}

static bool inline picovm_is_pte_invalid_or_block(picovm_pte_t pte)
{
	return !picovm_pte_valid(pte) || picovm_pte_block(pte);
}

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::static kvm_pgtable_stage2_pte_rpot(kvm_pte_t pte)
enum picovm_pgtable_prot picovm_pgtable_stage2_pte_prot(picovm_pte_t pte)
{
	enum picovm_pgtable_prot prot = pte & PICOVM_PTE_LEAF_ATTR_HI_SW;

	if (!picovm_pte_valid(pte))
		return prot;

	if (pte & PICOVM_PTE_LEAF_ATTR_LO_S2_S2AP_R)
		prot |= PICOVM_PGTABLE_PROT_R;
	if (pte & PICOVM_PTE_LEAF_ATTR_LO_S2_S2AP_W)
		prot |= PICOVM_PGTABLE_PROT_W;
	if (!(pte & PICOVM_PTE_LEAF_ATTR_HI_S2_XN))
		prot |= PICOVM_PGTABLE_PROT_X;

	return prot;
}

enum picovm_pgtable_prot picovm_pgtable_hyp_pte_prot(picovm_pte_t pte)
{
	enum picovm_pgtable_prot prot = pte & PICOVM_PTE_LEAF_ATTR_HI_SW;
	u32 ap;

	if (!picovm_pte_valid(pte))
		return prot;

	if (!(pte & PICOVM_PTE_LEAF_ATTR_HI_S1_XN))
		prot |= PICOVM_PGTABLE_PROT_X;

	ap = FIELD_GET(PICOVM_PTE_LEAF_ATTR_LO_S1_AP, pte);
	if (ap == PICOVM_PTE_LEAF_ATTR_LO_S1_AP_RO)
		prot |= PICOVM_PGTABLE_PROT_R;
	else if (ap == PICOVM_PTE_LEAF_ATTR_LO_S1_AP_RW)
		prot |= PICOVM_PGTABLE_PROT_RW;

	return prot;
}

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::static kvm_pgtable_idx(u64 addr, u32 level)
static u32 picovm_pgtable_idx(u64 addr, u32 level)
{
	u64 shift = picovm_granule_shift(level);
	u64 mask = BIT(PAGE_SHIFT - 3) - 1;

	return (addr >> shift) & mask;
}

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::static kvm_pgd_page_idx(struct kvm_pgtable *pgt, u64 addr)
static u32 picovm_pgd_page_idx(struct picovm_pgtable *pgt, u64 addr)
{
	u64 shift = picovm_granule_shift(pgt->start_level - 1); /* May underflow */
	u64 mask = BIT(pgt->ia_bits) - 1;

	return (addr & mask) >> shift;
}

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::static kvm_pgd_pages(u32 ia_bits, u32 start_level)
static u32 picovm_pgd_pages(u32 ia_bits, u32 start_level)
{
	struct picovm_pgtable pgt = {
		.ia_bits	= ia_bits,
		.start_level	= start_level,
	};

	return picovm_pgd_page_idx(&pgt, -1ULL) + 1;
}

static bool picovm_pte_table(picovm_pte_t pte, u32 level)
{
	if (level == PICOVM_PGTABLE_MAX_LEVELS - 1)
		return false;

	if (!picovm_pte_valid(pte))
		return false;

	return FIELD_GET(PICOVM_PTE_TYPE, pte) == PICOVM_PTE_TYPE_TABLE;
}

static u64 picovm_make_hyp_attr(enum picovm_pgtable_prot prot)
{
	bool device = prot & PICOVM_PGTABLE_PROT_DEVICE;
	u32 mtype = device ? MT_DEVICE_nGnRE : MT_NORMAL;
	u64 attr = FIELD_PREP(PICOVM_PTE_LEAF_ATTR_LO_S1_ATTRIDX, mtype);

	u32 sh = PICOVM_PTE_LEAF_ATTR_LO_S1_SH_IS;
	u32 ap = (prot & PICOVM_PGTABLE_PROT_W) ?
		 PICOVM_PTE_LEAF_ATTR_LO_S1_AP_RW :
		 PICOVM_PTE_LEAF_ATTR_LO_S1_AP_RO;

	BUG_ON(!(prot & PICOVM_PGTABLE_PROT_R));
	if (prot & PICOVM_PGTABLE_PROT_X)
		// TODO: does this need to be a propagated EINVAL?
		BUG_ON(prot & PICOVM_PGTABLE_PROT_W);
	else
		attr |= PICOVM_PTE_LEAF_ATTR_HI_S1_XN;

	attr |= FIELD_PREP(PICOVM_PTE_LEAF_ATTR_LO_S1_AP, ap);
	attr |= FIELD_PREP(PICOVM_PTE_LEAF_ATTR_LO_S1_SH, sh);
	attr |= PICOVM_PTE_LEAF_ATTR_LO_S1_AF;
	attr |= prot & PICOVM_PTE_LEAF_ATTR_HI_SW;

	return attr;
}

static u64 picovm_make_stage2_attr(enum picovm_pgtable_prot prot)
{
	bool device = prot & PICOVM_PGTABLE_PROT_DEVICE;
	u32 mtype = device ? MT_DEVICE_nGnRE : MT_NORMAL;
	u64 attr = mtype << 2;
	u32 sh = PICOVM_PTE_LEAF_ATTR_LO_S2_SH_IS;

	if (!(prot & PICOVM_PGTABLE_PROT_X))
		attr |= PICOVM_PTE_LEAF_ATTR_HI_S1_XN;
	else
		// TODO: does this need to be a propagated EINVAL?
		BUG_ON(device);

	if (prot & PICOVM_PGTABLE_PROT_R)
		attr |= PICOVM_PTE_LEAF_ATTR_LO_S2_S2AP_R;

	if (prot & PICOVM_PGTABLE_PROT_W)
		attr |= PICOVM_PTE_LEAF_ATTR_LO_S2_S2AP_W;

	attr |= FIELD_PREP(PICOVM_PTE_LEAF_ATTR_LO_S2_SH, sh);
	attr |= PICOVM_PTE_LEAF_ATTR_LO_S2_AF;
	attr |= prot & PICOVM_PTE_LEAF_ATTR_HI_SW;

	return attr;
}

static u64 picovm_make_page_pte(bool is_hyp, u64 phys, enum picovm_pgtable_prot prot)
{
	u64 pte = 0;

	pte |= PICOVM_PTE_VALID;
	pte |= FIELD_PREP(PICOVM_PTE_TYPE, PICOVM_PTE_TYPE_PAGE);
	pte |= is_hyp ? picovm_make_hyp_attr(prot) : picovm_make_stage2_attr(prot);
	pte |= phys & GENMASK(47, 12);
	return pte;
}

static picovm_pte_t picovm_init_table_pte(picovm_pte_t *childp)
{
	picovm_pte_t pte = picovm_phys_to_pte(hyp_virt_to_phys(childp));

	pte |= FIELD_PREP(PICOVM_PTE_TYPE, PICOVM_PTE_TYPE_TABLE);
	pte |= PICOVM_PTE_VALID;
	return pte;
}

static picovm_pte_t picovm_init_valid_leaf_pte(u64 pa, picovm_pte_t attr)
{
	picovm_pte_t pte = picovm_phys_to_pte(pa);
	u64 type = PICOVM_PTE_TYPE_PAGE;

	pte |= attr & (PICOVM_PTE_LEAF_ATTR_LO | PICOVM_PTE_LEAF_ATTR_HI);
	pte |= FIELD_PREP(PICOVM_PTE_TYPE, type);
	pte |= PICOVM_PTE_VALID;

	return pte;
}

static picovm_pte_t picovm_init_invalid_leaf_owner(u8 owner_id)
{
	return FIELD_PREP(PICOVM_INVALID_PTE_OWNER_MASK, owner_id);
}

int __picovm_pgtable_early_mapping(struct picovm_pgtable *pgt, u64 addr, bool is_hyp)
{
	picovm_pteref_t pteref, childp;
	picovm_pte_t pte;
	u64 level;
	phys_addr_t phys;

	u32 idx = picovm_pgd_page_idx(pgt, addr);
	pteref = &pgt->pgd[idx * PTRS_PER_PTE];

	for (level = pgt->start_level; level < PICOVM_PGTABLE_MAX_LEVELS - 1; level++) {
		idx = picovm_pgtable_idx(addr, level);
		pte = pteref[idx];
		if (picovm_pte_table(pte, level)) {
			phys = picovm_pte_to_phys(pte);
			pteref = (picovm_pteref_t)hyp_phys_to_virt(phys);
		} else {
			childp = is_hyp ? 
				(picovm_pteref_t)hyp_early_alloc_page() :
				(picovm_pteref_t)host_stage2_early_alloc_page();
			if (!childp)
				return -ENOMEM;

			// initialize the pte as a table
			pte = picovm_init_table_pte(childp);
			pteref[idx] = pte;
			pteref = childp;
		}
	}

	pteref[picovm_pgtable_idx(addr, PICOVM_PGTABLE_MAX_LEVELS-1)] = 0;
	return 0;
}

int picovm_pgtable_hyp_early_mapping(struct picovm_pgtable *pgt, u64 addr)
{
	return __picovm_pgtable_early_mapping(pgt, addr, true);
}

int picovm_pgtable_stage2_early_mapping(struct picovm_pgtable *pgt, u64 addr)
{
	return __picovm_pgtable_early_mapping(pgt, addr, false);
}

int picovm_pgtable_hyp_init(struct picovm_pgtable *pgt, u32 va_bits)
{
	u64 nr_pages;
	int i, ret = 0;
	
	pgt->ia_bits		= va_bits;
	pgt->start_level	= 0;
	pgt->mmu		= NULL;
	
	nr_pages = picovm_pgd_pages(pgt->ia_bits, pgt->start_level);
	pgt->pgd = (picovm_pteref_t)hyp_early_alloc_contig(nr_pages);
	if (!pgt->pgd)
		return -ENOMEM;

	for (i = 0; i < hyp_memblock_nr; i++) {
		struct memblock_region *reg = &hyp_memory[i];
		u64 start = reg->base;
		u64 end = start + reg->size;
	
		for (phys_addr_t phys = start; phys < end; phys += PAGE_SIZE) {
			u64 addr = (u64)hyp_phys_to_virt(phys);
			ret = picovm_pgtable_hyp_early_mapping(pgt, addr);
			if (ret)
				return ret;
		}
	}
	
	return ret;
}

static int stage2_map_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
	picovm_pte_t* ptep = ctx->ptep;
	struct picovm_stage2_map_data *data = ctx->arg;
	phys_addr_t phys = data->phys + ctx->ofs;
	picovm_pte_t new;

	if (picovm_phys_is_valid(phys)) {
		u64 attr = picovm_make_page_pte(false, phys, data->prot);
		new = picovm_init_valid_leaf_pte(phys, attr);
	} else {
		new = picovm_init_invalid_leaf_owner(data->owner_id);
	}

	if (picovm_pte_valid(ctx->old)) {
		phys_addr_t ipa = ctx->addr;
		dsb(ishst);
		ipa >>= 12;
		__tlbi_level(ipas2e1is, ipa, PICOVM_PGTABLE_MAX_LEVELS-1);
		dsb(ish);
		__tlbi(vmalle1is);
		dsb(ish);
		isb();
	}

	smp_store_release(ptep, new);
	return 0;
}

static int hyp_map_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
	picovm_pte_t* ptep = ctx->ptep;
	struct picovm_hyp_map_data *data = ctx->arg;
	phys_addr_t phys = data->phys + ctx->ofs;

	smp_store_release(ptep, picovm_make_page_pte(true, phys, data->prot));
	return 0;
}

static int hyp_unmap_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
	picovm_pte_t* ptep = ctx->ptep;
	WRITE_ONCE(*ptep, 0);
	dsb(ishst);
	__tlbi_level(vale2is, __TLBI_VADDR(ctx->addr, 0), PICOVM_PGTABLE_MAX_LEVELS-1);
	dsb(ish);
	isb();
	return 0;
}

static picovm_pte_t* _picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 addr)
{
	int idx, level;
	picovm_pteref_t pteref;
	picovm_pte_t pte;
	phys_addr_t phys;
	
	idx = picovm_pgd_page_idx(pgt, addr);
	pteref = &pgt->pgd[idx * PTRS_PER_PTE];

	for (level = pgt->start_level; level < PICOVM_PGTABLE_MAX_LEVELS-1; level++) {
		int idx = picovm_pgtable_idx(addr, level);
		pte = pteref[idx];
		if (picovm_is_pte_invalid_or_block(pte)) {
			return NULL;
		}
		phys = picovm_pte_to_phys(pte);
		pteref = (picovm_pteref_t)hyp_phys_to_virt(phys);
	}

	return &pteref[picovm_pgtable_idx(addr, PICOVM_PGTABLE_MAX_LEVELS-1)];
}

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size, struct kvm_pgtable_walker *walker)
int picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 addr, u64 size, struct picovm_pgtable_walker *walker)
{
	int ret = 0;
	u64 start = ALIGN_DOWN(addr, PAGE_SIZE);
	u64 end = PAGE_ALIGN(addr + size);
	u64 cur;
	struct picovm_pgtable_visit_ctx ctx;

	for (cur = start; cur < end; cur += PAGE_SIZE) {
		picovm_pte_t *ptep = _picovm_pgtable_walk(pgt, cur);
		if (ptep == NULL) {
			return -1;
		}

		ctx.ptep = ptep;
		ctx.old = READ_ONCE(*ptep);
		ctx.arg = walker->arg;
		ctx.addr = cur;
		ctx.ofs = cur - start;

		ret = walker->cb(&ctx);
		if (ret) {
			return -1;
		}
	}
	return ret;
}

struct leaf_walk_data {
	picovm_pte_t	pte;
};

static int leaf_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
	struct leaf_walk_data *data = ctx->arg;
	data->pte   = ctx->old;

	return 0;
}

int picovm_pgtable_get_leaf(struct picovm_pgtable *pgt, u64 addr, picovm_pte_t *ptep)
{
	struct leaf_walk_data data;
	struct picovm_pgtable_walker walker = {
		.cb	= leaf_walker,
		.arg	= &data,
	};
	int ret;

	ret = picovm_pgtable_walk(pgt, ALIGN_DOWN(addr, PAGE_SIZE), PAGE_SIZE, &walker);
	if (!ret) {
		if (ptep)
			*ptep  = data.pte;
	}

	return ret;
}

#define GET_FIELD(val, NAME)	(((val) & NAME ## _MASK) >> NAME ## _SHIFT)

static inline void picovm_assert(bool test)
{
	BUG_ON(test);
}

void check_stage2_configuration(u64 vtcr)
{
	u32 ia_bits = 64 - FIELD_GET(GENMASK(5,0), vtcr);
	u32 starting_level = 2U - GET_FIELD(vtcr, VTCR_EL2_SL0);

	// checking the granual size
	picovm_assert(GET_FIELD(vtcr, VTCR_EL2_TG0) != PICOVM_CONFIG_GRANULE_SIZE);

	// checking the maximum input address size
	// NOTE: because we configure IA_BITS to 48bits, the TTBR points to a
	// single level 0 table (not a concatenation of level 1 tables), so
	// we don't need additional checks
	picovm_assert(ia_bits != PICOVM_CONFIG_IA_BITS);

	// checking the starting level
	picovm_assert(starting_level != PICOVM_CONFIG_STARTING_LEVEL);
}

/*
 * Hierarchical page table structure with 4 levels:
 *
 * Level     Table Size       Entries
 * -------------------------------------
 * lvl0      4 KB             512 (9 bits)
 * lvl1      512 * 4 KB       512 (9 bits per entry)
 * lvl2      512 * 512 * 4 KB 512 (9 bits per entry)
 * lvl3      512 * 512 * 512  Pages (9 bits per entry)
 *
 * Total pages addressable: 134,480,385
 */
int picovm_pgtable_stage2_init(struct picovm_pgtable *pgt, struct picovm_s2_mmu *mmu)
{
	size_t nr_pages;
	int i, ret = 0;

	pgt->ia_bits = PICOVM_CONFIG_IA_BITS;
	pgt->start_level = PICOVM_CONFIG_STARTING_LEVEL;
	pgt->mmu = mmu;

	nr_pages = picovm_pgd_pages(pgt->ia_bits, pgt->start_level);
	pgt->pgd = (picovm_pteref_t)host_stage2_early_alloc_contig(nr_pages);
	if (!pgt->pgd)
		return -ENOMEM;

	for (i = 0; i < hyp_memblock_nr; i++) {
		struct memblock_region *reg = &hyp_memory[i];
		u64 start = reg->base;
		u64 end = start + reg->size;
	
		for (phys_addr_t phys = start; phys < end; phys += PAGE_SIZE) {
			ret = picovm_pgtable_stage2_early_mapping(pgt, phys);
			if (ret)
				return ret;
		}
	}

	dsb(ishst);
	return ret;
}

int picovm_pgtable_stage2_map(struct picovm_pgtable *pgt, u64 addr, u64 size,
			      u64 phys, enum picovm_pgtable_prot prot)
{
	int ret;
	struct picovm_stage2_map_data map_data = {
		.phys = ALIGN_DOWN(phys, PAGE_SIZE),
		.prot = prot,
	};

	struct picovm_pgtable_walker walker = {
		.cb = stage2_map_walker,
		.arg = &map_data,
	};

	ret = picovm_pgtable_walk(pgt, addr, size, &walker);
	dsb(ishst);
	return ret;
}

int picovm_pgtable_stage2_set_owner(struct picovm_pgtable *pgt, u64 addr, u64 size,
				    u8 owner_id)
{
	int ret;
	struct picovm_stage2_map_data map_data = {
		.phys		= PICOVM_PHYS_INVALID,
		.owner_id	= owner_id,
	};
	struct picovm_pgtable_walker walker = {
		.cb		= stage2_map_walker,
		.arg		= &map_data,
	};

	if (owner_id > PICOVM_MAX_OWNER_ID)
		return -EINVAL;

	ret = picovm_pgtable_walk(pgt, addr, size, &walker);
	return ret;
}

int picovm_pgtable_hyp_map(struct picovm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			enum picovm_pgtable_prot prot)
{
	int ret;
	struct picovm_hyp_map_data map_data = {
		.phys = ALIGN_DOWN(phys, PAGE_SIZE),
		.prot = prot,
	};

	struct picovm_pgtable_walker walker = {
		.cb  = hyp_map_walker,
		.arg = &map_data,
	};

	ret = picovm_pgtable_walk(pgt, addr, size, &walker);
	dsb(ishst);
	isb();

	return ret;
}

int picovm_pgtable_hyp_unmap(struct picovm_pgtable *pgt, u64 addr, u64 size)
{
	int ret;

	struct picovm_pgtable_walker walker = {
		.cb = hyp_unmap_walker,
	};

	ret = picovm_pgtable_walk(pgt, addr, size, &walker);
	return ret;
}

// Copied from arch/arm64/include/asm/stage2_pgtable.h
#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
#define stage2_pgtable_levels(ipa)	ARM64_HW_PGTABLE_LEVELS((ipa) - 4)

// Copied from arch/arm64/include/asm/kvm_arm.h
#define VTCR_EL2_LVLS_TO_SL0(levels)	\
	((VTCR_EL2_TGRAN_SL0_BASE - (4 - (levels))) << VTCR_EL2_SL0_SHIFT)

u64 picovm_get_vtcr(u64 mmfr0, u64 mmfr1, u32 phys_shift)
{
	u64 vtcr = VTCR_EL2_FLAGS;
	u8 lvls;

	vtcr |= picovm_get_parange(mmfr0) << VTCR_EL2_PS_SHIFT;
	vtcr |= VTCR_EL2_T0SZ(phys_shift);
	/*
	 * Use a minimum 2 level page table to prevent splitting
	 * host PMD huge pages at stage2.
	 */
	lvls = stage2_pgtable_levels(phys_shift);
	if (lvls < 2)
		lvls = 2;
	vtcr |= VTCR_EL2_LVLS_TO_SL0(lvls);

#ifdef CONFIG_ARM64_HW_AFDBM
	/*
	 * Enable the Hardware Access Flag management, unconditionally
	 * on all CPUs. The features is RES0 on CPUs without the support
	 * and must be ignored by the CPUs.
	 */
	vtcr |= VTCR_EL2_HA;
#endif /* CONFIG_ARM64_HW_AFDBM */

	/* Set the vmid bits */
	vtcr |= (get_vmid_bits(mmfr1) == 16) ?
		VTCR_EL2_VS_16BIT :
		VTCR_EL2_VS_8BIT;

	return vtcr;
}

