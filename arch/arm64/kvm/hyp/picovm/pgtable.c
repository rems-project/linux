/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm64/kvm/hyp/pgtable.c 
 */
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


// NOTE: from arch/arm64/include/asm/pgtable-hwdef.h
/*
 * Size mapped by an entry at level n ( 0 <= n <= 3)
 * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
 * in the final page. The maximum number of translation levels supported by
 * the architecture is 4. Hence, starting at level n, we have further
 * ((4 - n) - 1) levels of translation excluding the offset within the page.
 * So, the total number of bits mapped by an entry at level n is :
 *
 *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
 *
 * Rearranging it a bit we get :
 *   (4 - n) * (PAGE_SHIFT - 3) + 3
 */
#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)

// NOTE: based on arch/arm64/include/asm/kvm_pgtable.h
static inline u64 picovm_granule_shift(u32 level)
{
	/* Assumes KVM_PGTABLE_MAX_LEVELS is 4 */
	return ARM64_HW_PGTABLE_LEVEL_SHIFT(level);
}


// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c
#define PICOVM_PTE_TYPE				BIT(1)
#define PICOVM_PTE_TYPE_BLOCK			0
#define PICOVM_PTE_TYPE_PAGE			1
#define PICOVM_PTE_TYPE_TABLE			1

#define PICOVM_PTE_LEAF_ATTR_LO			GENMASK(11, 2)

#define PICOVM_PTE_LEAF_ATTR_LO_S1_AP		GENMASK(7, 6)
#define PICOVM_PTE_LEAF_ATTR_LO_S1_AP_RO	3
#define PICOVM_PTE_LEAF_ATTR_LO_S1_AP_RW	1

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

static bool inline picovm_pte_block(picovm_pte_t pte)
{
	return !(pte & PICOVM_PTE_TYPE);
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

int picovm_pgtable_hyp_init(struct picovm_pgtable *pgt, u32 va_bits)
{
	u64 levels = 4;

	pgt->pgd = (picovm_pteref_t) hyp_early_alloc_page();
	if (!pgt->pgd)
		return ENOMEM;

	pgt->ia_bits		= va_bits;
	pgt->start_level	= PICOVM_PGTABLE_MAX_LEVELS - levels;
	pgt->mmu		= NULL;

	return 0;
}


static int stage2_map_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
	picovm_pte_t* ptep = ctx->ptep;
	struct picovm_stage2_map_data *data = ctx->arg;
	phys_addr_t pa = data->phys + ctx->ofs;

	picovm_pte_t new = pa | data->prot;

	WRITE_ONCE(*ptep, 0);
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

	smp_store_release(ctx->ptep, new);
	return 0;
}

static int hyp_map_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
	picovm_pte_t* ptep = ctx->ptep;
	struct picovm_hyp_map_data *data = ctx->arg; 
	phys_addr_t pa = data->phys + ctx->ofs;
	picovm_pte_t new = pa | data->prot;

	smp_store_release(ptep, new);
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

static picovm_pte_t* _picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 ia)
{
	int level, idx;
	picovm_pte_t pte;
	phys_addr_t child_phys;
	u64 *childp;

	// Level 0
	idx = picovm_pgtable_idx(ia, 0);
	pte = pgt->pgd[idx];
	if (picovm_is_pte_invalid_or_block(pte)) {
		return NULL;
	}
	child_phys = picovm_pte_to_phys(pte);
	childp = hyp_phys_to_virt(child_phys);

	// Walk down to PICOVM_PGTABLE_MAX_LEVELS-1
	for (level = 1; level < PICOVM_PGTABLE_MAX_LEVELS-1; level++) {
		int idx = picovm_pgtable_idx(ia, level);
		pte = childp[idx];
		if (picovm_is_pte_invalid_or_block(pte)) {
			return NULL;
		}
		child_phys = picovm_pte_to_phys(pte);
		childp = hyp_phys_to_virt(child_phys);
	}

	return &childp[picovm_pgtable_idx(ia, PICOVM_PGTABLE_MAX_LEVELS-1)];
}

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size, struct kvm_pgtable_walker *walker)
int picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 addr, u64 size, struct picovm_pgtable_walker *walker)
{
	int r;
	u64 start = ALIGN_DOWN(addr, PAGE_SIZE);
	u64 end = PAGE_ALIGN(addr + size);

	for (u64 cur = start; cur < end; cur += PAGE_SIZE) {
		picovm_pte_t *ptep = _picovm_pgtable_walk(pgt, cur);

		struct picovm_pgtable_visit_ctx ctx = {
			.ptep	= ptep,
			.old	= READ_ONCE(*ptep),
			.arg	= walker->arg,
			.addr	= cur,
			.ofs	= cur - start,
		};

		r = walker->cb(&ctx);
		if (r) {
			return -1;
		}
	}
	return r;
}

#define GET_FIELD(val, NAME)	(((val) & NAME ## _MASK) >> NAME ## _SHIFT)

static inline void picovm_assert(bool test)
{
	BUG_ON(test);
}

static void check_stage2_configuration(void)
{
	u64 vtcr = read_sysreg(vtcr_el2);
	u32 ia_bits = 64 - VTCR_EL2_T0SZ(vtcr);
	u32 starting_level = 2U - GET_FIELD(vtcr, VTCR_EL2_SL0);

	// checking the granual size
	picovm_assert(GET_FIELD(vtcr, VTCR_EL2_TG0) == PICOVM_CONFIG_GRANULE_SIZE);
	
	// checking the maximum input address size
	// NOTE: because we configure IA_BITS to 48bits, the TTBR points to a
	// single level 0 table (not a concatenation of level 1 tables), so
	// we don't need additional checks
	picovm_assert(ia_bits == PICOVM_CONFIG_IA_BITS);

	// checking the starting level
	picovm_assert(starting_level == PICOVM_CONFIG_STARTING_LEVEL);
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
	size_t pgd_sz;
	check_stage2_configuration();
	pgt->ia_bits = PICOVM_CONFIG_IA_BITS;
	pgt->start_level = PICOVM_CONFIG_STARTING_LEVEL;
	pgt->mmu = mmu;

	pgd_sz = picovm_pgd_pages(pgt->ia_bits, pgt->start_level) * PAGE_SIZE;
	// TODO: use picovm_early_alloc?
	pgt->pgd = (picovm_pteref_t)hyp_early_alloc_contig(pgd_sz);
	// pgt->pgd = (picovm_pteref_t)alloc_pages_exact(pgd_sz, GFP_KERNEL_ACCOUNT | __GFP_ZERO); // (picovm_pteref_t)host_s2_zalloc_pages_exact(pgd_sz);
	if (!pgt->pgd)
		return -ENOMEM;
	dsb(ishst);
	return 0;
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

