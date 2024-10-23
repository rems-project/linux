#include "linux/fs.h"
#include <picovm/config.h>
#include <picovm/prelude.h>
#include <picovm/memory.h>
#include <picovm/picovm_host.h>
#include <picovm/picovm_pgtable.h>

#include <picovm/linux/barrier.h>
#include <picovm/linux/tlbflush.h>


// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c
#define PICOVM_PTE_TYPE			BIT(1)
#define PICOVM_PTE_TYPE_BLOCK		0
#define PICOVM_PTE_TYPE_PAGE		1
#define PICOVM_PTE_TYPE_TABLE		1

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c
#define PICOVM_PTE_LEAF_ATTR_LO_S2_MEMATTR	GENMASK(5, 2)
#define PICOVM_PTE_LEAF_ATTR_LO_S2_S2AP_R	BIT(6)
#define PICOVM_PTE_LEAF_ATTR_LO_S2_S2AP_W	BIT(7)
#define PICOVM_PTE_LEAF_ATTR_LO_S2_SH	GENMASK(9, 8)
#define PICOVM_PTE_LEAF_ATTR_LO_S2_SH_IS	3
#define PICOVM_PTE_LEAF_ATTR_LO_S2_AF	BIT(10)

#define PICOVM_PTE_LEAF_ATTR_HI		GENMASK(63, 51)

#define PICOVM_PTE_LEAF_ATTR_HI_SW		GENMASK(58, 55)

#define PICOVM_PTE_LEAF_ATTR_HI_S1_XN	BIT(54)

#define PICOVM_PTE_LEAF_ATTR_HI_S2_XN	BIT(54)

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
	struct picovm_pgtable_walker *walker;
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

static int break_pte(const struct picovm_pgtable_visit_ctx *ctx)
{
  if (picovm_pte_valid(ctx->old)) {
    phys_addr_t ipa = ctx->addr;
  	ipa >>= 12;
	  __tlbi_level(ipas2e1is, ipa, PICOVM_PGTABLE_MAX_LEVELS-1);
	  dsb(ish);
	  __tlbi(vmalle1is);
	  dsb(ish);
	  isb();
  }

  return 0;
}

int picovm_pgtable_hyp_init(struct picovm_pgtable *pgt, u32 va_bits)
{
	u64 levels = 4;

	pgt->pgd = (picovm_pteref_t)malloc(NULL);
	if (!pgt->pgd)
		return ENOMEM;

	pgt->ia_bits		= va_bits;
	pgt->start_level	= PICOVM_PGTABLE_MAX_LEVELS - levels;
	pgt->mmu		= NULL;

	return 0;
}


static int stage2_map_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
  int ret;
  picovm_pte_t* ptep = ctx->ptep;
  struct picovm_stage2_map_data *data = ctx->arg;
  phys_addr_t pa = data->phys + ctx->ofs;
  picovm_pte_t new = pa | data->prot;
 
  WRITE_ONCE(ptep, 0);
  ret = break_pte(ctx);
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
  return 0;
}

picovm_pte_t* _picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 ia) {
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

  // Walkk down to PICOVM_PGTABLE_MAX_LEVELS-1
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

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size,
//		     struct kvm_pgtable_walker *walker)
int picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 addr, u64 size,
		     struct picovm_pgtable_walker *walker)
{
  int r;
  u64 start	= ALIGN_DOWN(addr, PAGE_SIZE);
	u64 end	= PAGE_ALIGN(addr + size);

  for (u64 cur = start; cur < end; cur += PAGE_SIZE) {
    picovm_pte_t *ptep = _picovm_pgtable_walk(pgt, cur);

    struct picovm_pgtable_visit_ctx ctx = {
      .ptep = ptep,
      .old	= READ_ONCE(*ptep),
      .arg = walker->arg,
      .addr = cur,
      .ofs = cur - start,
    };

    r = walker->cb(&ctx);
    if (r) {
      return -1;
    }
  }
  return r;
}

// The control register for stage 2 of the EL1&0 translation regime.
static inline u64 read_vtcr_el2(void)
{
	u64 reg;
	asm volatile("mrs %0, vtcr_el2": "=r" (reg));
	return reg;
}


#define VTCR_EL2_TG0_SHIFT	14
#define VTCR_EL2_TG0_MASK	0b11 << VTCR_EL2_TG0_SHIFT // bits[15:14]

#define VTCL_EL2_SL0_SHIFT	6
#define VTCL_EL2_SL0_MASK	0b11 << VTCL_EL2_SL0_SHIFT // bits[7:6]

#define VTCR_EL2_T0SZ_SHIFT	0
#define VTCR_EL2_T0SZ_MASK	0b11111 // bits[5:0]

#define GET_FIELD(val, NAME)	(((val) & NAME ## _MASK) >> NAME ## _SHIFT)


void check_stage2_configuration(void)
{
	u64 vtcr = read_vtcr_el2();
	u32 ia_bits = 64 - GET_FIELD(vtcr,VTCR_EL2_T0SZ);
	u32 starting_level = 2U - GET_FIELD(vtcr, VTCL_EL2_SL0);

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


// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::int __kvm_pgtable_stage2_init(struct kvm_pgtable *pgt, struct kvm_s2_mmu *mmu,
//			    struct kvm_pgtable_mm_ops *mm_ops,
//			    enum kvm_pgtable_stage2_flags flags,
//			    kvm_pgtable_force_pte_cb_t force_pte_cb)
int picovm_pgtable_stage2_init(struct picovm_pgtable *pgt)
{
	check_stage2_configuration();

  pgt->ia_bits = PICOVM_CONFIG_IA_BITS;
  pgt->start_level = PICOVM_CONFIG_STARTING_LEVEL;
  size_t pgd_sz = picovm_pgd_pages(pgt->ia_bits, pgt->start_level) * PAGE_SIZE;
  pgt->pgd = (picovm_pteref_t)malloc(pgd_sz);   // (picovm_pteref_t)host_s2_zalloc_pages_exact(pgd_sz);
  if (!pgt->pgd)
    return -ENOMEM;

  dsb(ishst);
  return 0;

	// u64 idx_tbl0 = addr >> 
	// u32 idx_tbl1 = (addr >> 30) & 0x1ff;
	// u32 idx_tbl2 = (addr >> 21) & 0x1ff;
	// u32 idx_tbl3 = (addr >> 12) & 0x1ff;

/*

1 lvl0 table		4K
512 lvl1
512*512 lvl2
512*512*512 lvl3

// 134,480,385 pages

*/
}

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::int kvm_pgtable_stage2_map(struct picovm_pgtable *pgt, u64 addr, u64 size, 
//      u64 phys, enum kvm_pgtable_prot prot, void *mc, enum kvm_pgtable_walk_flags flags)
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

// NOTE: based on linux/arch/arm64/kvm/hyp/pgtable.c::int kvm_pgtable_hyp_map(struct picovm_pgtable *pgt, u64 addr, u64 size, u64 phys,
//			enum picovm_pgtable_prot prot)
int picovm_pgtable_hyp_map(struct picovm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			enum picovm_pgtable_prot prot)
{
  int ret;
  struct picovm_hyp_map_data map_data = {
		.phys	= ALIGN_DOWN(phys, PAGE_SIZE),
    .prot = prot,
	};

	struct picovm_pgtable_walker walker = {
		.cb	= hyp_map_walker,
		.arg	= &map_data,
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
  dsb(ishst);
	isb();
  
  return 0;
}

