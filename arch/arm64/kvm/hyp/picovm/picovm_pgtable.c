#include "asm/memory.h"
#include "picovm/prelude.h"
#include <picovm/config.h>
#include <picovm/picovm_pgtable.h>

// TODO: how to import null and boolean true / false
#define NULL ((void *)0)

// TODO(note):based on linux/arch/arm64/kvm/hyp/pgtable.c::struct kvm_hyp_map_data
struct picovm_hyp_map_data {
	const u64 phys;
	enum picovm_pgtable_prot prot;
};

// TODO(note):based on linux/arch/arm64/kvm/hyp/pgtable.c::struct kvm_pgtable_walk_data
struct picovm_pgtable_walk_data {
  struct picovm_pgtable_walker *walker;
  const u64			start;
	u64				addr;
	const u64			end;
};

// TODO(note):based on linux/arch/arm64/kvm/hyp/pgtable.c::static kvm_pgtable_idx(u64 addr, u32 level)
static u32 picovm_pgtable_idx(u64 addr, u32 level)
{
	u64 shift = picovm_granule_shift(level);
	u64 mask = BIT(PAGE_SHIFT - 3) - 1;

	return (addr >> shift) & mask;
}

static int stage2_map_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
  // TODO
  return 0;
}

static int hyp_map_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
  picovm_pte_t* ptep = ctx->ptep;
  struct picovm_hyp_map_data *data = ctx->arg; 
  phys_addr_t pa = data->phys + ctx->ofs;
  picovm_pte_t new = pa | data->prot;
  
  *ptep = new;
  return 0;
}

static int hyp_unmap_walker(const struct picovm_pgtable_visit_ctx *ctx)
{
  picovm_pte_t* ptep = ctx->ptep;
  *ptep = 0;
}

picovm_pte_t* _picovm_pgtable_walk(struct picovm_pgtable *pgt, u64 ia) {
  // Level 0
  int pgd_idx = picovm_pgtable_idx(ia, 0);
  picovm_pte_t pgd_desc = pgt->pgd[pgd_idx];
  if ((pgd_desc & 0b11) != 0b11) {
    return NULL;
  }

  phys_addr_t pud_phys = picovm_pte_to_phys(pgd_desc);
  u64 *pud = phys_to_virt(pud_phys);

  // Level 1
  int pud_idx = picovm_pgtable_idx(ia, 1);
  picovm_pte_t pud_desc = pud[pud_idx];
  if ((pud_desc & 0b11) != 0b11) {
    return NULL;
  }

  phys_addr_t pmd_phys = picovm_pte_to_phys(pud_desc);
  u64 *pmd = phys_to_virt(pmd_phys);

  // Level 2
  int pmd_idx = picovm_pgtable_idx(ia, 2);
  picovm_pte_t pmd_desc = pmd[pmd_idx];
  if ((pmd_desc & 0b11) != 0b11) {
    return NULL;
  }

  // Level 3
  phys_addr_t pte_phys = picovm_pte_to_phys(pmd_desc);
  picovm_pte_t *pte = phys_to_virt(pte_phys);
  return &pte[picovm_pgtable_idx(ia, 3)];
}

// TODO(note):based on linux/arch/arm64/kvm/hyp/pgtable.c::int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size,
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
      .ptep=ptep,
      .arg=walker->arg,
      .ofs=cur - start,
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


/**
TODO: remove this comment

 * __kvm_pgtable_stage2_init() - Initialise a guest stage-2 page-table.
 * @pgt:	Uninitialised page-table structure to initialise.
 * @mmu:	S2 MMU context for this S2 translation
 *
 * Return: 0 on success, negative error code on failure.
 */
int picovm_pgtable_stage2_init(struct picovm_pgtable *pgt)
{
	u64 addr = 0;

	check_stage2_configuration();

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


/*
TODO: remove this comment

 * kvm_pgtable_stage2_map() - Install a mapping in a guest stage-2 page-table.
 * @pgt:	Page-table structure initialised by kvm_pgtable_stage2_init*().
 * @addr:	Intermediate physical address at which to place the mapping.
 * @size:	Size of the mapping.
 * @phys:	Physical address of the memory to map.
 * @prot:	Permissions and attributes for the mapping.
 *
 * The offset of @addr within a page is ignored, @size is rounded-up to
 * the next page boundary and @phys is rounded-down to the previous page
 * boundary.
 *
 * If device attributes are not explicitly requested in @prot, then the
 * mapping will be normal, cacheable.
 *
 * Note that the update of a valid leaf PTE in this function will be aborted,
 * if it's trying to recreate the exact same mapping or only change the access
 * permissions. Instead, the vCPU will exit one more time from guest if still
 * needed and then go through the path of relaxing permissions.
 *
 * Note that this function will both coalesce existing table entries and split
 * existing block mappings, relying on page-faults to fault back areas outside
 * of the new mapping lazily.
 *
 * Return: 0 on success, negative error code on failure.

*/

int picovm_pgtable_stage2_map(struct picovm_pgtable *pgt, u64 addr, u64 size,
			   u64 phys, enum picovm_pgtable_prot prot)
{
	// TODO
	return 0;
}

// TODO(note):based on linux/arch/arm64/kvm/hyp/pgtable.c::int kvm_pgtable_hyp_map(struct picovm_pgtable *pgt, u64 addr, u64 size, u64 phys,
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
