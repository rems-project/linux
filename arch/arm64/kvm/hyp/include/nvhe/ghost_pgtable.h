/* Ghost code to compute the interpretation of page tables in a
	 concise representation that we can use in executable assertions, as
	 ordered lists of "maplet"s.  This file defines that interpretation, using
	 ghost_maplets.h.
*/

#ifndef _GHOST_PGTABLE_H
#define _GHOST_PGTABLE_H


#include <nvhe/ghost_maplets.h>
#include <nvhe/memory.h>   // for hyp_phys_to_virt
#include <nvhe/mem_protect.h>   // for PKVM_ID_HOST etc

#include <nvhe/ghost_pfn_set.h>


/*************************************************************************h
 * Page table entry kind 
 *************************************************************************/

/*
 * Concrete masks, and field bitpatterns for a variety of PTE bits
 *
 * Key:
 *	PTE_FIELD_XYZ_LO is the bit index the field XYZ starts at
 *	PTE_FIELD_XYZ_LEN is the number of bits the field comprises.
 *	PTE_FIELD_XYZ_MASK is a mask where only the bits of field XYZ are set to 1.
 *	PTE_FIELD_XYZ_ABC is a PTE_FIELD_XYZ_LEN-length bitpattern corresponding to state ABC, of field XYZ.
 *
 *  PTE_FIELD_Sn_LVLm_... is one of the above, but only valid for Stage n at Level m
 *
 * Not all fields will define all variants (e.g. the _LEN is often implicit and not directly needed).
 */

#define PTE_FIELD_INVALID_00 0b00
#define PTE_FIELD_INVALID_10 0b10

#define PTE_FIELD_LVL012_BLOCK 0b01
#define PTE_FIELD_LVL012_TABLE 0b11

#define PTE_FIELD_LVL3_PAGE 0b11
#define PTE_FIELD_LVL3_RESERVED 0b01

#define PTE_FIELD_OWNER_ID_LO 2
#define PTE_FIELD_PKVM_OWNER_ID_HOST (PKVM_ID_HOST << PTE_FIELD_OWNER_ID_LO)
#define PTE_FIELD_PKVM_OWNER_ID_HYP (PKVM_ID_HYP << PTE_FIELD_OWNER_ID_LO)
#define PTE_FIELD_PKVM_OWNER_ID_GUEST (PKVM_ID_GUEST << PTE_FIELD_OWNER_ID_LO)

// G.b p2742 4KB translation granule has a case split on whether "the Effective value of TCR_ELx.DS or VTCR_EL2.DS is 1".
// DS is for 52-bit output addressing with FEAT_LPA2, and is zero in the register values we see; I'll hard-code that for now.  Thus, G.b says:
// - For a level 1 Block descriptor, bits[47:30] are bits[47:30] of the output address. This output address specifies a 1GB block of memory.
// - For a level 2 Block descriptor, bits[47:21] are bits[47:21] of the output address.This output address specifies a 2MB block of memory.
#define PTE_FIELD_LVL1_OA_MASK GENMASK(47, 30)
#define PTE_FIELD_LVL2_OA_MASK GENMASK(47, 21)
#define PTE_FIELD_LVL3_OA_MASK GENMASK(47, 12)

static u64 PTE_FIELD_OA_MASK[4] = {
	[1] = PTE_FIELD_LVL1_OA_MASK,
	[2] = PTE_FIELD_LVL2_OA_MASK,
	[3] = PTE_FIELD_LVL3_OA_MASK,
};

#define PTE_FIELD_UPPER_ATTRS_LO 59
#define PTE_FIELD_UPPER_ATTRS_MASK GENMASK(63, 50)

#define PTE_FIELD_LOWER_ATTRS_LO 2
#define PTE_FIELD_LOWER_ATTRS_MASK GENMASK(11, 2)

#define PTE_FIELD_ATTRS_MASK (PTE_FIELD_UPPER_ATTRS_MASK | PTE_FIELD_LOWER_ATTRS_MASK)

/* outside of realm security state, bit[55] is IGNORED, so can be used by software */
#define PTE_FIELD_UPPER_ATTRS_SW_LO 55
#define PTE_FIELD_UPPER_ATTRS_SW_MASK GENMASK(58, 55)

#define PTE_FIELD_TABLE_UPPER_IGNORED_MASK GENMASK(58, 51)
#define PTE_FIELD_TABLE_IGNORED_MASK (PTE_FIELD_LOWER_ATTRS_MASK | PTE_FIELD_TABLE_UPPER_IGNORED_MASK)

#define PTE_FIELD_TABLE_NEXT_LEVEL_ADDR_MASK GENMASK(47,12)

#define PTE_FIELD_S1_AP2_LO 7
#define PTE_FIELD_S1_AP2_MASK BIT(7)
#define PTE_FIELD_S1_AP2_READ_ONLY (1UL)
#define PTE_FIELD_S1_AP2_READ_WRITE (0UL)

#define PTE_FIELD_S1_AP1_LO 6
#define PTE_FIELD_S1_AP1_MASK BIT(6)

#define PTE_FIELD_S1_XN_LO 54
#define PTE_FIELD_S1_XN_MASK BIT(54)
#define PTE_FIELD_S1_XN_NOT_EXEC_NEVER (0UL)
#define PTE_FIELD_S1_XN_EXEC_NEVER (1UL)

#define PTE_FIELD_S1_ATTRINDX_LO 2
#define PTE_FIELD_S1_ATTRINDX_MASK GENMASK(4, 2)

#define PTE_FIELD_S2_S2AP10_LO 6
#define PTE_FIELD_S2_S2AP10_MASK GENMASK(7, 6)

#define PTE_FIELD_S2_S2AP0_LO 6
#define PTE_FIELD_S2_S2AP0_MASK BIT(6)
#define PTE_FIELD_S2_S2AP0_READABLE (1UL)
#define PTE_FIELD_S2_S2AP0_NOT_READABLE (0UL)

#define PTE_FIELD_S2_S2AP1_LO 7
#define PTE_FIELD_S2_S2AP1_MASK BIT(7)
#define PTE_FIELD_S2_S2AP1_WRITEABLE (1UL)
#define PTE_FIELD_S2_S2AP1_NOT_WRITEABLE (0UL)

#define PTE_FIELD_S2_XN_LO 53
#define PTE_FIELD_S2_XN_MASK GENMASK(54, 53)
/*
 * S2 XN is actually two bits encoding EL1 and EL0 execution separately.
 * but we assume they're either both allowed (00) or both forbidden (10)
 */
#define PTE_FIELD_S2_XN_NOT_EXEC_NEVER (0b00UL)
#define PTE_FIELD_S2_XN_EXEC_NEVER (0b10UL)

#define PTE_FIELD_S2_MEMATTR_LO 2
#define PTE_FIELD_S2_MEMATTR_MASK GENMASK(5, 2)

#define PTE_FIELD_S2_MEMATTR_DEVICE_nGnRE (0b0010UL)
#define PTE_FIELD_S2_MEMATTR_NORMAL_OUTER_INNER_WRITE_BACK_CACHEABLE (0b1111UL)

/**
 * PTE_EXTRACT() - Extract a PTE_FIELD from a value.
 *
 * e.g. PTE_EXTRACT(PTE_FIELD_S1_XN, 1 << PTE_FIELD_S1_XN_LO) == 1
 */
#define PTE_EXTRACT(FIELD_PREFIX, VAL) \
	(((VAL) & FIELD_PREFIX##_MASK) >> FIELD_PREFIX##_LO)

static inline bool __s1_is_ro(u64 pte) { return PTE_EXTRACT(PTE_FIELD_S1_AP2, pte) == PTE_FIELD_S1_AP2_READ_ONLY; }
static inline bool __s1_is_xn(u64 pte) { return PTE_EXTRACT(PTE_FIELD_S1_XN, pte) == PTE_FIELD_S1_XN_EXEC_NEVER; }

static inline bool __s2_is_r(u64 pte) { return PTE_EXTRACT(PTE_FIELD_S2_S2AP0, pte) == PTE_FIELD_S2_S2AP0_READABLE; }
static inline bool __s2_is_w(u64 pte) { return PTE_EXTRACT(PTE_FIELD_S2_S2AP1, pte) == PTE_FIELD_S2_S2AP1_WRITEABLE; }
static inline bool __s2_is_xn(u64 pte) { return PTE_EXTRACT(PTE_FIELD_S2_XN, pte) == PTE_FIELD_S2_XN_EXEC_NEVER; }
static inline bool __s2_is_x(u64 pte) { return PTE_EXTRACT(PTE_FIELD_S2_XN, pte) != PTE_FIELD_S2_XN_NOT_EXEC_NEVER; }

/* Technically, MemAttr is not a PTE field, but actually stored in the MAIR_ELx register, but whatever */
#define MEMATTR_LEN 8
#define MEMATTR_MASK GENMASK(7,0)
#define EXTRACT_MEMATTR(MAIR, IDX) (((MAIR) >> ((IDX) * MEMATTR_LEN)) & MEMATTR_MASK)

#define MEMATTR_FIELD_DEVICE_nGnRE (0b00000100UL)
#define MEMATTR_FIELD_NORMAL_OUTER_INNER_WRITE_BACK_CACHEABLE (0b11111111)

// the logical entry kinds
typedef enum entry_kind {
	EK_INVALID,
	EK_BLOCK,
	EK_TABLE,
	EK_PAGE_DESCRIPTOR,
	EK_BLOCK_NOT_PERMITTED,
	EK_RESERVED,
	EK_DUMMY
} entry_kind_type;


/* Parsers from concrete to abstract */

#define GHOST_ATTR_MAX_LEVEL 3

/**
 * struct aal - Record of upper+lower attribute bits of a PTE at each level down the walk.
 */
struct aal {
	u64 attr_at_level[4];
};

#define DUMMY_AAL ((struct aal){.attr_at_level={0}})

typedef struct mair {
	bool present;
	u8 attrs[8];
} ghost_mair_t;

static inline ghost_mair_t read_mair(u64 mair)
{
	ghost_mair_t attrs;
	attrs.present = true;

	for (int i = 0 ; i < 8; i++){
		attrs.attrs[i] = EXTRACT_MEMATTR(mair, i);
	}

	return attrs;
}

static inline ghost_mair_t no_mair(void) {
	return (ghost_mair_t){
		.present = false
	};
}

/**
 * parse_annot() - Construct an abstracted owner annotation from a concrete descriptor.
 */
struct maplet_target_annot parse_annot(u64 desc);

/**
 * parse_attrs() - Construct abstracted maplet attributes from the concrete pte encoding.
 * @stage: the stage (either GHOST_STAGE1 or GHOST_STAGE2) to parse the pte as from.
 * @mair: the concrete MAIR_ELx value to use for Stage 1 memory attributes.
 * @desc: the concrete 64-bit descriptor.
 * @level: the level this PTE is at in the table.
 * @next_level_aal: the attrs-at-level so far, for re-constructing hierarchical permissions.
 */
struct maplet_attributes parse_attrs(ghost_stage_t stage, ghost_mair_t mair, u64 desc, u8 level, struct aal next_level_aal);

/**
 * parse_mapped() - Construct abstracted mapping target from an OA and attributes.
 */
struct maplet_target_mapped parse_mapped(ghost_stage_t stage, ghost_mair_t mair, u8 level, u64 oa, u64 nr_pages, u64 desc, struct aal next_level_aal);

#define DUMMY_ATTR 0

/**
 * abstract_pgtable - Mappings correspodning to a tree of translation tables.
 * @root: (for implementation refinement checks) the recorded root of the tree of translation tables.
 * @table_pfns: (for implementation refinement checks) the range of the underlying pool and donated pages that could hold pagetable pages.
 * @mapping: the mapping itself.
 */
struct abstract_pgtable_struct {
	u64 root;
	struct pfn_set table_pfns;
	mapping mapping;
};

typedef struct abstract_pgtable_struct abstract_pgtable; // let's be more pure-functional and less Linux style here

enum entry_kind entry_kind(unsigned long long pte, unsigned char level);
void hyp_put_ek(enum entry_kind ek);
void hyp_put_entry(kvm_pte_t pte, u8 level);
void hyp_put_abstract_pgtable(abstract_pgtable *ap, u64 indent);

mapping ghost_record_pgtable(struct kvm_pgtable *pgt, struct pfn_set *out_pfns, char *doc, u64 i);
mapping ghost_record_pgtable_and_check(mapping map_old, struct kvm_pgtable *pg, bool dump, char *doc, u64 i);

// start from an arbitrary point down in the walk
mapping ghost_record_pgtable_partial(kvm_pte_t *pgtable, ghost_stage_t stage, ghost_mair_t mair, u8 level, u64 va_partial, struct aal aal_partial, char *doc, u64 i);

// the ap variants are similar to the above but also record the mapping root
void ghost_record_pgtable_ap(abstract_pgtable *ap_out, struct kvm_pgtable *pg, u64 pool_range_start, u64 pool_range_end, char *doc, u64 i);

void abstract_pgtable_copy(abstract_pgtable *dst, abstract_pgtable *src);

// TODO: cleanup below here.
void dump_pgtable(struct kvm_pgtable pg);
void ghost_dump_pgtable(struct kvm_pgtable *pg, char *doc, u64 i);
void ghost_dump_pgtable_locked(struct kvm_pgtable *pg, char *doc, u64 i);

#endif // _GHOST_PGTABLE_H
