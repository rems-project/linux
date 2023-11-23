#ifndef _GHOST_MAPLETS_H
#define _GHOST_MAPLETS_H

#include "ghost_glist.h"

#include <asm/kvm_pgtable.h>

#include <linux/memblock.h>   /* for enum memblock_flags */

#include <nvhe/ghost_printer.h>

/* ****************** maplet types ****************** */

/* A struct maplet records a single piece of contiguous
   input-to-output address mapping (or invalid-entry annotation).  A
   linked list of maplets records an entire mapping, with invariant
   that such lists are functional and sorted by input address,
   increasing (with smallest at the list head).  The host pagetable
   records an "annotation" in certain invalid entries, e.g. to record
   that those pages are part of pKVM so should not be mapped on
   demand.  A linked list of maplets should thus abstract to a finite
   map from page virtual addresses to the union of
   (phys,prot,attribute) records and annotations.
   Non-host pgtables will abstract to mappings using just the first of those two.
   To avoid massive repetition, given the limitations of the C type system,
   we use the same type to record the hyp_memory mapping, whose
   target type is an enum memblock_flags (as in include/linux/memblock.h),
   by adding a third union member.
 */


/* the attributes are in the same representation as the Arm ARM "Attribute fields in stage 2 VMSAv8-64 Block and Page descriptors" I.a D8.3.2 D8-5126 I_GBPDK for 4k granule 48-bit OA block and page descriptors, with non-attribute bits masked to zero by pte & (GENMASK(63,50) | GENMASK(11,2) in ghost_pgtable.c.

Should we instead use the proper interpretation of those bits (which would then also involve various system-register values)?

More-or-less punting so far on the hierarchical aspects thereof - mostly looking just at the leaf block or page descriptor attributes - we do record the table descriptor attributes, but AFAIK they are always zero.

Generic pte bitmasks are defined in arch/arm64/include/asm/kvm_pgtable.h, e.g.

#define KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR	GENMASK(5, 2)
#define KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R	BIT(6)
#define KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W	BIT(7)

etc.

That kvm_pgtable.h also defines enum kvm_pgtable_prot - Page-table permissions and attributes - which includes:

  (1) KVM_PGTABLE_PROT_SW{0,1,2,3} are bits 55,56,57,58 - but these (confusingly!) are Arm-A bits.

  pKVM-specific bitmasks are defined in arch/arm64/kvm/hyp/include/nvhe/mem_protect.h,
  using two of the software-defined bits (55 and 56):

  enum pkvm_page_state {
v  	PKVM_PAGE_OWNED			= 0ULL,
  	PKVM_PAGE_SHARED_OWNED		= KVM_PGTABLE_PROT_SW0,
  	PKVM_PAGE_SHARED_BORROWED	= KVM_PGTABLE_PROT_SW1,
  	__PKVM_PAGE_RESERVED		= KVM_PGTABLE_PROT_SW0 |
  					  KVM_PGTABLE_PROT_SW1,

  (2) KVM_PGTABLE_PROT_{X,W,R,DEVICE,NC} are bits 0,1,2,3,4 - but those (confusingly!) aren't Arm-A bits; they're defined in arch/arm64/include/asm/kvm_pgtable.h and mapped to and from Arm-A by pgtable.c:{hyp_set_prot_attr(),kvm_pgtable_hyp_pte_prot()}

  The pKVM-used values of the latter are (I hope) just the combinations defined below that:

  #define PKVM_HOST_MEM_PROT	KVM_PGTABLE_PROT_RWX
  #define PKVM_HOST_MMIO_PROT	KVM_PGTABLE_PROT_RW

  #define PAGE_HYP		KVM_PGTABLE_PROT_RW
  #define PAGE_HYP_EXEC		(KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_X)
  #define PAGE_HYP_RO		(KVM_PGTABLE_PROT_R)
  #define PAGE_HYP_DEVICE		(PAGE_HYP | KVM_PGTABLE_PROT_DEVICE)

*/

/**
 * enum maplet_permissions - Abstract permissions for a range of OA, as bitflags
 */
enum maplet_permissions {
	MAPLET_PERM_R = 1,
	MAPLET_PERM_W = 2,
	MAPLET_PERM_X = 4,

	/*
	 * MAPLET_PERM_UNKNOWN for encodings that do not correspond to any of the above.
	 */
	MAPLET_PERM_UNKNOWN = 8,
};
#define MAPLET_PERM_RW (MAPLET_PERM_R | MAPLET_PERM_W)
#define MAPLET_PERM_RWX (MAPLET_PERM_R | MAPLET_PERM_W | MAPLET_PERM_X)

/**
 * enum maplet_permissions - Abstract ownership state of some OA range.
 */
enum maplet_page_state {
	MAPLET_PAGE_STATE_PRIVATE_OWNED,
	MAPLET_PAGE_STATE_SHARED_OWNED,
	MAPLET_PAGE_STATE_SHARED_BORROWED,

	/*
	 * MAPLET_PAGE_STATE_UNKNOWN for encodings that don't correspond to any of the above states.
	 */
	MAPLET_PAGE_STATE_UNKNOWN,
};

/**
 * enum maplet_memtype_attr - Abstract memory type.
 */
enum maplet_memtype_attr {
	MAPLET_MEMTYPE_DEVICE,
	MAPLET_MEMTYPE_NORMAL_CACHEABLE,

	/* MAPLET_MEMTYPE_UNKNOWN for encodings that do not correspond to any of the above */
	MAPLET_MEMTYPE_UNKNOWN,
};

struct maplet_attributes {
	enum maplet_permissions prot;
	enum maplet_page_state provenance;
	enum maplet_memtype_attr memtype;

	/**
	 * @raw_arch_attrs: the raw descriptor, masked to the attribute bits
	 * Not semantically meaningful, but used in printing and diffs.
	 */
	u64 raw_arch_attrs;
};

enum maplet_target_kind {
	MAPLET_MAPPED,
	MAPLET_UNMAPPED, /* with owner annotation */
	MAPLET_MEMBLOCK,

	/**
	 * @MAPLET_ABSENT
	 * this should never appear in a mapping except within the implementation of mapping_minus;
	 * it's just s device so that that can be implemented using mapping_plus
	 */
	MAPLET_ABSENT,
};

/**
 * struct maplet_target_mapped - An OA (output-address) range and attributes
 */
struct maplet_target_mapped {
	u64 oa_range_start;
	u64 oa_range_nr_pages;
	struct maplet_attributes attrs;
};

/**
 * enum maplet_owner_annotation - Abstract ownership identifier of some location.
 */
enum maplet_owner_annotation {
	MAPLET_OWNER_ANNOT_OWNED_HOST,
	MAPLET_OWNER_ANNOT_OWNED_GUEST,
	MAPLET_OWNER_ANNOT_OWNED_HYP,

	/*
	 * MAPLET_OWNER_ANNOT_UNKNOWN for encodings that don't match one of the known encodings of the above.
	 */
	MAPLET_OWNER_ANNOT_UNKNOWN,
};

struct maplet_target_annot {
	enum maplet_owner_annotation owner;

	/**
	 * the raw descriptor
	 * not semantically meaningful, used in printing and diffs.
	 */
	u64 raw_arch_annot;
};

/**
 * struct maplet_target - State for the range of the mapping.
 */
struct maplet_target {
	enum maplet_target_kind kind;
	union {
		struct maplet_target_mapped map;
		struct maplet_target_annot annot;
		enum memblock_flags memblock;
	};
};

typedef enum mapping_stage {
	GHOST_STAGE2,
	GHOST_STAGE1,

	/**
	 * @GHOST_STAGE_NONE: for memblocks and other non-pgtable mappings.
	 */
	GHOST_STAGE_NONE,
} ghost_stage_t;

/**
 * struct maplet - a single contiguous mapping.
 */
struct maplet {
	/**
	 * @list: a mapping is an ordered linked-list of these maplets.
	 */
	struct glist_node list;

	/**
	 * @stage: which stage of translation this maplet is for.
	 *
	 * This doesn't affect the semantics, only the pretty printing.
	 */
	ghost_stage_t stage;

	/**
	 * @ia_range_start:
	 * @ia_range_nr_pages: the range of input-address this maplet is for.
	 */
	u64 ia_range_start;
	u64 ia_range_nr_pages;

	/**
	 * @target: the output for this range.
	 */
	struct maplet_target target;
};

bool maplet_eq_nonattr(struct maplet *m1, struct maplet *m2);
bool maplet_eq(struct maplet *m1, struct maplet *m2);

/*
 * Constructing maplets:
 */
struct maplet_target maplet_target_mapped(u64 oa_start,  u64 nr_pages, struct maplet_target_mapped m);
struct maplet_target maplet_target_mapped_ext(u64 oa_start,  u64 nr_pages, enum maplet_permissions prot, enum maplet_page_state page_state, enum maplet_memtype_attr memtype);
struct maplet_target maplet_target_mapped_attrs(u64 oa_start,  u64 nr_pages, struct maplet_attributes attrs);
struct maplet_target maplet_target_annot(struct maplet_target_annot annot);
struct maplet_target maplet_target_annot_ext(enum maplet_owner_annotation owner_id);
struct maplet_target maplet_target_memblock(enum memblock_flags flags);
struct maplet_target maplet_target_absent(void);


/* We'll set up a large pool of maplets in a global variable. This is
   an arbitrary hack - it's hard to know how big this should be, but
   if it never runs out during testing, that's ok - this ghost code is
   not intended to be there in production builds */
#define MAX_MAPLETS 100000

struct maplets {
	struct maplet maplets[MAX_MAPLETS];
	struct glist_head free;
};

extern struct maplets maplets_pool;

/* users of ghost_maplets.{c,h} should see an opaque type of mappings */
typedef struct glist_head mapping;

void free_mapping(mapping map);
void extend_mapping_coalesce(mapping *mapp, ghost_stage_t stage, u64 ia, u64 nr_pages, struct maplet_target t);
void hyp_put_mapping(mapping map, u64 indent);
bool interpret_equals(mapping map1, mapping map2, u64 indent);

mapping mapping_empty_(void); // the extra _ is to avoid a nameclash with the unrelated include/linux/pagemap.h
mapping mapping_singleton(ghost_stage_t stage, u64 virt, u64 nr_pages, struct maplet_target t);
mapping mapping_plus(mapping map1, mapping map2);
mapping mapping_minus(mapping map1, u64 virt, u64 nr_pages);
mapping mapping_copy(mapping map);
mapping mapping_annot(mapping map);
mapping mapping_shared(mapping map);
mapping mapping_nonannot(mapping map);

bool mapping_submapping(mapping map1, mapping map2, char *s, char *s1, char *s2, u64 indent);
bool mapping_equal(mapping map1, mapping map2, char *s, char *s1, char *s2, u64 indent);
void check_mapping_equal(mapping map1, mapping map2);
bool mapping_disjoint(mapping map1, mapping map2, char *s, char *s1, char *s2, u64 indent);
bool mapping_in_domain(u64 virt, mapping map);
bool mapping_lookup(u64 virt, mapping map, struct maplet_target *tp);

/**
 * mapping_oa() - Do a translation from an ia to an oa
 *
 * Returns false if not in domain of mapping, or if not mapped.
 * Writes to out the OA if found.
 */
bool mapping_oa(u64 ia, mapping map, u64 *out);

typedef enum {
	MAP_INSERT_PAGE,
	MAP_REMOVE_PAGE,
	MAP_UPDATE_PAGE
} mapping_update_kind_t;

#define MAPLET_NONE maplet_target_absent()

/**
 * mapping_update() - Write an update to a mapping.
 * @in: the mapping to base the update on.
 * @kind: what kind of update to perform.
 * @ia: the stage of pagetable this is.
 * @ia: the input address to target this update on.
 * @nr_pages: the number of pages the update is over.
 * @t: the target to insert (if applicable).
 *
 * Makes a copy of `in`, frees any old maplets `out` had, writes result to `out`
 *
 * If kind == MAP_REMOVE_PAGE, then `t` should be MAPLET_NONE, and if any IA is already mapped, panics.
 * If kind == MAP_INSERT_PAGE and any of that IA is already mapped, then panics.
 * If kind == MAP_UPDATE_PAGE and any of that IA is not already mapped, then panics.
 */
void mapping_update(
	mapping *out,
	mapping in,
	mapping_update_kind_t kind,
	ghost_stage_t stage,
	u64 ia,
	u64 nr_pages,
	struct maplet_target t
);

// deallocate @map_out and set it to point to a new copy of the mapping in @map
void mapping_move(mapping *map_out, mapping map);


void ghost_lock_maplets(void);
void ghost_unlock_maplets(void);
inline void ghost_assert_maplets_locked(void);

/* don't call these directly, instead use ghost_printf %g(maplet) and %g(maplet_target) codes */
int gp_put_maplet_target(gp_stream_t *out, struct maplet_target *target);
int gp_put_maplet(gp_stream_t *out, struct maplet *maplet);

void hyp_put_maplet_target(struct maplet_target *target, u64 indent);
void hyp_put_maplet(struct maplet *maplet, u64 indent);

#endif  // _GHOST_MAPLETS_H





