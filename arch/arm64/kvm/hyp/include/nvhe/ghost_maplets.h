#ifndef _GHOST_MAPLETS_H
#define _GHOST_MAPLETS_H

#include "ghost_glist.h"

#include <asm/kvm_pgtable.h>

#include <linux/memblock.h>   /* for enum memblock_flags */

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

/* we represent the mapping target type as a C discriminated union, to be clean and have a good correspondence to the ultimate math definitions, verbose though C unions are */

enum maplet_target_kind {
	MAPPED,
	ANNOT,
	MEMBLOCK,
	ABSENT                          // this should never appear in a mapping except within the implementation of mapping_minus; it's just s device so that that can be implemented using mapping_plus
};

#define GHOST_ATTR_MAX_LEVEL 4

struct maplet_target_mapped {
        phys_addr_t phys;               // page-aligned.  Should be "output address"??
	u64 page_state;                 // the two sw bits, KVM_PGTABLE_PROT_SW0 | KVM_PGTABLE_PROT_SW1, as used in enum pkvm_page_state
	u64 arch_prot;                  // the architectural protection bits, KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R (bit 6) | KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W (bit 7) | KVM_PTE_LEAF_ATTR_HI_S2_XN` (bit 54)  (not to be confused with enum kvm_pgtable_prot values)
	u64 attr;                       // should eventually be defunct
        u64 attr_at_level[GHOST_ATTR_MAX_LEVEL]; // the attribute fields at each level - or with bit 0 set if absent
};

struct maplet_target_annot {
	u64 owner_id;                   // bits 9:2 of a non-zero invalid entry, pulled out into a mem_protect.h enum pkvm_component_id value with FIELD_GET(KVM_INVALID_PTE_OWNER_MASK /*GENMASK(9,2)*/, _ )
	u64 owner;                      // bits 63:1 of a non-zero invalid entry, with bit zero cleared // should eventually be defunct
};

struct maplet_target_memblock {
	enum memblock_flags flags;
};

struct maplet_target {
	enum maplet_target_kind k;
	union maplet_target_union {
		struct maplet_target_mapped m;
		struct maplet_target_annot a;
		struct maplet_target_memblock b;
	} u;
};

struct maplet {
	struct glist_node list;
        u64 virt;         // page-aligned   // TODO: should be "input address"?
	u64 size;         // number of pages
	struct maplet_target target;
};

bool maplet_eq_nonattr(struct maplet *m1, struct maplet *m2);
bool maplet_eq(struct maplet *m1, struct maplet *m2);

struct aal {
	u64 attr_at_level[GHOST_ATTR_MAX_LEVEL];
};

/* constructors for struct maplet_target */
/* the new "semantic" versions */
struct maplet_target maplet_target_mapped_ext(phys_addr_t phys, u64 page_state, u64 arch_prot);
struct maplet_target maplet_target_annot_ext(u64 owner_id);
/* the old "pte bits" versions */
struct maplet_target maplet_target_mapped(phys_addr_t phys, u64 attr, struct aal aal);
struct maplet_target maplet_target_shared(u64 owner);
struct maplet_target maplet_target_annot(u64 owner);
struct maplet_target maplet_target_memblock(enum memblock_flags flags);

struct aal dummy_aal(void);
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
void extend_mapping_coalesce(mapping *mapp, u64 virt, u64 nr_pages, struct maplet_target t);
void hyp_put_maplet(struct maplet *maplet, u64 indent);
void hyp_put_mapping(mapping map, u64 indent);
bool interpret_equals(mapping map1, mapping map2, u64 indent);
void diff_mappings(mapping map1, mapping map2, u64 indent);

mapping mapping_empty_(void); // the extra _ is to avoid a nameclash with the unrelated include/linux/pagemap.h
mapping mapping_singleton(u64 virt, u64 nr_pages, struct maplet_target t);
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

// deallocate @map_out and set it to point to a new copy of the mapping in @map
void mapping_move(mapping *map_out, mapping map);



void ghost_lock_maplets(void);
void ghost_unlock_maplets(void);
inline void ghost_assert_maplets_locked(void);

#endif  // _GHOST_MAPLETS_H





