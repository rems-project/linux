/* Ghost code to compute the interpretation of page tables in a
   concise representation that we can use in executable assertions, as
   ordered lists of "maplet"s.  This file defines that interpretation, using
   ghost_maplets.h. 
*/

#ifndef _GHOST_PGTABLE_H
#define _GHOST_PGTABLE_H


#include "./ghost_maplets.h"
#include "./include/nvhe/memory.h"   // for hyp_phys_to_virt


/*************************************************************************h
 * Page table entry kind 
 *************************************************************************/

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

// the entry kind bit representations
#define ENTRY_INVALID_0 0
#define ENTRY_INVALID_2 2
#define ENTRY_BLOCK 1
#define ENTRY_RESERVED 1
#define ENTRY_PAGE_DESCRIPTOR 3
#define ENTRY_TABLE 3


#define DUMMY_ATTR 0

#define GHOST_MAX_PFN_SET_LEN 64

struct pfn_set {
	u64 len;
	phys_addr_t pfns[GHOST_MAX_PFN_SET_LEN];
};

void ghost_pfn_set_insert(struct pfn_set *set, u64 pfn);
bool ghost_pfn_set_contains(struct pfn_set *set, u64 pfn);
void ghost_pfn_set_dump(struct pfn_set *set);
void ghost_pfn_set_copy(struct pfn_set *dst, struct pfn_set *src);

struct abstract_pgtable_struct {
	phys_addr_t root;
	mapping mapping;
};

typedef struct abstract_pgtable_struct abstract_pgtable; // let's be more pure-functional and less Linux style here

enum entry_kind entry_kind(unsigned long long pte, unsigned char level);
void hyp_put_ek(enum entry_kind ek);
void hyp_put_entry(kvm_pte_t pte, u8 level);
void dump_pgtable(struct kvm_pgtable pg);
void ghost_dump_pgtable(struct kvm_pgtable *pg, char *doc, u64 i);
void ghost_dump_pgtable_locked(struct kvm_pgtable *pg, char *doc, u64 i);

mapping interpret_pgtable(kvm_pte_t *pgd, bool noisy);
mapping ghost_record_pgtable(struct kvm_pgtable *pg, char *doc, u64 i);
mapping ghost_record_pgtable_and_check(mapping map_old, struct kvm_pgtable *pg, bool dump, char *doc, u64 i);

mapping ghost_record_pgtable_partial(kvm_pte_t *pgtable, u64 level, u64 va_partial, struct aal aal_partial, char *doc, u64 i);
void ghost_dump_pgtable_diff(mapping map_old, struct kvm_pgtable *pg, char *doc, u64 i);


// the ap variants are similar to the above but also record the mapping root
abstract_pgtable interpret_pgtable_ap(kvm_pte_t *pgd, bool noisy);
abstract_pgtable ghost_record_pgtable_ap(struct kvm_pgtable *pg, char *doc, u64 i);
abstract_pgtable ghost_record_pgtable_and_check_ap(abstract_pgtable map_old, struct kvm_pgtable *pg, bool dump, char *doc, u64 i);
void ghost_dump_pgtable_diff_ap(abstract_pgtable map_old, struct kvm_pgtable *pg, char *doc, u64 i);

void ghost_test(void);

abstract_pgtable abstract_pgtable_copy(abstract_pgtable src);

#endif // _GHOST_PGTABLE_H
