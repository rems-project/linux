/* Ghost code to compute the interpretation of page tables in a
   concise representation that we can use in executable assertions, as
   ordered lists of "maplet"s.  This file defines these maplets and
   the operations on them.

   The linking for this is a bit awkward, as it has to be used both
   from arch/arm64/kvm/hyp/pgtable.c and from the
   arch/arm64/kvm/hyp/nvhe/ code, and that pgtable.c AIUI is compiled
   once and then linked into the kernel image twice, once by whatever
   the normal kernel build process is, and once in the pKVM EL2
   section by the nvhe/ Makefile.  I've put the non-nvhe-specific
   ghost pagetable files here, with their include files in this same
   directory, and the nvhe-specific files in nvhe/, with (different
   purely by historical accident) their include files in
   include/nvhe/.  There's probably a better way.

   We need dynamic memory management for the interpretations, so that
   different functions (perhaps in different threads) can
   simultaneously record the initial abstract state of a pagetable.
   It's unclear whether that should be done with a general-purpose
   malloc/free-interface allocator or something special-purpose.  I
   guess the former in general, but for now I'll do the latter,
   keeping all maplets as linked lists within a single global array
   (protected by a single global ghost_lock), and keeping a free list of
   unallocated maplets. To follow linux-kernel style (and to
   be able to use their sorting functions), we'll use the linux list
   types from include/linux/list.h.

   2022-08: this use of the linux doubly-linked circular lists turns out
   to be awkward when one wants more functional-looking spec code,
   as one can't sensibly just pass the list head struct around by value
   (because the first and last nodes point back to the head).  We could
   roll our own singly-linked lists, but O(1) concatenation is useful
   for freeing maplet-lists, so perhaps best singly-linked lists with
   the head pointing to first and last nodes?

   Then we also want some kind of region-based memory management for the
   transient ghost state within each function. 
*/


#include <asm/kvm_mmu.h>

#include "./debug-pl011.h"
#include "./ghost_extra_debug-pl011.h"

#include "./ghost_maplets.h"
//#include <linux/list_sort.h>

#include <nvhe/spinlock.h>   // no idea whether this will work - probably not
#include <asm/kvm_pgtable.h>
#include <nvhe/mem_protect.h>





/* ****************** the global pool of maplets ****************** */

struct maplets maplets_pool;

bool maplets_init=false;

DEFINE_HYP_SPINLOCK(ghost_maplets_lock);


/* ****************** maplet target constructors ****************** */

struct aal dummy_aal(void)
{
	struct aal ret;
	int i;
	for (i=0; i<GHOST_ATTR_MAX_LEVEL; i++)
		ret.attr_at_level[i]=1;
	return ret;
}


struct maplet_target maplet_target_mapped_ext(phys_addr_t phys, u64 page_state, u64 arch_prot)
{
	int i;
	u64 attr = page_state | arch_prot;
	struct aal aal = dummy_aal();
	struct maplet_target t = (struct maplet_target){ .k=MAPPED, .u={.m={
				.phys = phys,
				.page_state = page_state,
				.arch_prot = arch_prot,
				.attr = attr}}};
	for (i=0; i<GHOST_ATTR_MAX_LEVEL; i++)
		t.u.m.attr_at_level[i]=aal.attr_at_level[i];
	return t;
}

struct maplet_target maplet_target_mapped(phys_addr_t phys, u64 attr, struct aal aal)
{
	int i;
	struct maplet_target t = (struct maplet_target){ .k=MAPPED, .u={.m={
				.phys = phys,
				.page_state = attr & (KVM_PGTABLE_PROT_SW0 | KVM_PGTABLE_PROT_SW1),
				.arch_prot = attr & (KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R /*bit 6*/ | KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W /*bit 7*/ | KVM_PTE_LEAF_ATTR_HI_S2_XN /*bit 54*/),
				.attr = attr}}};
	for (i=0; i<GHOST_ATTR_MAX_LEVEL; i++)
		t.u.m.attr_at_level[i]=aal.attr_at_level[i];
	return t;
}
// horrible hack: duplication of the following from the middle of mem_protect.c
#define KVM_INVALID_PTE_OWNER_MASK	GENMASK(9, 2)
struct maplet_target maplet_target_annot_ext(u64 owner_id) {
	u64 owner = FIELD_PREP(KVM_INVALID_PTE_OWNER_MASK /*GENMASK(9,2)*/, owner_id);
	return (struct maplet_target){ .k=ANNOT, .u={.a={
				.owner_id = owner_id,
				.owner = owner}}};
}

struct maplet_target maplet_target_annot(u64 owner) {
	return (struct maplet_target){ .k=ANNOT, .u={.a={
				.owner_id = FIELD_GET(KVM_INVALID_PTE_OWNER_MASK /*GENMASK(9,2)*/, owner),
				.owner = owner}}};
}

struct maplet_target maplet_target_memblock(enum memblock_flags flags) {
	return (struct maplet_target){ .k=MEMBLOCK, .u={.b={.flags=flags}}};
}

struct maplet_target maplet_target_absent(void) {
	return (struct maplet_target){ .k=ABSENT /*, .u=uninit */ };
}

/* ****************** maplet init, alloc, free ****************** */

/* init: add all the maplets to the free list */
void init_maplets(void)
{
	u64 i;
	INIT_GLIST_HEAD(&maplets_pool.free);
	for (i=0; i<MAX_MAPLETS; i++) {
		glist_add(&maplets_pool.maplets[i].list, &maplets_pool.free);
	}
}


/* alloc: move the head of the free list in @maplets_pool (if it exists) to become the new last entry of maplets_list, and return a pointer to its enclosing maplet */
struct maplet * get_maplet(struct glist_head *maplets_list)
{
	struct glist_node *node;
	struct maplet *ret;
	if (glist_empty(&maplets_pool.free))
		check_assert_fail("get_maplet: no free maplets");
	node = maplets_pool.free.first;
	ret = glist_entry(node, struct maplet, list);
	glist_move_head_to_tail(&maplets_pool.free, maplets_list);
	return ret;
}

/* free: stitch all nodes of maplets_list into the start of the free list of the pool */
void free_mapping(struct glist_head maplets_list)
{
	if (!glist_empty(&maplets_list)) {

		if (glist_empty(&maplets_pool.free)) {
			maplets_pool.free.first = maplets_list.first;
			maplets_pool.free.last = maplets_list.last;
		} else {
			maplets_list.last->next = maplets_pool.free.first;
			maplets_pool.free.first = maplets_list.first;
		}
	}
}


/* ******************  maplets locking and auto-init *************** */
void ghost_lock_maplets(void)
{
	//hyp_puts("ghost_lock_maplets");
	hyp_spin_lock(&ghost_maplets_lock);
	if (!maplets_init) {
		init_maplets();
		maplets_init = true;
	}
	//hyp_puts("ghost_lock_maplets succeed");
}
void ghost_unlock_maplets(void)
{
	//hyp_puts("ghost_unlock_maplets");
	hyp_spin_unlock(&ghost_maplets_lock);
}


/* ******************  maplets extend  *************** */

// extend maplets with one new maplet, coalescing it into the existing tail of the list if both are mapped and contiguous in va and pa, and with the same attr, or if both are annot and contiguous in va, and otherwise adding as a newly allocated maplet taken from the pool


bool attr_at_level_equal(u64 attr_at_level1[GHOST_ATTR_MAX_LEVEL], u64 attr_at_level2[GHOST_ATTR_MAX_LEVEL])
{
	bool ret = true;
	int i;
	for (i=0; i<GHOST_ATTR_MAX_LEVEL; i++)
		ret = ret && (attr_at_level1[i] == attr_at_level2[i]);
	return ret;
}
void extend_mapping_coalesce(struct glist_head *maplets_list, u64 virt, u64 nr_pages, struct maplet_target t)
{
	struct maplet *tail;
	struct maplet *m_new;

	//hyp_putsp("extend_mapping_coalesce ");

	tail = glist_last_entry_or_null(maplets_list, struct maplet, list);

        if (tail != NULL && virt <= tail->virt) {  hyp_putsxn("virt",virt,64); check_assert_fail("extend maplets_coalesce given non-increasing virt"); }
	if (tail != NULL &&
		virt == tail->virt + tail->size*PAGE_SIZE &&
		t.k == tail->target.k &&
		((t.k == MAPPED) ?
			/* mapped */
			((t.u.m.phys == tail->target.u.m.phys + tail->size*PAGE_SIZE) &&
				(t.u.m.page_state == tail->target.u.m.page_state) &&
				(t.u.m.arch_prot == tail->target.u.m.arch_prot) &&
				(t.u.m.attr == tail->target.u.m.attr) &&
				(attr_at_level_equal(t.u.m.attr_at_level, tail->target.u.m.attr_at_level))) : ((t.k == ANNOT) ?
			/* annot */
			((t.u.a.owner_id == tail->target.u.a.owner_id) &&
				(t.u.a.owner == tail->target.u.a.owner))
			/* memblock */
			: (t.u.b.flags == tail->target.u.b.flags))
			)
		) {
		tail->size += nr_pages;
		//hyp_putsp("tail ");
		//hyp_put_maplet(tail,0);
		//hyp_putsp("\n");
	} else {
		m_new = get_maplet(maplets_list);
		m_new->virt=virt;
		m_new->size=nr_pages;
		m_new->target=t;
		//hyp_putsp("m_new ");
		//hyp_put_maplet(m_new,0);
		//hyp_putsp("\n");

	}
	//hyp_put_mapping(*maplets_list,4);
	//hyp_putsp("\n");
}

// create mapping with no maplets
mapping mapping_empty_(void) {
	struct glist_head head;
	INIT_GLIST_HEAD(&head);
	return head;
}

// create mapping with a single maplet
mapping mapping_singleton(u64 virt, u64 nr_pages, struct maplet_target t) {
	struct glist_head head;
	INIT_GLIST_HEAD(&head);
	extend_mapping_coalesce(&head, virt, nr_pages, t);
	return head;
}




/* ****************** maplets printing ****************** */

void hyp_put_maplet(struct maplet *maplet, u64 i)
{
	int j;
	bool allzero;
	hyp_puti(i);
	//hyp_putsxn("node",(u64)maplet,64);
	//hyp_putsxn("next",(u64)(maplet->list.next),64);
	hyp_putsxn("virt",maplet->virt,64);
	hyp_putsxn("virt'",maplet->virt+maplet->size*PAGE_SIZE,64);
	switch (maplet->target.k) {
	case MAPPED:
		hyp_putsxn("phys",maplet->target.u.m.phys,64);
		hyp_putsxn("phys'",maplet->target.u.m.phys+maplet->size*PAGE_SIZE,64);
		break;
	case ANNOT:
		hyp_putsxn("owner ",maplet->target.u.a.owner,64);
		hyp_putsp("                       ");
		break;
	case MEMBLOCK:
		hyp_putsxn("flags ",(u64)maplet->target.u.b.flags,64);
		hyp_putsp(" ");
		if (maplet->target.u.b.flags & MEMBLOCK_HOTPLUG) hyp_putsp("HOTPLUG "); else hyp_putsp("        ");
		if (maplet->target.u.b.flags & MEMBLOCK_MIRROR)  hyp_putsp("MIRROR "); else hyp_putsp("       ");
		if (maplet->target.u.b.flags & MEMBLOCK_NOMAP)   hyp_putsp("NOMAP"); else hyp_putsp("     ");
		hyp_putsp("  ");
		break;
	case ABSENT:
		hyp_putsp("ABSENT                        ");
		break;
	}
	hyp_putsxn("size(b,p)",maplet->size*PAGE_SIZE,64);
	hyp_putsxn("",(u32)maplet->size,32);
	switch (maplet->target.k) {
	case MAPPED:
		// bits 56,55: two of the SW bits
		switch (maplet->target.u.m.page_state /*maplet->target.u.m.attr & PKVM_PAGE_STATE_PROT_MASK*/) {
		case PKVM_PAGE_OWNED: hyp_putsp("OW"); break;
		case PKVM_PAGE_SHARED_OWNED: hyp_putsp("SO"); break;
		case PKVM_PAGE_SHARED_BORROWED: hyp_putsp("SB"); break;
		case __PKVM_PAGE_RESERVED: hyp_putsp("RE"); break;
		}
		hyp_putsp(" ");
		// bits 7,6: S2AP[1:0]    (for Stage 2)
		// for "a stage 1 translation that supports one Exception level" (which I guess is pKVM's own mapping), 7 is AP[2], controlling W, and 6 is RES1, so this will still work
		switch (maplet->target.u.m.arch_prot /*maplet->target.u.m.attr */& KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R) {
		case (KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R): hyp_putsp("R"); break;
		case (0): hyp_putsp("-"); break;
		}
		switch (maplet->target.u.m.arch_prot /*maplet->target.u.m.attr */ & KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W) {
		case (KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W): hyp_putsp("W"); break;
		case (0): hyp_putsp("-"); break;
		}
		switch (maplet->target.u.m.arch_prot /*maplet->target.u.m.attr */ & KVM_PTE_LEAF_ATTR_HI_S1_XN) {  // TODO: refine for SCTLR_EL2.WXN==1 case, variously for stage 1 and stage 2
		case (KVM_PTE_LEAF_ATTR_HI_S1_XN): hyp_putsp("-"); break;
		case (0): hyp_putsp("X"); break;
		}
		hyp_putsp(" ");
		// the rest of the attributes
		allzero=true;
		for (j=0; j<GHOST_ATTR_MAX_LEVEL; j++) {
			if ((maplet->target.u.m.attr_at_level[j] & 1) == 0) {
				allzero = allzero && (maplet->target.u.m.attr_at_level[j] == 0);
			}
		}
		hyp_putsxn(" attr'",maplet->target.u.m.attr & ( ~(PKVM_PAGE_STATE_PROT_MASK|KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R|KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W|KVM_PTE_LEAF_ATTR_HI_S1_XN)),64);
		if (!allzero) {
			for (j=0; j<GHOST_ATTR_MAX_LEVEL; j++) {
				if ((maplet->target.u.m.attr_at_level[j] & 1) == 0) {
					hyp_putsxn("",maplet->target.u.m.attr_at_level[j],64);
				}
			}
		}
		break;
	case ANNOT:
		break;
	case MEMBLOCK:
		break;
	case ABSENT:
		break;
	}
}

void hyp_put_mapping(struct glist_head head, u64 i)
{
        struct glist_node *pos = NULL;
        struct maplet *m;
	bool first;
	u64 phys_first;
	u64 size_first;

	first=true;
	if (glist_empty(&head)) {
		hyp_putspi("empty\n",i);
		return;
	}
	glist_for_each( pos, &head)
	{
		hyp_puti(i);
		//hyp_putsxn("hyp_put_maplets pos",(u64)pos,64);
		m = glist_entry(pos, struct maplet, list);
		if (!first && m->target.k == MAPPED && m->target.u.m.phys == phys_first + size_first*PAGE_SIZE)
			hyp_putc('-');
		else
			hyp_putc(' ');
		if (first && m->target.k == MAPPED) {
			phys_first = m->target.u.m.phys;
			size_first = m->size;
			first = false;
		}
                hyp_put_maplet(m, 0);
                hyp_putc('\n');
        }
}



/* ****************** maplets sorting ****************** */

bool maplet_target_eq(struct maplet_target t1, struct maplet_target t2) {
	return t1.k == t2.k && (t1.k == MAPPED)?(t1.u.m.phys == t2.u.m.phys && t1.u.m.page_state == t2.u.m.page_state && t1.u.m.arch_prot == t2.u.m.arch_prot && t1.u.m.attr == t2.u.m.attr && attr_at_level_equal(t1.u.m.attr_at_level, t2.u.m.attr_at_level)):((t1.k == ANNOT)?(t1.u.a.owner_id == t2.u.a.owner_id && t1.u.a.owner == t2.u.a.owner):(t1.u.b.flags == t2.u.b.flags));
}

bool maplet_eq(struct maplet *m1, struct maplet *m2)
{
	return m1->virt == m2->virt && m1->size == m2->size && maplet_target_eq(m1->target, m2->target);
}

/*
static int maplet_compare_virt(const void *lhs, const void *rhs)
{
        if (((const struct maplet *)lhs)->virt < ((const struct maplet *)rhs)->virt) return -1;
        if (((const struct maplet *)lhs)->virt > ((const struct maplet *)rhs)->virt) return 1;
        return 0;
}

static int maplet_compare_phys(const void *lhs, const void *rhs)
{
        if (((const struct maplet *)lhs)->phys < ((const struct maplet *)rhs)->phys) return -1;
        if (((const struct maplet *)lhs)->phys > ((const struct maplet *)rhs)->phys) return 1;
        return 0;
}

static int maplet_compare_virt_list(void *_priv, const struct list_head *lhs, const struct list_head *rhs)
{
	return maplet_compare_virt(list_entry(lhs,struct maplet, list), list_entry(rhs,struct maplet, list));
}

static int maplet_compare_phys_list(void *_priv, const struct list_head *lhs, const struct list_head *rhs)
{
	return maplet_compare_phys(list_entry(lhs,struct maplet, list), list_entry(rhs,struct maplet, list));
}
*/

/*
void sort_maplets_virt(struct list_head *ms)
{
        list_sort(NULL, ms, maplet_compare_virt_list);
}

void sort_maplets_phys(struct list_head *ms)
{
        list_sort(NULL, ms, maplet_compare_phys_list);
}
*/


/* ****************** maplets equality check ****************** */
/* TODO: this checks the maplets are identical (NEW: no longer ignoring attr), but assumes the mappings are normalised.   OLD: (which with distinct attr they may not be) . Probably we should do a submapping check (which is more sophisticated) both ways? */
bool interpret_equals(struct glist_head head1, struct glist_head head2, u64 i)
{
	struct glist_node *pos1, *pos2;
	struct maplet *m1, *m2;
	//sort_maplets_virt(ms1);
	//sort_maplets_virt(ms2);

	if (glist_empty(&head1) && glist_empty(&head2))
		return true;
	if (glist_empty(&head1) || glist_empty(&head2)) {
		hyp_putsp(GHOST_WHITE_ON_RED);
		hyp_putspi("interpret_equals mismatch one empty ", i);
		hyp_putsp(GHOST_NORMAL);
		return false;
	}

	for ( (pos1 = head1.first, pos2 = head2.first);
	      (pos1 != NULL && pos2 != NULL);
	      (pos1 = pos1->next, pos2=pos2->next) ) {
		      m1 = glist_entry(pos1, struct maplet, list);
		      m2 = glist_entry(pos2, struct maplet, list);
		      if ( !(maplet_eq(m1, m2)) ) {
			      hyp_puti(i);
			      hyp_putsp(GHOST_WHITE_ON_RED);
			      hyp_putsxn("interpret_equals mismatch at virt1", m1->virt, 64);
			      hyp_putsxn("virt2", m2->virt, 64);
			      hyp_putsp(GHOST_NORMAL);
			      hyp_putc('\n');
			      return false;
		      }
        }

	if (! (pos1 == NULL && pos2 == NULL)) {
		hyp_putsp(GHOST_WHITE_ON_RED);
		hyp_putspi("interpret_equals mismatch different lengths", i);
		hyp_putsp(GHOST_NORMAL);
		return false;
	}

	return true;
}



/* ****************** maplets diff ****************** */

/* print the naive set diff between two mappings, printing each element of ms1 that isn't in ms2, just looking at equality of their entries. This doesn't (but could) exploit the ordering invariant */
void diff_mappings_one_way(struct glist_head head1, struct glist_head head2, char *s, u64 i)
{
	struct glist_node *pos1, *pos2;
	struct maplet *m1, *m2;
	if (glist_empty(&head1))
		return;
	glist_for_each(pos1, &head1) {
		m1 = glist_entry(pos1, struct maplet, list);
		if (!glist_empty(&head2)) {
			glist_for_each(pos2, &head2) {
				m2 = glist_entry(pos2, struct maplet, list);
				if (maplet_eq(m1, m2)) goto found;
			}
		}
		hyp_putspi(s, i);
		hyp_put_maplet(m1, i+2);
                hyp_putc('\n');
found: ;
	}
	return;
}

void diff_mappings(struct glist_head head1, struct glist_head head2, u64 i)
{
	hyp_putspi("diff_mappings\n", i);
	diff_mappings_one_way(head1,head2,"removed ", i+2);
	diff_mappings_one_way(head2,head1,"added   ", i+2);
	hyp_putspi("end diff_mappings\n", i);
}




// check that ms1 and ms2 are equal mappings
bool mapping_equal(struct glist_head head1, struct glist_head head2, char *s, char *s1, char *s2, u64 i)
{
	hyp_putspi(s, i);
	hyp_putsp(" ");
	hyp_putsp("mapping_equal ");
	hyp_putsp(s1);
	hyp_putsp(" ");
	hyp_putsp(s2);
	hyp_putsp(" ");
	if (interpret_equals(head1, head2, i+2)) {
		hyp_puts("true");
		return true;
	}
	else {
		hyp_putsp(GHOST_WHITE_ON_RED);
		hyp_putsp("false");
		hyp_putsp(GHOST_NORMAL);
		hyp_putsp("\n");
		return false;
	}
}

// check that head1 is a sub-finite-map of head2, i.e.
// forall virt. [[head1]](virt) defined => [[head2]](virt) defined and equal to [[head1]](virt)
// assumes both are ordered by virt and are "normalised", with no contiguous (+identical attr) maplets
// as an exercise, try something reasonably efficient, with a single traversal of the two lists - which ended up pretty far on the imperative side, not close to something one would auto-generate from a more mathematical version
void maplet_shift(struct maplet *m1, u64 shift) {
	m1->virt += shift;
	m1->size -= shift / PAGE_SIZE;
	if (m1->target.k == MAPPED ) {
		m1->target.u.m.phys += shift;
	}
}

bool mapping_submapping(struct glist_head head1, struct glist_head head2, char *s, char *s1, char *s2, u64 i)
{
	struct glist_node *pos1, *pos2;
	struct maplet *m1, *m2;
	struct maplet mc1, mc2;

	bool m2_init=false;

	if (glist_empty(&head1)) // nothing in &head1 to check; succeed
		return true;

	pos2 = head2.first;

	glist_for_each(pos1, &head1) {
		m1 = glist_entry(pos1, struct maplet, list);
		mc1 = *m1;

		if (mc1.size == 0) // nothing left of the current m1 to check; move to next m1
			continue;

		if (m2_init)
			goto foo;

new_m2:
		if (pos2 == NULL)  // still something to check but no more head2 entries; fail
			goto not_found;

		m2 = glist_entry(pos2, struct maplet, list);
		mc2 = *m2;
		m2_init = true;

foo:
		if (mc2.size == 0) { // this m2 will be useless; move to next m2
			pos2 = pos2->next;
			goto new_m2;
		}

		if (mc1.virt >= mc2.virt + mc2.size * PAGE_SIZE) { // remaining m1 start is beyond current m2 end; move to next m2
			pos2 = pos2->next;
			goto new_m2;
		}

                if (mc1.virt < mc2.virt) { // remaining m1 start is strictly before current m2 start; fail
			goto not_found;
		}

		if (mc1.virt > mc2.virt) { // remaining m1 start is strictly after current m2 start (but before its end); discard that prefix of current m2
			maplet_shift(&mc2, mc1.virt - mc2.virt);  // (discarding explicitly to keep the cases simple)
		}

		// now we know remains of current m1 and (after that shift) the current m2 are non-empty
		// and mc1.virt == mc2.virt,
		// so there's some non-empty overlap between them.

		if (mc1.target.k == mc2.target.k && (mc1.target.k == MAPPED)?(mc1.target.u.m.phys == mc2.target.u.m.phys && mc1.target.u.m.page_state == mc2.target.u.m.page_state && mc1.target.u.m.arch_prot == mc2.target.u.m.arch_prot && mc1.target.u.m.attr == mc2.target.u.m.attr && attr_at_level_equal(mc1.target.u.m.attr_at_level, mc2.target.u.m.attr_at_level)/* not checking attr here as we don't know what it should be set to: && mc1.attr == mc2.attr*/):(mc1.target.u.a.owner_id == mc2.target.u.a.owner_id && mc1.target.u.a.owner == mc2.target.u.a.owner)) {
			// the common prefix matches
			if (mc1.virt + mc1.size * PAGE_SIZE <= mc2.virt + mc2.size * PAGE_SIZE) {
				// current m1 done
				continue;
			} else {
				// some of m1 remaining
				maplet_shift(&mc1, (mc2.virt + mc2.size * PAGE_SIZE) - (mc1.virt + mc1.size * PAGE_SIZE));
				continue;
			}
		} else {
			// the common prefix doesn't match
			goto mismatch;
		}
	}
	// all of &head1 matched
	hyp_putspi(s, i);
	hyp_putsp(" ");
	hyp_putsp("submapping ");
	hyp_putsp(s1);
	hyp_putsp(" ");
	hyp_putsp(s2);
	hyp_putsp(" ok");
	hyp_putc('\n');
	return true;

not_found:
	hyp_putspi(s, i);
	hyp_putsp(" ");
	hyp_putsp(GHOST_WHITE_ON_RED);
	hyp_putsp("submapping ");
	hyp_putsp(s1);
	hyp_putsp(" ");
	hyp_putsp(s2);
	hyp_putsp(" no corresponding mapping found for ");
	hyp_putsxn("virt",mc1.virt,64);
	hyp_putsp(GHOST_NORMAL);
	hyp_putsp("in\n");
	hyp_put_maplet(m1, i+2);
	hyp_putc('\n');
	hyp_putspi(s1, i+2);hyp_putc('\n');
	hyp_put_mapping(head1, i+2);
	hyp_putspi(s2, i+2);hyp_putc('\n');
	hyp_put_mapping(head2, i+2);
	return false;

mismatch:
	hyp_putspi(s, i);
	hyp_putsp(" ");
	hyp_putsp(GHOST_WHITE_ON_RED);
	hyp_putsp("submapping ");
	hyp_putsp(s1);
	hyp_putsp(" ");
	hyp_putsp(s2);
	hyp_putsp(" mismatch at ");
	hyp_putsxn("virt",mc1.virt,64);
	hyp_putsp(GHOST_NORMAL);
	hyp_putsp("in\n");
	hyp_put_maplet(m1, i+2);
	hyp_putc('\n');
	hyp_put_maplet(m2, i+2);
	hyp_putc('\n');
	hyp_puti(i+2);
	hyp_putsxn("mc1.virt",mc1.virt,64); hyp_putsxn("mc2.virt",mc2.virt,64);
	//	hyp_putsxn("mc1 phys",mc1.phys,64);hyp_putsxn("mc2 phys",mc2.phys,64);
	//hyp_putsxn("mc1 attr",mc1.attr,64);hyp_putsxn("mc2 attr",mc2.attr,64);
	hyp_putc('\n');
	hyp_putspi(s1, i+2);hyp_putc('\n');
	hyp_put_mapping(head1, i+2);
	hyp_putspi(s2, i+2);hyp_putc('\n');
	hyp_put_mapping(head2, i+2);
	return false;
}



// make a deep copy of a mapping
struct glist_head mapping_copy(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	if (glist_empty(&head)) // nothing in head
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		extend_mapping_coalesce(&res, m2->virt, m2->size, m2->target);
	}

	return res;
}

// make a deep copy of a mapping - used only in mapping_minus
struct glist_head mapping_copy_except_absent(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	if (glist_empty(&head)) // nothing in head
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		if (m2->target.k != ABSENT)
			extend_mapping_coalesce(&res, m2->virt, m2->size, m2->target);
	}

	return res;
}


// compute the annotated submapping of head and return it, allocating as needed
struct glist_head mapping_annot(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	if (glist_empty(&head)) // nothing in head
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		if (m2->target.k == ANNOT) {
			extend_mapping_coalesce(&res, m2->virt, m2->size, m2->target);
		}
	}

	return res;
}


// compute the shared (PKVM_PAGE_SHARED_OWNED / PKVM_PAGE_SHARED_BORROWED) submapping of head and return it, allocating as needed
struct glist_head mapping_shared(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	if (glist_empty(&head)) // nothing in head
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		if (m2->target.k == MAPPED && ((m2->target.u.m.page_state == PKVM_PAGE_SHARED_OWNED) || (m2->target.u.m.page_state == PKVM_PAGE_SHARED_BORROWED))) {
			extend_mapping_coalesce(&res, m2->virt, m2->size, m2->target);
		}
	}

	return res;
}


// compute the non-annotated submapping of ms2 and put it in ms1, allocating as needed
struct glist_head mapping_nonannot(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	if (glist_empty(&head)) // nothing in ms2
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		if (m2->target.k == MAPPED) {
			extend_mapping_coalesce(&res, m2->virt, m2->size, m2->target);
		}
	}

	return res;
}




// compute head2 oplus head3
// relies on extend_mapping_coalesce to produce normalised output
struct glist_head mapping_plus(struct glist_head head2, struct glist_head head3)
{
	struct glist_node *pos2, *pos3;  // current list entry from each
	struct maplet *m2, *m3;         // current maplet from each
	struct maplet mc2, mc3;         // current working maplet from each - the initial part(s) of mc2 will get removed when handled (either copied to ms1 or discarded)

	struct glist_head *ms2 = &head2;
	struct glist_head *ms3 = &head3;
	struct glist_head res = mapping_empty_();

	bool ms2_exhausted=false;
	bool ms3_exhausted=false;

	bool mc2_exhausted=true;
	bool mc3_exhausted=true;

	u64 mc2_size_initial, mc2_size_remaining;

	struct glist_node fake_zeroth_node_2;
	struct glist_node fake_zeroth_node_3;

	fake_zeroth_node_2.next = ms2->first;
	fake_zeroth_node_3.next = ms3->first;

	pos2 = &fake_zeroth_node_2;
	pos3 = &fake_zeroth_node_3;

	//hyp_putsp("mapping_plus\n");
	//hyp_put_maplets(ms2);
	//hyp_putc('\n');
	//hyp_put_maplets(ms3);
	//hyp_putc('\n');

	do {
		// if we don't have a current working maplet for ms2, and there are more there, get the next one
		while (mc2_exhausted && !ms2_exhausted) {
			if (pos2->next == NULL) {
				ms2_exhausted = true;
			} else {
				pos2 = pos2->next;
				m2 = glist_entry(pos2, struct maplet, list);
				mc2 = *m2;
				if (mc2.size == 0) {
					//continue;
				} else {
					mc2_exhausted = false;
				}
			}
		}
		// if we don't have a current working maplet for ms3, and there are more there, get the next one
		while (mc3_exhausted && !ms3_exhausted) {
			if (pos3->next == NULL) {
				ms3_exhausted = true;
			} else {
				pos3 = pos3->next;
				m3 = glist_entry(pos3, struct maplet, list);
				mc3 = *m3;
				if (mc3.size == 0) {
					//continue;
				} else {
					mc3_exhausted = false;
				}
			}
		}
		if (!mc2_exhausted) {
			// something left in ms2
			if (mc3_exhausted) {
				// no ms3 left; copy mc2 to output
				extend_mapping_coalesce(&res, mc2.virt, mc2.size, mc2.target);
				mc2_exhausted = true;
			} else if (mc2.virt < mc3.virt && mc2.virt + mc2.size*PAGE_SIZE <= mc3.virt) {
				// all of mc2 is strictly before the start of mc3; copy all of mc2 to output
				extend_mapping_coalesce(&res, mc2.virt, mc2.size, mc2.target);
				mc2_exhausted = true;
			} else if (mc2.virt < mc3.virt && mc2.virt + mc2.size*PAGE_SIZE > mc3.virt) {
				// some but not all of mc2 is strictly before the start of mc3; copy that initial part of mc2 to output
				mc2_size_initial = (mc3.virt - mc2.virt) / PAGE_SIZE;
				mc2_size_remaining = mc2.size - mc2_size_initial;
				extend_mapping_coalesce(&res, mc2.virt, mc2_size_initial, mc2.target);
				maplet_shift(&mc2, mc2_size_initial * PAGE_SIZE);
			} else if (mc2.virt >= mc3.virt && mc2.virt + mc2.size*PAGE_SIZE <= mc3.virt+mc3.size*PAGE_SIZE) {
				// mc2 is within mc3; discard this mc2
				mc2_exhausted = true;
			} else if (mc2.virt >= mc3.virt && mc2.virt + mc2.size*PAGE_SIZE >  mc3.virt+mc3.size*PAGE_SIZE && mc2.virt < mc3.virt+mc3.size*PAGE_SIZE ) {
				// mc2 starts within but extends strictly beyond the end of mc3; discard that initial part of mc2
				mc2_size_initial = (mc3.virt+mc3.size*PAGE_SIZE - mc2.virt) / PAGE_SIZE;
				maplet_shift(&mc2, mc2_size_initial * PAGE_SIZE);
			} else if (mc2.virt >= mc3.virt+mc3.size*PAGE_SIZE) {
				// mc2 starts beyond the end of mc3; copy this mc3 to output
				extend_mapping_coalesce(&res, mc3.virt, mc3.size, mc3.target);
				mc3_exhausted=true;
			} else {
				check_assert_fail("mapping_plus missing case");
			}
		} else if (!mc3_exhausted) {
				// no mc2 left but some mc3; copy mc3 to output
			extend_mapping_coalesce(&res, mc3.virt, mc3.size, mc3.target);
			mc3_exhausted = true;
		} else {
			// both exhausted
		}
	} while (!(ms2_exhausted && ms3_exhausted));

	//hyp_put_maplets(res);
	//hyp_putc('\n');
	return res;
}


// compute head2 \ (virt..virt+nr_pages)
// (this has an inefficient extra copy, but avoids having to futz with the mapping_plus code)
struct glist_head mapping_minus(struct glist_head head2, u64 virt, u64 nr_pages)
{
	struct glist_head tmp1 = mapping_plus(head2, mapping_singleton(virt, nr_pages, maplet_target_absent()));
	struct glist_head tmp2 = mapping_copy_except_absent(tmp1);
	free_mapping(tmp1);
	return tmp2;
}


// check that head1 and head2 have disjoint domains
bool mapping_disjoint(struct glist_head head1, struct glist_head head2, char *s, char *s1, char *s2, u64 i)
{
	struct glist_node *pos1, *pos2;  // current list entry from each
	struct maplet *m1, *m2;         // current maplet from each

	struct glist_head *ms1 = &head1;
	struct glist_head *ms2 = &head2;

	bool ms1_exhausted=false;
	bool ms2_exhausted=false;

	bool m1_do_next=true;
	bool m2_do_next=true;

	bool disjoint;

	struct glist_node fake_zeroth_node_1;
	struct glist_node fake_zeroth_node_2;

	fake_zeroth_node_1.next = ms1->first;
	fake_zeroth_node_2.next = ms2->first;

	pos1 = &fake_zeroth_node_1;
	pos2 = &fake_zeroth_node_2;

	//hyp_putsp("mapping_disjoint\n");
	//hyp_put_maplets(ms1);
	//hyp_putc('\n');
	//hyp_put_maplets(ms2);
	//hyp_putc('\n');

	do {
		// if we don't have a current maplet for ms1, and there is more there, get the next one
		while (m1_do_next && !ms1_exhausted) {
			if (pos1->next == NULL) {
				ms1_exhausted = true;
			} else {
				pos1 = pos1->next;
				m1 = glist_entry(pos1, struct maplet, list);
				if (m1->size != 0)
					m1_do_next = false;
			}
		}
		// if we don't have a current working maplet for ms2, and there is more there, get the next one
		while (m2_do_next && !ms2_exhausted) {
			if (pos2->next == NULL) {
				ms2_exhausted = true;
			} else {
				pos2 = pos2->next;
				m2 = list_entry(pos2, struct maplet, list);
				if (m2->size != 0)
					m2_do_next = false;
			}
		}

		if (ms1_exhausted || ms2_exhausted) {
			disjoint = true;
			break;
		}
		if (m1->virt + m1->size*PAGE_SIZE <= m2->virt) {
			// all of m1 is strictly before the start of m2; drop m1
			m1_do_next = true;
		} else if (m2->virt + m2->size*PAGE_SIZE <= m1->virt) {
			// all of m2 is strictly before the start of m1; drop m2
			m2_do_next = true;
		} else {
			disjoint = false;
			break;
		}
	} while (true);

	hyp_putspi(s, i);
	hyp_putsp(" ");
	hyp_putsp("disjoint ");
	hyp_putsp(s1);
	hyp_putsp(" ");
	hyp_putsp(s2);
	if (disjoint) {
		hyp_putsp(" ok\n");
		return true;
	} else {
		hyp_putsp(GHOST_WHITE_ON_RED);
		hyp_putsp(" not disjoint - overlaps on:\n");
		hyp_put_maplet(m1, i+2);
		hyp_putc('\n');
		hyp_put_maplet(m2, i+2);
		hyp_putsp(GHOST_NORMAL);
		hyp_putc('\n');
		hyp_putspi(s1, i+2);hyp_putc('\n');
		hyp_put_mapping(head1, i+2);
		hyp_putspi(s2, i+2);hyp_putc('\n');
		hyp_put_mapping(head2, i+2);
		return false;
	}
}





/* compute whether addr is in the domain of mapping ms1 */
bool maplet_in_domain(u64 virt, struct maplet *m)
{
	if (m==NULL)
		return false;
	return (virt >= m->virt && virt < m->virt + m->size*PAGE_SIZE);
}


bool mapping_in_domain(u64 virt, struct glist_head head)
{
	struct glist_node *pos1;
	struct maplet *m1;
	if (glist_empty(&head))
		return false;
	glist_for_each(pos1, &head) {
		m1 = glist_entry(pos1, struct maplet, list);
		if (maplet_in_domain(virt, m1)) {
			return true;
		}
	}
	return false;
}

bool mapping_lookup(u64 virt, struct glist_head head, struct maplet_target *tp)
{
	struct glist_node *pos1;
	struct maplet *m1;
	if (glist_empty(&head))
		return false;
	glist_for_each(pos1, &head) {
		m1 = glist_entry(pos1, struct maplet, list);
		if (maplet_in_domain(virt, m1)) {
			*tp = m1->target;
			return true;
		}
	}
	return false;
}

