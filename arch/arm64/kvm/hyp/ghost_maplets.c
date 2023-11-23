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

#include <hyp/ghost_extra_debug-pl011.h>

#include <nvhe/ghost_maplets.h>
#include <nvhe/ghost_kvm_pgtable.h>
//#include <linux/list_sort.h>

#include <nvhe/spinlock.h>   // no idea whether this will work - probably not
#include <asm/kvm_pgtable.h>
#include <nvhe/mem_protect.h>
#include <nvhe/ghost_asserts.h>
#include <nvhe/ghost_context.h>

#include <nvhe/ghost_printer.h>




/* ****************** the global pool of maplets ****************** */

struct maplets maplets_pool;

bool maplets_init=false;

DEFINE_HYP_SPINLOCK(ghost_maplets_lock);

inline void ghost_assert_maplets_locked(void) {
	hyp_assert_lock_held(&ghost_maplets_lock);
}

/* ****************** maplet target constructors ****************** */

struct maplet_target maplet_target_mapped(u64 oa_start,  u64 nr_pages, struct maplet_target_mapped m)
{
	struct maplet_target t = {
		.kind = MAPLET_MAPPED,
		.map = m,
	};
	return t;
}

struct maplet_target maplet_target_mapped_attrs(u64 oa_start, u64 nr_pages, struct maplet_attributes attrs)
{
	struct maplet_target t = {
		.kind = MAPLET_MAPPED,
		.map = (struct maplet_target_mapped){
			.oa_range_start = oa_start,
			.oa_range_nr_pages = nr_pages,
			.attrs = attrs,
		},
	};
	return t;
}

struct maplet_target maplet_target_mapped_ext(u64 oa_start, u64 nr_pages, enum maplet_permissions prot, enum maplet_page_state page_state, enum maplet_memtype_attr memtype)
{
	struct maplet_target t = {
		.kind = MAPLET_MAPPED,
		.map = (struct maplet_target_mapped){
			.oa_range_start = oa_start,
			.oa_range_nr_pages = nr_pages,
			.attrs = (struct maplet_attributes){
				.prot = prot,
				.provenance = page_state,
				.memtype = memtype,
				.raw_arch_attrs = 0,
			},
		},
	};
	return t;
}

struct maplet_target maplet_target_annot(struct maplet_target_annot annot)
{
	struct maplet_target t = {
		.kind = MAPLET_UNMAPPED,
		.annot = annot,
	};
	return t;
}

struct maplet_target maplet_target_annot_ext(enum maplet_owner_annotation owner)
{
	struct maplet_target t;
	t.kind = MAPLET_UNMAPPED;
	t.annot.owner = owner;
	t.annot.raw_arch_annot = 0;
	return t;
}

struct maplet_target maplet_target_memblock(enum memblock_flags flags)
{
	struct maplet_target t = {
		.kind = MAPLET_MEMBLOCK,
		.memblock = flags,
	};
	return t;
}

struct maplet_target maplet_target_absent(void)
{
	struct maplet_target t = {
		.kind = MAPLET_ABSENT,
	};
	return t;
}

static u64 ia_range_end(struct maplet m)
{
	return m.ia_range_start + m.ia_range_nr_pages*PAGE_SIZE;
}

static u64 oa_range_end(struct maplet_target_mapped m)
{
	return m.oa_range_start + m.oa_range_nr_pages*PAGE_SIZE;
}

static bool is_oa_marked_shared(struct maplet_target t)
{
	switch (t.kind) {
	case MAPLET_MAPPED:
		switch (t.map.attrs.provenance) {
		case MAPLET_PAGE_STATE_PRIVATE_OWNED:
			return false;
		case MAPLET_PAGE_STATE_SHARED_BORROWED:
		case MAPLET_PAGE_STATE_SHARED_OWNED:
			return true;
		default:
			BUG();
		}
		unreachable();
	default:
		return false;
	};
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
	ghost_assert_maplets_locked();
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
	hyp_spin_lock(&ghost_maplets_lock);
	if (!maplets_init) {
		init_maplets();
		maplets_init = true;
	}
}

void ghost_unlock_maplets(void)
{
	hyp_spin_unlock(&ghost_maplets_lock);
}

/* ******************  maplets extend  *************** */

bool maplet_target_can_extend(struct maplet *lhs, u64 ia, u64 nr_pages, struct maplet_target *rhs)
{
	if (lhs->target.kind != rhs->kind)
		return false;

	// ia range must be contiguous
	if (ia_range_end(*lhs) != ia)
		return false;

	switch (lhs->target.kind) {
	case MAPLET_MAPPED:
		// if mapping, oa range must also match
		if (oa_range_end(lhs->target.map) != rhs->map.oa_range_start)
			return false;

		// and both have the same attributes
		if (   (lhs->target.map.attrs.prot != rhs->map.attrs.prot)
		    || (lhs->target.map.attrs.provenance != rhs->map.attrs.provenance)
		    || (lhs->target.map.attrs.memtype != rhs->map.attrs.memtype))
			return false;

		return true;
	case MAPLET_UNMAPPED:
		return (lhs->target.annot.owner == rhs->annot.owner);
	case MAPLET_MEMBLOCK:
		return (lhs->target.memblock == rhs->memblock);
	case MAPLET_ABSENT:
		return false;
	}
}

/**
 * extend_mapping_coalesce() - Extend maplets with one new maplet.
 *
 * Coalesces it into the existing tail of the list if
 * both are mapped and contiguous in va and pa, and with the same attr,
 * or if both are annot and contiguous in va;
 * otherwise, adding as a newly allocated maplet taken from the pool.
 */
void extend_mapping_coalesce(struct glist_head *maplets_list, ghost_stage_t stage, u64 ia, u64 nr_pages, struct maplet_target t)
{
	struct maplet *tail;
	struct maplet *m_new;

	ghost_assert_maplets_locked();

	tail = glist_last_entry_or_null(maplets_list, struct maplet, list);

	if (tail != NULL && ia <= tail->ia_range_start) {
		// should never try extend a mapping with non-monotonically-increasing input addresses.
		ghost_assert(false);
	}

	if (tail != NULL && maplet_target_can_extend(tail, ia, nr_pages, &t)) {
		tail->ia_range_nr_pages += nr_pages;
		
		if (tail->target.kind == MAPLET_MAPPED)
			tail->target.map.oa_range_nr_pages += nr_pages;
	} else {
		m_new = get_maplet(maplets_list);
		m_new->stage = stage;
		m_new->ia_range_start = ia;
		m_new->ia_range_nr_pages = nr_pages;
		m_new->target = t;
	}
}

// create mapping with no maplets
mapping mapping_empty_(void) {
	struct glist_head head;
	ghost_assert_maplets_locked();
	INIT_GLIST_HEAD(&head);
	return head;
}

// create mapping with a single maplet
mapping mapping_singleton(ghost_stage_t stage, u64 virt, u64 nr_pages, struct maplet_target t) {
	struct glist_head head;
	ghost_assert_maplets_locked();
	INIT_GLIST_HEAD(&head);
	extend_mapping_coalesce(&head, stage, virt, nr_pages, t);
	return head;
}

/* ****************** maplets printing ****************** */

int gp_put_maplet_target(gp_stream_t *out, struct maplet_target *target)
{
	// for hypervisor-controlled pgtables, the targets are always physical addresses
	// also pad the names to length 5 for consistency
	char *oa_name_kind = "phys ";
	char *oa_post_name_kind = "phys'";

	// targets are printed as:
	// for   MAPPED: "${oa_name}:${oa} ${oa_name'}:${oa'} ${page_state} ${permissions} ${memorytype} (raw_arch_prot ${raw_arch_prot})"
	// for UNMAPPED: "owner ${owner_id} (raw_arch_annot ${raw_arch_annot})"
	// for MEMBLOCK: "memblock ${memblock_flags}"
	//
	// we pad each out so it's width 50 chars, and the names and raw bits align.

	// we make each branch here output a string of length 2*25=50 chars.
	switch (target->kind) {
	case MAPLET_MAPPED: {
		struct maplet_target_mapped m = target->map;
		struct maplet_attributes attrs = m.attrs;

		u64 oa = m.oa_range_start;
		u64 oa_end = oa_range_end(m);

		char page_state[] = {'-', '-', '\0'};
		char perms[] = {'-', '-', '-', '\0'};
		char memty[] = {'-', '\0'};

		switch (attrs.provenance) {
		case MAPLET_PAGE_STATE_PRIVATE_OWNED:
			page_state[0] = '-';
			page_state[1] = 'O';
			break;
		case MAPLET_PAGE_STATE_SHARED_OWNED:
			page_state[0] = 'S';
			page_state[1] = 'O';
			break;
		case MAPLET_PAGE_STATE_SHARED_BORROWED:
			page_state[0] = 'S';
			page_state[1] = 'B';
			break;
		case MAPLET_PAGE_STATE_UNKNOWN:
			page_state[0] = '?';
			page_state[1] = '?';
			break;
		}

		if (attrs.prot & MAPLET_PERM_R)
			perms[0] = 'R';

		if (attrs.prot & MAPLET_PERM_W)
			perms[1] = 'W';

		if (attrs.prot & MAPLET_PERM_X)
			perms[2] = 'X';

		switch (attrs.memtype) {
		case MAPLET_MEMTYPE_DEVICE:
		 	memty[0] = 'D';
			break;
		case MAPLET_MEMTYPE_NORMAL_CACHEABLE:
		 	memty[0] = 'M';
			break;
		case MAPLET_MEMTYPE_UNKNOWN:
		 	memty[0] = '?';
			break;
		default:
			BUG();
		}

		// each name is 5, and the
		return ghost_sprintf(
			out,
			"%s:%lx %s:%lx %s %s %s (raw_arch_prot %lx)",
			oa_name_kind, oa, oa_post_name_kind, oa_end,
			&page_state, &perms, &memty,
			attrs.raw_arch_attrs
		);
	};
	case MAPLET_UNMAPPED: {
	 	const char *owner;
		// each owner is 5 chars
		switch (target->annot.owner) {
		case MAPLET_OWNER_ANNOT_OWNED_HOST:
			owner = " HOST";
			break;
		case MAPLET_OWNER_ANNOT_OWNED_GUEST:
			owner = "GUEST";
			break;
		case MAPLET_OWNER_ANNOT_OWNED_HYP:
			owner = "  HYP";
			break;
		case MAPLET_OWNER_ANNOT_UNKNOWN:
			owner = "  ???";
			break;
		default:
			BUG();
		};

		return ghost_sprintf(out, "owner %s%39s", owner, "");
	}
	case MAPLET_MEMBLOCK:
		// this is length 9 + (2+8)
		return ghost_sprintf(out, "memblock %x%31s", (u32)target->memblock, "");
	default:
		BUG();
	}
	unreachable();
}

int gp_put_maplet(gp_stream_t *out, struct maplet *maplet)
{
	char *ia_name_kind;
	char *ia_post_name_kind;
	char *stage;

	u64 ia;
	u64 ia_end;

	ghost_assert_maplets_locked();

	// the names are always of length 5
	switch (maplet->stage) {
		case GHOST_STAGE2:
			ia_name_kind = "ipa..";
			ia_post_name_kind = "ipa'.";
			stage = "S2";
			break;
		case GHOST_STAGE1:
			/* Stage 1 in a single stage translation regime goes virt->phys directly. */
			ia_name_kind = "virt.";
			ia_post_name_kind = "virt'";
			stage = "S1";
			break;
		case GHOST_STAGE_NONE:
			/* Must be memblock, which are just phys */
			ia_name_kind = "phys.";
			ia_post_name_kind = "phys'";
			stage = "--";
			break;
		default:
			BUG();
	};

	// these are of length 5    +   1  +  2   +   16      + 1     = 25 chars.
	//                    (name) (colon) (0x) (01AB23EF) (space)
	ia = maplet->ia_range_start;
	ia_end = ia_range_end(*maplet);

	return ghost_sprintf(
		out, "%s %s:%lx %s:%lx nr_pages:%x %g(maplet_target)",
		stage, ia_name_kind, ia, ia_post_name_kind, ia_end, (u32)maplet->ia_range_nr_pages, &maplet->target
	);
}

void hyp_put_maplet_target(struct maplet_target *target, u64 indent)
{
	ghost_printf("%g(maplet_target)", target);
}

void hyp_put_maplet(struct maplet *maplet, u64 indent)
{
	ghost_printf("%g(maplet)", maplet);
}

void hyp_put_mapletptr(void *d)
{
	struct maplet *m = *(struct maplet**)d;
	hyp_put_maplet(m, 0);
}

void gp_put_mapping(gp_stream_t *out, mapping *mapp, u64 indent)
{
	struct glist_head head = *mapp;

	struct glist_node *pos = NULL;
	struct maplet *m;
	bool first;
	u64 phys_first;
	u64 size_first;

	ghost_assert_maplets_locked();

	first=true;
	if (glist_empty(&head)) {
		ghost_printf("%Iempty\n", indent);
		return;
	}

	glist_for_each( pos, &head)
	{
		char prefix;

		m = glist_entry(pos, struct maplet, list);
		if (!first && m->target.kind == MAPLET_MAPPED && m->target.map.oa_range_start == phys_first + size_first*PAGE_SIZE) {
			prefix = '-';
		} else {
			prefix = ' ';
		}

		if (first && m->target.kind == MAPLET_MAPPED) {
			phys_first = m->target.map.oa_range_start;
			size_first = m->target.map.oa_range_nr_pages;
			first = false;
		}
		ghost_printf("%I%c%g(maplet)\n", indent, prefix, m);
	}
}

void hyp_put_mapping(struct glist_head head, u64 i)
{
	ghost_printf("%gI(mapping)", &head, i);
}



/* ****************** maplets equality check ****************** */

bool __maplet_target_eq(struct maplet_target t1, struct maplet_target t2, bool check_oa_range_start, bool check_oa_range_size, bool check_attrs) {
	if (t1.kind != t2.kind)
		return false;

	switch (t1.kind) {
	case MAPLET_MAPPED:
		if (check_oa_range_start && (t1.map.oa_range_start != t2.map.oa_range_start))
			return false;
		if (check_oa_range_size && (t1.map.oa_range_nr_pages != t2.map.oa_range_nr_pages))
			return false;
		if (check_attrs && (t1.map.attrs.prot != t2.map.attrs.prot))
			return false;
		if (check_attrs && (t1.map.attrs.provenance != t2.map.attrs.provenance))
			return false;
		if (check_attrs && (t1.map.attrs.memtype != t2.map.attrs.memtype))
			return false;
		return true;
	case MAPLET_UNMAPPED:
		return (t1.annot.owner == t2.annot.owner);
	case MAPLET_MEMBLOCK:
		return (t1.memblock == t2.memblock);
	default:
		BUG();
	}
}

bool maplet_target_eq(struct maplet_target t1, struct maplet_target t2)
{
	return __maplet_target_eq(t1, t2, true, true, true);
}

bool maplet_target_eq_nonattr(struct maplet_target t1, struct maplet_target t2)
{
	return __maplet_target_eq(t1, t2, true, true, false);
}

bool maplet_target_eq_nonend(struct maplet_target t1, struct maplet_target t2)
{
	return __maplet_target_eq(t1, t2, true, false, true);
}

bool maplet_eq(struct maplet *m1, struct maplet *m2)
{
	return (
		   (m1->stage == m2->stage) /* sanity check */
		&& (m1->ia_range_start == m2->ia_range_start)
		&& (m1->ia_range_nr_pages == m2->ia_range_nr_pages)
		&& maplet_target_eq(m1->target, m2->target)
	);
}

bool maplet_eq_nonattr(struct maplet *m1, struct maplet *m2)
{
	return (
		   (m1->stage == m2->stage) /* sanity check */
		&& (m1->ia_range_start == m2->ia_range_start)
		&& (m1->ia_range_nr_pages == m2->ia_range_nr_pages)
		&& maplet_target_eq_nonattr(m1->target, m2->target)
	);
}

/* ****************** mapping equality ****************** */

/* TODO: this checks the maplets are identical (NEW: no longer ignoring attr), but assumes the mappings are normalised.   OLD: (which with distinct attr they may not be) . Probably we should do a submapping check (which is more sophisticated) both ways? */
bool interpret_equals(struct glist_head head1, struct glist_head head2, u64 i)
{
	struct glist_node *pos1, *pos2;
	struct maplet *m1, *m2;
	//sort_maplets_virt(ms1);
	//sort_maplets_virt(ms2);

	ghost_assert_maplets_locked();

	if (glist_empty(&head1) && glist_empty(&head2))
		return true;
	if (glist_empty(&head1) || glist_empty(&head2)) {
		return false;
	}

	for ( (pos1 = head1.first, pos2 = head2.first);
	      (pos1 != NULL && pos2 != NULL);
	      (pos1 = pos1->next, pos2=pos2->next) ) {
		      m1 = glist_entry(pos1, struct maplet, list);
		      m2 = glist_entry(pos2, struct maplet, list);
			if ( !(maplet_eq_nonattr(m1, m2)) ) {
				return false;
			}
	}

	if (! (pos1 == NULL && pos2 == NULL)) {
		return false;
	}

	return true;
}

void check_interpret_equals(struct glist_head head1, struct glist_head head2, u64 i)
{
	struct glist_node *pos1, *pos2;
	struct maplet *m1, *m2;

	ghost_assert_maplets_locked();
	GHOST_LOG_CONTEXT_ENTER();

	if (glist_empty(&head1) && glist_empty(&head2))
		goto out;

	if (glist_empty(&head1) || glist_empty(&head2)) {
		if (glist_empty(&head1))
			GHOST_WARN("check_interpret_equals mismatch first empty");
		else
			GHOST_WARN("check_interpret_equals mismatch second empty");
		ghost_spec_assert(false);
	}

	for ( (pos1 = head1.first, pos2 = head2.first);
	      (pos1 != NULL && pos2 != NULL);
	      (pos1 = pos1->next, pos2=pos2->next) ) {
		      m1 = glist_entry(pos1, struct maplet, list);
		      m2 = glist_entry(pos2, struct maplet, list);
		      if ( !(maplet_eq_nonattr(m1, m2)) ) {
			      GHOST_LOG_P(__func__, m1, hyp_put_mapletptr);
			      GHOST_LOG_P(__func__, m2, hyp_put_mapletptr);
			      GHOST_WARN("interpret_equals mismatch at virt1");
			      ghost_spec_assert(false);
		      }
        }

	if (! (pos1 == NULL && pos2 == NULL)) {
		GHOST_LOG(pos1, u64);
		GHOST_LOG(pos2, u64);
		GHOST_WARN("interpret_equals mismatch different lengths");
		ghost_spec_assert(false);
	}

out:
	GHOST_LOG_CONTEXT_EXIT();
}


// check that ms1 and ms2 are equal mappings
bool mapping_equal(struct glist_head head1, struct glist_head head2, char *s, char *s1, char *s2, u64 i)
{
	bool equal;
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_maplets_locked();

	equal = interpret_equals(head1, head2, i+2);
	if (!equal) {
		GHOST_LOG(s, str);
		GHOST_LOG(s1, str);
		GHOST_LOG(s2, str);
		GHOST_WARN("mappings not equal");
	}

	GHOST_LOG_CONTEXT_EXIT();
	return equal;
}

void check_mapping_equal(mapping map1, mapping map2)
{
	check_interpret_equals((struct glist_head)map1, (struct glist_head)map2, 0);
}

void maplet_shift(struct maplet *m1, u64 shift)
{
	m1->ia_range_start += shift;
	m1->ia_range_nr_pages -= shift / PAGE_SIZE;
	if (m1->target.kind == MAPLET_MAPPED) {
		m1->target.map.oa_range_start += shift;
		m1->target.map.oa_range_nr_pages -= shift / PAGE_SIZE;
	}
}

void maplet_target_reduce(struct maplet_target *t, u64 shift)
{
	switch (t->kind) {
	case MAPLET_MAPPED:
		t->map.oa_range_nr_pages -= shift / PAGE_SIZE;
		break;
	default:
		;
	}
}

// check that head1 is a sub-finite-map of head2, i.e.
// forall virt. [[head1]](virt) defined => [[head2]](virt) defined and equal to [[head1]](virt)
// assumes both are ordered by virt and are "normalised", with no contiguous (+identical attr) maplets
// as an exercise, try something reasonably efficient, with a single traversal of the two lists - which ended up pretty far on the imperative side, not close to something one would auto-generate from a more mathematical version
bool mapping_submapping(struct glist_head head1, struct glist_head head2, char *s, char *s1, char *s2, u64 i)
{
	struct glist_node *pos1, *pos2;
	struct maplet *m1, *m2;
	struct maplet mc1, mc2;

	bool m2_init=false;

	ghost_assert_maplets_locked();

	if (glist_empty(&head1)) // nothing in &head1 to check; succeed
		return true;

	pos2 = head2.first;

	glist_for_each(pos1, &head1) {
		m1 = glist_entry(pos1, struct maplet, list);
		mc1 = *m1;

		if (mc1.ia_range_nr_pages == 0) // nothing left of the current m1 to check; move to next m1
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
		if (mc2.ia_range_nr_pages == 0) { // this m2 will be useless; move to next m2
			pos2 = pos2->next;
			goto new_m2;
		}

		if (mc1.ia_range_start >= ia_range_end(mc2)) { // remaining m1 start is beyond current m2 end; move to next m2
			pos2 = pos2->next;
			goto new_m2;
		}

		if (mc1.ia_range_start < mc2.ia_range_start) { // remaining m1 start is strictly before current m2 start; fail
			goto not_found;
		}

		if (mc1.ia_range_start > mc2.ia_range_start) { // remaining m1 start is strictly after current m2 start (but before its end); discard that prefix of current m2
			maplet_shift(&mc2, mc1.ia_range_start - mc2.ia_range_start);  // (discarding explicitly to keep the cases simple)
		}

		// now we know remains of current m1 and (after that shift) the current m2 are non-empty
		// and mc1.ia_range_start == mc2.ia_range_start,
		// so there's some non-empty overlap between them.

		if (maplet_target_eq_nonend(mc1.target, mc2.target)) {
			// the common prefix matches
			if (ia_range_end(mc1) <= ia_range_end(mc2)) {
				// current m1 done
				continue;
			} else {
				// some of m1 remaining
				// move mc1 up to end of mc2, and check the next m2
				maplet_shift(&mc1, mc2.ia_range_nr_pages*PAGE_SIZE);
				goto new_m2;
			}
		} else {
			// the common prefix doesn't match
			goto mismatch;
		}
	}

	// all of &head1 matched
	ghost_printf("%I%s submapping %s %s ok\n", i, s, s1, s2);
	return true;

not_found:
	ghost_printf(
		"%I " GHOST_WHITE_ON_RED "submapping %s %s no corresponding maping found for virt:%p" GHOST_NORMAL " in\n"
		"%I%g(maplet)\n"
		"%I%s\n"
		"%gI(mapping)\n"
		"%I%s\n"
		"%gI(mapping)\n",
		i, s, s1, s2, mc1.ia_range_start,
		i+2, m1,
		i+2, s1,
		&head1, i+2,
		i+2, s2,
		&head2, i+2
	);
	return false;

mismatch:
	ghost_printf(
		"%I " GHOST_WHITE_ON_RED "submapping %s %s mismatch at virt:%p" GHOST_NORMAL " in\n"
		"%I%s:%g(maplet)\n"
		"%Ivs\n"
		"%I%s:%g(maplet)\n"
		"%I%s\n"
		"%gI(mapping)\n"
		"%I%s\n"
		"%gI(mapping)\n",
		i, s, s1, s2, mc1.ia_range_start,
		i+2, s1, &mc1,
		i+2, s2, &mc2,
		i+2, s1,
		&head1, i+2,
		i+2, s2,
		&head2, i+2
	);
	return false;
}



// make a deep copy of a mapping
struct glist_head mapping_copy(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	ghost_assert_maplets_locked();

	if (glist_empty(&head)) // nothing in head
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		extend_mapping_coalesce(&res, m2->stage, m2->ia_range_start, m2->ia_range_nr_pages, m2->target);
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
		if (m2->target.kind != MAPLET_ABSENT)
			extend_mapping_coalesce(&res, m2->stage, m2->ia_range_start, m2->ia_range_nr_pages, m2->target);
	}

	return res;
}


// compute the annotated submapping of head and return it, allocating as needed
struct glist_head mapping_annot(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	ghost_assert_maplets_locked();

	if (glist_empty(&head)) // nothing in head
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		if (m2->target.kind == MAPLET_UNMAPPED)
			extend_mapping_coalesce(&res, m2->stage, m2->ia_range_start, m2->ia_range_nr_pages, m2->target);
	}

	return res;
}


// compute the shared (PKVM_PAGE_SHARED_OWNED / PKVM_PAGE_SHARED_BORROWED) submapping of head and return it, allocating as needed
struct glist_head mapping_shared(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	ghost_assert_maplets_locked();

	if (glist_empty(&head)) // nothing in head
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		if (m2->target.kind == MAPLET_MAPPED && is_oa_marked_shared(m2->target))
			extend_mapping_coalesce(&res, m2->stage, m2->ia_range_start, m2->ia_range_nr_pages, m2->target);
	}

	return res;
}


// compute the non-annotated submapping of ms2 and put it in ms1, allocating as needed
struct glist_head mapping_nonannot(struct glist_head head)
{
	struct glist_node *pos2;
	struct maplet *m2;

	struct glist_head res = mapping_empty_();

	ghost_assert_maplets_locked();

	if (glist_empty(&head)) // nothing in ms2
		return res;

	glist_for_each(pos2, &head) {
		m2 = glist_entry(pos2, struct maplet, list);
		if (m2->target.kind == MAPLET_MAPPED)
			extend_mapping_coalesce(&res, m2->stage, m2->ia_range_start, m2->ia_range_nr_pages, m2->target);
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

	ghost_assert_maplets_locked();

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
				if (mc2.ia_range_nr_pages == 0) {
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
				if (mc3.ia_range_nr_pages == 0) {
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
				extend_mapping_coalesce(&res, mc2.stage, mc2.ia_range_start, mc2.ia_range_nr_pages, mc2.target);
				mc2_exhausted = true;
			} else if (mc2.ia_range_start < mc3.ia_range_start && ia_range_end(mc2) <= mc3.ia_range_start) {
				// all of mc2 is strictly before the start of mc3; copy all of mc2 to output
				extend_mapping_coalesce(&res, mc2.stage, mc2.ia_range_start, mc2.ia_range_nr_pages, mc2.target);
				mc2_exhausted = true;
			} else if (mc2.ia_range_start < mc3.ia_range_start && ia_range_end(mc2) > mc3.ia_range_start) {
				struct maplet_target mc2_t = mc2.target;
				// some but not all of mc2 is strictly before the start of mc3; copy that initial part of mc2 to output
				mc2_size_initial = (mc3.ia_range_start - mc2.ia_range_start) / PAGE_SIZE;
				mc2_size_remaining = mc2.ia_range_nr_pages - mc2_size_initial;
				// don't put the whole maplet target in there, split it up and only put in taret up to start of mc3
				maplet_target_reduce(&mc2_t, mc2_size_remaining * PAGE_SIZE);
				extend_mapping_coalesce(&res, mc2.stage, mc2.ia_range_start, mc2_size_initial, mc2_t);
				maplet_shift(&mc2, mc2_size_initial * PAGE_SIZE);
			} else if (mc2.ia_range_start >= mc3.ia_range_start && ia_range_end(mc2) <= ia_range_end(mc3)) {
				// mc2 is within mc3; discard this mc2
				mc2_exhausted = true;
			} else if (mc2.ia_range_start >= mc3.ia_range_start && ia_range_end(mc2) > ia_range_end(mc3) && mc2.ia_range_start < ia_range_end(mc3) ) {
				// mc2 starts within but extends strictly beyond the end of mc3; discard that initial part of mc2
				mc2_size_initial = (ia_range_end(mc3) - mc2.ia_range_start) / PAGE_SIZE;
				maplet_shift(&mc2, mc2_size_initial * PAGE_SIZE);
			} else if (mc2.ia_range_start >= ia_range_end(mc3)) {
				// mc2 starts beyond the end of mc3; copy this mc3 to output
				extend_mapping_coalesce(&res, mc3.stage, mc3.ia_range_start, mc3.ia_range_nr_pages, mc3.target);
				mc3_exhausted=true;
			} else {
				check_assert_fail("mapping_plus missing case");
			}
		} else if (!mc3_exhausted) {
				// no mc2 left but some mc3; copy mc3 to output
			extend_mapping_coalesce(&res, mc3.stage, mc3.ia_range_start, mc3.ia_range_nr_pages, mc3.target);
			mc3_exhausted = true;
		} else {
			// both exhausted
		}
	} while (!(ms2_exhausted && ms3_exhausted));

	//hyp_put_maplets(res);
	//hyp_putc('\n');
	return res;
}


// compute head2 \ (ia_range_start..ia_range_start+nr_pages)
// (this has an inefficient extra copy, but avoids having to futz with the mapping_plus code)
struct glist_head mapping_minus(struct glist_head head2, u64 virt, u64 nr_pages)
{
	struct glist_head tmp1, tmp2;
	ghost_assert_maplets_locked();
	tmp1 = mapping_plus(head2, mapping_singleton(GHOST_STAGE_NONE, virt, nr_pages, maplet_target_absent()));
	tmp2 = mapping_copy_except_absent(tmp1);
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

	ghost_assert_maplets_locked();

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
				if (m1->ia_range_nr_pages != 0)
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
				if (m2->ia_range_nr_pages != 0)
					m2_do_next = false;
			}
		}

		if (ms1_exhausted || ms2_exhausted) {
			disjoint = true;
			break;
		}
		if (ia_range_end(*m1) <= m2->ia_range_start) {
			// all of m1 is strictly before the start of m2; drop m1
			m1_do_next = true;
		} else if (ia_range_end(*m2) <= m1->ia_range_start) {
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
bool maplet_in_domain(u64 ia, struct maplet *m)
{
	if (m == NULL)
		return false;

	return (m->ia_range_start <= ia && ia < ia_range_end(*m));
}


bool mapping_in_domain(u64 virt, struct glist_head head)
{
	struct glist_node *pos1;
	struct maplet *m1;

	ghost_assert_maplets_locked();

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

bool __mapping_lookup(u64 virt, struct glist_head head, struct maplet **p)
{
	struct glist_node *pos1;
	struct maplet *m1;

	ghost_assert_maplets_locked();

	if (glist_empty(&head))
		return false;
	glist_for_each(pos1, &head) {
		m1 = glist_entry(pos1, struct maplet, list);
		if (maplet_in_domain(virt, m1)) {
			*p = m1;
			return true;
		}
	}
	return false;
}

bool mapping_lookup(u64 virt, struct glist_head head, struct maplet_target *tp)
{
	struct maplet *m1;
	bool found = __mapping_lookup(virt, head, &m1);

	if (found) {
		*tp = m1->target;
	}

	return found;
}

bool mapping_oa(u64 ia, mapping map, u64 *out)
{
	struct maplet *m1;
	bool found = __mapping_lookup(ia, map, &m1);

	if (found) {
		switch (m1->target.kind) {
		case MAPLET_MAPPED:
			/* index into OA range same as index into IA range */
			*out = m1->target.map.oa_range_start + (ia - m1->ia_range_start);
			return true;
		default:
			return false;
		}
	} else {
		return false;
	}
}

void mapping_move(mapping *map_out, mapping map)
{
	free_mapping(*map_out);
	*map_out = map;
}

void mapping_update(mapping *out, mapping in, mapping_update_kind_t kind, ghost_stage_t stage, u64 ia, u64 nr_pages, struct maplet_target t)
{
	mapping copy = mapping_copy(in);
	free_mapping(*out);

	switch (kind) {
	case MAP_REMOVE_PAGE:
		if (t.kind != MAPLET_ABSENT)
			ghost_assert(false);

		for (u64 p = 0; p < nr_pages; p++) {
			if (!mapping_in_domain(ia + p*PAGE_SIZE, copy)) {
				ghost_assert(false);
			}
		}
		copy = mapping_minus(copy, ia, 1);
		break;
	case MAP_INSERT_PAGE:
		for (u64 p = 0; p < nr_pages; p++) {
			if (mapping_in_domain(ia + p*PAGE_SIZE, copy)) {
				ghost_assert(false);
			}
		}
		copy = mapping_plus(copy, mapping_singleton(stage, ia, nr_pages, t));
		break;
	case MAP_UPDATE_PAGE:
		for (u64 p = 0; p < nr_pages; p++) {
			if (!mapping_in_domain(ia + p*PAGE_SIZE, copy)) {
				ghost_assert(false);
			}
		}
		/* mapping plus discards lhs and overwrites with rhs */
		copy = mapping_plus(copy, mapping_singleton(stage, ia, nr_pages, t));
		break;
	}

	*out = copy;
}