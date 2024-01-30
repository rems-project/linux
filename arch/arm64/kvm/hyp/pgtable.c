// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stand-alone page-table allocator for hyp stage-1 and guest stage-2.
 * No bombay mix was harmed in the writing of this file.
 *
 * Copyright (C) 2020 Google LLC
 * Author: Will Deacon <will@kernel.org>
 */

#include <linux/bitfield.h>
#include <asm/kvm_pgtable.h>
#include <asm/stage2_pgtable.h>


#define KVM_PTE_TYPE			BIT(1)
#define KVM_PTE_TYPE_BLOCK		0
#define KVM_PTE_TYPE_PAGE		1
#define KVM_PTE_TYPE_TABLE		1

#define KVM_PTE_LEAF_ATTR_LO		GENMASK(11, 2)

#define KVM_PTE_LEAF_ATTR_LO_S1_ATTRIDX	GENMASK(4, 2)
#define KVM_PTE_LEAF_ATTR_LO_S1_AP	GENMASK(7, 6)
#define KVM_PTE_LEAF_ATTR_LO_S1_AP_RO	3
#define KVM_PTE_LEAF_ATTR_LO_S1_AP_RW	1
#define KVM_PTE_LEAF_ATTR_LO_S1_SH	GENMASK(9, 8)
#define KVM_PTE_LEAF_ATTR_LO_S1_SH_IS	3
#define KVM_PTE_LEAF_ATTR_LO_S1_AF	BIT(10)

#define KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR	GENMASK(5, 2)
#define KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R	BIT(6)
#define KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W	BIT(7)
#define KVM_PTE_LEAF_ATTR_LO_S2_SH	GENMASK(9, 8)
#define KVM_PTE_LEAF_ATTR_LO_S2_SH_IS	3
#define KVM_PTE_LEAF_ATTR_LO_S2_AF	BIT(10)

#define KVM_PTE_LEAF_ATTR_HI		GENMASK(63, 51)

#define KVM_PTE_LEAF_ATTR_HI_SW		GENMASK(58, 55)

#define KVM_PTE_LEAF_ATTR_HI_S1_XN	BIT(54)

#define KVM_PTE_LEAF_ATTR_HI_S2_XN	BIT(54)

#define KVM_PTE_LEAF_ATTR_S2_PERMS	(KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R | \
					 KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W | \
					 KVM_PTE_LEAF_ATTR_HI_S2_XN)

#define KVM_INVALID_PTE_OWNER_MASK	GENMASK(9, 2)
#define KVM_MAX_OWNER_ID		FIELD_MAX(KVM_INVALID_PTE_OWNER_MASK)

/*
 * Used to indicate a pte for which a 'break-before-make' sequence is in
 * progress.
 */
#define KVM_INVALID_PTE_LOCKED		BIT(10)


/* verification hack. TODO: add a CN feature to do this less intrusively. */
extern void *hyp_zalloc_hyp_page(void *arg);
extern void *hyp_phys_to_virt(phys_addr_t phys);
extern phys_addr_t hyp_virt_to_phys(void *virt);
extern void hyp_get_page(void *addr);

/* CN specification for the allocator.

   FIXME: For now, we assume an unrealistic, over-simplified allocator
   specification. For instance, the following assumes that the offset
   used in the hyp/phys is effectively a compile-time constant (does
   not change and does not require resource ownership to be accessed.
   We also entirely omit the ownership of the allocator pool in the
   specification. Instead, we have to connect this verification to our
   previous buddy allocator verification.
*/

/*@
predicate {bool exists} Cond_Zero_Page (pointer p) {
  if (p == NULL) {
    return {exists: false};
  }
  else {
    take X = each (i32 i; 0i32 <= i && i < 4096i32)
        {Owned<char>(array_shift<char>(p, i))};
    assert (each (i32 i; 0i32 <= i && i < 4096i32)
        {X[i] == 0u8});
    return {exists: true};
  }
}
@*/

/*@
function (u64) phys_virt_offset ()

function (bool) valid_phys_virt_offset ()
{ mod(phys_virt_offset (), 4096u64) == 0u64 }

function (pointer) hyp_phys_to_virt (u64 phys)
{
  ((pointer) (phys - phys_virt_offset ()))
}

spec hyp_phys_to_virt (u64 phys)
  requires true
  ensures
    return == hyp_phys_to_virt (phys)

function (u64) hyp_virt_to_phys (pointer virt)
{
  ((u64) virt) + phys_virt_offset ()
}

spec hyp_virt_to_phys (pointer virt)
  requires true
  ensures
    return == hyp_virt_to_phys (virt)
@*/

/*@
function (bool) valid_hyp_virt_page (pointer p)
{
  (mod(((u64) p), 4096u64) == 0u64) &&
  (hyp_virt_to_phys(p) < power(2u64, 48u64))
}

spec hyp_zalloc_hyp_page (pointer arg)
  requires true
  ensures
    take P = Cond_Zero_Page (return);
    valid_hyp_virt_page(return)

spec hyp_get_page (pointer arg)
  requires true
  ensures true
@*/


/*@
predicate (void) MM_Ops(pointer p) {
  take data = Owned<struct kvm_pgtable_mm_ops>(p);
  assert (data.zalloc_page == &hyp_zalloc_hyp_page);
  assert (data.phys_to_virt == &hyp_phys_to_virt);
  assert (data.virt_to_phys == &hyp_virt_to_phys);
  assert (data.get_page == &hyp_get_page);
  return;
}
@*/

/* constraints on level, see arch/arm64/include/asm/pgtable-hwdef.h */
/*@
function (bool) valid_pgtable_level (u32 level)
{
  0u32 <= level && level <= 3u32
}
@*/

/* see struct kvm_pgtable defn in arch/arm64/include/asm/kvm_pgtable.h */
/*@
predicate (map <i32, u64>) PTE_Array (pointer p) {
  assert (mod((u64)p, 4096u64) == 0u64);
  take ptes = each (i32 i; 0i32 <= i && i < 512i32)
    {Owned<kvm_pte_t>(array_shift<kvm_pte_t>(p, i))};
  return ptes;
}

predicate (void) Page_Table_Entries (pointer p, u32 level) {
  assert (valid_pgtable_level(level));
  take ptes = PTE_Array (p);
  take children = each (i32 i; 0i32 <= i && i < 512i32)
    {Indirect_Page_Table_Entries (array_shift<kvm_pte_t>(p, i), level, ptes[i])};
  return;
}
@*/


/*@ function (u8) kvm_pte_table (kvm_pte_t pte, u32 level) @*/

/* more abstract CN counterparts to table queries
  - note about level: in this ARM pgtable, the page & table encodings are
    shared, and entries at the final level are automatically not tables */
/*@
function [rec] (boolean) is_possible_table_entry1 (u64 encoded)
  { kvm_pte_table(encoded, 0u32) == 1u8 }
function (boolean) is_possible_table_entry (u64 encoded)
  { is_valid_pte_entry(encoded) && is_possible_table_entry1(encoded) }
function (boolean) level_has_tables (u32 level)
  { valid_pgtable_level(level + 1u32) }
function (boolean) is_table_entry_at (u64 encoded, u32 level)
  { is_possible_table_entry(encoded) && level_has_tables(level) }

function (pointer) decode_table_entry_pointer (u64 encoded)
{
  hyp_phys_to_virt (decode_table_entry_phys (encoded))
}

predicate {bool x} Indirect_Page_Table_Entries (pointer p, u32 level, u64 encoded) {
  if (is_table_entry_at (encoded, level)) {
    assert (valid_pgtable_level(level));
    assert (good<kvm_pte_t *> (decode_table_entry_pointer (encoded)));
    take x = Page_Table_Entries (decode_table_entry_pointer (encoded), level + 1u32);
    return {x: true};
  }
  else {
    return {x: false};
  }
}
@*/

/*@
function (u64) align_u64 (u64 x, u64 n)
  { shift_left (shift_right (x, n), n) }

function (boolean) aligned_u64 (u64 x, u64 n)
  { align_u64 (x, n) == x }
@*/

/* Page tables are 4096 bytes in size (2 ^ 12), which is 512 entries on a
 * 64-bit platform, resolving 9 bits, however, the top-level variant (called a
 * page directory) resolves some excess bits and is a little bigger, thus the
 * extra_bits output argument. A max-size 4-level page table resolves 48 bits,
 * 9 less per level, leaving 12 bits (the page size) unresolved.
 */
enum {
  enum_PTRS_PER_PTE = PTRS_PER_PTE,
  enum_EAGAIN = EAGAIN,
};
/*@
function (u32) pgd_extra_bits(u32 ia_bits, u32 start_level)
{
  let pt_bits_resolved = 48u32 - (9u32 * start_level);
  let extra_bits = ia_bits - pt_bits_resolved;
  extra_bits
}

predicate {u32 extra_bits, struct kvm_pgtable data}
        Pg_Table (pointer p) {
  take Data = Owned<struct kvm_pgtable>(p);

  assert ((0u32 < Data.ia_bits) && (Data.ia_bits <= 52u32));
  let extra_bits = pgd_extra_bits(Data.ia_bits, Data.start_level);
  assert (extra_bits == 0u32 || extra_bits == 2u32 || extra_bits == 4u32);
  assert (aligned_u64 ((u64) Data.pgd, 12u64 + ((u64) extra_bits)));
  assert (valid_pgtable_level(Data.start_level));

  take Entries = Pg_Table_Toplevel (Data.pgd, Data.start_level, extra_bits);

  return {extra_bits: extra_bits, data: Data};
}

predicate (void) Pg_Table_Toplevel (pointer p, u32 start_level, u32 extra_bits) {
  take Toplevel_Table = each (i32 i; 0i32 <= i && i < shift_left(6i32, (i32)extra_bits))
    {Page_Table_Entries(array_shift<kvm_pte_t[enum_PTRS_PER_PTE]>(p, i), start_level)};
  return;
}

datatype possible_mm_ops {
  No_MM_Ops {},
  Has_MM_Ops {pointer mm_ops}
}

function (boolean) possible_mm_ops_agree (possible_mm_ops o, pointer m) {
  match o {
    No_MM_Ops {} => {true}
    Has_MM_Ops {mm_ops: m2} => {m == m2}
  }
}

predicate {u32 flags, pointer arg} KVM_PgTable_Walker (pointer p) {
  take D = Owned<struct kvm_pgtable_walker>(p);
  take X = Hyp_Walker_Cases (D.cb, D.arg, D.flags);
  return {flags: D.flags, arg: D.arg};
}

predicate {u64 addr, u64 end, {pointer walker, pointer arg} walker, u32 flags}
    KVM_PgTable_Walk_Data (pointer p) {
  take D = Owned<struct kvm_pgtable_walk_data>(p);
  take Walker = KVM_PgTable_Walker(D.walker);
  let walker = {walker: D.walker, arg: Walker.arg};
  return {addr: D.addr, end: D.end, walker: walker, flags: Walker.flags};
}
@*/

struct kvm_pgtable_walk_data {
	struct kvm_pgtable_walker	*walker;

	const u64			start;
	u64				addr;
	const u64			end;
};

/*@ function (u8) kvm_phys_is_valid(u64 phys) @*/

static bool kvm_phys_is_valid(u64 phys)
/*@ cn_function kvm_phys_is_valid @*/
/*@ ensures return == kvm_phys_is_valid(phys) @*/
{
	return phys < BIT(id_aa64mmfr0_parange_to_phys_shift(ID_AA64MMFR0_EL1_PARANGE_MAX));
}

/*@
function (bool) pure_kvm_block_mapping_supported(u64 addr, u64 end, u64 phys, u32 level)
{
  kvm_level_supports_block_mapping(level) != 0u8 &&
  (! (kvm_granule_size(level) > (end - addr))) &&
  (! ((kvm_phys_is_valid(phys) != 0u8) && (! aligned_u64(phys, kvm_granule_shift(level))))) &&
  aligned_u64(addr, kvm_granule_shift(level))
}
@*/

static bool kvm_block_mapping_supported(const struct kvm_pgtable_visit_ctx *ctx, u64 phys)
/*@ requires take Ctx = Owned(ctx) @*/
/*@ requires valid_pgtable_level(Ctx.level) @*/
/*@ ensures take Ctx2 = Owned(ctx) @*/
/*@ ensures Ctx2 == Ctx @*/
/*@ ensures return == (pure_kvm_block_mapping_supported(Ctx.addr, Ctx.end, phys, Ctx.level)
  ? 1u8 : 0u8) @*/
{
	u64 granule = kvm_granule_size(ctx->level);

	if (!kvm_level_supports_block_mapping(ctx->level))
		return false;

	if (granule > (ctx->end - ctx->addr))
		return false;

	if (kvm_phys_is_valid(phys) && !IS_ALIGNED(phys, granule))
		return false;

	return IS_ALIGNED(ctx->addr, granule);
}


/*@
cn_function (u32) purekvm_pgtable_idx(u64 addr, u32 level) {
  (u32) (bw_and_uf((u64) ((u32) shift_right (addr, kvm_granule_shift(level))), 511u64))
}
@*/

static u32 kvm_pgtable_idx(struct kvm_pgtable_walk_data *data, u32 level)
/*@ requires take Data = Owned (data) @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ ensures take Data2 = Owned (data) @*/
/*@ ensures 0u32 <= return && return < power(2u32, 12u32 - 3u32) @*/
/*@ ensures Data2 == Data @*/
/*@ ensures return == purekvm_pgtable_idx(Data.addr, level) @*/
{
	u64 shift = kvm_granule_shift(level);
	u64 mask = BIT(PAGE_SHIFT - 3) - 1;

	return (data->addr >> shift) & mask;
}

/*@
function (u32) pure__kvm_pgd_page_idx(u32 ia_bits, u32 start_level, u64 addr) {
  (u32) shift_right (
    bw_and_uf(addr, (shift_left(1u64, (u64)(ia_bits))) - 1u64),
    kvm_granule_shift(start_level - 1u32)
  )
}
@*/

static u32 kvm_pgd_page_idx(struct kvm_pgtable *pgt, u64 addr)
/*@ requires take PTStruct = Owned<struct kvm_pgtable>(pgt) @*/
/*@ requires ((0u32 < PTStruct.ia_bits) && (PTStruct.ia_bits < 64u32)) @*/
/*@ requires valid_pgtable_level(PTStruct.start_level) @*/
/*@ requires let extra_bits = pgd_extra_bits(PTStruct.ia_bits, PTStruct.start_level) @*/
/*@ requires 0u32 <= extra_bits; extra_bits <= 4u32 @*/
/*@ ensures shift_right(return, extra_bits) == 0u32 @*/
/*@ ensures take PTStruct2 = Owned<struct kvm_pgtable>(pgt) @*/
/*@ ensures PTStruct2 == PTStruct @*/
/*@ ensures return == pure__kvm_pgd_page_idx(PTStruct.ia_bits, PTStruct.start_level, addr) @*/
{
	u64 shift = kvm_granule_shift(pgt->start_level - 1); /* May underflow */
	u64 mask = BIT(pgt->ia_bits) - 1;

	return (addr & mask) >> shift;
}

static u32 kvm_pgd_pages(u32 ia_bits, u32 start_level)
{
	struct kvm_pgtable pgt = {
		.ia_bits	= ia_bits,
		.start_level	= start_level,
	};

	return kvm_pgd_page_idx(&pgt, -1ULL) + 1;
}

static bool kvm_pte_table(kvm_pte_t pte, u32 level)
/*@ cn_function kvm_pte_table @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ ensures return == (is_table_entry_at(pte, level) ? 1u8 : 0u8) @*/
{
	if (level == KVM_PGTABLE_MAX_LEVELS - 1)
		return false;

	/*@ unfold is_possible_table_entry1(pte); @*/
	/*@ unfold is_valid_pte_entry(pte); @*/
	if (!kvm_pte_valid(pte)) {
		return false;
	}

	return FIELD_GET(KVM_PTE_TYPE, pte) == KVM_PTE_TYPE_TABLE;
}

static kvm_pte_t *kvm_pte_follow(kvm_pte_t pte, struct kvm_pgtable_mm_ops *mm_ops)
/*@ requires good<kvm_pte_t *>(decode_table_entry_pointer (pte)) @*/
/*@ requires take Ops = MM_Ops(mm_ops) @*/
/*@ ensures take Ops2 = MM_Ops(mm_ops) @*/
/*@ ensures return == decode_table_entry_pointer (pte) @*/
{
	return mm_ops->phys_to_virt(kvm_pte_to_phys(pte));
}

static void kvm_clear_pte(kvm_pte_t *ptep)
{
	WRITE_ONCE(*ptep, 0);
}

static kvm_pte_t kvm_init_table_pte(kvm_pte_t *childp, struct kvm_pgtable_mm_ops *mm_ops)
/*@ requires take Ops = MM_Ops(mm_ops) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires valid_hyp_virt_page(childp) @*/
/*@ ensures take Ops2 = MM_Ops(mm_ops) @*/
/*@ ensures is_possible_table_entry(return) @*/
/*@ ensures decode_table_entry_pointer(return) == childp @*/
{
	kvm_pte_t pte = kvm_phys_to_pte(mm_ops->virt_to_phys(childp));

	pte |= FIELD_PREP(KVM_PTE_TYPE, KVM_PTE_TYPE_TABLE);
	pte |= KVM_PTE_VALID;

	/*@ unfold decode_table_entry_phys(pte); @*/
	/*@ assert (decode_table_entry_pointer(pte) == childp); @*/
	/*@ unfold is_possible_table_entry1(pte); @*/
	/*@ unfold is_valid_pte_entry(pte); @*/
	/*@ assert (is_possible_table_entry(pte)); @*/

	return pte;
}

/*@
function (kvm_pte_t) kvm_init_valid_leaf_pte (u64 pa, kvm_pte_t attr, u32 level)
@*/

static kvm_pte_t kvm_init_valid_leaf_pte(u64 pa, kvm_pte_t attr, u32 level)
/*@ cn_function kvm_init_valid_leaf_pte @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ ensures not (is_table_entry_at (return, level)) @*/
{
	kvm_pte_t pte = kvm_phys_to_pte(pa);
	u64 type = (level == KVM_PGTABLE_MAX_LEVELS - 1) ? KVM_PTE_TYPE_PAGE :
							   KVM_PTE_TYPE_BLOCK;

	pte |= attr & (KVM_PTE_LEAF_ATTR_LO | KVM_PTE_LEAF_ATTR_HI);
	pte |= FIELD_PREP(KVM_PTE_TYPE, type);
	pte |= KVM_PTE_VALID;

	/*@ unfold is_possible_table_entry1(pte); @*/
	return pte;
}

static kvm_pte_t kvm_init_invalid_leaf_owner(u8 owner_id)
{
	return FIELD_PREP(KVM_INVALID_PTE_OWNER_MASK, owner_id);
}

/*@
function (bool) flag_in_flags (i32 flag, i32 flags) {
  ((flag == KVM_PGTABLE_WALK_LEAF
        || flag == KVM_PGTABLE_WALK_TABLE_PRE
        || flag == KVM_PGTABLE_WALK_TABLE_POST)
    && (flag == KVM_PGTABLE_WALK_LEAF
        ? bw_and_uf (flags, KVM_PGTABLE_WALK_LEAF) != 0i32
        : true)
    && (flag == KVM_PGTABLE_WALK_TABLE_PRE
        ? bw_and_uf (flags, KVM_PGTABLE_WALK_TABLE_PRE) != 0i32
        : true)
    && (flag == KVM_PGTABLE_WALK_TABLE_POST
        ? bw_and_uf (flags, KVM_PGTABLE_WALK_TABLE_POST) != 0i32
        : true))
}
@*/

static int kvm_pgtable_visitor_cb(struct kvm_pgtable_walk_data *data,
				  const struct kvm_pgtable_visit_ctx *ctx,
				  enum kvm_pgtable_walk_flags visit)
/*@ requires take Data = KVM_PgTable_Walk_Data(data) @*/
/*@ requires take Ctx = Owned(ctx) @*/
/*@ requires valid_pgtable_level(Ctx.level) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires take pte = Owned(Ctx.ptep) @*/
/*@ requires take IPT = Indirect_Page_Table_Entries (Ctx.ptep, Ctx.level, pte) @*/
/*@ requires take Ops = MM_Ops(Ctx.mm_ops) @*/
/*@ requires flag_in_flags ((i32) visit, (i32) (Data.flags)) @*/
/*@ requires (visit == (u32)KVM_PGTABLE_WALK_LEAF) ==
    (not(is_table_entry_at(pte, Ctx.level))) @*/
/*@ requires Ctx.arg == Data.walker.arg @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures Data2 == Data @*/
/*@ ensures take Ctx2 = Owned(ctx) @*/
/*@ ensures Ctx2 == Ctx @*/
/*@ ensures take pte2 = Owned(Ctx.ptep) @*/
/*@ ensures take IPT2 = Indirect_Page_Table_Entries (Ctx.ptep, Ctx.level, pte2) @*/
/*@ ensures take Ops2 = MM_Ops(Ctx.mm_ops) @*/
/*@ ensures Ops2 == Ops @*/
/*@ ensures visit == ((u32)KVM_PGTABLE_WALK_TABLE_PRE)
    ? pte2 == pte : true @*/
{
	struct kvm_pgtable_walker *walker = data->walker;
	WARN_ON_ONCE(kvm_pgtable_walk_shared(ctx) && !kvm_pgtable_walk_lock_held());
	return walker->cb(ctx, visit);
}

/*@
function (bool) walk_again_case(i32 r, u32 flags)
  { r == (0i32 - enum_EAGAIN) &&
    bw_and_uf(flags, (u32) KVM_PGTABLE_WALK_HANDLE_FAULT) == 0u32
  }
@*/

static bool kvm_pgtable_walk_continue(const struct kvm_pgtable_walker *walker,
				      int r)
/*@ requires take Walker = KVM_PgTable_Walker (walker) @*/
/*@ ensures take Walker2 = KVM_PgTable_Walker (walker) @*/
/*@ ensures Walker2 == Walker @*/
/*@ ensures return == ((r == 0i32) || walk_again_case(r, Walker.flags) ? 1u8 : 0u8) @*/
{
	/*
	 * Visitor callbacks return EAGAIN when the conditions that led to a
	 * fault are no longer reflected in the page tables due to a race to
	 * update a PTE. In the context of a fault handler this is interpreted
	 * as a signal to retry guest execution.
	 *
	 * Ignore the return code altogether for walkers outside a fault handler
	 * (e.g. write protecting a range of memory) and chug along with the
	 * page table walk.
	 */
	if (r == -EAGAIN)
		return !(walker->flags & KVM_PGTABLE_WALK_HANDLE_FAULT);

	return !r;
}

static int __kvm_pgtable_walk(struct kvm_pgtable_walk_data *data,
			      struct kvm_pgtable_mm_ops *mm_ops, kvm_pteref_t pgtable, u32 level);

static inline int __kvm_pgtable_visit(struct kvm_pgtable_walk_data *data,
				      struct kvm_pgtable_mm_ops *mm_ops,
				      kvm_pteref_t pteref, u32 level)
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires take pte = Owned<kvm_pte_t>(pteref) @*/
/*@ requires take IPT = Indirect_Page_Table_Entries (pteref, level, pte) @*/
/*@ requires take Ops = MM_Ops(mm_ops) @*/
/*@ requires Data.addr <= Data.end @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures Data2.end == Data.end @*/
/*@ ensures Data2.walker == Data.walker @*/
/*@ ensures Data2.flags == Data.flags @*/
/*@ ensures take pte2 = Owned<kvm_pte_t>(pteref) @*/
/*@ ensures take IPT2 = Indirect_Page_Table_Entries (pteref, level, pte2) @*/
/*@ ensures take Ops2 = MM_Ops(mm_ops) @*/
/*@ ensures Ops2 == Ops @*/
/*@ ensures ((Data2.addr < Data2.end) && (return == 0i32)) ?
        (Data2.addr == (align_u64 (Data.addr, kvm_granule_shift(level)) +
            shift_left(1u64, kvm_granule_shift(level))))
        : true @*/
/*@ ensures ! walk_again_case(return, Data.flags) @*/
{
	enum kvm_pgtable_walk_flags flags = data->walker->flags;
	kvm_pte_t *ptep = kvm_dereference_pteref(data->walker, pteref);
	struct kvm_pgtable_visit_ctx ctx = {
		.ptep	= ptep,
		.old	= READ_ONCE(*ptep),
		.arg	= data->walker->arg,
		.mm_ops	= mm_ops,
		.start	= data->start,
		.addr	= data->addr,
		.end	= data->end,
		.level	= level,
		.flags	= flags,
	};
	int ret = 0;
	bool reload = false;
	kvm_pteref_t childp;
	bool table = kvm_pte_table(ctx.old, level);

	if (table && (ctx.flags & KVM_PGTABLE_WALK_TABLE_PRE)) {
		ret = kvm_pgtable_visitor_cb(data, &ctx, KVM_PGTABLE_WALK_TABLE_PRE);
		reload = true;
	}

	if (!table && (ctx.flags & KVM_PGTABLE_WALK_LEAF)) {
		ret = kvm_pgtable_visitor_cb(data, &ctx, KVM_PGTABLE_WALK_LEAF);
		reload = true;
	}

	/*
	 * Reload the page table after invoking the walker callback for leaf
	 * entries or after pre-order traversal, to allow the walker to descend
	 * into a newly installed or replaced table.
	 */
	if (reload) {
		ctx.old = READ_ONCE(*ptep);
		table = kvm_pte_table(ctx.old, level);
	}

	if (!kvm_pgtable_walk_continue(data->walker, ret))
		goto out;

	if (!table) {
		data->addr = ALIGN_DOWN(data->addr, kvm_granule_size(level));
		data->addr += kvm_granule_size(level);
		goto out;
	}

	childp = (kvm_pteref_t)kvm_pte_follow(ctx.old, mm_ops);
	ret = __kvm_pgtable_walk(data, mm_ops, childp, level + 1);
	if (!kvm_pgtable_walk_continue(data->walker, ret))
		goto out;

	if (ctx.flags & KVM_PGTABLE_WALK_TABLE_POST)
		ret = kvm_pgtable_visitor_cb(data, &ctx, KVM_PGTABLE_WALK_TABLE_POST);

out:
	if (kvm_pgtable_walk_continue(data->walker, ret))
		return 0;

	return ret;
}

static int __kvm_pgtable_walk(struct kvm_pgtable_walk_data *data,
			      struct kvm_pgtable_mm_ops *mm_ops, kvm_pteref_t pgtable, u32 level)
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires take PTEs = Page_Table_Entries (pgtable, level) @*/
/*@ requires let orig_data = data @*/
/*@ requires let orig_pgtable = pgtable @*/
/*@ requires let orig_mm_ops = mm_ops @*/
/*@ requires take Ops = MM_Ops(mm_ops) @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires let orig_level = level @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures Data2.end == Data.end @*/
/*@ ensures Data2.walker == Data.walker @*/
/*@ ensures Data2.flags == Data.flags @*/
/*@ ensures take PTEs2 = Page_Table_Entries (pgtable, level) @*/
/*@ ensures take Ops2 = MM_Ops(mm_ops) @*/
/*@ ensures Ops2 == Ops @*/
/*@ ensures ((Data2.addr < Data2.end) && (return == 0i32)) ?
    (Data2.addr == (align_u64 (Data.addr, kvm_granule_shift(level - 1u32)) +
        shift_left(1u64, kvm_granule_shift(level - 1u32))))
    : true @*/
/*@ ensures ! walk_again_case(return, Data.flags) @*/
{
	u32 idx;
	int ret = 0;

	//CERB_WORK_AROUND: expression statements
	//if (WARN_ON_ONCE(level >= KVM_PGTABLE_MAX_LEVELS))
	if ((level >= KVM_PGTABLE_MAX_LEVELS))
		return -EINVAL;

	for (idx = kvm_pgtable_idx(data, level); idx < PTRS_PER_PTE; ++idx)
	/*@ inv take Data3 = KVM_PgTable_Walk_Data (data) @*/
	/*@ inv take PTEs3 = Page_Table_Entries (pgtable, level) @*/
	/*@ inv 0u32 <= idx && idx <= ((u32)enum_PTRS_PER_PTE) @*/
	/*@ inv data == orig_data @*/
	/*@ inv pgtable == orig_pgtable @*/
	/*@ inv level == orig_level @*/
	/*@ inv Data3.end == Data.end @*/
	/*@ inv Data3.walker == Data.walker @*/
	/*@ inv Data3.flags == Data.flags @*/
	/*@ inv mm_ops == orig_mm_ops @*/
	/*@ inv take Ops3 = MM_Ops(mm_ops) @*/
	/*@ inv ret == 0i32 @*/
	/*@ inv ((Data3.addr == Data.addr) && (idx == purekvm_pgtable_idx(Data.addr, level)))
		||
		(Data3.addr >= Data.end)
		||
		((Data.addr < Data.end) && Data3.addr ==
			(align_u64 (Data.addr, kvm_granule_shift(level - 1u32)) +
				shift_left((u64)idx, kvm_granule_shift(level)))) @*/
	{
		kvm_pteref_t pteref = &pgtable[idx];


		if (data->addr >= data->end)
			break;

		/*@ extract Owned<kvm_pte_t>, (i32)idx; @*/
		/*@ instantiate good<kvm_pte_t>, (i32)idx; @*/
		/*@ extract Indirect_Page_Table_Entries, (i32)idx; @*/

		ret = __kvm_pgtable_visit(data, mm_ops, pteref, level);

		if (ret)
			break;
	}

	return ret;
}

static int _kvm_pgtable_walk(struct kvm_pgtable *pgt, struct kvm_pgtable_walk_data *data)
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires take PT = Pg_Table (pgt) @*/
/*@ requires let orig_data = data @*/
/*@ requires let orig_pgt = pgt @*/
/*@ requires take Ops = MM_Ops(PT.data.mm_ops) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures take PT2 = Pg_Table (pgt) @*/
/*@ ensures PT2 == PT @*/
/*@ ensures take Ops2 = MM_Ops(PT.data.mm_ops) @*/
/*@ ensures Data2.walker == Data.walker @*/
{
	u32 idx;
	int ret = 0;
	u64 limit = BIT(pgt->ia_bits);

	if (data->addr > limit || data->end > limit)
		return -ERANGE;

	if (!pgt->pgd)
		return -EINVAL;

	for (idx = kvm_pgd_page_idx(pgt, data->addr); data->addr < data->end; ++idx)
	/*@ inv take Data3 = KVM_PgTable_Walk_Data (data) @*/
	/*@ inv take PT3 = Pg_Table(pgt) @*/
	/*@ inv take Ops3 = MM_Ops(PT.data.mm_ops) @*/
	/*@ inv data == orig_data @*/
	/*@ inv pgt == orig_pgt @*/
	/*@ inv PT3 == PT @*/
	/*@ inv Ops3 == Ops @*/
	/*@ inv Data3.end == Data.end @*/
	/*@ inv Data3.walker == Data.walker @*/
	/*@ inv Data3.flags == Data.flags @*/
	/*@ inv Data.end <= shift_left(1u64, (u64) PT.data.ia_bits) @*/
	/*@ inv (! (Data3.addr < Data.end)) || (idx == pure__kvm_pgd_page_idx(PT.data.ia_bits,
			PT.data.start_level, Data3.addr)) @*/
	{
		kvm_pteref_t pteref = &pgt->pgd[idx * PTRS_PER_PTE];

		/*@ extract Page_Table_Entries, (i32)idx; @*/

		ret = __kvm_pgtable_walk(data, pgt->mm_ops, pteref, pgt->start_level);
		if (ret)
			break;
	}

	return ret;
}

int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size,
		     struct kvm_pgtable_walker *walker)
/*@ requires take PT = Pg_Table (pgt) @*/
/*@ requires take W = KVM_PgTable_Walker (walker) @*/
/*@ requires take Ops = MM_Ops(PT.data.mm_ops) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ ensures take PT2 = Pg_Table (pgt) @*/
/*@ ensures PT2 == PT @*/
/*@ ensures take Ops2 = MM_Ops(PT.data.mm_ops) @*/
/*@ ensures take W2 = KVM_PgTable_Walker (walker) @*/
/*@ ensures W2.arg == W.arg @*/
{
	/* CN modification: align addr first, avoid self-referential init */
	u64 addr2 = ALIGN_DOWN(addr, PAGE_SIZE);
	struct kvm_pgtable_walk_data walk_data = {
		.start	= addr2,
		.addr	= addr2,
		.end	= PAGE_ALIGN(addr + size),
		.walker	= walker,
	};
	int r;

	r = kvm_pgtable_walk_begin(walker);
	if (r)
		return r;

	r = _kvm_pgtable_walk(pgt, &walk_data);
	kvm_pgtable_walk_end(walker);

	return r;
}

struct leaf_walk_data {
	kvm_pte_t	pte;
	u32		level;
};

static int leaf_walker(const struct kvm_pgtable_visit_ctx *ctx,
		       enum kvm_pgtable_walk_flags visit)
{
	struct leaf_walk_data *data = ctx->arg;

	data->pte   = ctx->old;
	data->level = ctx->level;

	return 0;
}

int kvm_pgtable_get_leaf(struct kvm_pgtable *pgt, u64 addr,
			 kvm_pte_t *ptep, u32 *level)
{
	struct leaf_walk_data data;
	struct kvm_pgtable_walker walker = {
		.cb	= leaf_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF,
		.arg	= &data,
	};
	int ret;

	ret = kvm_pgtable_walk(pgt, ALIGN_DOWN(addr, PAGE_SIZE),
			       PAGE_SIZE, &walker);
	if (!ret) {
		if (ptep)
			*ptep  = data.pte;
		if (level)
			*level = data.level;
	}

	return ret;
}

struct hyp_map_data {
	const u64			phys;
	kvm_pte_t			attr;
};

static int hyp_set_prot_attr(enum kvm_pgtable_prot prot, kvm_pte_t *ptep)
/* not much to prove for (C) safety of this function */
/*@ requires take P = Owned(ptep) @*/
/*@ ensures take P2 = Owned(ptep) @*/
{
	bool device = prot & KVM_PGTABLE_PROT_DEVICE;
	u32 mtype = device ? MT_DEVICE_nGnRE : MT_NORMAL;
	kvm_pte_t attr = FIELD_PREP(KVM_PTE_LEAF_ATTR_LO_S1_ATTRIDX, mtype);
	u32 sh = KVM_PTE_LEAF_ATTR_LO_S1_SH_IS;
	u32 ap = (prot & KVM_PGTABLE_PROT_W) ? KVM_PTE_LEAF_ATTR_LO_S1_AP_RW :
					       KVM_PTE_LEAF_ATTR_LO_S1_AP_RO;

	if (!(prot & KVM_PGTABLE_PROT_R))
		return -EINVAL;

	if (prot & KVM_PGTABLE_PROT_X) {
		if (prot & KVM_PGTABLE_PROT_W)
			return -EINVAL;

		if (device)
			return -EINVAL;
	} else {
		attr |= KVM_PTE_LEAF_ATTR_HI_S1_XN;
	}

	attr |= FIELD_PREP(KVM_PTE_LEAF_ATTR_LO_S1_AP, ap);
	attr |= FIELD_PREP(KVM_PTE_LEAF_ATTR_LO_S1_SH, sh);
	attr |= KVM_PTE_LEAF_ATTR_LO_S1_AF;
	attr |= prot & KVM_PTE_LEAF_ATTR_HI_SW;
	*ptep = attr;

	return 0;
}

/*@
predicate void Hyp_Map_Data (pointer p) {
  assert (good<struct hyp_map_data *>(p));
  take O = Owned<struct hyp_map_data>(p);
  return;
}
@*/

enum kvm_pgtable_prot kvm_pgtable_hyp_pte_prot(kvm_pte_t pte)
{
	enum kvm_pgtable_prot prot = pte & KVM_PTE_LEAF_ATTR_HI_SW;
	u32 ap;

	if (!kvm_pte_valid(pte))
		return prot;

	if (!(pte & KVM_PTE_LEAF_ATTR_HI_S1_XN))
		prot |= KVM_PGTABLE_PROT_X;

	ap = FIELD_GET(KVM_PTE_LEAF_ATTR_LO_S1_AP, pte);
	if (ap == KVM_PTE_LEAF_ATTR_LO_S1_AP_RO)
		prot |= KVM_PGTABLE_PROT_R;
	else if (ap == KVM_PTE_LEAF_ATTR_LO_S1_AP_RW)
		prot |= KVM_PGTABLE_PROT_RW;

	return prot;
}

static bool hyp_map_walker_try_leaf(const struct kvm_pgtable_visit_ctx *ctx,
				    struct hyp_map_data *data)
/*@ requires take Ctx = Owned(ctx) @*/
/*@ requires valid_pgtable_level(Ctx.level) @*/
/*@ requires take D = Hyp_Map_Data(data) @*/
/*@ requires take pte = Owned<kvm_pte_t>(Ctx.ptep) @*/
/*@ requires not (is_table_entry_at (pte, Ctx.level)) @*/
/*@ requires take Ops = MM_Ops(Ctx.mm_ops) @*/
/*@ ensures take Ctx2 = Owned(ctx) @*/
/*@ ensures Ctx2 == Ctx @*/
/*@ ensures take D2 = Hyp_Map_Data(data) @*/
/*@ ensures D2 == D @*/
/*@ ensures take pte2 = Owned<kvm_pte_t>(Ctx.ptep) @*/
/*@ ensures take Ops2 = MM_Ops(Ctx.mm_ops) @*/
/*@ ensures not (is_table_entry_at (pte2, Ctx.level)) @*/
{
	u64 phys = data->phys + (ctx->addr - ctx->start);
	kvm_pte_t new;

	if (!kvm_block_mapping_supported(ctx, phys))
		return false;

	new = kvm_init_valid_leaf_pte(phys, data->attr, ctx->level);
	if (ctx->old == new)
		return true;
	if (!kvm_pte_valid(ctx->old))
		ctx->mm_ops->get_page(ctx->ptep);
	else if (WARN_ON((ctx->old ^ new) & ~KVM_PTE_LEAF_ATTR_HI_SW))
		return false;

	smp_store_release(ctx->ptep, new);
	return true;
}


static inline void coerce_page_to_ptes(kvm_pte_t *ptep)
/*@ trusted @*/
/*@ requires take ZP = Cond_Zero_Page (ptep) @*/
/*@ requires ZP.exists @*/
/*@ ensures take ptes = PTE_Array (ptep) @*/
/*@ ensures each (i32 i; i <= 0i32 && i < 4096i32) {ptes[i] == 0u64} @*/
{
}

static inline void coerce_null_ptes_to_IPT(kvm_pte_t *ptep, u32 level)
/*@ trusted @*/
/*@ requires take ptes = PTE_Array (ptep) @*/
/*@ requires each (i32 i; i <= 0i32 && i < 4096i32) {ptes[i] == 0u64} @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ ensures take ptes2 = Page_Table_Entries (ptep, level) @*/
{
}


static int hyp_map_walker(const struct kvm_pgtable_visit_ctx *ctx,
			  enum kvm_pgtable_walk_flags visit)
/*@ requires take Ctx = Owned(ctx) @*/
/*@ requires valid_pgtable_level(Ctx.level) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires take D = Hyp_Map_Data(Ctx.arg) @*/
/*@ requires take pte = Owned<kvm_pte_t>(Ctx.ptep) @*/
/*@ requires not(is_table_entry_at(pte, Ctx.level)) @*/
/*@ requires take Ops = MM_Ops(Ctx.mm_ops) @*/
/*@ ensures take Ctx2 = Owned(ctx) @*/
/*@ ensures Ctx2 == Ctx @*/
/*@ ensures take D2 = Hyp_Map_Data(Ctx.arg) @*/
/*@ ensures take pte2 = Owned<kvm_pte_t>(Ctx.ptep) @*/
/*@ ensures take IPT2 = Indirect_Page_Table_Entries(Ctx.ptep, Ctx.level, pte2) @*/
/*@ ensures D2 == D @*/
/*@ ensures take Ops2 = MM_Ops(Ctx.mm_ops) @*/
{
	kvm_pte_t *childp, new;
	struct hyp_map_data *data = ctx->arg;
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;

	if (hyp_map_walker_try_leaf(ctx, data))
		return 0;

	if (WARN_ON(ctx->level == KVM_PGTABLE_MAX_LEVELS - 1))
		return -EINVAL;

	childp = (kvm_pte_t *)mm_ops->zalloc_page(NULL);
	if (!childp)
		return -ENOMEM;

	/* this is where we need to turn a char[] into a kvm_pte_t[] (i.e. a u64[]) */
	coerce_page_to_ptes(childp);
	coerce_null_ptes_to_IPT(childp, ctx->level + 1);

	new = kvm_init_table_pte(childp, mm_ops);
	mm_ops->get_page(ctx->ptep);
	smp_store_release(ctx->ptep, new);

	return 0;
}

/*@
predicate (void) Hyp_Map_Walker_Case
        (pointer f, pointer x, u32 flags) {
  assert (f == &hyp_map_walker);
  assert (flags == ((u32) KVM_PGTABLE_WALK_LEAF));
  take D = Hyp_Map_Data(x);
  return;
}

predicate (void) Hyp_Walker_Cases
        (pointer f, pointer x, u32 flags) {
  take X = Hyp_Map_Walker_Case (f, x, flags);
  return X;
}

@*/

int kvm_pgtable_hyp_map(struct kvm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			enum kvm_pgtable_prot prot)
/*@ requires take PT = Pg_Table(pgt) @*/
/*@ requires take Ops = MM_Ops(PT.data.mm_ops) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ ensures take PT2 = Pg_Table(pgt) @*/
/*@ ensures PT2.extra_bits == PT.extra_bits @*/
/*@ ensures PT2.data == PT.data @*/
/*@ ensures take Ops2 = MM_Ops(PT.data.mm_ops) @*/
{
	int ret;
	struct hyp_map_data map_data = {
		.phys	= ALIGN_DOWN(phys, PAGE_SIZE),
	};
	struct kvm_pgtable_walker walker = {
		.cb	= hyp_map_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF,
		.arg	= &map_data,
	};

	ret = hyp_set_prot_attr(prot, &map_data.attr);
	if (ret)
		return ret;

	ret = kvm_pgtable_walk(pgt, addr, size, &walker);
	dsb(ishst);
	isb();
	return ret;
}

static int hyp_unmap_walker(const struct kvm_pgtable_visit_ctx *ctx,
			    enum kvm_pgtable_walk_flags visit)
{
	kvm_pte_t *childp = NULL;
	u64 granule = kvm_granule_size(ctx->level);
	u64 *unmapped = ctx->arg;
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;

	if (!kvm_pte_valid(ctx->old))
		return -EINVAL;

	if (kvm_pte_table(ctx->old, ctx->level)) {
		childp = kvm_pte_follow(ctx->old, mm_ops);

		if (mm_ops->page_count(childp) != 1)
			return 0;

		kvm_clear_pte(ctx->ptep);
		dsb(ishst);
		__tlbi_level(vae2is, __TLBI_VADDR(ctx->addr, 0), ctx->level);
	} else {
		if (ctx->end - ctx->addr < granule)
			return -EINVAL;

		kvm_clear_pte(ctx->ptep);
		dsb(ishst);
		__tlbi_level(vale2is, __TLBI_VADDR(ctx->addr, 0), ctx->level);
		*unmapped += granule;
	}

	dsb(ish);
	isb();
	mm_ops->put_page(ctx->ptep);

	if (childp)
		mm_ops->put_page(childp);

	return 0;
}

u64 kvm_pgtable_hyp_unmap(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	u64 unmapped = 0;
	struct kvm_pgtable_walker walker = {
		.cb	= hyp_unmap_walker,
		.arg	= &unmapped,
		.flags	= KVM_PGTABLE_WALK_LEAF | KVM_PGTABLE_WALK_TABLE_POST,
	};

	if (!pgt->mm_ops->page_count)
		return 0;

	kvm_pgtable_walk(pgt, addr, size, &walker);
	return unmapped;
}

int kvm_pgtable_hyp_init(struct kvm_pgtable *pgt, u32 va_bits,
			 struct kvm_pgtable_mm_ops *mm_ops)
{
	u64 levels = ARM64_HW_PGTABLE_LEVELS(va_bits);

	pgt->pgd = (kvm_pteref_t)mm_ops->zalloc_page(NULL);
	if (!pgt->pgd)
		return -ENOMEM;

	pgt->ia_bits		= va_bits;
	pgt->start_level	= KVM_PGTABLE_MAX_LEVELS - levels;
	pgt->mm_ops		= mm_ops;
	pgt->mmu		= NULL;
	pgt->force_pte_cb	= NULL;

	return 0;
}

static int hyp_free_walker(const struct kvm_pgtable_visit_ctx *ctx,
			   enum kvm_pgtable_walk_flags visit)
{
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;

	if (!kvm_pte_valid(ctx->old))
		return 0;

	mm_ops->put_page(ctx->ptep);

	if (kvm_pte_table(ctx->old, ctx->level))
		mm_ops->put_page(kvm_pte_follow(ctx->old, mm_ops));

	return 0;
}

void kvm_pgtable_hyp_destroy(struct kvm_pgtable *pgt)
{
	struct kvm_pgtable_walker walker = {
		.cb	= hyp_free_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF | KVM_PGTABLE_WALK_TABLE_POST,
	};

	WARN_ON(kvm_pgtable_walk(pgt, 0, BIT(pgt->ia_bits), &walker));
	pgt->mm_ops->put_page(kvm_dereference_pteref(&walker, pgt->pgd));
	pgt->pgd = NULL;
}

struct stage2_map_data {
	const u64			phys;
	kvm_pte_t			attr;
	u8				owner_id;

	kvm_pte_t			*anchor;
	kvm_pte_t			*childp;

	struct kvm_s2_mmu		*mmu;
	void				*memcache;

	/* Force mappings to page granularity */
	bool				force_pte;
};

u64 kvm_get_vtcr(u64 mmfr0, u64 mmfr1, u32 phys_shift)
{
	u64 vtcr = VTCR_EL2_FLAGS;
	u8 lvls;

	vtcr |= kvm_get_parange(mmfr0) << VTCR_EL2_PS_SHIFT;
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

static bool stage2_has_fwb(struct kvm_pgtable *pgt)
{
	if (!cpus_have_const_cap(ARM64_HAS_STAGE2_FWB))
		return false;

	return !(pgt->flags & KVM_PGTABLE_S2_NOFWB);
}

#define KVM_S2_MEMATTR(pgt, attr) PAGE_S2_MEMATTR(attr, stage2_has_fwb(pgt))

static int stage2_set_prot_attr(struct kvm_pgtable *pgt, enum kvm_pgtable_prot prot,
				kvm_pte_t *ptep)
{
	bool device = prot & KVM_PGTABLE_PROT_DEVICE;
	kvm_pte_t attr = device ? KVM_S2_MEMATTR(pgt, DEVICE_nGnRE) :
			    KVM_S2_MEMATTR(pgt, NORMAL);
	u32 sh = KVM_PTE_LEAF_ATTR_LO_S2_SH_IS;

	if (!(prot & KVM_PGTABLE_PROT_X))
		attr |= KVM_PTE_LEAF_ATTR_HI_S2_XN;
	else if (device)
		return -EINVAL;

	if (prot & KVM_PGTABLE_PROT_R)
		attr |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R;

	if (prot & KVM_PGTABLE_PROT_W)
		attr |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W;

	attr |= FIELD_PREP(KVM_PTE_LEAF_ATTR_LO_S2_SH, sh);
	attr |= KVM_PTE_LEAF_ATTR_LO_S2_AF;
	attr |= prot & KVM_PTE_LEAF_ATTR_HI_SW;
	*ptep = attr;

	return 0;
}

enum kvm_pgtable_prot kvm_pgtable_stage2_pte_prot(kvm_pte_t pte)
{
	enum kvm_pgtable_prot prot = pte & KVM_PTE_LEAF_ATTR_HI_SW;

	if (!kvm_pte_valid(pte))
		return prot;

	if (pte & KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R)
		prot |= KVM_PGTABLE_PROT_R;
	if (pte & KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W)
		prot |= KVM_PGTABLE_PROT_W;
	if (!(pte & KVM_PTE_LEAF_ATTR_HI_S2_XN))
		prot |= KVM_PGTABLE_PROT_X;

	return prot;
}

static bool stage2_pte_needs_update(kvm_pte_t old, kvm_pte_t new)
{
	if (!kvm_pte_valid(old) || !kvm_pte_valid(new))
		return true;

	return ((old ^ new) & (~KVM_PTE_LEAF_ATTR_S2_PERMS));
}

static bool stage2_pte_is_counted(kvm_pte_t pte)
{
	/*
	 * The refcount tracks valid entries as well as invalid entries if they
	 * encode ownership of a page to another entity than the page-table
	 * owner, whose id is 0.
	 */
	return !!pte;
}

static bool stage2_pte_is_locked(kvm_pte_t pte)
{
	return !kvm_pte_valid(pte) && (pte & KVM_INVALID_PTE_LOCKED);
}

static bool stage2_try_set_pte(const struct kvm_pgtable_visit_ctx *ctx, kvm_pte_t new)
{
	if (!kvm_pgtable_walk_shared(ctx)) {
		WRITE_ONCE(*ctx->ptep, new);
		return true;
	}

	return cmpxchg(ctx->ptep, ctx->old, new) == ctx->old;
}

/**
 * stage2_try_break_pte() - Invalidates a pte according to the
 *			    'break-before-make' requirements of the
 *			    architecture.
 *
 * @ctx: context of the visited pte.
 * @mmu: stage-2 mmu
 *
 * Returns: true if the pte was successfully broken.
 *
 * If the removed pte was valid, performs the necessary serialization and TLB
 * invalidation for the old value. For counted ptes, drops the reference count
 * on the containing table page.
 */
static bool stage2_try_break_pte(const struct kvm_pgtable_visit_ctx *ctx,
				 struct kvm_s2_mmu *mmu)
{
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;

	if (stage2_pte_is_locked(ctx->old)) {
		/*
		 * Should never occur if this walker has exclusive access to the
		 * page tables.
		 */
		WARN_ON(!kvm_pgtable_walk_shared(ctx));
		return false;
	}

	if (!stage2_try_set_pte(ctx, KVM_INVALID_PTE_LOCKED))
		return false;

	/*
	 * Perform the appropriate TLB invalidation based on the evicted pte
	 * value (if any).
	 */
	if (kvm_pte_table(ctx->old, ctx->level))
		kvm_call_hyp(__kvm_tlb_flush_vmid, mmu);
	else if (kvm_pte_valid(ctx->old))
		kvm_call_hyp(__kvm_tlb_flush_vmid_ipa, mmu, ctx->addr, ctx->level);

	if (stage2_pte_is_counted(ctx->old))
		mm_ops->put_page(ctx->ptep);

	return true;
}

static void stage2_make_pte(const struct kvm_pgtable_visit_ctx *ctx, kvm_pte_t new)
{
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;

	WARN_ON(!stage2_pte_is_locked(*ctx->ptep));

	if (stage2_pte_is_counted(new))
		mm_ops->get_page(ctx->ptep);

	smp_store_release(ctx->ptep, new);
}

static void stage2_put_pte(const struct kvm_pgtable_visit_ctx *ctx, struct kvm_s2_mmu *mmu,
			   struct kvm_pgtable_mm_ops *mm_ops)
{
	/*
	 * Clear the existing PTE, and perform break-before-make with
	 * TLB maintenance if it was valid.
	 */
	if (kvm_pte_valid(ctx->old)) {
		kvm_clear_pte(ctx->ptep);
		kvm_call_hyp(__kvm_tlb_flush_vmid_ipa, mmu, ctx->addr, ctx->level);
	}

	mm_ops->put_page(ctx->ptep);
}

static bool stage2_pte_cacheable(struct kvm_pgtable *pgt, kvm_pte_t pte)
{
	u64 memattr = pte & KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR;
	return kvm_pte_valid(pte) && memattr == KVM_S2_MEMATTR(pgt, NORMAL);
}

static bool stage2_pte_executable(kvm_pte_t pte)
{
	return kvm_pte_valid(pte) && !(pte & KVM_PTE_LEAF_ATTR_HI_S2_XN);
}

static u64 stage2_map_walker_phys_addr(const struct kvm_pgtable_visit_ctx *ctx,
				       const struct stage2_map_data *data)
{
	u64 phys = data->phys;

	/*
	 * Stage-2 walks to update ownership data are communicated to the map
	 * walker using an invalid PA. Avoid offsetting an already invalid PA,
	 * which could overflow and make the address valid again.
	 */
	if (!kvm_phys_is_valid(phys))
		return phys;

	/*
	 * Otherwise, work out the correct PA based on how far the walk has
	 * gotten.
	 */
	return phys + (ctx->addr - ctx->start);
}

static bool stage2_leaf_mapping_allowed(const struct kvm_pgtable_visit_ctx *ctx,
					struct stage2_map_data *data)
{
	u64 phys = stage2_map_walker_phys_addr(ctx, data);

	if (data->force_pte && (ctx->level < (KVM_PGTABLE_MAX_LEVELS - 1)))
		return false;

	return kvm_block_mapping_supported(ctx, phys);
}

static int stage2_map_walker_try_leaf(const struct kvm_pgtable_visit_ctx *ctx,
				      struct stage2_map_data *data)
{
	kvm_pte_t new;
	u64 phys = stage2_map_walker_phys_addr(ctx, data);
	u64 granule = kvm_granule_size(ctx->level);
	struct kvm_pgtable *pgt = data->mmu->pgt;
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;

	if (!stage2_leaf_mapping_allowed(ctx, data))
		return -E2BIG;

	if (kvm_phys_is_valid(phys))
		new = kvm_init_valid_leaf_pte(phys, data->attr, ctx->level);
	else
		new = kvm_init_invalid_leaf_owner(data->owner_id);

	/*
	 * Skip updating the PTE if we are trying to recreate the exact
	 * same mapping or only change the access permissions. Instead,
	 * the vCPU will exit one more time from guest if still needed
	 * and then go through the path of relaxing permissions.
	 */
	if (!stage2_pte_needs_update(ctx->old, new))
		return -EAGAIN;

	/* If we're only changing software bits, then store them and go! */
	if (!kvm_pgtable_walk_shared(ctx) &&
	    !((ctx->old ^ new) & ~KVM_PTE_LEAF_ATTR_HI_SW)) {
		WRITE_ONCE(*ctx->ptep, new);
		return 0;
	}

	if (!stage2_try_break_pte(ctx, data->mmu))
		return -EAGAIN;

	/* Perform CMOs before installation of the guest stage-2 PTE */
	if (mm_ops->dcache_clean_inval_poc && stage2_pte_cacheable(pgt, new))
		mm_ops->dcache_clean_inval_poc(kvm_pte_follow(new, mm_ops),
						granule);

	if (mm_ops->icache_inval_pou && stage2_pte_executable(new))
		mm_ops->icache_inval_pou(kvm_pte_follow(new, mm_ops), granule);

	stage2_make_pte(ctx, new);

	return 0;
}

static int stage2_map_walk_table_pre(const struct kvm_pgtable_visit_ctx *ctx,
				     struct stage2_map_data *data)
{
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;
	kvm_pte_t *childp = kvm_pte_follow(ctx->old, mm_ops);
	int ret;

	if (!stage2_leaf_mapping_allowed(ctx, data))
		return 0;

	ret = stage2_map_walker_try_leaf(ctx, data);
	if (ret)
		return ret;

	mm_ops->free_removed_table(childp, ctx->level);
	return 0;
}

static int stage2_map_walk_leaf(const struct kvm_pgtable_visit_ctx *ctx,
				struct stage2_map_data *data)
{
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;
	kvm_pte_t *childp, new;
	int ret;

	ret = stage2_map_walker_try_leaf(ctx, data);
	if (ret != -E2BIG)
		return ret;

	if (WARN_ON(ctx->level == KVM_PGTABLE_MAX_LEVELS - 1))
		return -EINVAL;

	if (!data->memcache)
		return -ENOMEM;

	childp = mm_ops->zalloc_page(data->memcache);
	if (!childp)
		return -ENOMEM;

	if (!stage2_try_break_pte(ctx, data->mmu)) {
		mm_ops->put_page(childp);
		return -EAGAIN;
	}

	/*
	 * If we've run into an existing block mapping then replace it with
	 * a table. Accesses beyond 'end' that fall within the new table
	 * will be mapped lazily.
	 */
	new = kvm_init_table_pte(childp, mm_ops);
	stage2_make_pte(ctx, new);

	return 0;
}

/*
 * The TABLE_PRE callback runs for table entries on the way down, looking
 * for table entries which we could conceivably replace with a block entry
 * for this mapping. If it finds one it replaces the entry and calls
 * kvm_pgtable_mm_ops::free_removed_table() to tear down the detached table.
 *
 * Otherwise, the LEAF callback performs the mapping at the existing leaves
 * instead.
 */
static int stage2_map_walker(const struct kvm_pgtable_visit_ctx *ctx,
			     enum kvm_pgtable_walk_flags visit)
{
	struct stage2_map_data *data = ctx->arg;

	switch (visit) {
	case KVM_PGTABLE_WALK_TABLE_PRE:
		return stage2_map_walk_table_pre(ctx, data);
	case KVM_PGTABLE_WALK_LEAF:
		return stage2_map_walk_leaf(ctx, data);
	default:
		return -EINVAL;
	}
}

int kvm_pgtable_stage2_map(struct kvm_pgtable *pgt, u64 addr, u64 size,
			   u64 phys, enum kvm_pgtable_prot prot,
			   void *mc, enum kvm_pgtable_walk_flags flags)
{
	int ret;
	struct stage2_map_data map_data = {
		.phys		= ALIGN_DOWN(phys, PAGE_SIZE),
		.mmu		= pgt->mmu,
		.memcache	= mc,
		.force_pte	= pgt->force_pte_cb && pgt->force_pte_cb(addr, addr + size, prot),
	};
	struct kvm_pgtable_walker walker = {
		.cb		= stage2_map_walker,
		.flags		= flags |
				  KVM_PGTABLE_WALK_TABLE_PRE |
				  KVM_PGTABLE_WALK_LEAF,
		.arg		= &map_data,
	};

	if (WARN_ON((pgt->flags & KVM_PGTABLE_S2_IDMAP) && (addr != phys)))
		return -EINVAL;

	ret = stage2_set_prot_attr(pgt, prot, &map_data.attr);
	if (ret)
		return ret;

	ret = kvm_pgtable_walk(pgt, addr, size, &walker);
	dsb(ishst);
	return ret;
}

int kvm_pgtable_stage2_set_owner(struct kvm_pgtable *pgt, u64 addr, u64 size,
				 void *mc, u8 owner_id)
{
	int ret;
	struct stage2_map_data map_data = {
		.phys		= KVM_PHYS_INVALID,
		.mmu		= pgt->mmu,
		.memcache	= mc,
		.owner_id	= owner_id,
		.force_pte	= true,
	};
	struct kvm_pgtable_walker walker = {
		.cb		= stage2_map_walker,
		.flags		= KVM_PGTABLE_WALK_TABLE_PRE |
				  KVM_PGTABLE_WALK_LEAF,
		.arg		= &map_data,
	};

	if (owner_id > KVM_MAX_OWNER_ID)
		return -EINVAL;

	ret = kvm_pgtable_walk(pgt, addr, size, &walker);
	return ret;
}

static int stage2_unmap_walker(const struct kvm_pgtable_visit_ctx *ctx,
			       enum kvm_pgtable_walk_flags visit)
{
	struct kvm_pgtable *pgt = ctx->arg;
	struct kvm_s2_mmu *mmu = pgt->mmu;
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;
	kvm_pte_t *childp = NULL;
	bool need_flush = false;

	if (!kvm_pte_valid(ctx->old)) {
		if (stage2_pte_is_counted(ctx->old)) {
			kvm_clear_pte(ctx->ptep);
			mm_ops->put_page(ctx->ptep);
		}
		return 0;
	}

	if (kvm_pte_table(ctx->old, ctx->level)) {
		childp = kvm_pte_follow(ctx->old, mm_ops);

		if (mm_ops->page_count(childp) != 1)
			return 0;
	} else if (stage2_pte_cacheable(pgt, ctx->old)) {
		need_flush = !stage2_has_fwb(pgt);
	}

	/*
	 * This is similar to the map() path in that we unmap the entire
	 * block entry and rely on the remaining portions being faulted
	 * back lazily.
	 */
	stage2_put_pte(ctx, mmu, mm_ops);

	if (need_flush && mm_ops->dcache_clean_inval_poc)
		mm_ops->dcache_clean_inval_poc(kvm_pte_follow(ctx->old, mm_ops),
					       kvm_granule_size(ctx->level));

	if (childp)
		mm_ops->put_page(childp);

	return 0;
}

int kvm_pgtable_stage2_unmap(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	struct kvm_pgtable_walker walker = {
		.cb	= stage2_unmap_walker,
		.arg	= pgt,
		.flags	= KVM_PGTABLE_WALK_LEAF | KVM_PGTABLE_WALK_TABLE_POST,
	};

	return kvm_pgtable_walk(pgt, addr, size, &walker);
}

struct stage2_attr_data {
	kvm_pte_t			attr_set;
	kvm_pte_t			attr_clr;
	kvm_pte_t			pte;
	u32				level;
};

static int stage2_attr_walker(const struct kvm_pgtable_visit_ctx *ctx,
			      enum kvm_pgtable_walk_flags visit)
{
	kvm_pte_t pte = ctx->old;
	struct stage2_attr_data *data = ctx->arg;
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;

	if (!kvm_pte_valid(ctx->old))
		return -EAGAIN;

	data->level = ctx->level;
	data->pte = pte;
	pte &= ~data->attr_clr;
	pte |= data->attr_set;

	/*
	 * We may race with the CPU trying to set the access flag here,
	 * but worst-case the access flag update gets lost and will be
	 * set on the next access instead.
	 */
	if (data->pte != pte) {
		/*
		 * Invalidate instruction cache before updating the guest
		 * stage-2 PTE if we are going to add executable permission.
		 */
		if (mm_ops->icache_inval_pou &&
		    stage2_pte_executable(pte) && !stage2_pte_executable(ctx->old))
			mm_ops->icache_inval_pou(kvm_pte_follow(pte, mm_ops),
						  kvm_granule_size(ctx->level));

		if (!stage2_try_set_pte(ctx, pte))
			return -EAGAIN;
	}

	return 0;
}

static int stage2_update_leaf_attrs(struct kvm_pgtable *pgt, u64 addr,
				    u64 size, kvm_pte_t attr_set,
				    kvm_pte_t attr_clr, kvm_pte_t *orig_pte,
				    u32 *level, enum kvm_pgtable_walk_flags flags)
{
	int ret;
	kvm_pte_t attr_mask = KVM_PTE_LEAF_ATTR_LO | KVM_PTE_LEAF_ATTR_HI;
	struct stage2_attr_data data = {
		.attr_set	= attr_set & attr_mask,
		.attr_clr	= attr_clr & attr_mask,
	};
	struct kvm_pgtable_walker walker = {
		.cb		= stage2_attr_walker,
		.arg		= &data,
		.flags		= flags | KVM_PGTABLE_WALK_LEAF,
	};

	ret = kvm_pgtable_walk(pgt, addr, size, &walker);
	if (ret)
		return ret;

	if (orig_pte)
		*orig_pte = data.pte;

	if (level)
		*level = data.level;
	return 0;
}

int kvm_pgtable_stage2_wrprotect(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	return stage2_update_leaf_attrs(pgt, addr, size, 0,
					KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W,
					NULL, NULL, 0);
}

kvm_pte_t kvm_pgtable_stage2_mkyoung(struct kvm_pgtable *pgt, u64 addr)
{
	kvm_pte_t pte = 0;
	int ret;

	ret = stage2_update_leaf_attrs(pgt, addr, 1, KVM_PTE_LEAF_ATTR_LO_S2_AF, 0,
				       &pte, NULL,
				       KVM_PGTABLE_WALK_HANDLE_FAULT |
				       KVM_PGTABLE_WALK_SHARED);
	if (!ret)
		dsb(ishst);

	return pte;
}

kvm_pte_t kvm_pgtable_stage2_mkold(struct kvm_pgtable *pgt, u64 addr)
{
	kvm_pte_t pte = 0;
	stage2_update_leaf_attrs(pgt, addr, 1, 0, KVM_PTE_LEAF_ATTR_LO_S2_AF,
				 &pte, NULL, 0);
	/*
	 * "But where's the TLBI?!", you scream.
	 * "Over in the core code", I sigh.
	 *
	 * See the '->clear_flush_young()' callback on the KVM mmu notifier.
	 */
	return pte;
}

bool kvm_pgtable_stage2_is_young(struct kvm_pgtable *pgt, u64 addr)
{
	kvm_pte_t pte = 0;
	stage2_update_leaf_attrs(pgt, addr, 1, 0, 0, &pte, NULL, 0);
	return pte & KVM_PTE_LEAF_ATTR_LO_S2_AF;
}

int kvm_pgtable_stage2_relax_perms(struct kvm_pgtable *pgt, u64 addr,
				   enum kvm_pgtable_prot prot)
{
	int ret;
	u32 level;
	kvm_pte_t set = 0, clr = 0;

	if (prot & KVM_PTE_LEAF_ATTR_HI_SW)
		return -EINVAL;

	if (prot & KVM_PGTABLE_PROT_R)
		set |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R;

	if (prot & KVM_PGTABLE_PROT_W)
		set |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W;

	if (prot & KVM_PGTABLE_PROT_X)
		clr |= KVM_PTE_LEAF_ATTR_HI_S2_XN;

	ret = stage2_update_leaf_attrs(pgt, addr, 1, set, clr, NULL, &level,
				       KVM_PGTABLE_WALK_HANDLE_FAULT |
				       KVM_PGTABLE_WALK_SHARED);
	if (!ret)
		kvm_call_hyp(__kvm_tlb_flush_vmid_ipa, pgt->mmu, addr, level);
	return ret;
}

static int stage2_flush_walker(const struct kvm_pgtable_visit_ctx *ctx,
			       enum kvm_pgtable_walk_flags visit)
{
	struct kvm_pgtable *pgt = ctx->arg;
	struct kvm_pgtable_mm_ops *mm_ops = pgt->mm_ops;

	if (!stage2_pte_cacheable(pgt, ctx->old))
		return 0;

	if (mm_ops->dcache_clean_inval_poc)
		mm_ops->dcache_clean_inval_poc(kvm_pte_follow(ctx->old, mm_ops),
					       kvm_granule_size(ctx->level));
	return 0;
}

int kvm_pgtable_stage2_flush(struct kvm_pgtable *pgt, u64 addr, u64 size)
{
	struct kvm_pgtable_walker walker = {
		.cb	= stage2_flush_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF,
		.arg	= pgt,
	};

	if (stage2_has_fwb(pgt))
		return 0;

	return kvm_pgtable_walk(pgt, addr, size, &walker);
}


int __kvm_pgtable_stage2_init(struct kvm_pgtable *pgt, struct kvm_s2_mmu *mmu,
			      struct kvm_pgtable_mm_ops *mm_ops,
			      enum kvm_pgtable_stage2_flags flags,
			      kvm_pgtable_force_pte_cb_t force_pte_cb)
{
	size_t pgd_sz;
	u64 vtcr = mmu->arch->vtcr;
	u32 ia_bits = VTCR_EL2_IPA(vtcr);
	u32 sl0 = FIELD_GET(VTCR_EL2_SL0_MASK, vtcr);
	u32 start_level = VTCR_EL2_TGRAN_SL0_BASE - sl0;

	pgd_sz = kvm_pgd_pages(ia_bits, start_level) * PAGE_SIZE;
	pgt->pgd = (kvm_pteref_t)mm_ops->zalloc_pages_exact(pgd_sz);
	if (!pgt->pgd)
		return -ENOMEM;

	pgt->ia_bits		= ia_bits;
	pgt->start_level	= start_level;
	pgt->mm_ops		= mm_ops;
	pgt->mmu		= mmu;
	pgt->flags		= flags;
	pgt->force_pte_cb	= force_pte_cb;

	/* Ensure zeroed PGD pages are visible to the hardware walker */
	dsb(ishst);
	return 0;
}

size_t kvm_pgtable_stage2_pgd_size(u64 vtcr)
{
	u32 ia_bits = VTCR_EL2_IPA(vtcr);
	u32 sl0 = FIELD_GET(VTCR_EL2_SL0_MASK, vtcr);
	u32 start_level = VTCR_EL2_TGRAN_SL0_BASE - sl0;

	return kvm_pgd_pages(ia_bits, start_level) * PAGE_SIZE;
}

static int stage2_free_walker(const struct kvm_pgtable_visit_ctx *ctx,
			      enum kvm_pgtable_walk_flags visit)
{
	struct kvm_pgtable_mm_ops *mm_ops = ctx->mm_ops;

	if (!stage2_pte_is_counted(ctx->old))
		return 0;

	mm_ops->put_page(ctx->ptep);

	if (kvm_pte_table(ctx->old, ctx->level))
		mm_ops->put_page(kvm_pte_follow(ctx->old, mm_ops));

	return 0;
}

void kvm_pgtable_stage2_destroy(struct kvm_pgtable *pgt)
{
	size_t pgd_sz;
	struct kvm_pgtable_walker walker = {
		.cb	= stage2_free_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF |
			  KVM_PGTABLE_WALK_TABLE_POST,
	};

	WARN_ON(kvm_pgtable_walk(pgt, 0, BIT(pgt->ia_bits), &walker));
	pgd_sz = kvm_pgd_pages(pgt->ia_bits, pgt->start_level) * PAGE_SIZE;
	pgt->mm_ops->free_pages_exact(kvm_dereference_pteref(&walker, pgt->pgd), pgd_sz);
	pgt->pgd = NULL;
}

void kvm_pgtable_stage2_free_removed(struct kvm_pgtable_mm_ops *mm_ops, void *pgtable, u32 level)
{
	kvm_pteref_t ptep = (kvm_pteref_t)pgtable;
	struct kvm_pgtable_walker walker = {
		.cb	= stage2_free_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF |
			  KVM_PGTABLE_WALK_TABLE_POST,
	};
	struct kvm_pgtable_walk_data data = {
		.walker	= &walker,

		/*
		 * At this point the IPA really doesn't matter, as the page
		 * table being traversed has already been removed from the stage
		 * 2. Set an appropriate range to cover the entire page table.
		 */
		.addr	= 0,
		.end	= kvm_granule_size(level),
	};

	WARN_ON(__kvm_pgtable_walk(&data, mm_ops, ptep, level + 1));

	WARN_ON(mm_ops->page_count(pgtable) != 1);
	mm_ops->put_page(pgtable);
}

/* more verification hacks */
int verification_deps (void) {
  (void) hyp_zalloc_hyp_page;
  (void) hyp_phys_to_virt;
  (void) hyp_virt_to_phys;
  (void) hyp_get_page;
  (void) enum_PTRS_PER_PTE;
  return 9;
}

