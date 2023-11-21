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

#define KVM_PTE_VALID			BIT(0)

#define KVM_PTE_TYPE			BIT(1)
#define KVM_PTE_TYPE_BLOCK		0
#define KVM_PTE_TYPE_PAGE		1
#define KVM_PTE_TYPE_TABLE		1

//CERB_WORK_AROUND: feature not yet supported: SDecl_bitfield
//#define KVM_PTE_ADDR_MASK		GENMASK(47, PAGE_SHIFT)
//#define KVM_PTE_ADDR_51_48		GENMASK(15, 12)
#define KVM_PTE_ADDR_MASK		__GENMASK(47, PAGE_SHIFT)
#define KVM_PTE_ADDR_51_48		__GENMASK(15, 12)

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

#define KVM_PTE_LEAF_ATTR_HI_S1_XN	BIT(54)

#define KVM_PTE_LEAF_ATTR_HI_S2_XN	BIT(54)

#define KVM_PTE_LEAF_ATTR_S2_PERMS	(KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R | \
					 KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W | \
					 KVM_PTE_LEAF_ATTR_HI_S2_XN)

#define KVM_PTE_LEAF_ATTR_S2_IGNORED	GENMASK(58, 55)

#define KVM_INVALID_PTE_OWNER_MASK	GENMASK(63, 56)
#define KVM_MAX_OWNER_ID		1


/* verification hack. TODO: add a CN feature to do this less intrusively. */
extern void *hyp_zalloc_hyp_page(void *arg);
extern void *hyp_phys_to_virt(phys_addr_t phys);
extern phys_addr_t hyp_virt_to_phys(void *virt);

/*@
predicate {bool exists} Cond_Zero_Page (pointer p) {
  if (p == NULL) {
    return {exists: false};
  }
  else {
    take X = each (i32 i; 0i32 <= i && i < 4096i32)
        {Owned<char>(p + (i * 1i32))};
    assert (each (i32 i; 0i32 <= i && i < 4096i32)
        {X[i] == 0u8});
    return {exists: true};
  }
}
@*/

/* FIXME: the bit about phys_virt_offset is probably a lie, and asserts that
   it is a true constant, rather than just constant after initialisation */
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

/* FIXME: this spec is a lie, and omits entirely the pool ownership */
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
@*/


/*@
predicate (void) MM_Ops(pointer p) {
  take data = Owned<struct kvm_pgtable_mm_ops>(p);
  assert (data.zalloc_page == &hyp_zalloc_hyp_page);
  assert (data.phys_to_virt == &hyp_phys_to_virt);
  assert (data.virt_to_phys == &hyp_virt_to_phys);
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
    {Owned<kvm_pte_t>(p + (i * ((i32) (sizeof <kvm_pte_t>))))};
  return ptes;
}

predicate (void) Page_Table_Entries (pointer p, u32 level) {
  assert (valid_pgtable_level(level));
  take ptes = PTE_Array (p);
  take children = each (i32 i; 0i32 <= i && i < 512i32)
    {Indirect_Page_Table_Entries (p + (i * ((i32) (sizeof <kvm_pte_t>))), level + 1u32, ptes[i])};
  return;
}

function (boolean) is_valid_pte_entry (u64 encoded)
function (boolean) is_table_entry (u64 encoded)
function (u64) decode_table_entry_phys (u64 encoded)

function (pointer) decode_table_entry_pointer (u64 encoded)
{
  hyp_phys_to_virt (decode_table_entry_phys (encoded))
}

lemma table_entry_is_valid (u64 encoded)
  requires
    good<kvm_pte_t>(encoded)
  ensures
    is_table_entry(encoded) ? is_valid_pte_entry(encoded) : true

predicate {bool x} Indirect_Page_Table_Entries (pointer p, u32 level, u64 encoded) {
  assert (valid_pgtable_level(level) || not(is_table_entry (encoded)));
  take x = Indirect_Page_Table_Entries2(p, level, encoded);
  return x;
}

predicate {bool x} Indirect_Page_Table_Entries2 (pointer p, u32 level, u64 encoded) {
  if (is_table_entry (encoded)) {
    assert (valid_pgtable_level(level));
    assert (good<kvm_pte_t *> (decode_table_entry_pointer (encoded)));
    take x = Page_Table_Entries (decode_table_entry_pointer (encoded), level);
    return {x: true};
  }
  else {
    return {x: false};
  }
}
@*/

/*@
function (boolean) aligned_u64 (u64 x, u64 n)
  { shift_left (shift_right (x, n), n) == x }
@*/

/* Page tables are 4096 bytes in size (2 ^ 12), which is 512 entries on a
 * 64-bit platform, resolving 9 bits, however, the top-level variant (called a
 * page directory) resolves some excess bits and is a little bigger, thus the
 * extra_bits output argument. A max-size 4-level page table resolves 48 bits,
 * 9 less per level, leaving 12 bits (the page size) unresolved.
 */
/*@
predicate {pointer mm_ops, u32 extra_bits} Pg_Table
        (pointer p, boolean with_entries) {
  take Data = Owned<struct kvm_pgtable>(p);
  take Ops = MM_Ops(Data.mm_ops);

  assert ((0u32 < Data.ia_bits) && (Data.ia_bits <= 52u32));
  let pt_bits_resolved = 48u32 - (9u32 * Data.start_level);
  let extra_bits = Data.ia_bits - pt_bits_resolved;
  assert (extra_bits == 0u32 || extra_bits == 2u32 || extra_bits == 4u32);
  assert (aligned_u64 ((u64) Data.pgd, 12u64 + ((u64) extra_bits)));

  take Entries = Pg_Table_Toplevel (Data.pgd, with_entries);

  return {extra_bits: extra_bits, mm_ops: Data.mm_ops};
}

predicate (void) Pg_Table_Toplevel (pointer p, boolean exists) {
  if (exists) {
    take Toplevel_Table = each (i32 i; 0i32 <= i && i < 16i32)
      {Page_Table_Entries(p + (i * 4096i32), 0u32)};
    return;
  }
  else {
    return;
  }
}

predicate {u32 flags} KVM_PgTable_Walker (pointer p) {
  take D = Owned<struct kvm_pgtable_walker>(p);
  take X = Hyp_Walker_Cases (D.cb, D.arg, D.flags);
  return {flags: D.flags};
}

predicate {pointer pgt, u64 addr, u64 end, u32 flags}
    KVM_PgTable_Walk_Data (pointer p) {
  take D = Owned<struct kvm_pgtable_walk_data>(p);
  take Walker = KVM_PgTable_Walker(D.walker);
  return {pgt: D.pgt, addr: D.addr, end: D.end, flags: Walker.flags};
}
@*/

struct kvm_pgtable_walk_data {
	struct kvm_pgtable		*pgt;
	struct kvm_pgtable_walker	*walker;

	u64				addr;
	u64				end;
};

/*@ function (u64) kvm_granule_shift (u32 level) @*/

static u64 kvm_granule_shift(u32 level)
/*@ cn_function kvm_granule_shift @*/
/*@ requires valid_pgtable_level(level) || level == (0u32 - 1u32) @*/
/*@ ensures 0u64 <= return && return < 64u64 @*/
/*@ ensures return == kvm_granule_shift(level) @*/
{
	/* Assumes KVM_PGTABLE_MAX_LEVELS is 4 */
	return ARM64_HW_PGTABLE_LEVEL_SHIFT(level);
}

/*@ cn_function (u64) kvm_granule_size(u32 level) @*/

static u64 kvm_granule_size(u32 level)
/*@ cn_function kvm_granule_size @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ ensures return == kvm_granule_size(level) @*/
{
	return BIT(kvm_granule_shift(level));
}

#define KVM_PHYS_INVALID (-1ULL)

static bool kvm_phys_is_valid(u64 phys)
{
	return phys < BIT(id_aa64mmfr0_parange_to_phys_shift(ID_AA64MMFR0_PARANGE_MAX));
}

static bool kvm_level_supports_block_mapping(u32 level)
{
	/*
	 * Reject invalid block mappings and don't bother with 4TB mappings for
	 * 52-bit PAs.
	 */
	return !(level == 0 || (PAGE_SIZE != SZ_4K && level == 1));
}

static bool kvm_block_mapping_supported(u64 addr, u64 end, u64 phys, u32 level)
/*@ requires valid_pgtable_level(level) @*/
{
	u64 granule = kvm_granule_size(level);

	if (!kvm_level_supports_block_mapping(level))
		return false;

	if (granule > (end - addr))
		return false;

	if (kvm_phys_is_valid(phys) && !IS_ALIGNED(phys, granule))
		return false;

	return IS_ALIGNED(addr, granule);
}


static u32 kvm_pgtable_idx(struct kvm_pgtable_walk_data *data, u32 level)
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures 0u32 <= return && return < power(2u32, 12u32 - 3u32) @*/
/*@ ensures Data2 == Data @*/
{
	u64 shift = kvm_granule_shift(level);
	u64 mask = BIT(PAGE_SHIFT - 3) - 1;

	/* CN addition */
	u32 shifted = data->addr >> shift;

	return shifted & mask;
}

static u32 __kvm_pgd_page_idx(struct kvm_pgtable *pgt, u64 addr)
/* bitwise arithmetic, also revisit questions about pgd layout */
/*@ requires take PgTableStruct = Owned<struct kvm_pgtable>(pgt) @*/
/*@ requires ((0u32 < PgTableStruct.ia_bits) && (PgTableStruct.ia_bits < 64u32)) @*/
/*@ requires valid_pgtable_level(PgTableStruct.start_level); PgTableStruct.start_level > 0u32 @*/
/*@ ensures take PgTableStruct2 = Owned<struct kvm_pgtable>(pgt) @*/
/*@ ensures PgTableStruct2 == PgTableStruct @*/
{
	u64 shift = kvm_granule_shift(pgt->start_level - 1); /* May underflow */
	u64 mask = BIT(pgt->ia_bits) - 1;

	return (addr & mask) >> shift;
}

static u32 kvm_pgd_page_idx(struct kvm_pgtable_walk_data *data)
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires take PgTableStruct = Owned<struct kvm_pgtable>(Data.pgt) @*/
/*@ requires ((0u32 < PgTableStruct.ia_bits) && (PgTableStruct.ia_bits < 64u32)) @*/
/*@ requires valid_pgtable_level(PgTableStruct.start_level); PgTableStruct.start_level > 0u32 @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures Data2 == Data @*/
/*@ ensures take PgTableStruct2 = Owned<struct kvm_pgtable>(Data.pgt) @*/
/*@ ensures PgTableStruct2 == PgTableStruct @*/
{
	return __kvm_pgd_page_idx(data->pgt, data->addr);
}

static u32 kvm_pgd_pages(u32 ia_bits, u32 start_level)
{
	struct kvm_pgtable pgt = {
		.ia_bits	= ia_bits,
		.start_level	= start_level,
	};

	return __kvm_pgd_page_idx(&pgt, -1ULL) + 1;
}

/*@
function (u8) kvm_pte_valid (kvm_pte_t pte)

lemma kvm_pte_valid_is_valid (kvm_pte_t pte)
  requires true
  ensures
    is_valid_pte_entry(pte) == (kvm_pte_valid(pte) == 1u8)
@*/

static bool kvm_pte_valid(kvm_pte_t pte)
/*@ cn_function kvm_pte_valid @*/
/*@ ensures return == (is_valid_pte_entry(pte) ? 1u8 : 0u8) @*/
{
	/*@ apply kvm_pte_valid_is_valid(pte); @*/
	return pte & KVM_PTE_VALID;
}

/*@
function (u8) kvm_pte_table (kvm_pte_t pte, u32 level)

lemma kvm_pte_table_is_table (kvm_pte_t pte, u32 level)
  requires
    valid_pgtable_level(level + 1u32)
  ensures
    kvm_pte_table(pte, level) == (is_table_entry(pte) ? 1u8 : 0u8)
@*/

static bool kvm_pte_table(kvm_pte_t pte, u32 level)
/*@ cn_function kvm_pte_table @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ ensures return == ((valid_pgtable_level(level + 1u32) && is_table_entry(pte)) ? 1u8 : 0u8) @*/
{
	if (level == KVM_PGTABLE_MAX_LEVELS - 1)
		return false;

	/*@ apply table_entry_is_valid(pte); @*/
	/*@ apply kvm_pte_valid_is_valid(pte); @*/
	/*@ apply kvm_pte_table_is_table(pte, level); @*/
	if (!kvm_pte_valid(pte)) {
		return false;
	}

	return FIELD_GET(KVM_PTE_TYPE, pte) == KVM_PTE_TYPE_TABLE;
}

/*@ function (u64) kvm_pte_to_phys (kvm_pte_t pte)

lemma kvm_pte_to_phys_is_decode (kvm_pte_t pte)
  requires
    true
  ensures
    kvm_pte_to_phys(pte) == decode_table_entry_phys(pte)
@*/

static u64 kvm_pte_to_phys(kvm_pte_t pte)
/*@ cn_function kvm_pte_to_phys @*/
/*@ ensures return == decode_table_entry_phys (pte) @*/
{
	u64 pa = pte & KVM_PTE_ADDR_MASK;

	if (PAGE_SHIFT == 16)
		pa |= FIELD_GET(KVM_PTE_ADDR_51_48, pte) << 48;

	/*@ apply kvm_pte_to_phys_is_decode(pte); @*/
	return pa;
}

/*@ function (kvm_pte_t) kvm_phys_to_pte(u64 pa) @*/

static kvm_pte_t kvm_phys_to_pte(u64 pa)
/*@ cn_function kvm_phys_to_pte @*/
/*@ ensures return == kvm_phys_to_pte(pa) @*/
{
	kvm_pte_t pte = pa & KVM_PTE_ADDR_MASK;

	if (PAGE_SHIFT == 16)
		pte |= FIELD_PREP(KVM_PTE_ADDR_51_48, pa >> 48);

	return pte;
}

static kvm_pte_t *kvm_pte_follow(kvm_pte_t pte, struct kvm_pgtable_mm_ops *mm_ops)
/*@ requires is_table_entry (pte) @*/
/*@ requires good<kvm_pte_t *>(decode_table_entry_pointer (pte)) @*/
/*@ requires take Ops = MM_Ops(mm_ops) @*/
/*@ ensures take Ops2 = MM_Ops(mm_ops) @*/
/*@ ensures Ops2 == Ops @*/
/*@ ensures return == decode_table_entry_pointer (pte) @*/
{
	return mm_ops->phys_to_virt(kvm_pte_to_phys(pte));
}

static void kvm_clear_pte(kvm_pte_t *ptep)
{
	WRITE_ONCE(*ptep, 0);
}

static void kvm_set_table_pte(kvm_pte_t *ptep, kvm_pte_t *childp,
			      struct kvm_pgtable_mm_ops *mm_ops)
/*@ requires take Ops = MM_Ops(mm_ops) @*/
/*@ requires take pte_old = Owned<kvm_pte_t>(ptep) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires valid_hyp_virt_page(childp) @*/
/*@ ensures take pte2 = Owned<kvm_pte_t>(ptep) @*/
/*@ ensures take Ops2 = MM_Ops(mm_ops) @*/
/*@ ensures Ops2 == Ops @*/
/*@ ensures is_table_entry(pte2) @*/
/*@ ensures decode_table_entry_pointer(pte2) == childp @*/
{
	kvm_pte_t old = *ptep, pte = kvm_phys_to_pte(mm_ops->virt_to_phys(childp));

	pte |= FIELD_PREP(KVM_PTE_TYPE, KVM_PTE_TYPE_TABLE);
	pte |= KVM_PTE_VALID;

	WARN_ON(kvm_pte_valid(old));
	/*@ apply kvm_pte_to_phys_is_decode(pte); @*/
	/*@ assert (decode_table_entry_pointer(pte) == childp); @*/
	/*@ apply kvm_pte_table_is_table(pte, 0u32); @*/
	/*@ assert (is_table_entry(pte)); @*/
	smp_store_release(ptep, pte);
}

/*@
function (kvm_pte_t) kvm_init_valid_leaf_pte (u64 pa, kvm_pte_t attr, u32 level)

lemma kvm_init_valid_leaf_pte_not_table (u64 pa, kvm_pte_t attr, u32 level)
  requires
    valid_pgtable_level(level)
  ensures
    not (is_table_entry (kvm_init_valid_leaf_pte(pa, attr, level)))
@*/


static kvm_pte_t kvm_init_valid_leaf_pte(u64 pa, kvm_pte_t attr, u32 level)
/*@ cn_function kvm_init_valid_leaf_pte @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ ensures not (is_table_entry (return)) @*/
{
	kvm_pte_t pte = kvm_phys_to_pte(pa);
	u64 type = (level == KVM_PGTABLE_MAX_LEVELS - 1) ? KVM_PTE_TYPE_PAGE :
							   KVM_PTE_TYPE_BLOCK;

	/* FIXME: we need a better way to do this, but otherwise the if-then-else above hurts */
	if (level == KVM_PGTABLE_MAX_LEVELS - 1)
		;

	pte |= attr & (KVM_PTE_LEAF_ATTR_LO | KVM_PTE_LEAF_ATTR_HI);
	pte |= FIELD_PREP(KVM_PTE_TYPE, type);
	pte |= KVM_PTE_VALID;

	/*@ assert (pte == kvm_init_valid_leaf_pte(pa, attr, level)); @*/
	/*@ apply kvm_init_valid_leaf_pte_not_table(pa, attr, level); @*/
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

static int kvm_pgtable_visitor_cb(struct kvm_pgtable_walk_data *data, u64 addr,
				  u32 level, kvm_pte_t *ptep,
				  enum kvm_pgtable_walk_flags flag)
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires take pte = Owned(ptep) @*/
/*@ requires take IPT = Indirect_Page_Table_Entries (ptep, level + 1u32, pte) @*/
/*@ requires take PgTableStruct = Owned<struct kvm_pgtable>(Data.pgt) @*/
/*@ requires flag_in_flags ((i32)flag, (i32) (Data.flags)) @*/
/*@ requires (flag == (u32)KVM_PGTABLE_WALK_LEAF) ==
    (not(is_table_entry(pte))) @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures Data2.end == Data.end @*/
/*@ ensures Data2.pgt == Data.pgt @*/
/*@ ensures take pte2 = Owned(ptep) @*/
/*@ ensures take IPT2 = Indirect_Page_Table_Entries (ptep, level + 1u32, pte2) @*/
/*@ ensures take PgTableStruct2 = Owned<struct kvm_pgtable>(Data.pgt) @*/
/*@ ensures PgTableStruct2.mm_ops == PgTableStruct.mm_ops @*/
/*@ ensures flag == ((u32)KVM_PGTABLE_WALK_TABLE_PRE)
    ? pte2 == pte : true @*/
{
	struct kvm_pgtable_walker *walker = data->walker;
	return walker->cb(addr, data->end, level, ptep, flag, walker->arg);
}

static int __kvm_pgtable_walk(struct kvm_pgtable_walk_data *data,
			      kvm_pte_t *pgtable, u32 level);

static inline int __kvm_pgtable_visit(struct kvm_pgtable_walk_data *data,
				      kvm_pte_t *ptep, u32 level)
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires take pte = Owned(ptep) @*/
/*@ requires take IPT = Indirect_Page_Table_Entries (ptep, level + 1u32, pte) @*/
/*@ requires take PgTableStruct = Owned<struct kvm_pgtable>(Data.pgt) @*/
/*@ requires take Ops = MM_Ops(PgTableStruct.mm_ops) @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures Data2.end == Data.end @*/
/*@ ensures Data2.pgt == Data.pgt @*/
/*@ ensures take pte2 = Owned(ptep) @*/
/*@ ensures take IPT2 = Indirect_Page_Table_Entries (ptep, level + 1u32, pte2) @*/
/*@ ensures take PgTableStruct2 = Owned<struct kvm_pgtable>(Data.pgt) @*/
/*@ ensures PgTableStruct2.mm_ops == PgTableStruct.mm_ops @*/
/*@ ensures take Ops2 = MM_Ops(PgTableStruct.mm_ops) @*/
/*@ ensures Ops2 == Ops @*/
{
	int ret = 0;
	u64 addr = data->addr;
	kvm_pte_t *childp, pte = *ptep;
	bool table = kvm_pte_table(pte, level);
	enum kvm_pgtable_walk_flags flags = data->walker->flags;

	if (table && (flags & KVM_PGTABLE_WALK_TABLE_PRE)) {
		ret = kvm_pgtable_visitor_cb(data, addr, level, ptep,
					     KVM_PGTABLE_WALK_TABLE_PRE);
	}

	if (!table && (flags & KVM_PGTABLE_WALK_LEAF)) {
		ret = kvm_pgtable_visitor_cb(data, addr, level, ptep,
					     KVM_PGTABLE_WALK_LEAF);
		pte = *ptep;
		table = kvm_pte_table(pte, level);
	}

	if (ret)
		goto out;

	if (!table) {
		data->addr = ALIGN_DOWN(data->addr, kvm_granule_size(level));
		data->addr += kvm_granule_size(level);
		goto out;
	}

	childp = kvm_pte_follow(pte, data->pgt->mm_ops);
	ret = __kvm_pgtable_walk(data, childp, level + 1);
	if (ret)
		goto out;

	if (flags & KVM_PGTABLE_WALK_TABLE_POST) {
		ret = kvm_pgtable_visitor_cb(data, addr, level, ptep,
					     KVM_PGTABLE_WALK_TABLE_POST);
	}

out:
	return ret;
}

static int __kvm_pgtable_walk(struct kvm_pgtable_walk_data *data,
			      kvm_pte_t *pgtable, u32 level)
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires take PTEs = Page_Table_Entries (pgtable, level) @*/
/*@ requires let orig_data = data @*/
/*@ requires let orig_pgtable = pgtable @*/
/*@ requires take PgTableStruct = Owned<struct kvm_pgtable>(Data.pgt) @*/
/*@ requires take Ops = MM_Ops(PgTableStruct.mm_ops) @*/
/*@ requires valid_pgtable_level(level) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires let orig_level = level @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
/*@ ensures Data2.end == Data.end @*/
/*@ ensures Data2.pgt == Data.pgt @*/
/*@ ensures take PTEs2 = Page_Table_Entries (pgtable, level) @*/
/*@ ensures take PgTableStruct2 = Owned<struct kvm_pgtable>(Data.pgt) @*/
/*@ ensures PgTableStruct2.mm_ops == PgTableStruct.mm_ops @*/
/*@ ensures take Ops2 = MM_Ops(PgTableStruct.mm_ops) @*/
/*@ ensures Ops2 == Ops @*/
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
	/*@ inv 0u32 <= idx && idx < power(2u32, 12u32 - 2u32) @*/
	/*@ inv data == orig_data @*/
	/*@ inv pgtable == orig_pgtable @*/
	/*@ inv level == orig_level @*/
	/*@ inv Data3.end == Data.end @*/
	/*@ inv Data3.pgt == Data.pgt @*/
	/*@ inv take PgTableStruct3 = Owned<struct kvm_pgtable>(Data.pgt) @*/
	/*@ inv PgTableStruct3.mm_ops == PgTableStruct.mm_ops @*/
	/*@ inv take Ops3 = MM_Ops(PgTableStruct.mm_ops) @*/
	/*@ inv Ops3 == Ops @*/
	{
		kvm_pte_t *ptep = &pgtable[idx];

		if (data->addr >= data->end)
			break;

		/*@ extract Owned<kvm_pte_t>, (i32)idx; @*/
		/*@ instantiate good<kvm_pte_t>, (i32)idx; @*/
		/*@ extract Indirect_Page_Table_Entries, (i32)idx; @*/

		ret = __kvm_pgtable_visit(data, ptep, level);
		if (ret)
			break;
	}

	return ret;
}

static int _kvm_pgtable_walk(struct kvm_pgtable_walk_data *data)
/* another bogus trusted, the problem here is the relationship between
   idx and data->addr < data->end. We need the latter to imply idx < lim,
   where lim is the geometry of the toplevel pgtable (potentially wider
   than the other ones, thus this function). */
/*@ trusted @*/
/*@ requires take Data = KVM_PgTable_Walk_Data (data) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires let orig_data = data @*/
/*@ ensures take Data2 = KVM_PgTable_Walk_Data (data) @*/
{
	u32 idx;
	int ret = 0;
	struct kvm_pgtable *pgt = data->pgt;
	u64 limit = BIT(pgt->ia_bits);

	if (data->addr > limit || data->end > limit)
		return -ERANGE;

	if (!pgt->pgd)
		return -EINVAL;

	for (idx = kvm_pgd_page_idx(data); data->addr < data->end; ++idx)
	/*@ inv take D = Owned<struct kvm_pgtable_walk_data>(data) @*/
	/*@ inv take PT = Pg_Table(pgt, true) @*/
	/*@ inv pgt == D.pgt @*/
	/*@ inv pgt == Data.pgt @*/
	/*@ inv data == orig_data @*/
	/*@ inv take Walker = KVM_PgTable_Walker(D.walker) @*/
	/*@ inv 0u32 <= idx && idx < 16u32 @*/
	{
		kvm_pte_t *ptep = &pgt->pgd[idx * PTRS_PER_PTE];

		ret = __kvm_pgtable_walk(data, ptep, pgt->start_level);
		if (ret)
			break;
	}

	return ret;
}

int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size,
		     struct kvm_pgtable_walker *walker)
/* bogus trusted attribute here to try out other functions */
/*@ trusted @*/
{
	/* CN modification: align addr first, avoid self-referential init */
	addr = ALIGN_DOWN(addr, PAGE_SIZE);
	struct kvm_pgtable_walk_data walk_data = {
		.pgt	= pgt,
		.addr	= addr,
		.end	= PAGE_ALIGN(addr + size),
		.walker	= walker,
	};

	return _kvm_pgtable_walk(&walk_data);
}

struct hyp_map_data {
	u64				phys;
	kvm_pte_t			attr;
	struct kvm_pgtable_mm_ops	*mm_ops;
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
	*ptep = attr;

	return 0;
}

/*@
predicate {pointer mm_ops} Hyp_Map_Data (pointer p) {
  assert (mod((u64)p, 32u64) == 0u64);
  take O = Owned<struct hyp_map_data>(p);
  take Ops = MM_Ops(O.mm_ops);
  return {mm_ops: O.mm_ops};
}
@*/

static bool hyp_map_walker_try_leaf(u64 addr, u64 end, u32 level,
				    kvm_pte_t *ptep, struct hyp_map_data *data)
/*@ requires valid_pgtable_level(level) @*/
/*@ requires take D = Hyp_Map_Data(data) @*/
/*@ requires take pte = Owned<kvm_pte_t>(ptep) @*/
/*@ requires not(is_table_entry(pte)) @*/
/*@ ensures take D2 = Hyp_Map_Data(data) @*/
/*@ ensures take pte2 = Owned<kvm_pte_t>(ptep) @*/
/*@ ensures not(is_table_entry(pte2)) @*/
/*@ ensures D2 == D @*/
{
	kvm_pte_t new, old = *ptep;
	u64 granule = kvm_granule_size(level), phys = data->phys;

	if (!kvm_block_mapping_supported(addr, end, phys, level))
		return false;

	/* Tolerate KVM recreating the exact same mapping */
	new = kvm_init_valid_leaf_pte(phys, data->attr, level);
	if (old != new && !WARN_ON(kvm_pte_valid(old)))
		smp_store_release(ptep, new);

	data->phys += granule;
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


static int hyp_map_walker(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
			  enum kvm_pgtable_walk_flags flag, void * const arg)
/*@ requires valid_pgtable_level(level) @*/
/*@ requires valid_phys_virt_offset () @*/
/*@ requires take D = Hyp_Map_Data(arg) @*/
/*@ requires take pte = Owned<kvm_pte_t>(ptep) @*/
/*@ requires not(is_table_entry(pte)) @*/
/*@ ensures take D2 = Hyp_Map_Data(arg) @*/
/*@ ensures take pte2 = Owned<kvm_pte_t>(ptep) @*/
/*@ ensures take IPT2 = Indirect_Page_Table_Entries(ptep, level + 1u32, pte2) @*/
{
	kvm_pte_t *childp;
	struct hyp_map_data *data = arg;
	struct kvm_pgtable_mm_ops *mm_ops = data->mm_ops;

	if (hyp_map_walker_try_leaf(addr, end, level, ptep, arg))
		return 0;

	if (WARN_ON(level == KVM_PGTABLE_MAX_LEVELS - 1))
		return -EINVAL;

	childp = (kvm_pte_t *)mm_ops->zalloc_page(NULL);
	if (!childp)
		return -ENOMEM;

	/* this is where we need to turn a char[] into a kvm_pte_t[] (i.e. a u64[]) */
	coerce_page_to_ptes(childp);
	coerce_null_ptes_to_IPT(childp, level + 1);

	kvm_set_table_pte(ptep, childp, mm_ops);
	return 0;
}

/*@
predicate (void) Hyp_Map_Walker_Case (pointer f, pointer x, u32 flags) {
  assert (f == &hyp_map_walker);
  assert (flags == ((u32) KVM_PGTABLE_WALK_LEAF));
  take D = Hyp_Map_Data(x);
  return;
}

predicate (void) Hyp_Walker_Cases (pointer f, pointer x, u32 flags) {
  take X = Hyp_Map_Walker_Case (f, x, flags);
  return;
}

@*/

int kvm_pgtable_hyp_map(struct kvm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			enum kvm_pgtable_prot prot)
/*@ requires take PT = Pg_Table(pgt, true) @*/
/*@ ensures take PT2 = Pg_Table(pgt, true) @*/
{
	int ret;
	struct hyp_map_data map_data = {
		.phys	= ALIGN_DOWN(phys, PAGE_SIZE),
		.mm_ops	= pgt->mm_ops,
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

int kvm_pgtable_hyp_init(struct kvm_pgtable *pgt, u32 va_bits,
			 struct kvm_pgtable_mm_ops *mm_ops)
{
	u64 levels = ARM64_HW_PGTABLE_LEVELS(va_bits);

	pgt->pgd = (kvm_pte_t *)mm_ops->zalloc_page(NULL);
	if (!pgt->pgd)
		return -ENOMEM;

	pgt->ia_bits		= va_bits;
	pgt->start_level	= KVM_PGTABLE_MAX_LEVELS - levels;
	pgt->mm_ops		= mm_ops;
	pgt->mmu		= NULL;
	return 0;
}

static int hyp_free_walker(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
			   enum kvm_pgtable_walk_flags flag, void * const arg)
{
	struct kvm_pgtable_mm_ops *mm_ops = arg;

	mm_ops->put_page((void *)kvm_pte_follow(*ptep, mm_ops));
	return 0;
}

void kvm_pgtable_hyp_destroy(struct kvm_pgtable *pgt)
{
	struct kvm_pgtable_walker walker = {
		.cb	= hyp_free_walker,
		.flags	= KVM_PGTABLE_WALK_TABLE_POST,
		.arg	= pgt->mm_ops,
	};

	WARN_ON(kvm_pgtable_walk(pgt, 0, BIT(pgt->ia_bits), &walker));
	pgt->mm_ops->put_page(pgt->pgd);
	pgt->pgd = NULL;
}

struct stage2_map_data {
	u64				phys;
	kvm_pte_t			attr;
	u8				owner_id;

	kvm_pte_t			*anchor;
	kvm_pte_t			*childp;

	struct kvm_s2_mmu		*mmu;
	void				*memcache;

	struct kvm_pgtable_mm_ops	*mm_ops;
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

	/*
	 * Enable the Hardware Access Flag management, unconditionally
	 * on all CPUs. The features is RES0 on CPUs without the support
	 * and must be ignored by the CPUs.
	 */
	vtcr |= VTCR_EL2_HA;

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
	*ptep = attr;

	return 0;
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

static void stage2_put_pte(kvm_pte_t *ptep, struct kvm_s2_mmu *mmu, u64 addr,
			   u32 level, struct kvm_pgtable_mm_ops *mm_ops)
{
	/*
	 * Clear the existing PTE, and perform break-before-make with
	 * TLB maintenance if it was valid.
	 */
	if (kvm_pte_valid(*ptep)) {
		kvm_clear_pte(ptep);
		kvm_call_hyp(__kvm_tlb_flush_vmid_ipa, mmu, addr, level);
	}

	mm_ops->put_page(ptep);
}

static int stage2_map_walker_try_leaf(u64 addr, u64 end, u32 level,
				      kvm_pte_t *ptep,
				      struct stage2_map_data *data)
{
	kvm_pte_t new, old = *ptep;
	u64 granule = kvm_granule_size(level), phys = data->phys;
	struct kvm_pgtable_mm_ops *mm_ops = data->mm_ops;

	if (!kvm_block_mapping_supported(addr, end, phys, level))
		return -E2BIG;

	if (kvm_phys_is_valid(phys))
		new = kvm_init_valid_leaf_pte(phys, data->attr, level);
	else
		new = kvm_init_invalid_leaf_owner(data->owner_id);

	if (stage2_pte_is_counted(old)) {
		/*
		 * Skip updating the PTE if we are trying to recreate the exact
		 * same mapping or only change the access permissions. Instead,
		 * the vCPU will exit one more time from guest if still needed
		 * and then go through the path of relaxing permissions.
		 */
		if (!stage2_pte_needs_update(old, new))
			return -EAGAIN;

		stage2_put_pte(ptep, data->mmu, addr, level, mm_ops);
	}

	smp_store_release(ptep, new);
	if (stage2_pte_is_counted(new))
		mm_ops->get_page(ptep);
	if (kvm_phys_is_valid(phys))
		data->phys += granule;
	return 0;
}

static int stage2_map_walk_table_pre(u64 addr, u64 end, u32 level,
				     kvm_pte_t *ptep,
				     struct stage2_map_data *data)
{
	if (data->anchor)
		return 0;

	if (!kvm_block_mapping_supported(addr, end, data->phys, level))
		return 0;

	data->childp = kvm_pte_follow(*ptep, data->mm_ops);
	kvm_clear_pte(ptep);

	/*
	 * Invalidate the whole stage-2, as we may have numerous leaf
	 * entries below us which would otherwise need invalidating
	 * individually.
	 */
	kvm_call_hyp(__kvm_tlb_flush_vmid, data->mmu);
	data->anchor = ptep;
	return 0;
}

static int stage2_map_walk_leaf(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
				struct stage2_map_data *data)
{
	struct kvm_pgtable_mm_ops *mm_ops = data->mm_ops;
	kvm_pte_t *childp, pte = *ptep;
	int ret;

	if (data->anchor) {
		if (stage2_pte_is_counted(pte))
			mm_ops->put_page(ptep);

		return 0;
	}

	ret = stage2_map_walker_try_leaf(addr, end, level, ptep, data);
	if (ret != -E2BIG)
		return ret;

	if (WARN_ON(level == KVM_PGTABLE_MAX_LEVELS - 1))
		return -EINVAL;

	if (!data->memcache)
		return -ENOMEM;

	childp = mm_ops->zalloc_page(data->memcache);
	if (!childp)
		return -ENOMEM;

	/*
	 * If we've run into an existing block mapping then replace it with
	 * a table. Accesses beyond 'end' that fall within the new table
	 * will be mapped lazily.
	 */
	if (stage2_pte_is_counted(pte))
		stage2_put_pte(ptep, data->mmu, addr, level, mm_ops);

	kvm_set_table_pte(ptep, childp, mm_ops);
	mm_ops->get_page(ptep);

	return 0;
}

static int stage2_map_walk_table_post(u64 addr, u64 end, u32 level,
				      kvm_pte_t *ptep,
				      struct stage2_map_data *data)
{
	struct kvm_pgtable_mm_ops *mm_ops = data->mm_ops;
	kvm_pte_t *childp;
	int ret = 0;

	if (!data->anchor)
		return 0;

	if (data->anchor == ptep) {
		childp = data->childp;
		data->anchor = NULL;
		data->childp = NULL;
		ret = stage2_map_walk_leaf(addr, end, level, ptep, data);
	} else {
		childp = kvm_pte_follow(*ptep, mm_ops);
	}

	mm_ops->put_page(childp);
	mm_ops->put_page(ptep);

	return ret;
}

/*
 * This is a little fiddly, as we use all three of the walk flags. The idea
 * is that the TABLE_PRE callback runs for table entries on the way down,
 * looking for table entries which we could conceivably replace with a
 * block entry for this mapping. If it finds one, then it sets the 'anchor'
 * field in 'struct stage2_map_data' to point at the table entry, before
 * clearing the entry to zero and descending into the now detached table.
 *
 * The behaviour of the LEAF callback then depends on whether or not the
 * anchor has been set. If not, then we're not using a block mapping higher
 * up the table and we perform the mapping at the existing leaves instead.
 * If, on the other hand, the anchor _is_ set, then we drop references to
 * all valid leaves so that the pages beneath the anchor can be freed.
 *
 * Finally, the TABLE_POST callback does nothing if the anchor has not
 * been set, but otherwise frees the page-table pages while walking back up
 * the page-table, installing the block entry when it revisits the anchor
 * pointer and clearing the anchor to NULL.
 */
static int stage2_map_walker(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
			     enum kvm_pgtable_walk_flags flag, void * const arg)
{
	struct stage2_map_data *data = arg;

	switch (flag) {
	case KVM_PGTABLE_WALK_TABLE_PRE:
		return stage2_map_walk_table_pre(addr, end, level, ptep, data);
	case KVM_PGTABLE_WALK_LEAF:
		return stage2_map_walk_leaf(addr, end, level, ptep, data);
	case KVM_PGTABLE_WALK_TABLE_POST:
		return stage2_map_walk_table_post(addr, end, level, ptep, data);
	}

	return -EINVAL;
}

int kvm_pgtable_stage2_map(struct kvm_pgtable *pgt, u64 addr, u64 size,
			   u64 phys, enum kvm_pgtable_prot prot,
			   void *mc)
{
	int ret;
	struct stage2_map_data map_data = {
		.phys		= ALIGN_DOWN(phys, PAGE_SIZE),
		.mmu		= pgt->mmu,
		.memcache	= mc,
		.mm_ops		= pgt->mm_ops,
	};
	struct kvm_pgtable_walker walker = {
		.cb		= stage2_map_walker,
		.flags		= KVM_PGTABLE_WALK_TABLE_PRE |
				  KVM_PGTABLE_WALK_LEAF |
				  KVM_PGTABLE_WALK_TABLE_POST,
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
		.mm_ops		= pgt->mm_ops,
		.owner_id	= owner_id,
	};
	struct kvm_pgtable_walker walker = {
		.cb		= stage2_map_walker,
		.flags		= KVM_PGTABLE_WALK_TABLE_PRE |
				  KVM_PGTABLE_WALK_LEAF |
				  KVM_PGTABLE_WALK_TABLE_POST,
		.arg		= &map_data,
	};

	if (owner_id > KVM_MAX_OWNER_ID)
		return -EINVAL;

	ret = kvm_pgtable_walk(pgt, addr, size, &walker);
	return ret;
}

static bool stage2_pte_cacheable(struct kvm_pgtable *pgt, kvm_pte_t pte)
{
	u64 memattr = pte & KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR;
	return memattr == KVM_S2_MEMATTR(pgt, NORMAL);
}

static int stage2_unmap_walker(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
			       enum kvm_pgtable_walk_flags flag,
			       void * const arg)
{
	struct kvm_pgtable *pgt = arg;
	struct kvm_s2_mmu *mmu = pgt->mmu;
	struct kvm_pgtable_mm_ops *mm_ops = pgt->mm_ops;
	kvm_pte_t pte = *ptep, *childp = NULL;
	bool need_flush = false;

	if (!kvm_pte_valid(pte)) {
		if (stage2_pte_is_counted(pte)) {
			kvm_clear_pte(ptep);
			mm_ops->put_page(ptep);
		}
		return 0;
	}

	if (kvm_pte_table(pte, level)) {
		childp = kvm_pte_follow(pte, mm_ops);

		if (mm_ops->page_count(childp) != 1)
			return 0;
	} else if (stage2_pte_cacheable(pgt, pte)) {
		need_flush = !stage2_has_fwb(pgt);
	}

	/*
	 * This is similar to the map() path in that we unmap the entire
	 * block entry and rely on the remaining portions being faulted
	 * back lazily.
	 */
	stage2_put_pte(ptep, mmu, addr, level, mm_ops);

	if (need_flush) {
		__flush_dcache_area(kvm_pte_follow(pte, mm_ops),
				    kvm_granule_size(level));
	}

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
	kvm_pte_t	attr_set;
	kvm_pte_t	attr_clr;
	kvm_pte_t	pte;
	u32		level;
};

static int stage2_attr_walker(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
			      enum kvm_pgtable_walk_flags flag,
			      void * const arg)
{
	kvm_pte_t pte = *ptep;
	struct stage2_attr_data *data = arg;

	if (!kvm_pte_valid(pte))
		return 0;

	data->level = level;
	data->pte = pte;
	pte &= ~data->attr_clr;
	pte |= data->attr_set;

	/*
	 * We may race with the CPU trying to set the access flag here,
	 * but worst-case the access flag update gets lost and will be
	 * set on the next access instead.
	 */
	if (data->pte != pte)
		WRITE_ONCE(*ptep, pte);

	return 0;
}

static int stage2_update_leaf_attrs(struct kvm_pgtable *pgt, u64 addr,
				    u64 size, kvm_pte_t attr_set,
				    kvm_pte_t attr_clr, kvm_pte_t *orig_pte,
				    u32 *level)
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
		.flags		= KVM_PGTABLE_WALK_LEAF,
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
					NULL, NULL);
}

kvm_pte_t kvm_pgtable_stage2_mkyoung(struct kvm_pgtable *pgt, u64 addr)
{
	kvm_pte_t pte = 0;
	stage2_update_leaf_attrs(pgt, addr, 1, KVM_PTE_LEAF_ATTR_LO_S2_AF, 0,
				 &pte, NULL);
	dsb(ishst);
	return pte;
}

kvm_pte_t kvm_pgtable_stage2_mkold(struct kvm_pgtable *pgt, u64 addr)
{
	kvm_pte_t pte = 0;
	stage2_update_leaf_attrs(pgt, addr, 1, 0, KVM_PTE_LEAF_ATTR_LO_S2_AF,
				 &pte, NULL);
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
	stage2_update_leaf_attrs(pgt, addr, 1, 0, 0, &pte, NULL);
	return pte & KVM_PTE_LEAF_ATTR_LO_S2_AF;
}

int kvm_pgtable_stage2_relax_perms(struct kvm_pgtable *pgt, u64 addr,
				   enum kvm_pgtable_prot prot)
{
	int ret;
	u32 level;
	kvm_pte_t set = 0, clr = 0;

	if (prot & KVM_PGTABLE_PROT_R)
		set |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R;

	if (prot & KVM_PGTABLE_PROT_W)
		set |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W;

	if (prot & KVM_PGTABLE_PROT_X)
		clr |= KVM_PTE_LEAF_ATTR_HI_S2_XN;

	ret = stage2_update_leaf_attrs(pgt, addr, 1, set, clr, NULL, &level);
	if (!ret)
		kvm_call_hyp(__kvm_tlb_flush_vmid_ipa, pgt->mmu, addr, level);
	return ret;
}

static int stage2_flush_walker(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
			       enum kvm_pgtable_walk_flags flag,
			       void * const arg)
{
	struct kvm_pgtable *pgt = arg;
	struct kvm_pgtable_mm_ops *mm_ops = pgt->mm_ops;
	kvm_pte_t pte = *ptep;

	if (!kvm_pte_valid(pte) || !stage2_pte_cacheable(pgt, pte))
		return 0;

	__flush_dcache_area(kvm_pte_follow(pte, mm_ops), kvm_granule_size(level));
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

int kvm_pgtable_stage2_init_flags(struct kvm_pgtable *pgt, struct kvm_arch *arch,
				  struct kvm_pgtable_mm_ops *mm_ops,
				  enum kvm_pgtable_stage2_flags flags)
{
	size_t pgd_sz;
	u64 vtcr = arch->vtcr;
	u32 ia_bits = VTCR_EL2_IPA(vtcr);
	u32 sl0 = FIELD_GET(VTCR_EL2_SL0_MASK, vtcr);
	u32 start_level = VTCR_EL2_TGRAN_SL0_BASE - sl0;

	pgd_sz = kvm_pgd_pages(ia_bits, start_level) * PAGE_SIZE;
	pgt->pgd = mm_ops->zalloc_pages_exact(pgd_sz);
	if (!pgt->pgd)
		return -ENOMEM;

	pgt->ia_bits		= ia_bits;
	pgt->start_level	= start_level;
	pgt->mm_ops		= mm_ops;
	pgt->mmu		= &arch->mmu;
	pgt->flags		= flags;

	/* Ensure zeroed PGD pages are visible to the hardware walker */
	dsb(ishst);
	return 0;
}

static int stage2_free_walker(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
			      enum kvm_pgtable_walk_flags flag,
			      void * const arg)
{
	struct kvm_pgtable_mm_ops *mm_ops = arg;
	kvm_pte_t pte = *ptep;

	if (!stage2_pte_is_counted(pte))
		return 0;

	mm_ops->put_page(ptep);

	if (kvm_pte_table(pte, level))
		mm_ops->put_page(kvm_pte_follow(pte, mm_ops));

	return 0;
}

void kvm_pgtable_stage2_destroy(struct kvm_pgtable *pgt)
{
	size_t pgd_sz;
	struct kvm_pgtable_walker walker = {
		.cb	= stage2_free_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF |
			  KVM_PGTABLE_WALK_TABLE_POST,
		.arg	= pgt->mm_ops,
	};

	WARN_ON(kvm_pgtable_walk(pgt, 0, BIT(pgt->ia_bits), &walker));
	pgd_sz = kvm_pgd_pages(pgt->ia_bits, pgt->start_level) * PAGE_SIZE;
	pgt->mm_ops->free_pages_exact(pgt->pgd, pgd_sz);
	pgt->pgd = NULL;
}

#define KVM_PTE_LEAF_S2_COMPAT_MASK	(KVM_PTE_LEAF_ATTR_S2_PERMS | \
					 KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR | \
					 KVM_PTE_LEAF_ATTR_S2_IGNORED)

static int stage2_check_permission_walker(u64 addr, u64 end, u32 level,
					  kvm_pte_t *ptep,
					  enum kvm_pgtable_walk_flags flag,
					  void * const arg)
{
	kvm_pte_t old_attr, pte = *ptep, *new_attr = arg;

	/*
	 * Compatible mappings are either invalid and owned by the page-table
	 * owner (whose id is 0), or valid with matching permission attributes.
	 */
	if (kvm_pte_valid(pte)) {
		old_attr = pte & KVM_PTE_LEAF_S2_COMPAT_MASK;
		if (old_attr != *new_attr)
			return -EEXIST;
	} else if (pte) {
		return -EEXIST;
	}

	return 0;
}

int kvm_pgtable_stage2_find_range(struct kvm_pgtable *pgt, u64 addr,
				  enum kvm_pgtable_prot prot,
				  struct kvm_mem_range *range)
{
	kvm_pte_t attr;
	struct kvm_pgtable_walker check_perm_walker = {
		.cb		= stage2_check_permission_walker,
		.flags		= KVM_PGTABLE_WALK_LEAF,
		.arg		= &attr,
	};
	u64 granule, start, end;
	u32 level;
	int ret;

	ret = stage2_set_prot_attr(pgt, prot, &attr);
	if (ret)
		return ret;
	attr &= KVM_PTE_LEAF_S2_COMPAT_MASK;

	for (level = pgt->start_level; level < KVM_PGTABLE_MAX_LEVELS; level++) {
		granule = kvm_granule_size(level);
		start = ALIGN_DOWN(addr, granule);
		end = start + granule;

		if (!kvm_level_supports_block_mapping(level))
			continue;

		if (start < range->start || range->end < end)
			continue;

		/*
		 * Check the presence of existing mappings with incompatible
		 * permissions within the current block range, and try one level
		 * deeper if one is found.
		 */
		ret = kvm_pgtable_walk(pgt, start, granule, &check_perm_walker);
		if (ret != -EEXIST)
			break;
	}

	if (!ret) {
		range->start = start;
		range->end = end;
	}

	return ret;
}

/* more verification hacks */
static int verification_deps (void) {
  (void) hyp_zalloc_hyp_page;
  (void) hyp_phys_to_virt;
  (void) hyp_virt_to_phys;
  return 9;
}

