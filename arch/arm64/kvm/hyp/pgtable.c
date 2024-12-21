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

#include <asm/allocator_spec.cn.h>

/*@

// --- mm_ops specification ----------------------------------------------------

predicate (void) MM_Ops(pointer p)
{
  take data = Owned<struct kvm_pgtable_mm_ops>(p);
  assert (ptr_eq(data.zalloc_page,&hyp_zalloc_hyp_page));
  assert (ptr_eq(data.phys_to_virt,&hyp_phys_to_virt));
  assert (ptr_eq(data.virt_to_phys,&hyp_virt_to_phys));
  assert (ptr_eq(data.get_page,&hyp_get_page));
  return;
}

datatype possible_mm_ops {
  No_MM_Ops {},
  Has_MM_Ops {pointer mm_ops}
}

function (boolean) possible_mm_ops_agree (possible_mm_ops o, pointer m)
{
  match o {
    No_MM_Ops {} => {true}
    Has_MM_Ops {mm_ops: m2} => {ptr_eq (m,m2)}
  }
}
@*/


// --- page table definitions --------------------------------------------------

// We assume a setup where pages, and hence individual page tables,
// are 4096 bytes in size (2^12). On a 64-bit platform (with pointers
// of 2^3 bytes size) that means an individual page table can fit
// 2^9=512 entries. An overall page table has maximum depth of four
// levels (levels 0 -- 3). For any given 64-bit pointer, to be
// address-translated, only a portion of up to 48 bits are the actual
// address (the *input address*). In the most basic setup, these 48
// bits are divided into four times 9 bits, which are taken as indices
// into page table levels 0 through 3, with the remaining 12 bits used
// as an offset into the page of physical memory obtained from the
// page table lookup (if the address is mapped).
//
// Different configurations from this basic setup are possible: input
// addresses can be made smaller by setting an appropriate hardware
// register, and the page table depth can be reduced by setting the
// initial translation level to be greater than 0.
//
// For small input address sizes (relative to the number of
// translation levels), the default table encoding would lead to
// wasted space and pointer indirection, due to mostly-empty top level
// page tables (i.e. 12 bits, plus 9 bits times the number of
// translation levels, could encode significantly larger addresses
// than the chosen input address size).
//
// When the input address size is sufficiently small for that, it is
// then possible to optimise and use *concatenated page tables*:
// instead of a regular level-n page-table setup, using the
// concatenated-page-table scheme, one gets a level-(n-1) page table
// where the top level becomes *an array of page tables* that
// effectively represents the two upper levels of the page table
// within a single page: the part of the input address dedicated for
// the initial level of the address translation is used to index the
// page-table array, the resulting page-table is indexed using the
// next 9-bit index. When the input address size permits, the
// concatenated scheme is selected by chosing an initial translation
// level that is one greater than what one would have chosen
// otherwise.
//
// Note: Armv8.2 introduced an architecture extension that allows for
// input addresses of larger sizes, up to 52 bits, and initial address
// translation levels of -1, which our specification does not handle
// yet.



/*@
@*/
enum {
  enum_PTRS_PER_PTE = PTRS_PER_PTE,
  enum_EAGAIN = EAGAIN,
  enum_KVM_PGTABLE_MAX_LEVELS = KVM_PGTABLE_MAX_LEVELS

//  enum_KVM_PTE_LEAF_ATTR_LO = KVM_PTE_LEAF_ATTR_LO,
//  enum_KVM_PTE_LEAF_ATTR_HI = KVM_PTE_LEAF_ATTR_HI,
//  enum_KVM_PTE_VALID = KVM_PTE_VALID
};
/*@

function (u64) KVM_PTE_LEAF_ATTR_LO ()
{
  0b11111111110u64
}

function (u64) KVM_PTE_LEAF_ATTR_HI ()
{
  shift_left(0b1111111111111u64,51u64)
}

function (u64) KVM_PTE_VALID ()
{
  0b1u64
}

function (u64) KVM_PTE_LEAF_ATTR_HI_SW ()
{
  shift_left(0b1111u64,55u64)
}


// Looking at BS thesis section 7.3.1

datatype packed_table {
  PackedTable { integer table }
}

datatype info {
  I_Invalid {},
  I_Block_or_page {
    u64 output_address, // actual size depending on level
    boolean is_page // bit 1
    // u16 upper_attrs, // actually 14 bits
    // u16 lower_attrs, // actually 10 bits
  },
  I_Table {
    packed_table table
    // u16 attrs, // actually 14 bits
  }
}

type_synonym entry = {
    u64 code,
    info info
}




datatype table {
  Table { map<u64, entry> entries }
}

function (packed_table) pack_table (table t)
function (table) unpack_table (packed_table t)


lemma table_packing (table t)
  requires true;
  ensures unpack_table(pack_table(t)) == t;





// constraints on level, see arch/arm64/include/asm/pgtable-hwdef.h

// copying part of kvm_pte_table
function (boolean) is_max_level (u32 level)
{
  level == (u32) enum_KVM_PGTABLE_MAX_LEVELS - 1u32
}


function (boolean) is_page_or_table_type (kvm_pte_t pte)
{
  (pte & 0x2u64) == 0x2u64
}


function (boolean) valid_pgtable_level (u32 level)
{
  0u32 <= level && level <= 3u32
}



function (boolean) cn_pte_table (kvm_pte_t pte, u32 level)
{
  cn_pte_valid(pte)
  && is_page_or_table_type(pte)
  && !is_max_level(level)
}


// - note about level: in this ARM pgtable, the page & table encodings are
//   shared, and entries at the final level are automatically not tables


function (pointer) decode_table_entry_pointer (u64 encoded)
{
  hyp_phys_to_virt (cn_pte_to_phys (encoded))
}

function (u64) align_u64 (u64 x, u64 n)
{
  shift_left (shift_right (x, n), n)
}

function (boolean) aligned_u64 (u64 x, u64 n)
{
  align_u64 (x, n) == x
}

function (u32) pgd_extra_bits(u32 ia_bits, u32 start_level)
{
  let levels = 4u32 - start_level;
  let bits_covered = levels * 9u32 + 12u32;
  let bits_missing = (ia_bits <= bits_covered) ? 0u32 : (ia_bits - bits_covered);
  bits_missing
}


// see struct kvm_pgtable defn in arch/arm64/include/asm/kvm_pgtable.h


predicate (entry) PageTableEntry(pointer p, u32 level)
{
   take code = Owned<kvm_pte_t>(p);
   take info = PageTableEntrySubtable(p,level,code);
   return { code: code, info: info };
}


predicate (info) PageTableEntrySubtable(pointer unused_p, u32 level, u64 pte)
{
  if (cn_pte_table(pte,level)) {
      // assert (valid_pgtable_level(level));
      // assert (good<kvm_pte_t *>(decode_table_entry_pointer (encoded)));
      let table_pointer = decode_table_entry_pointer (pte);
      take table = PageTable(table_pointer, level + 1u32);
      return I_Table { table: pack_table(table) };
  }
  else {
    let is_valid = cn_pte_valid(pte);
    let is_page_type = is_page_or_table_type(pte);
    let is_block = is_valid && !is_page_type;
//    assert (is_block implies (cn_level_supports_block_mapping(level))); // TODO: maybe more
    let info = 
      if (!is_valid) { I_Invalid {} }
      else { I_Block_or_page { output_address: cn_pte_to_phys(pte), is_page: is_page_type } }
    ;
    return info;
  }
}

predicate (info) OLD_PageTableEntrySubtable(pointer unused_p, u32 level, u64 pte)
{
  if (!cn_pte_valid(pte)) {
    return I_Invalid {};
  }
  else {
    if (is_page_or_table_type(pte) && !is_max_level(level)) {
      // assert (valid_pgtable_level(level));
      // assert (good<kvm_pte_t *>(decode_table_entry_pointer (encoded)));
      let table_pointer = decode_table_entry_pointer (pte);
      take table = PageTable(table_pointer, level + 1u32);
      return I_Table { table: pack_table(table) };
    }
    else {
      let is_page = is_page_or_table_type(pte);
      let is_block = !is_page;
      let output_address = cn_pte_to_phys(pte);
      assert (is_block implies (cn_level_supports_block_mapping(level))); // TODO: maybe more
      return I_Block_or_page { output_address: output_address, is_page: is_page };
    }
  }
}


predicate table PageTable(pointer base, u32 level)
{
  take entries = each (u64 i; 0u64 <= i && i < 512u64)
                      {PageTableEntry(array_shift<kvm_pte_t>(base, i), level)};
  return Table { entries: entries };
}

predicate {struct kvm_pgtable data, map<u64,table> tables} PageDirectory (pointer p)
{
  take Data = Owned<struct kvm_pgtable>(p);
  let extra_bits = pgd_extra_bits(Data.ia_bits, Data.start_level);

  assert (39u32 <= Data.ia_bits && Data.ia_bits <= 48u32);
  assert (0u32 <= extra_bits && extra_bits <= 4u32);
  // assert (aligned_u64 ((u64) Data.pgd, 12u64 + ((u64) extra_bits)));
  assert (valid_pgtable_level(Data.start_level));

  take tables = each (u64 i; 0u64 <= i && i < (u64) shift_left(1u32,extra_bits))
                     {PageTable(array_shift<kvm_pte_t[enum_PTRS_PER_PTE]>(Data.pgd, i), Data.start_level)};

  //return {extra_bits: extra_bits, data: Data};
  return {data: Data, tables: tables};
}

@*/


struct kvm_pgtable_walk_data {
	struct kvm_pgtable_walker	*walker;

	const u64			start;
	u64				addr;
	const u64			end;
};

/*@

// --- parameterisation of page-table walker -----------------------------------

predicate {u32 flags, pointer arg} KVM_PgTable_Walker (pointer p)
{
  take D = Owned<struct kvm_pgtable_walker>(p);
  take X = Hyp_Walker_Cases (D.cb, D.arg, D.flags);
  return {flags: D.flags, arg: D.arg};
}

predicate {u64 addr, u64 end, {pointer walker, pointer arg} walker, u32 flags}
    KVM_PgTable_Walk_Data (pointer p)
{
  take D = Owned<struct kvm_pgtable_walk_data>(p);
  take Walker = KVM_PgTable_Walker(D.walker);
  let walker = {walker: D.walker, arg: Walker.arg};
  return {addr: D.addr, end: D.end, walker: walker, flags: Walker.flags};
}
@*/






/*@ function (boolean) cn_phys_is_valid(u64 phys) { phys < 0x1000000000000u64 } @*/

static bool kvm_phys_is_valid(u64 phys)
/*@ ensures return == (cn_phys_is_valid(phys) ? 1u8 : 0u8);
@*/
{
	return phys < BIT(id_aa64mmfr0_parange_to_phys_shift(ID_AA64MMFR0_EL1_PARANGE_MAX));
}


/*@
function (boolean) cn_block_mapping_supported(u64 addr, u64 end, u64 phys, u32 level)
{
  cn_level_supports_block_mapping(level)
  && (! (cn_granule_size(level) > (end - addr)))
  && (! (cn_phys_is_valid(phys) && (! aligned_u64(phys, cn_granule_shift(level)))))
  && aligned_u64(addr, cn_granule_shift(level))
}
@*/

static bool kvm_block_mapping_supported(const struct kvm_pgtable_visit_ctx *ctx, u64 phys)
/*@ requires take Ctx = Owned(ctx);
             valid_pgtable_level(Ctx.level);
    ensures  take Ctx2 = Owned(ctx);
             Ctx2 == Ctx;
             return == (cn_block_mapping_supported(Ctx.addr, Ctx.end, phys, Ctx.level)
                        ? 1u8 : 0u8);
@*/
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
function (u32) purekvm_pgtable_idx(u64 addr, u32 level)
{
  (u32) (bw_and_uf((u64) ((u32) shift_right (addr, cn_granule_shift(level))), 511u64))
}
@*/

static u32 kvm_pgtable_idx(struct kvm_pgtable_walk_data *data, u32 level)
/*@ requires take Data = Owned (data);
             valid_pgtable_level(level);
    ensures  take Data2 = Owned (data);
             0u32 <= return && return < shift_left(1u32, 12u32 - 3u32);
             Data2 == Data;
             return == purekvm_pgtable_idx(Data.addr, level);
@*/
{
	u64 shift = kvm_granule_shift(level);
	u64 mask = BIT(PAGE_SHIFT - 3) - 1;

	return (data->addr >> shift) & mask;
}

/*@
function (u32) pure__kvm_pgd_page_idx(u32 ia_bits, u32 start_level, u64 addr)
{
  (u32) shift_right (
    bw_and_uf(addr, (shift_left(1u64, (u64)(ia_bits))) - 1u64),
    cn_granule_shift(start_level - 1u32)
  )
}
@*/

static u32 kvm_pgd_page_idx(struct kvm_pgtable *pgt, u64 addr)
/*@ requires take PTStruct = Owned<struct kvm_pgtable>(pgt);
             ((0u32 < PTStruct.ia_bits) && (PTStruct.ia_bits < 64u32));
             valid_pgtable_level(PTStruct.start_level);
             let extra_bits = pgd_extra_bits(PTStruct.ia_bits, PTStruct.start_level);
             0u32 <= extra_bits; extra_bits <= 4u32;
    ensures  shift_right(return, extra_bits) == 0u32;
             take PTStruct2 = Owned<struct kvm_pgtable>(pgt);
             PTStruct2 == PTStruct;
             return == pure__kvm_pgd_page_idx(PTStruct.ia_bits, PTStruct.start_level, addr); @*/
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
/*@ requires valid_pgtable_level(level);
    ensures  return == (cn_pte_table(pte, level) ? 1u8 : 0u8); @*/
{
	if (level == KVM_PGTABLE_MAX_LEVELS - 1)
		return false;

	if (!kvm_pte_valid(pte)) {
		return false;
	}

	return FIELD_GET(KVM_PTE_TYPE, pte) == KVM_PTE_TYPE_TABLE;
}

static kvm_pte_t *kvm_pte_follow(kvm_pte_t pte, struct kvm_pgtable_mm_ops *mm_ops)
/*@ requires good<kvm_pte_t *>(decode_table_entry_pointer (pte));
    requires take Ops = MM_Ops(mm_ops);
    ensures  take Ops2 = MM_Ops(mm_ops);
             ptr_eq (return,decode_table_entry_pointer (pte)); @*/
{
	return mm_ops->phys_to_virt(kvm_pte_to_phys(pte));
}

static void kvm_clear_pte(kvm_pte_t *ptep)
{
	WRITE_ONCE(*ptep, 0);
}

static kvm_pte_t kvm_init_table_pte(kvm_pte_t *childp, struct kvm_pgtable_mm_ops *mm_ops)
/*@ requires take Ops = MM_Ops(mm_ops);
             valid_phys_virt_offset ();
             valid_hyp_virt_page(childp);
    ensures  take Ops2 = MM_Ops(mm_ops);
             cn_pte_valid(return) && is_page_or_table_type(return);
             addr_eq(decode_table_entry_pointer(return),childp); @*/
{
	kvm_pte_t pte = kvm_phys_to_pte(mm_ops->virt_to_phys(childp));

	pte |= FIELD_PREP(KVM_PTE_TYPE, KVM_PTE_TYPE_TABLE);
	pte |= KVM_PTE_VALID;


	return pte;
}



/*@ function (kvm_pte_t) kvm_init_valid_leaf_pte (u64 pa, kvm_pte_t attr, u32 level) @*/

static kvm_pte_t kvm_init_valid_leaf_pte(u64 pa, kvm_pte_t attr, u32 level)
/*@ cn_function kvm_init_valid_leaf_pte;
    requires valid_pgtable_level(level);
    ensures return == kvm_init_valid_leaf_pte(pa, attr, level);

            cn_pte_valid(return);
            cn_pte_to_phys(return) == cn_pte_to_phys(cn_phys_to_pte(pa));
            is_page_or_table_type(return) == is_max_level(level);
@*/
{
	kvm_pte_t pte = kvm_phys_to_pte(pa);
	u64 type = (level == KVM_PGTABLE_MAX_LEVELS - 1) ? KVM_PTE_TYPE_PAGE :
							   KVM_PTE_TYPE_BLOCK;

	pte |= attr & (KVM_PTE_LEAF_ATTR_LO | KVM_PTE_LEAF_ATTR_HI);
	pte |= FIELD_PREP(KVM_PTE_TYPE, type);
	pte |= KVM_PTE_VALID;

	return pte;
}

static kvm_pte_t kvm_init_invalid_leaf_owner(u8 owner_id)
{
	return FIELD_PREP(KVM_INVALID_PTE_OWNER_MASK, owner_id);
}

/*@
function (boolean) flag_in_flags (i32 flag, i32 flags)
{
  (flag == KVM_PGTABLE_WALK_LEAF
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
      : true)
}
@*/

static int kvm_pgtable_visitor_cb(struct kvm_pgtable_walk_data *data,
				  const struct kvm_pgtable_visit_ctx *ctx,
				  enum kvm_pgtable_walk_flags visit)
/*@ requires take Data = KVM_PgTable_Walk_Data(data);
             take Ctx = Owned(ctx);
             valid_pgtable_level(Ctx.level);
             valid_phys_virt_offset ();
             take pte = Owned(Ctx.ptep);
             take IPT = PageTableEntrySubtable (Ctx.ptep, Ctx.level, pte);
             take Ops = MM_Ops(Ctx.mm_ops);
             flag_in_flags ((i32) visit, (i32) (Data.flags));
             (visit == (u32)KVM_PGTABLE_WALK_LEAF) == (!(cn_pte_table(pte, Ctx.level)));
             ptr_eq(Ctx.arg,Data.walker.arg);
    ensures  take Data2 = KVM_PgTable_Walk_Data (data);
             Data2 == Data;
             take Ctx2 = Owned(ctx);
             Ctx2 == Ctx;
             take pte2 = Owned(Ctx.ptep);
             take IPT2 = PageTableEntrySubtable (Ctx.ptep, Ctx.level, pte2);
             take Ops2 = MM_Ops(Ctx.mm_ops);
             Ops2 == Ops;
             visit == ((u32)KVM_PGTABLE_WALK_TABLE_PRE) ? pte2 == pte : true; @*/
{
	struct kvm_pgtable_walker *walker = data->walker;
	WARN_ON_ONCE(kvm_pgtable_walk_shared(ctx) && !kvm_pgtable_walk_lock_held());
	return walker->cb(ctx, visit);
}

/*@
function (boolean) walk_again_case(i32 r, u32 flags)
{
  r == (0i32 - enum_EAGAIN) &&
  bw_and_uf(flags, (u32) KVM_PGTABLE_WALK_HANDLE_FAULT) == 0u32
}
@*/

static bool kvm_pgtable_walk_continue(const struct kvm_pgtable_walker *walker,
				      int r)
/*@ requires take Walker = KVM_PgTable_Walker (walker);
    ensures  take Walker2 = KVM_PgTable_Walker (walker);
             Walker2 == Walker;
             return == ((r == 0i32) || walk_again_case(r, Walker.flags) ? 1u8 : 0u8); @*/
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
/*@ requires take Data = KVM_PgTable_Walk_Data (data);
             valid_pgtable_level(level);
             valid_phys_virt_offset ();
             take pte = PageTableEntry(pteref, level);
             take Ops = MM_Ops(mm_ops);
             Data.addr <= Data.end;
    ensures  take Data2 = KVM_PgTable_Walk_Data (data);
             Data2.end == Data.end;
             Data2.walker == Data.walker;
             Data2.flags == Data.flags;
             take pte2 = PageTableEntry(pteref, level);
             take Ops2 = MM_Ops(mm_ops);
             Ops2 == Ops;
             ((Data2.addr < Data2.end) && (return == 0i32)) implies
               (Data2.addr == (align_u64 (Data.addr, cn_granule_shift(level)) +
            shift_left(1u64, cn_granule_shift(level))));
             ! walk_again_case(return, Data.flags); @*/
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
/*@ requires take Data = KVM_PgTable_Walk_Data (data);
             take PTEs = PageTable (pgtable, level);
             let orig_data = data;
             let orig_pgtable = pgtable;
             let orig_mm_ops = mm_ops;
             take Ops = MM_Ops(mm_ops);
             valid_pgtable_level(level);
             valid_phys_virt_offset ();
             let orig_level = level;
    ensures  take Data2 = KVM_PgTable_Walk_Data (data);
             Data2.end == Data.end;
             Data2.walker == Data.walker;
             Data2.flags == Data.flags;
             take PTEs2 = PageTable (pgtable, level);
             take Ops2 = MM_Ops(mm_ops);
             Ops2 == Ops;
             ((Data2.addr < Data2.end) && (return == 0i32)) ?
    (Data2.addr == (align_u64 (Data.addr, cn_granule_shift(level - 1u32)) +
        shift_left(1u64, cn_granule_shift(level - 1u32))))
    : true;
    ensures ! walk_again_case(return, Data.flags); @*/
{
	u32 idx;
	int ret = 0;

	//CERB_WORK_AROUND: expression statements
	//if (WARN_ON_ONCE(level >= KVM_PGTABLE_MAX_LEVELS))
	if ((level >= KVM_PGTABLE_MAX_LEVELS))
		return -EINVAL;

	for (idx = kvm_pgtable_idx(data, level); idx < PTRS_PER_PTE; ++idx)
	/*@ inv take Data3 = KVM_PgTable_Walk_Data (data);
	        take PTEs3 = PageTable (pgtable, level);
	        0u32 <= idx && idx <= ((u32)enum_PTRS_PER_PTE);
	        ptr_eq(data,orig_data);
	        ptr_eq(pgtable,orig_pgtable);
	        level == orig_level;
	        Data3.end == Data.end;
	        Data3.walker == Data.walker;
	        Data3.flags == Data.flags;
	        ptr_eq(mm_ops,orig_mm_ops);
	        take Ops3 = MM_Ops(mm_ops);
	        ret == 0i32;
	        ((Data3.addr == Data.addr) && (idx == purekvm_pgtable_idx(Data.addr, level)))
		||
		(Data3.addr >= Data.end)
		||
		((Data.addr < Data.end) && Data3.addr ==
			(align_u64 (Data.addr, cn_granule_shift(level - 1u32)) +
				shift_left((u64)idx, cn_granule_shift(level)))); @*/
	{
		kvm_pteref_t pteref = &pgtable[idx];


		if (data->addr >= data->end)
			break;

		/*@ extract PageTableEntry, (u64)idx; @*/

		ret = __kvm_pgtable_visit(data, mm_ops, pteref, level);

		if (ret)
			break;
	}

	return ret;
}

static int _kvm_pgtable_walk(struct kvm_pgtable *pgt, struct kvm_pgtable_walk_data *data)
/*@ requires take Data = KVM_PgTable_Walk_Data (data);
             take PT = PageDirectory (pgt);
             let orig_data = data;
             let orig_pgt = pgt;
             take Ops = MM_Ops(PT.data.mm_ops);
             valid_phys_virt_offset ();
    ensures  take Data2 = KVM_PgTable_Walk_Data (data);
             take PT2 = PageDirectory (pgt);
             PT2.data == PT.data;
             take Ops2 = MM_Ops(PT.data.mm_ops);
             Data2.walker == Data.walker; @*/
{
	u32 idx;
	int ret = 0;
	u64 limit = BIT(pgt->ia_bits);

	if (data->addr > limit || data->end > limit)
		return -ERANGE;

	if (!pgt->pgd)
		return -EINVAL;

	for (idx = kvm_pgd_page_idx(pgt, data->addr); data->addr < data->end; ++idx)
	/*@ inv take Data3 = KVM_PgTable_Walk_Data (data);
	        take PT3 = PageDirectory(pgt);
	        take Ops3 = MM_Ops(PT.data.mm_ops);
	        ptr_eq (data,orig_data);
	        ptr_eq(pgt,orig_pgt);
	        PT3.data == PT.data;
	        Ops3 == Ops;
	        Data3.end == Data.end;
	        Data3.walker == Data.walker;
	        Data3.flags == Data.flags;
	        Data.end <= shift_left(1u64, (u64) PT.data.ia_bits);
	        (! (Data3.addr < Data.end)) || (idx == pure__kvm_pgd_page_idx(PT.data.ia_bits,
			PT.data.start_level, Data3.addr)); @*/
	{
		kvm_pteref_t pteref = &pgt->pgd[idx * PTRS_PER_PTE];

		/*@ extract PageTable, (u64)idx; @*/

		ret = __kvm_pgtable_walk(data, pgt->mm_ops, pteref, pgt->start_level);
		if (ret)
			break;
	}

	return ret;
}

int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size,
		     struct kvm_pgtable_walker *walker)
/*@ requires take PT = PageDirectory (pgt);
             take W = KVM_PgTable_Walker (walker);
             take Ops = MM_Ops(PT.data.mm_ops);
             valid_phys_virt_offset ();
    ensures  take PT2 = PageDirectory (pgt);
             PT2.data == PT.data;
             take Ops2 = MM_Ops(PT.data.mm_ops);
             take W2 = KVM_PgTable_Walker (walker);
             ptr_eq(W2.arg,W.arg); @*/
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
/*@ requires take P = Owned(ptep);
    ensures  take P2 = Owned(ptep); @*/
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
/*@ requires take Ctx = Owned(ctx);
             valid_pgtable_level(Ctx.level);
             take D = Owned<struct hyp_map_data>(data);
             take pte = Owned<kvm_pte_t>(Ctx.ptep);
             ! (cn_pte_table (pte, Ctx.level));
             take Ops = MM_Ops(Ctx.mm_ops);
    ensures  take Ctx2 = Owned(ctx);
             Ctx2 == Ctx;
             take D2 = Owned<struct hyp_map_data>(data);
             D2 == D;
             take pte2 = Owned<kvm_pte_t>(Ctx.ptep);
             take Ops2 = MM_Ops(Ctx.mm_ops);
             ! (cn_pte_table (pte2, Ctx.level)); 

             let phys = D.phys+Ctx.addr - Ctx.start;
             let block_mapping_supported = cn_block_mapping_supported(Ctx.addr, Ctx.end, phys, Ctx.level);
             let new = kvm_init_valid_leaf_pte(phys, D.attr, Ctx.level);
             let new_old_bad_difference = ((Ctx.old ^ new) & ~(KVM_PTE_LEAF_ATTR_HI_SW ())) != 0x0u64;

             let no = !block_mapping_supported || (cn_pte_valid(Ctx.old) && new_old_bad_difference);
             let yes_unchanged = (block_mapping_supported && Ctx.old == new);

             no implies (return == 0u8 && pte == pte2);
             yes_unchanged implies (return == 1u8 && pte == pte2);
             (!(no || yes_unchanged)) implies (return == 1u8 && pte2 == new);
           
@*/
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


/*@
predicate (map <u64, pte>) PTE_Array (pointer p)
{
  assert (mod((u64)p, 4096u64) == 0u64);
  take ptes = each (u64 i; 0u64 <= i && i < 512u64)
                   {Owned<kvm_pte_t>(array_shift<kvm_pte_t>(p, i))};
  return ptes;
}
@*/

static inline void coerce_page_to_ptes(kvm_pte_t *ptep)
/*@ trusted;
    requires take ZP = Cond_Zero_Page (ptep);
             ZP.exists;
    ensures take ptes = PTE_Array (ptep);
            each (u64 i; 0u64 <= i && i < 512u64) {ptes[i] == 0u64}; @*/
{
}

static inline void coerce_null_ptes_to_IPT(kvm_pte_t *ptep, u32 level)
/*@ trusted;
    requires take ptes = PTE_Array (ptep);
             each (u64 i; 0u64 <= i && i < 512u64) {ptes[i] == 0u64};
             valid_pgtable_level(level);
    ensures  take ptes2 = PageTable (ptep, level); @*/
{
}


static int hyp_map_walker(const struct kvm_pgtable_visit_ctx *ctx,
			  enum kvm_pgtable_walk_flags visit)
/*@ requires take Ctx = Owned(ctx);
             valid_pgtable_level(Ctx.level);
             valid_phys_virt_offset ();
             take D = Owned<struct hyp_map_data>(Ctx.arg);
             take pte = PageTableEntry(Ctx.ptep, Ctx.level);
             !(cn_pte_table(pte.code, Ctx.level));
             take Ops = MM_Ops(Ctx.mm_ops);
    ensures  take Ctx2 = Owned(ctx);
             Ctx2 == Ctx;
             take D2 = Owned<struct hyp_map_data>(Ctx.arg);
             take new = PageTableEntry(Ctx.ptep, Ctx.level);
             D2 == D;
             take Ops2 = MM_Ops(Ctx.mm_ops); @*/
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
predicate (void) Hyp_Map_Walker_Case(pointer f, pointer x, u32 flags)
{
  assert (ptr_eq(f,&hyp_map_walker));
  assert (flags == ((u32) KVM_PGTABLE_WALK_LEAF));
  take D = Owned<struct hyp_map_data>(x);
  return;
}

predicate (void) Hyp_Walker_Cases(pointer f, pointer x, u32 flags)
{
  take X = Hyp_Map_Walker_Case (f, x, flags);
  return X;
}

@*/

int kvm_pgtable_hyp_map(struct kvm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			enum kvm_pgtable_prot prot)
/*@ requires take PT = PageDirectory(pgt);
             take Ops = MM_Ops(PT.data.mm_ops);
             valid_phys_virt_offset ();
    ensures  take PT2 = PageDirectory(pgt);
             //PT2.extra_bits == PT.extra_bits;
             PT2.data == PT.data;
             take Ops2 = MM_Ops(PT.data.mm_ops); @*/
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
  (void) include_allocator_spec;
  (void) hyp_zalloc_hyp_page;
  (void) hyp_phys_to_virt;
  (void) hyp_virt_to_phys;
  (void) hyp_get_page;
  (void) enum_PTRS_PER_PTE;
  (void) enum_KVM_PGTABLE_MIN_BLOCK_LEVEL;
  return 9;
}
