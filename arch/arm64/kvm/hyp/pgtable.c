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


// GHOST
#include <asm/kvm_mmu.h>      // needed for debug-pl011.h
#include <nvhe/debug-pl011.h>
#include <nvhe/ghost_extra_debug-pl011.h>
//#include <nvhe/ghost_check_pgtables.h>
#include <nvhe/ghost_pgtable.h>
#include <nvhe/ghost_control.h>

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
// /GHOST


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

struct kvm_pgtable_walk_data {
	struct kvm_pgtable_walker	*walker;

	const u64			start;
	u64				addr;
	const u64			end;
};


// for GHOST code: this type definition was just before kvm_get_vtcr, but we need it earlier to state pre/postconditions in __kvm_pgtable_walk, as we're doing that specific for the stage2, not for arbitrary callbacks
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

// GHOST
bool is_stage2_map_walker(struct kvm_pgtable_walk_data *data);

void ghost_dump_kvm_pgtable(struct kvm_pgtable *pgt, u64 i)
{
	hyp_puti(i);
	hyp_putsxn("ia_bits",pgt->ia_bits,32);
	hyp_putsxn("start_level",pgt->start_level,32);
	hyp_putsxn("pgd",(u64)(pgt->pgd),64);
}
void ghost_dump_kvm_pgtable_walk_data(struct kvm_pgtable_walk_data *data, u64 i)
{
	hyp_puti(i);
	hyp_puts("pgd:");
	/* ghost_dump_kvm_pgtable(data->pgt, 0); */
	hyp_putsxn("start",data->start,64);
	hyp_putsxn("addr",data->addr,64);
	hyp_putsxn("end",data->end,64);
	hyp_putc('\n');
}

// /GHOST

static bool kvm_phys_is_valid(u64 phys)
{
	return phys < BIT(id_aa64mmfr0_parange_to_phys_shift(ID_AA64MMFR0_EL1_PARANGE_MAX));
}

static bool kvm_block_mapping_supported(const struct kvm_pgtable_visit_ctx *ctx, u64 phys)
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

static u32 kvm_pgtable_idx(struct kvm_pgtable_walk_data *data, u32 level)
{
	u64 shift = kvm_granule_shift(level);
	u64 mask = BIT(PAGE_SHIFT - 3) - 1;

	return (data->addr >> shift) & mask;
}

static u32 kvm_pgd_page_idx(struct kvm_pgtable *pgt, u64 addr)
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
{
	if (level == KVM_PGTABLE_MAX_LEVELS - 1)
		return false;

	if (!kvm_pte_valid(pte))
		return false;

	return FIELD_GET(KVM_PTE_TYPE, pte) == KVM_PTE_TYPE_TABLE;
}

static kvm_pte_t *kvm_pte_follow(kvm_pte_t pte, struct kvm_pgtable_mm_ops *mm_ops)
{
	return mm_ops->phys_to_virt(kvm_pte_to_phys(pte));
}

static void kvm_clear_pte(kvm_pte_t *ptep)
{
	WRITE_ONCE(*ptep, 0);
}

static kvm_pte_t kvm_init_table_pte(kvm_pte_t *childp, struct kvm_pgtable_mm_ops *mm_ops)
{
	kvm_pte_t pte = kvm_phys_to_pte(mm_ops->virt_to_phys(childp));

	pte |= FIELD_PREP(KVM_PTE_TYPE, KVM_PTE_TYPE_TABLE);
	pte |= KVM_PTE_VALID;
	return pte;
}

static kvm_pte_t kvm_init_valid_leaf_pte(u64 pa, kvm_pte_t attr, u32 level)
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

static int kvm_pgtable_visitor_cb(struct kvm_pgtable_walk_data *data,
				  const struct kvm_pgtable_visit_ctx *ctx,
				  enum kvm_pgtable_walk_flags visit)
{
	struct kvm_pgtable_walker *walker = data->walker;

	/* Ensure the appropriate lock is held (e.g. RCU lock for stage-2 MMU) */
	WARN_ON_ONCE(kvm_pgtable_walk_shared(ctx) && !kvm_pgtable_walk_lock_held());
	return walker->cb(ctx, visit);
}

static bool kvm_pgtable_walk_continue(const struct kvm_pgtable_walker *walker,
				      int r)
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
			      struct kvm_pgtable_mm_ops *mm_ops, kvm_pteref_t pgtable, u32 level,
			      u64 ghost_va_partial);

static inline int __kvm_pgtable_visit(struct kvm_pgtable_walk_data *data,
				      struct kvm_pgtable_mm_ops *mm_ops,
				      kvm_pteref_t pteref, u32 level,
				      u64 ghost_va_partial)
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

	// GHOST
	//if (ghost_extra_debug_initialised) {
	//	hyp_putsxn("__kvm_pgtable_visit &ret",(u64)&ret,64);
	//	hyp_putc('\n');
	//}
	// /GHOST

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
	ret = __kvm_pgtable_walk(data, mm_ops, childp, level + 1, ghost_va_partial);
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
			      struct kvm_pgtable_mm_ops *mm_ops, kvm_pteref_t pgtable, u32 level,
			      u64 ghost_va_partial)
{
	u32 idx;
	int ret = 0;

	// GHOST
	bool ghost_check = ghost_control.check___kvm_pgtable_walk && is_stage2_map_walker(data); // turning off for now
	u64 i = 4 + level * 2;  /* base indent */
	u64 ghost_va_partial_new;
	mapping mapping_pre, mapping_post; // interpretation of pgt on entry and exit
	mapping mapping_pre_annot, mapping_post_annot; // interpretation of pgtable on entry and exit, cut down to annot parts
	mapping mapping_requested, mapping_pre_plus_requested;

	if (ghost_check) {
		hyp_putspi("__kvm_pgtable_walk ", i);
		if (level==0) ghost_dump_kvm_pgtable_walk_data(data, i);
		hyp_puti(i+2);
		hyp_putsxn("pgtable",(u64)pgtable,64);
		hyp_putsxn("level",level,32);
		hyp_putsxn("va_partial",ghost_va_partial,64);
		hyp_putc('\n');

		ghost_lock_maplets();
		mapping_pre = ghost_record_pgtable_partial(pgtable, level, ghost_va_partial, dummy_aal(), "__kvm_pgtable_walk pre", i+2);
		if (((struct stage2_map_data *)(data->walker->arg))->anchor == NULL) { // if anchor not set
			// TODO: I guess we need to cut down the (addr,end) to the footprint of the subpagetable we're working on. We don't see that in the boot as the fault-on-demand only seems to request a single-page mapping?  If it never does, the anchor machinery is irrelevant for that.
			mapping_requested = mapping_singleton(data->addr, (data->end - data->addr)/PAGE_SIZE, maplet_target_mapped(((struct stage2_map_data *)(data->walker->arg))->phys, DUMMY_ATTR, dummy_aal()));
		} else {
			mapping_requested = mapping_empty_();
		}
		ghost_unlock_maplets();
	}
	// /GHOST
	if (WARN_ON_ONCE(level >= KVM_PGTABLE_MAX_LEVELS)) {
		ret = -EINVAL;
		goto out;
	}

	for (idx = kvm_pgtable_idx(data, level); idx < PTRS_PER_PTE; ++idx) {
		kvm_pteref_t pteref = &pgtable[idx];

		if (data->addr >= data->end)
			break;

		// GHOST
                switch (level) {
                case 0: ghost_va_partial_new = ghost_va_partial | ((u64)idx << 39); break;
                case 1: ghost_va_partial_new = ghost_va_partial | ((u64)idx << 30); break;
                case 2: ghost_va_partial_new = ghost_va_partial | ((u64)idx << 21); break;
                case 3: ghost_va_partial_new = ghost_va_partial | ((u64)idx << 12); break;
                default: check_assert_fail("unhandled level"); // cases are exhaustive
                }
		// /GHOST
		ret = __kvm_pgtable_visit(data, mm_ops, pteref, level, ghost_va_partial_new);
		if (ret)
			break;
	}

out:
	// GHOST
	if (ghost_check) {
		// sketch of the postcondition - punting on sundry rounding and error/edge cases
		// some of this is shared with the kvm_pgtable_stage2_map postcondition, but for a subtable
		ghost_lock_maplets();
		mapping_post = ghost_record_pgtable_partial(pgtable, level, ghost_va_partial, dummy_aal(), "__kvm_pgtable_walk post", i+2);
		// postcondition: mapping_requested included in mapping_post
		mapping_submapping(mapping_requested, mapping_post, "__kvm_pgtable_walk_post", "mapping_requested", "mapping_post", i+2);
		// postcondition: mapping_post included in mapping_pre + mapping_requested
		mapping_pre_plus_requested = mapping_plus(mapping_pre, mapping_requested);
		mapping_submapping(mapping_post, mapping_pre_plus_requested, "__kvm_pgtable_walk_post", "mapping_post", "mapping_pre_plus_requested", i+2);
		// postcondition: mapping_post and mapping_pre have the same annotation part
		mapping_pre_annot = mapping_annot(mapping_pre);
		mapping_post_annot = mapping_annot(mapping_post);
		mapping_equal(mapping_pre_annot, mapping_post_annot, "__kvm_pgtable_walk_post annot equal", "mapping_pre_annot", "mapping_post_annot", i+2);
		free_mapping(mapping_pre);
		free_mapping(mapping_post);
		free_mapping(mapping_pre_annot);
		free_mapping(mapping_post_annot);
		free_mapping(mapping_requested);
		free_mapping(mapping_pre_plus_requested);
		ghost_unlock_maplets();
		// in addition to these, we need various properties of the intervening memory+tlbi+dsb state, as sketched for kvm_pgtable_stage2_map
		// if the anchor was set on entry, the mapping_requested was empty, but we should have free'd all the pages below, and cleared the anchor when we got back to it
	}
	// /GHOST
	return ret;
}

static int _kvm_pgtable_walk(struct kvm_pgtable *pgt, struct kvm_pgtable_walk_data *data)
{
	u32 idx;
	int ret = 0;
	u64 limit = BIT(pgt->ia_bits);
	u64 ghost_va_partial;
	// GHOST
	bool ghost_check = ghost_control.check__kvm_pgtable_walk &&  is_stage2_map_walker(data);/* turning off for now to reduce noise */
	u64 i=2; /* base indent */
	if (ghost_check) {
		hyp_putspi("_kvm_pgtable_walk\n", i);
	        ghost_dump_kvm_pgtable_walk_data(data, i+2);
		hyp_putsxn("pgt",(u64)pgt,64);
		hyp_putc('\n');
	}
	// /GHOST
	if (data->addr > limit || data->end > limit)
		return -ERANGE;

	if (!pgt->pgd)
		return -EINVAL;

	for (idx = kvm_pgd_page_idx(pgt, data->addr); data->addr < data->end; ++idx) {
		kvm_pteref_t pteref = &pgt->pgd[idx * PTRS_PER_PTE];

		// GHOST
		ghost_va_partial = 0;  // TODO?
		// /GHOST
		ret = __kvm_pgtable_walk(data, pgt->mm_ops, pteref, pgt->start_level, ghost_va_partial);
		if (ret)
			break;
	}

	return ret;
}

/* GHOST: maybe we'd just inline this in the verification of kvm_pgtable_stage2_map, rather than more-or-less duplicate their specifications? */
int kvm_pgtable_walk(struct kvm_pgtable *pgt, u64 addr, u64 size,
		     struct kvm_pgtable_walker *walker)
{
	struct kvm_pgtable_walk_data walk_data = {
		.start	= ALIGN_DOWN(addr, PAGE_SIZE),
		.addr	= ALIGN_DOWN(addr, PAGE_SIZE),
		.end	= PAGE_ALIGN(walk_data.addr + size),
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

static int hyp_map_walker(const struct kvm_pgtable_visit_ctx *ctx,
			  enum kvm_pgtable_walk_flags visit)
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

	new = kvm_init_table_pte(childp, mm_ops);
	mm_ops->get_page(ctx->ptep);
	smp_store_release(ctx->ptep, new);

	return 0;
}

int kvm_pgtable_hyp_map(struct kvm_pgtable *pgt, u64 addr, u64 size, u64 phys,
			enum kvm_pgtable_prot prot)
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

//  GHOST: struct stage2_map_data  was here; moved above
// /GHOST

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

	// GHOST
	//if (ghost_extra_debug_initialised) {
	//	hyp_putsxn("stage2_map_walker_try_leaf &new",(u64)&new,64);
	//	hyp_putc('\n');
	//}
	// /GHOST

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
	// GHOST
	//	if (ghost_extra_debug_initialised) {
	//	hyp_putsxn("stage2_map_walk_leaf &ret",(u64)&ret,64);
	//	hyp_putc('\n');
	//}
	// /GHOST

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

	// GHOST
	bool ghost_check = ghost_control.check_kvm_pgtable_stage2_map;
	int i=0;  /* base indent */
	mapping mapping_pre, mapping_post; // interpretation of pgt on entry and exit
	mapping mapping_pre_annot, mapping_post_annot; // interpretation of pgt on entry and exit, cut down to annot parts
	mapping mapping_requested, mapping_pre_plus_requested;
	if (ghost_check) {
		hyp_putspi("*********************************************************\n", i);
		hyp_putspi("kvm_pgtable_stage2_map:\n", i);

		// mapping_requested = addr..addr+size |-> (phys..phys+size, prot)
		ghost_lock_maplets();
		mapping_requested = mapping_singleton(addr, size / PAGE_SIZE, maplet_target_mapped(phys, DUMMY_ATTR, dummy_aal()));
// the attribute we see in the constructed table is
// 1000000000007fc
// 0000000100000000000000000000000000000000000000000000011111111100
// bits 56 and 10-2 all set
// 	56 is in 58:55 reserved for s/w use
//  10 is AF               the access flag
//  9:8 is SH[1:0]         11 for Normal memory means Inner Shareable (if effecticve VTCR_EL2.DS=0)
//  7:6 is S2AP[1:0]       11 means Access from N-s EL1 or N-s EL0 is Read/write
//  5:2 is MemAttr[3:0]    11 is Normal, Outer Write-Back Cacheable, Inner Write-Back Cacheable

		ghost_unlock_maplets();

		hyp_putspi("mapping_requested\n", i+2);
		hyp_put_mapping(mapping_requested, i+2);

		// record mapping on entry
		mapping_pre = ghost_record_pgtable(pgt, "kvm_pgtable_stage2_map pre", i+2);
	}
        // /GHOST

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

	if (WARN_ON((pgt->flags & KVM_PGTABLE_S2_IDMAP) && (addr != phys))) {
		ret = -EINVAL;
		goto out;
	}

	ret = stage2_set_prot_attr(pgt, prot, &map_data.attr);
	if (ret)
		goto out;

	ret = kvm_pgtable_walk(pgt, addr, size, &walker);
	dsb(ishst);
out:
	// GHOST
	if (ghost_check) {
		// sketch of the postcondition - punting on sundry rounding and error/edge cases
		ghost_lock_maplets();
		mapping_post = ghost_record_pgtable(pgt, "kvm_pgtable_stage2_map post", i+2);
		// postcondition: mapping_requested included in mapping_post
		mapping_submapping(mapping_requested, mapping_post, "kvm_pgtable_stage2_map post", "mapping_requested", "mapping_post", i+2);
		// postcondition: mapping_post included in mapping_pre + mapping_requested
		mapping_pre_plus_requested = mapping_plus(mapping_pre, mapping_requested);
		mapping_submapping(mapping_post, mapping_pre_plus_requested, "kvm_pgtable_stage2_map post", "mapping_post", "mapping_pre_plus_requested", i+2);
		// postcondition: mapping_post and mapping_pre have the same annotation part
		mapping_pre_annot = mapping_annot(mapping_pre);
		mapping_post_annot = mapping_annot(mapping_post);
		mapping_equal(mapping_pre_annot, mapping_post_annot, "kvm_pgtable_stage2_map post annot equal", "mapping_pre_annot", "mapping_post_annot", i+2);
		free_mapping(mapping_pre);
		free_mapping(mapping_post);
		free_mapping(mapping_pre_annot);
		free_mapping(mapping_post_annot);
		free_mapping(mapping_requested);
		free_mapping(mapping_pre_plus_requested);
		ghost_unlock_maplets();
		// in addition to these, we need to know:
		//  - that the second condition above held throughout any changes (with an invariant on the pgt)
		//  - that the break-before-make protocol and sufficient barriers have been conformed with (with that invariant being over some tlbi/dsb-state-annotated semantics)
		//  - the ownership transfer of pages between the pgt and by the allocator is handled correctly (standard separation-logic stuff)
		// perhaps we also need to know that new mappings are not block mappings, and that only block mappings will be lost?  Without that, mem_protect.c:host_stage2_idmap can't guarantee to actually establish the new mapping, as another thread could come in after the host_unlock_component().  If the code actually relies in that case on again trapping and remapping, liveness is questionable.
	}
	// /GHOST

	return ret;
}

// GHOST
bool is_stage2_map_walker(struct kvm_pgtable_walk_data *data)
{
	return data->walker->cb == stage2_map_walker;
}
// /GHOST

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

	// GHOST
	pgt->ghost_mapping = mapping_empty_();
	// /GHOST

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

	// GHOST
	u64 ghost_va_partial = 0;  // TODO?
	// /GHOST
	WARN_ON(__kvm_pgtable_walk(&data, mm_ops, ptep, level + 1, ghost_va_partial));

	WARN_ON(mm_ops->page_count(pgtable) != 1);
	mm_ops->put_page(pgtable);
}
