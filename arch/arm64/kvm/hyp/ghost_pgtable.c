/* Ghost code to compute the interpretation of page tables in a
   concise representation that we can use in executable assertions, as
   ordered lists of "maplet"s.  This file defines that interpretation, using
   ghost_maplets.h.
*/
#include <asm/kvm_mmu.h>

#include <hyp/ghost_extra_debug-pl011.h>
#include <nvhe/ghost_pgtable.h>
#include <nvhe/memory.h>   // for hyp_phys_to_virt
#include <nvhe/mem_protect.h>   // for PKVM_PAGE_SHARED_OWNED etc

#include <nvhe/ghost_pfn_set.h>
#include <nvhe/ghost_asserts.h>


#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

static ghost_mair_t pkvm_mair(void)
{
	// TODO: make part of ghost state and verify it's stable.
	return read_mair(read_sysreg(mair_el2));
}

/* page table entry kind: classify kind of entry */
enum entry_kind entry_kind(unsigned long long pte, unsigned char level)
{
	switch(level) {
	case 0:
	case 1:
	case 2: {
		switch (pte & GENMASK(1,0)) {
		case PTE_FIELD_INVALID_00:
		case PTE_FIELD_INVALID_10:
			return EK_INVALID;
		case PTE_FIELD_LVL012_BLOCK:
			return EK_BLOCK;
		case PTE_FIELD_LVL012_TABLE:
			return EK_TABLE;
		default:
			unreachable();
		};
		break;
	}
	case 3:
		switch (pte & GENMASK(1,0)) {
		case PTE_FIELD_INVALID_00:
		case PTE_FIELD_INVALID_10:
			return EK_INVALID;
		case PTE_FIELD_LVL3_RESERVED:
			return EK_RESERVED;
		case PTE_FIELD_LVL3_PAGE:
			return EK_PAGE_DESCRIPTOR;
		default:
			unreachable();
		}
		break;
	default:
		return EK_DUMMY;
	}
}


/* page-table entry kind: print entry kind */
int gp_put_ek(gp_stream_t *out, enum entry_kind ek)
{
	switch(ek) {
	case EK_INVALID:                return ghost_sprintf(out, "EK_INVALID");
	case EK_BLOCK:                  return ghost_sprintf(out, "EK_BLOCK");
	case EK_TABLE:                  return ghost_sprintf(out, "EK_TABLE");
	case EK_PAGE_DESCRIPTOR:        return ghost_sprintf(out, "EK_PAGE_DESCRIPTOR");
	case EK_BLOCK_NOT_PERMITTED:    return ghost_sprintf(out, "EK_BLOCK_NOT_PERMITTED");
	case EK_RESERVED:               return ghost_sprintf(out, "EK_RESERVED");
	case EK_DUMMY:                  return ghost_sprintf(out, "EK_DUMMY");
	}
}

/* page-table entry: print entry */
int gp_put_entry(gp_stream_t *out, kvm_pte_t pte, u8 level)
{
	u64 oa;
	enum entry_kind ek = entry_kind(pte, level);


	switch(ek) {
	case EK_INVALID:
	case EK_BLOCK:
	case EK_TABLE:
		return ghost_sprintf(out, "%g(ek)", ek);
		break;

	case EK_PAGE_DESCRIPTOR:
		oa = pte & GENMASK(47,12);
		return ghost_sprintf(out, "%g(ek) oa:%p", ek, oa);
		break;

	case EK_BLOCK_NOT_PERMITTED:
	case EK_RESERVED:
	case EK_DUMMY:
		return 0;

	default:
		unreachable();
	}

}

/* page-table: print table */
void _dump_pgtable(u64 *pgd, u8 level, u8 indent)
{
	u32 idx;
	if (pgd) {
		// dump this page
		ghost_printf("%Ilevel:%hhd table at virt:%p\n", indent, level, pgd);

		// dump each entry
		for (idx = 0; idx < 512; idx++) {
			kvm_pte_t pte = pgd[idx];
			if (pte!=0) {
				ghost_printf("%Ilevel:%hhd table at virt:%p raw:%lx %gL(entry)\n", indent+2, level, pgd+idx, pte, level);
			}
		}

		// dump any sub-pages
		for (idx = 0; idx < 512; idx++) {
			kvm_pte_t pte = pgd[idx];
			if (entry_kind(pte, level) == EK_TABLE) {
				u64 next_level_phys_address, next_level_virt_address;
				next_level_phys_address = pte & GENMASK(47,12);
				next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
				ghost_printf("%Iin level:%hhd table at virt:%p phys:%p\n", indent+2, level, next_level_virt_address, next_level_phys_address);
				_dump_pgtable((kvm_pte_t *)next_level_virt_address, level+1, indent+4);
				ghost_printf("\n");
			}
		}
	}
	else {
		ghost_printf("table address null\n");
	}
}


void dump_pgtable(struct kvm_pgtable pg)
{
	ghost_printf("ia_bits:%x ia_start_level:%d\n", pg.ia_bits, pg.start_level);
	_dump_pgtable(pg.pgd, pg.start_level, 0);
	return;
}

enum maplet_owner_annotation __parse_annot(u64 pte)
{
	switch (pte & GENMASK(63, 1)) {
	case PTE_FIELD_PKVM_OWNER_ID_HOST:
		return MAPLET_OWNER_ANNOT_OWNED_HOST;
	case PTE_FIELD_PKVM_OWNER_ID_HYP:
		return MAPLET_OWNER_ANNOT_OWNED_HYP;
	case PTE_FIELD_PKVM_OWNER_ID_GUEST:
		return MAPLET_OWNER_ANNOT_OWNED_GUEST;
	default:
		return MAPLET_OWNER_ANNOT_UNKNOWN;
	}
}

struct maplet_target_annot parse_annot(u64 desc)
{
	struct maplet_target_annot t;
	t.owner = __parse_annot(desc);
	t.raw_arch_annot = desc;
	return t;
}

struct maplet_attributes parse_attrs(ghost_stage_t stage, ghost_mair_t mair, u64 desc, u8 level, struct aal next_level_aal)
{
	// first fill in the permissions
	enum maplet_permissions perms;
	switch (stage) {
	case GHOST_STAGE1: {
		bool ro = __s1_is_ro(desc);
		bool xn = __s1_is_xn(desc);

		/* Stage1 always has R permission. */
		perms = MAPLET_PERM_R;

		/* If not read-only, also has W */
		if (!ro)
			perms |= MAPLET_PERM_W;

		/* If not e(x)-(n)ever, also has X */
		if (!xn)
			perms |= MAPLET_PERM_X;

		break;
	}
	case GHOST_STAGE2: {
		bool r = __s2_is_r(desc);
		bool w = __s2_is_w(desc);
		bool xn = __s2_is_xn(desc);

		perms = 0;

		if (r)
			perms |= MAPLET_PERM_R;

		if (w)
			perms |= MAPLET_PERM_W;

		if (!xn)
			perms |= MAPLET_PERM_X;

		/* check for bad encoding, and overrule anything we did if we find one */
		if (__s2_is_x(desc))
		 	perms = MAPLET_PERM_UNKNOWN;

		break;
	}
	case GHOST_STAGE_NONE:
		// can't parse attrs for a not-a-pagetable pte
		BUG();
	default:
		BUG();
	}

	// TODO: fill in hierarchical permissions from `next_level_aal`
	// rather than just giving up with UNKNOWN
	for (int i = 0; i < level; i++) {
		if (next_level_aal.attr_at_level[i]) {
			perms = MAPLET_PERM_UNKNOWN;
		}
	}

	// now extract the page state
	enum maplet_page_state page_state;
	// grab the software-defined bits from the upper attributes
	switch (desc & PTE_FIELD_UPPER_ATTRS_SW_MASK) {
	/* these PKVM_PAGE_x are defined to be equal to the _architectural_ bits */
	case PKVM_PAGE_OWNED:
		page_state = MAPLET_PAGE_STATE_PRIVATE_OWNED;
		break;
	case PKVM_PAGE_SHARED_OWNED:
		page_state = MAPLET_PAGE_STATE_SHARED_OWNED;
		break;
	case PKVM_PAGE_SHARED_BORROWED:
		page_state = MAPLET_PAGE_STATE_SHARED_BORROWED;
		break;
	default:
		page_state = MAPLET_PAGE_STATE_UNKNOWN;
	}

	// finally, read out the mem_attr
	enum maplet_memtype_attr memtype_attr;
	switch (stage) {
	case GHOST_STAGE1: {
		// hard case: pte contains AttrIndx, which indirects through MAIR_ELx
		u64 attr_idx = PTE_EXTRACT(PTE_FIELD_S1_ATTRINDX, desc);
		// mair must be read_mair(...) not no_mair() if asking for Stage 2
		ghost_assert(mair.present);
		switch(mair.attrs[attr_idx]) {
		case MEMATTR_FIELD_DEVICE_nGnRE:
			memtype_attr = MAPLET_MEMTYPE_DEVICE;
			break;
		case MEMATTR_FIELD_NORMAL_OUTER_INNER_WRITE_BACK_CACHEABLE:
			memtype_attr = MAPLET_MEMTYPE_NORMAL_CACHEABLE;
			break;
		default:
			memtype_attr = MAPLET_MEMTYPE_UNKNOWN;
			break;
		}
		break;
	}
	case GHOST_STAGE2:
		// easy case, MemAttr encoded directly into the pte.
		switch (PTE_EXTRACT(PTE_FIELD_S2_MEMATTR, desc)) {
		case PTE_FIELD_S2_MEMATTR_DEVICE_nGnRE:
			memtype_attr = MAPLET_MEMTYPE_DEVICE;
			break;
		case PTE_FIELD_S2_MEMATTR_NORMAL_OUTER_INNER_WRITE_BACK_CACHEABLE:
			memtype_attr = MAPLET_MEMTYPE_NORMAL_CACHEABLE;
			break;
		default:
			memtype_attr = MAPLET_MEMTYPE_UNKNOWN;
			break;
		}
		break;
	default:
		// already checked
		unreachable();
	}

	return (struct maplet_attributes){
		.prot = perms,
		.provenance = page_state,
		.memtype = memtype_attr,
		.raw_arch_attrs = desc & PTE_FIELD_ATTRS_MASK,
	};
}

struct maplet_target_mapped parse_mapped(ghost_stage_t stage, ghost_mair_t mair, u8 level, u64 oa, u64 nr_pages, u64 desc, struct aal next_level_aal)
{
	struct maplet_attributes attrs = parse_attrs(stage, mair, desc, level, next_level_aal);

	struct maplet_target_mapped m = {
		.oa_range_start = oa,
		.oa_range_nr_pages = nr_pages,
		.attrs = attrs,
	};

	return m;
}

/**
 * The number of pages a block/page mapping at level[n] covers.
 */
static u64 MAP_BLOCK_NR_PAGES[4] = {
	[0] = 0x8000000,
	[1] = 0x0040000,
	[2] = 0x0000200,
	[3] = 0x0000001,
};

void _interpret_pgtable(mapping *mapp, kvm_pte_t *pgd, struct pfn_set *pfns, ghost_stage_t stage, ghost_mair_t mair, u8 level, u64 va_partial, struct aal aal, bool noisy)
{
	if (noisy) { hyp_putsp("_interpret_pgtable "); hyp_putsxn("level", (u64)level, 8); hyp_putsxn("pgd", (u64)pgd, 64); }

	struct aal next_level_aal = aal;
	u64 nr_pages = MAP_BLOCK_NR_PAGES[level];

	for (u64 idx = 0; idx < 512; idx++) {
		u64 va_offset_in_region = idx * nr_pages * PAGE_SIZE;
		u64 va_partial_new = va_partial | va_offset_in_region;

		u64 pte = pgd[idx];
		enum entry_kind ek = entry_kind(pte, level);

		switch(ek) {
		case EK_INVALID:
			if (pte != 0)
				extend_mapping_coalesce(mapp, stage, va_partial_new, nr_pages, maplet_target_annot(parse_annot(pte)));
			break;
		case EK_BLOCK: {
			u64 oa = pte & PTE_FIELD_OA_MASK[level];
			u64 attr = pte & PTE_FIELD_ATTRS_MASK;
			if (noisy) { hyp_putsp("_interpret_pgtable block"); hyp_putsxn("va", va_partial_new, 64); hyp_putsxn("oa", oa, 64); hyp_putsxn("nr_pages", nr_pages, 64); }
			struct maplet_target_mapped t = parse_mapped(stage, mair, level, oa, nr_pages, attr, next_level_aal);
			extend_mapping_coalesce(mapp, stage, va_partial_new, nr_pages, maplet_target_mapped(va_partial_new, nr_pages, t));
			break;
		}
		case EK_TABLE: {
			u64 next_level_phys_address = pte & PTE_FIELD_TABLE_NEXT_LEVEL_ADDR_MASK;
			u64 next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
			next_level_aal.attr_at_level[level] = pte & (PTE_FIELD_UPPER_ATTRS_MASK | PTE_FIELD_TABLE_IGNORED_MASK);
			if (pfns)
				ghost_pfn_set_insert(pfns, hyp_virt_to_pfn(next_level_virt_address));
			_interpret_pgtable(mapp, (kvm_pte_t *)next_level_virt_address, pfns, stage, mair, level+1, va_partial_new, next_level_aal, noisy);
			break;
		}
		case EK_PAGE_DESCRIPTOR: {
			u64 oa = pte & PTE_FIELD_LVL3_OA_MASK;
			u64 attr = pte & PTE_FIELD_ATTRS_MASK;
			if (noisy) { hyp_putsp("_interpret_pgtable desc "); hyp_putsxn("va", va_partial_new, 64); hyp_putsxn("oa", oa, 64); }
			struct maplet_target_mapped t = parse_mapped(stage, mair, level, oa, nr_pages, attr, next_level_aal);
			extend_mapping_coalesce(mapp, stage, va_partial_new, 1, maplet_target_mapped(va_partial_new, nr_pages, t));
			break;
		}
		case EK_BLOCK_NOT_PERMITTED:
			check_assert_fail("unhandled EK_BLOCK_NOT_PERMITTED"); break;
		case EK_RESERVED:
			check_assert_fail("unhandled EK_RESERVED"); break;
		case EK_DUMMY:
			check_assert_fail("unhandled EK_DUMMY"); break;
		default:
			check_assert_fail("unhandled default");  break;
		}
	}
}

void ghost_record_pgtable_into(mapping *out, struct kvm_pgtable *pg, struct pfn_set *out_pfns, ghost_stage_t stage, ghost_mair_t mair, u64 i)
{
	//hyp_puts("interpret_pgtable");
	*out = mapping_empty_();
	struct aal aal;
	int j;

	for (j=0; j < GHOST_ATTR_MAX_LEVEL + 1; j++) {
		aal.attr_at_level[j] = 1;
	}

	if (pg)
		_interpret_pgtable(out, pg->pgd, out_pfns, stage, mair, 0, 0, aal, false);
}

mapping ghost_record_pgtable(struct kvm_pgtable *pgt, struct pfn_set *out_pfns, char *doc, u64 i)
{
	mapping map;
	bool is_s2 = pgt->mmu != NULL;
	ghost_stage_t stage = is_s2 ? GHOST_STAGE2 : GHOST_STAGE1;
	ghost_mair_t mair = is_s2 ? no_mair() : pkvm_mair();

	if (pgt->pgd == 0)
		map = mapping_empty_();
	else
		ghost_record_pgtable_into(&map, pgt, out_pfns, stage, mair, i);

	return map;
}

void ghost_record_pgtable_ap(abstract_pgtable *ap_out, struct kvm_pgtable *pgt, u64 pool_range_start, u64 pool_range_end, char *doc, u64 i)
{
	ghost_pfn_set_init(&ap_out->table_pfns, pool_range_start, pool_range_end);
	ap_out->mapping = ghost_record_pgtable(pgt, &ap_out->table_pfns, doc, i);
	ap_out->root = hyp_virt_to_phys(pgt->pgd);
}

mapping ghost_record_pgtable_and_check(mapping map_old, struct kvm_pgtable *pgt, bool dump, char *doc, u64 i)
{
	//hyp_puts("pgtable diff ");
	//hyp_puts(doc);
	//hyp_putc('\n');
	mapping map = ghost_record_pgtable(pgt, NULL, NULL, i);
	if (dump) {
		hyp_putspi(doc,i+2);
		hyp_put_mapping(map, i+4);
	}
	mapping_equal(map_old, map, "check equal", "old", doc, i+2);
	//	hyp_put_mapping(&maplets_a);
	return map;
}

mapping ghost_record_pgtable_partial(kvm_pte_t *pgtable, ghost_stage_t stage, ghost_mair_t mair, u8 level, u64 va_partial, struct aal aal_partial, char *doc, u64 i)
{
	mapping map = mapping_empty_();
	hyp_putspi(doc, i);
	hyp_putsp(" ");
	hyp_putsp("ghost_record_pgtable_2 ");
	hyp_putc('\n');
	if (pgtable==NULL) {
		hyp_putspi("pgtable==NULL\n", i);
		goto out;
	}
	_interpret_pgtable(&map, pgtable, NULL, stage, mair, level, va_partial, aal_partial, false /*noisy*/);
	hyp_put_mapping(map, i+2);
out:
	return map;
}

void abstract_pgtable_copy(abstract_pgtable *dst, abstract_pgtable *src)
{
	ghost_pfn_set_copy(&dst->table_pfns, &src->table_pfns);
	dst->mapping = mapping_copy(src->mapping);
	dst->root = src->root;
}

/// Dumping and diffing and stuff... TODO: CLEANUP

void ghost_dump_pgtable_locked(struct kvm_pgtable *pg, char *doc, u64 i)
{
	hyp_putspi(doc, i);
	hyp_putsp(" ");
	hyp_puts("ghost_dump_pgtable()\n");
	if (pg->pgd==0) {
		hyp_puts("empty");
		return;
	}
	mapping map = ghost_record_pgtable(pg, NULL, NULL, 0);
	//hyp_puts("ghost_dump_pgtable post interpret_pgtable()\n");
	hyp_put_mapping(map, i+2);
	// dump_pgtable(*pg); // to look at the raw pgtable - verbosely!
	free_mapping(map);
}


void ghost_dump_pgtable(struct kvm_pgtable *pg, char *doc, u64 i)
{
	ghost_lock_maplets();
	ghost_dump_pgtable_locked(pg,doc,i);
	ghost_unlock_maplets();
}

int gp_put_abstract_pgtable(gp_stream_t *out, abstract_pgtable *ap, u64 indent)
{
	return ghost_sprintf(
		out,
		"%g(mapping)\n"
		"%I%g(pfn_set)\n"
		"%Iroot:%p",
		&ap->mapping,
		indent, &ap->table_pfns,
		indent, ap->root
	);
}

void hyp_put_abstract_pgtable(abstract_pgtable *ap, u64 indent)
{
	ghost_printf("%gI(pgtable)", ap, indent);
}