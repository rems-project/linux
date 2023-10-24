/* Ghost code to compute the interpretation of page tables in a
   concise representation that we can use in executable assertions, as
   ordered lists of "maplet"s.  This file defines that interpretation, using
   ghost_maplets.h.
*/
#include <asm/kvm_mmu.h>

#include <nvhe/debug-pl011.h>
#include <nvhe/ghost_extra_debug-pl011.h>
#include <nvhe/ghost_pgtable.h>
#include <nvhe/memory.h>   // for hyp_phys_to_virt

#include <nvhe/ghost_pfn_set.h>
#include <nvhe/ghost_asserts.h>


#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

/* page table entry kind: classify kind of entry */
enum entry_kind entry_kind(unsigned long long pte, unsigned char level)
{
  switch(level) {
  case 0:
  case 1:
  case 2:
    {
      switch (pte & GENMASK(1,0)) {
      case ENTRY_INVALID_0:
      case ENTRY_INVALID_2:
	return EK_INVALID;
      case ENTRY_BLOCK:
	switch (level) {
	case 0:
	  return EK_BLOCK_NOT_PERMITTED;
	case 1:
        case 2:
	  return EK_BLOCK;
	}
      case ENTRY_TABLE:
	return EK_TABLE;
      default:
	// just to tell the compiler that the cases are exhaustive
	return EK_DUMMY;
      }
    }
  case 3:
    switch (pte & GENMASK(1,0)) {
    case ENTRY_INVALID_0:
    case ENTRY_INVALID_2:
      return EK_INVALID;
    case ENTRY_RESERVED:
      return EK_RESERVED;
    case ENTRY_PAGE_DESCRIPTOR:
      return EK_PAGE_DESCRIPTOR;
    }

  default:
    // just to tell the compiler that the cases are exhaustive
    return EK_DUMMY;
  }

  return EK_DUMMY;
}


/* page-table entry kind: print entry kind */
void hyp_put_ek(enum entry_kind ek)
{
        switch(ek) {
        case EK_INVALID:                hyp_putsp("EK_INVALID");                break;
        case EK_BLOCK:                  hyp_putsp("EK_BLOCK");                  break;
        case EK_TABLE:                  hyp_putsp("EK_TABLE");                  break;
        case EK_PAGE_DESCRIPTOR:        hyp_putsp("EK_PAGE_DESCRIPTOR");        break;
        case EK_BLOCK_NOT_PERMITTED:    hyp_putsp("EK_BLOCK_NOT_PERMITTED");    break;
        case EK_RESERVED:               hyp_putsp("EK_RESERVED");               break;
        case EK_DUMMY:                  hyp_putsp("EK_DUMMY");                  break;
        }
}

/* page-table entry: print entry */
void hyp_put_entry(kvm_pte_t pte, u8 level)
{
        enum entry_kind ek;
        u64 oa;
        ek = entry_kind(pte, level);
        hyp_put_ek(ek); hyp_putsp(" ");
        switch(ek) {
        case EK_INVALID:                break;
        case EK_BLOCK:                  break;
        case EK_TABLE:                  break;
        case EK_PAGE_DESCRIPTOR:
                oa = pte & GENMASK(47,12);
                hyp_putsxn("oa", oa, 64);
                break;
        case EK_BLOCK_NOT_PERMITTED:    break;
        case EK_RESERVED:               break;
        case EK_DUMMY:                  break;
        }

}

/* page-table: print table */
void _dump_pgtable(u64 *pgd, u8 level)
{
        u32 idx;
        if (pgd) {
                // dump this page
                hyp_putsxn("level",level,8);
                hyp_putsxn("table at virt", (u64)pgd, 64); hyp_puts("\n");
                for (idx = 0; idx < 512; idx++) {
                        kvm_pte_t pte = pgd[idx];
			if (pte!=0) {
				hyp_putsxn("level",level,8);
				hyp_putsxn("entry at virt",(u64)(pgd+idx),64);
				hyp_putsxn("raw",(u64)pte,64);
				hyp_put_entry(pte, level);
				hyp_puts("\n");
			}
                }
                // dump any sub-pages
                for (idx = 0; idx < 512; idx++) {
                        kvm_pte_t pte = pgd[idx];
                        if (entry_kind(pte, level) == EK_TABLE) {
                                u64 next_level_phys_address, next_level_virt_address;
                                next_level_phys_address = pte & GENMASK(47,12);
                                next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
                                hyp_putsxn("table phys", next_level_phys_address, 64);
                                hyp_putsxn("table virt", next_level_virt_address, 64);
				hyp_puts("\n");
                                _dump_pgtable((kvm_pte_t *)next_level_virt_address, level+1);
                                hyp_puts("\n");
                        }
                }
        }
        else {
                hyp_puts("table address null");
        }
}


void dump_pgtable(struct kvm_pgtable pg)
{
        hyp_putsxn("ia_bits", pg.ia_bits, 32);
        hyp_putsxn("ia_start_level", pg.start_level, 32);
        hyp_puts("");
        _dump_pgtable(pg.pgd, pg.start_level);

        return;
}


void _interpret_pgtable(mapping *mapp, kvm_pte_t *pgd, struct pfn_set *pfns, u8 level, u64 va_partial, struct aal aal, bool noisy)
{
        u64 idx;
        u64 va_partial_new;
        kvm_pte_t pte;
        enum entry_kind ek;
        u64 next_level_phys_address, next_level_virt_address;
	struct aal next_level_aal;
        u64 oa;
	u64 fake_oa;
	u64 attr;
	u64 nr_pages;

	if (noisy) { hyp_putsp("_interpret_pgtable "); hyp_putsxn("level", (u64)level, 8); hyp_putsxn("pgd", (u64)pgd, 64); }

	next_level_aal = aal;

        for (idx = 0; idx < 512; idx++) {
		//if (noisy) { hyp_putsxn("idx", idx, 16); }
                switch (level) {
                case 0: va_partial_new = va_partial | (idx << 39); break;
                case 1: va_partial_new = va_partial | (idx << 30); break;
                case 2: va_partial_new = va_partial | (idx << 21); break;
                case 3: va_partial_new = va_partial | (idx << 12); break;
                default: check_assert_fail("unhandled level"); // cases are exhaustive
                }

                pte = pgd[idx];

                ek = entry_kind(pte, level);
                switch(ek) {
                case EK_INVALID:
			if (pte != 0) {
				fake_oa = (pte >> 1) | GENMASK(63,63);
				nr_pages = 1; // TODO
				extend_mapping_coalesce(mapp, va_partial_new, nr_pages, maplet_target_annot(pte & GENMASK(61,1)));
			}
			break;
                case EK_BLOCK:
// G.b p2742 4KB translation granule has a case split on whether "the Effective value of TCR_ELx.DS or VTCR_EL2.DS is 1". DS is for 52-bit output addressing with FEAT_LPA2, and is zero in the register values we see; I'll hard-code that for now.  Thus, G.b says:
// - For a level 1 Block descriptor, bits[47:30] are bits[47:30] of the output address. This output address specifies a 1GB block of memory.
// - For a level 2 Block descriptor, bits[47:21] are bits[47:21] of the output address.This output address specifies a 2MB block of memory.
			switch (level) {
			case 1:
				oa = pte & GENMASK(47,30);
				nr_pages = /* 1GB/4K */ 0x40000;
				break;
			case 2:
				oa = pte & GENMASK(47,21);
				nr_pages = /* 2MB/4K */ 0x200;
				break;
			default:
				check_assert_fail("_interpret_pgtable bad block level");
				break;
			}
                        if (noisy) { hyp_putsp("_interpret_pgtable block"); hyp_putsxn("va", va_partial_new, 64); hyp_putsxn("oa", oa, 64); hyp_putsxn("nr_pages", nr_pages, 64); }
			/* These attribute bitmasks follow DDI 0478H.a D5-4840 for 4k granule 48-bit OA.  D5-4846 confusingly shows nT at [16] and OA (RES0 if FEAT_LPA not implemented) at [15:12]; not sure what's going on there.  */
			attr = pte & (GENMASK(63,50) | GENMASK(11,2)); // punting on hierarchical aspects of attributes
                        extend_mapping_coalesce(mapp, va_partial_new, nr_pages, maplet_target_mapped(oa, attr, next_level_aal));
                        break;
		case EK_TABLE:
                        next_level_phys_address = pte & GENMASK(47,12);
                        next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
                        //hyp_putsxn("table phys", next_level_phys_address, 64);
                        //hyp_putsxn("table virt", next_level_virt_address, 64);
			next_level_aal.attr_at_level[level] = pte & (GENMASK(63,59) | GENMASK(58,51) | GENMASK(11,2)); // the first are actual attributes, the second and third are Ignored bits
			if(pfns)
				ghost_pfn_set_insert(pfns, hyp_virt_to_pfn(next_level_virt_address));
                        _interpret_pgtable(mapp, (kvm_pte_t *)next_level_virt_address, pfns, level+1, va_partial_new, next_level_aal, noisy); break;
                case EK_PAGE_DESCRIPTOR:
                        oa = pte & GENMASK(47,12);
                        // hyp_putsxn("oa", oa, 64);
                        // now add (va_partial, oa) to the mappings
                        if (noisy) { hyp_putsp("_interpret_pgtable desc "); hyp_putsxn("va", va_partial_new, 64); hyp_putsxn("oa", oa, 64); }
			attr = pte & (GENMASK(63,50) | GENMASK(11,2)); // punting on hierarchical aspects of attributes
                        extend_mapping_coalesce(mapp, va_partial_new, 1, maplet_target_mapped(oa, attr, next_level_aal));
                        break;
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


// a caller is allowed to set @pfns to NULL if they don't care about the pfn set
mapping interpret_pgtable(kvm_pte_t *pgd, struct pfn_set *pfns, bool noisy)
{
	//hyp_puts("interpret_pgtable");
	mapping map = mapping_empty_();
	struct aal aal;
	int j;
	for (j=0; j<GHOST_ATTR_MAX_LEVEL; j++)
		aal.attr_at_level[j]=1;
	if (pgd==0)
		//hyp_puts("empty");
		return map;
	else
	{
		if(pfns)
			ghost_pfn_set_insert(pfns, hyp_virt_to_pfn(pgd));
		_interpret_pgtable(&map, pgd, pfns, 0, 0, aal, noisy);
		//hyp_put_mapping(map,2);
		return map;
	}
}


void interpret_pgtable_ap(abstract_pgtable *ap_out, kvm_pte_t *pgd, u64 pool_range_start, u64 pool_range_end, bool noisy)
{
	ghost_pfn_set_init(&ap_out->table_pfns, pool_range_start, pool_range_end);
	if (pgd==0) {
		ap_out->root = 0;
		ap_out->mapping=mapping_empty_();
	}
	else {
		ap_out->root = hyp_virt_to_phys(pgd);
		ap_out->mapping=interpret_pgtable(pgd, &ap_out->table_pfns, noisy);
	}
}


void ghost_dump_pgtable_locked(struct kvm_pgtable *pg, char *doc, u64 i)
{
	hyp_putspi(doc, i);
	hyp_putsp(" ");
	hyp_puts("ghost_dump_pgtable()\n");
	if (pg->pgd==0) {
		hyp_puts("empty");
		return;
	}
	mapping map = interpret_pgtable(pg->pgd, NULL, false /*noisy*/);
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

mapping ghost_record_pgtable(struct kvm_pgtable *pg, char *doc, u64 i)
{
	//hyp_puts("ghost_record_pgtable() ");
	//hyp_puts(doc);
	//hyp_putc('\n');
	mapping map = interpret_pgtable(pg->pgd, NULL, false /*noisy*/);
	//	hyp_put_mapping(map, i+2)
	return map;
}


void ghost_record_pgtable_ap(abstract_pgtable *ap_out, struct kvm_pgtable *pg, u64 pool_range_start, u64 pool_range_end, char *doc, u64 i)
{
	//hyp_puts("ghost_record_pgtable() ");
	//hyp_puts(doc);
	//hyp_putc('\n');
	interpret_pgtable_ap(ap_out, pg->pgd, pool_range_start, pool_range_end, false /*noisy*/);
	//	hyp_put_mapping(map, i+2)
}


mapping ghost_record_pgtable_and_check(mapping map_old, struct kvm_pgtable *pg, bool dump, char *doc, u64 i)
{
	//hyp_puts("pgtable diff ");
	//hyp_puts(doc);
	//hyp_putc('\n');
	mapping map = interpret_pgtable(pg->pgd, NULL, false /*noisy*/);
	if (dump) {
		hyp_putspi(doc,i+2);
		hyp_put_mapping(map, i+4);
	}
	mapping_equal(map_old, map, "check equal", "old", doc, i+2);
	//	hyp_put_mapping(&maplets_a);
	return map;
}

void ghost_record_pgtable_and_check_ap(abstract_pgtable *ap_new, abstract_pgtable *ap_old, struct kvm_pgtable *pg, bool dump, u64 pool_range_start, u64 pool_range_end, char *doc, u64 i)
{
	//hyp_puts("pgtable diff ");
	//hyp_puts(doc);
	//hyp_putc('\n');
	interpret_pgtable_ap(ap_new, pg->pgd, pool_range_start, pool_range_end, false /*noisy*/);
	if (dump) {
		hyp_putspi(doc,i+2);
		hyp_put_mapping(ap_new->mapping, i+4);
	}
	mapping_equal(ap_old->mapping, ap_new->mapping, "check equal", "old", doc, i+2);
	//	hyp_put_mapping(&maplets_a);
}



mapping ghost_record_pgtable_partial(kvm_pte_t *pgtable, u64 level, u64 va_partial, struct aal aal_partial,  char *doc, u64 i)
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
	_interpret_pgtable(&map, pgtable, NULL, level, va_partial, aal_partial, false /*noisy*/);
	hyp_put_mapping(map, i+2);
out:
	return map;
}



void ghost_dump_pgtable_diff(mapping map_old, struct kvm_pgtable *pg, char *doc, u64 i)
{
	ghost_lock_maplets();
	hyp_putspi(doc, i);
	hyp_putsp(" ");
	hyp_puts("ghost_dump_pgtable_diff\n");
	mapping map = interpret_pgtable(pg->pgd, NULL, false /*noisy*/);
	diff_mappings(map_old, map, i+2);
	//	hyp_put_mapping(&maplets_a);
	free_mapping(map);
	hyp_putspi("end ghost_dump_pgtable_diff\n", i);
	ghost_unlock_maplets();
}


void ghost_dump_pgtable_diff_ap(abstract_pgtable *ap_old, struct kvm_pgtable *pg, char *doc, u64 i)
{
	mapping map_old = ap_old->mapping;
	ghost_dump_pgtable_diff(map_old, pg, doc, i);
}


void ghost_test(void) {
}

void abstract_pgtable_copy(abstract_pgtable *dst, abstract_pgtable *src)
{
	dst->root = src->root;
	ghost_pfn_set_copy(&dst->table_pfns, &src->table_pfns);
	dst->mapping = mapping_copy(src->mapping);
}
