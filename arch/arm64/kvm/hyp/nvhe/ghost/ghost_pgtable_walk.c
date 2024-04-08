/* this isn't used in the current ghost instrumentation */

/*************************************************************************
 * Page table walk related data structures
 *************************************************************************/

// Page table walk

enum Fault {
  Fault_None,
  Fault_AccessFlag,
  Fault_Alignment,
  Fault_Background,
  Fault_Domain,
  Fault_Permission,
  Fault_Translation,
  Fault_AddressSize,
  Fault_SyncExternal,
  Fault_SyncExternalOnWalk,
  Fault_SyncParity,
  Fault_SyncParityOnWalk,
  Fault_AsyncParity,
  Fault_AsyncExternal,
  Fault_Debug,
  Fault_TLBConflict,
  Fault_BranchTarget,
  Fault_HWUpdateAccessFlag,
  Fault_Lockdown,
  Fault_Exclusive,
  Fault_ICacheMaint,
  Fault_Unreachable // dummy value added by PS
};

/* [XXX(JK) - I commented out the following part because 
struct
[[rc::refined_by("statuscode : Z")]]
[[rc::ptr_type("fault_record : ...")]]
FaultRecord {
  [[rc::field("statuscode @ int<u32>")]]
  enum Fault statuscode; // Fault Status
  //  AccType acctype; // Type of access that faulted
  //  FullAddress ipaddress; // Intermediate physical address
  //  boolean s2fs1walk; // Is on a Stage 1 page table walk
  //  boolean write; // TRUE for a write, FALSE for a read
  //  integer level; // For translation, access flag and permission faults
  //  bit extflag; // IMPLEMENTATION DEFINED syndrome for external aborts
  //  boolean secondstage; // Is a Stage 2 abort
  //  bits(4) domain; // Domain number, AArch32 only
  //  bits(2) errortype; // [Armv8.2 RAS] AArch32 AET or AArch64 SET
  //  bits(4) debugmoe; // Debug method of entry, from AArch32 only
};

struct 
FullAddress {
  unsigned long long address; // bits(52) address;
  // Can we annotate it with 1
  int NS; // bit NS; // '0' = Secure, '1' = Non-secure
};

struct 
AddressDescriptor {
  struct FaultRecord fault; // fault.statuscode indicates whether the address is valid
  //  MemoryAttributes memattrs;
  struct FullAddress paddress;
  unsigned long long vaddress; // bits(64) vaddress;
};

//struct Permissions {
// bits(3) ap; // Access permission bits
// bit xn; // Execute-never bit
// bit xxn; // [Armv8.2] Extended execute-never bit for stage 2
// bit pxn // Privileged execute-never bit
//}

struct TLBRecord {
 	//  Permissions        perms;
	//  bit 	             nG;	   // '0' = Global, '1' = not Global
	//  bits(4)	     domain;	   // AArch32 only
	//  bit		     GP;	   // Guarded Page
	//  boolean	     contiguous;   // Contiguous bit from page table
	//  integer	     level;	   // AArch32 Short-descriptor format: Indicates Section/Page
	//  integer	     blocksize;    // Describes size of memory translated in KBytes
	//  DescriptorUpdate   descupdate;   // [Armv8.1] Context for h/w update of table descriptor
	//  bit		     CnP;	   // [Armv8.2] TLB entry can be shared between different PEs
	struct AddressDescriptor  addrdesc;
};
*/ 

struct
TLBRecord {
  // flattend AddressDescriptor
  // - flattened FaultRecord (statuscode)
  enum Fault statuscode; 
  // - flattend FullAddress (address, NS)
  unsigned long long address;
  unsigned int NS; // bit NS; // '0' = secure, '1' = non-secure
  unsigned long long vaddress;
};

#define TLB_REC 0
#define INTERMEDIATE_ADDR 1

struct
LEVEL012_result {
  unsigned int decision; 

  unsigned long long intermediate_address;

  enum Fault statuscode; 
  unsigned long long address;
  unsigned int NS; // bit NS; // '0' = secure, '1' = non-secure
  unsigned long long vaddress;
};

struct TLBRecord mkFault(unsigned long long vaddress) {
  struct TLBRecord result;
  result.statuscode = Fault_Translation;
  result.address = 0;
  result.NS = 0;
  result.vaddress = vaddress;

  return result;
}


struct TLBRecord mkUnreachable(unsigned long long vaddress) {
  struct TLBRecord result;
  result.statuscode = Fault_Unreachable;
  result.address = 0;
  result.NS = 0;
  result.vaddress = vaddress;

  return result;
}


struct TLBRecord mkTranslation(unsigned long long vaddress, unsigned long long pa) {
  struct TLBRecord result;
  result.statuscode = Fault_None;
  result.address = pa;
  result.NS = 1;
  result.vaddress = vaddress;

  // hyp_putsxn("mkTranslation Fault_none",(u64)result.statuscode,64);

  return result;
}


struct TLBRecord mkTLBRecord(enum Fault stat, unsigned long long pa,
			     unsigned int ns, unsigned long long vaddress) {
  struct TLBRecord result;
  result.statuscode = stat; 
  result.address = pa;
  result.NS = ns; 
  result.vaddress = vaddress;
  
  return result;
}

/* [XXX(JK) - this one is not working with the current RefinedC. Missing this
 * feature is already reported.
struct TLBRecord mkFault_error(unsigned long long vaddress) {
  struct TLBRecord r = 
    { .addrdesc = { .fault = { .statuscode=Fault_Translation },
      .paddress =  { .address=0, .NS=0 }, .vaddress = vaddress } };
  // massively oversimplified
  return r;
} 

struct TLBRecord mkTranslation(uint64_t vaddress, uint64_t pa) {
  struct TLBRecord r =
    { .addrdesc = { .fault = { .statuscode=Fault_None }, 
      .paddress =  { .address=pa, .NS=1 }, .vaddress = vaddress } };
  // massively oversimplified
  return r;
}
*/

struct LEVEL012_result mkFaultLevel012 (unsigned long long vaddress) {
  struct LEVEL012_result result;
  result.decision = TLB_REC;
  result.intermediate_address = 0;

  result.statuscode = Fault_Translation;
  result.address = 0;
  result.NS = 0;
  result.vaddress = vaddress;

  return result;
}

struct LEVEL012_result mkUnreachableLevel012 (unsigned long long vaddress) {
  struct LEVEL012_result result;
  result.decision = TLB_REC;
  result.intermediate_address = 0;

  result.statuscode = Fault_Unreachable;
  result.address = 0;
  result.NS = 0;
  result.vaddress = vaddress;

  return result;
}


struct LEVEL012_result mkTranslationLevel012 (unsigned long long vaddress,
					      unsigned long long pa) {
  struct LEVEL012_result result;
  result.decision = TLB_REC;
  result.intermediate_address = 0;

  result.statuscode = Fault_None;
  result.address = pa;
  result.NS = 1;
  result.vaddress = vaddress;

  return result;
}

struct LEVEL012_result mkIntermediateLevel012 (unsigned long long intermediate) {
  struct LEVEL012_result result;
  result.decision = INTERMEDIATE_ADDR;  
  result.intermediate_address = intermediate;

  result.statuscode = Fault_None;
  result.address = 0;
  result.NS = 0;
  result.vaddress = 0;

  return result;
}

struct TLBRecord extractTLBRecord(struct LEVEL012_result res) {
  return mkTLBRecord(res.statuscode, res.address, res.NS, res.vaddress);
}

/*************************************************************************
 * Page table walk functions
 *************************************************************************/

// aarch64/translation/walk/AArch64.TranslationTableWalk
// TLBRecord AArch64.TranslationTableWalk(bits(52) ipaddress, boolean s1_nonsecure, bits(64) vaddress, AccType acctype, boolean iswrite, boolean secondstage, boolean s2fs1walk, integer size)

// There's a lot of detailed code here, but most relates to options
// that I think are irrelevant for us. The actual walk is the repeat
// loop on p7729-7730.  For now, I'll try for something clean that
// handles only the basic VA->PA part, ignoring attributes etc., not
// to follow the ASL closely.

// I've done this recursively, but we might well want to unfold
// explicitly, eg to more easily check the correspondence between
// the ASL and the compiled implementation of this

// Need to add range valeus for the mask if we hope to add invariants in here
unsigned long long AArch64_get_offset (unsigned long long vaddress,
				       unsigned char level) {
  
  unsigned long long offset = 0; // offset in bytes of entry from table_base
  
  switch (level) {
    case 0: offset = (vaddress & GENMASK(47,39)) >> (39-3); break;
    case 1: offset = (vaddress & GENMASK(38,30)) >> (30-3); break;
    case 2: offset = (vaddress & GENMASK(29,21)) >> (21-3); break;
    case 3: offset = (vaddress & GENMASK(20,12)) >> (12-3); break;
  }

  return offset;
}

struct TLBRecord AArch64_TranslationTableWalk_Level3(unsigned long long table_base,
						     unsigned long long vaddress) {
  unsigned long long pte; 

  unsigned long long offset; // offset in bytes of entry from table_base
  unsigned long long * table_base_ptr = (unsigned long long *)table_base;
  struct TLBRecord res;
  offset = AArch64_get_offset(vaddress, 3);
  
  // uintptr_t tbval = (uintptr_t) table_base;  
  // pte = *((unsigned long long*)(table_base + offset));
  pte = table_base_ptr[offset >> 3];  // PS fix to (presumably) JK adaption: offset is in bytes
  /* 
  pte = *((unsigned long long*)(((unsigned long long)table_base) + offset));
  */

//	hyp_putsp("AArch64_TranslationTableWalk_Level3: ");
//	hyp_putsxn("table_base",table_base,64);
//	hyp_putsxn("vaddress",vaddress,64);
//	hyp_putsxn("offset",offset,64);
//	hyp_putsxn("pte",pte,64);
//	hyp_putc('\n');


  switch (pte & GENMASK(1,0)) {
    case ENTRY_INVALID_0:
    case ENTRY_INVALID_2:
    case ENTRY_BLOCK:
      // invalid or fault entry
      return mkFault(vaddress);
    case ENTRY_PAGE_DESCRIPTOR: // page descriptor
	    //  hyp_putsp("AArch64_TranslationTableWalk_Level3: returning mkTranslation(...) ");
	    res = mkTranslation(vaddress, (pte & GENMASK(47,12)) | (vaddress & GENMASK(11,0)));
	    // hyp_putsxn("AArch64_TranslationTableWalk_Level3: res.statuscode",(u64)res.statuscode,64);
	    return res;
  }

  return mkUnreachable(vaddress);
}

struct LEVEL012_result AArch64_TranslationTableWalk_Level012(unsigned long long table_base, 
    unsigned char level,
    unsigned long long vaddress) {
  unsigned long long pte; 

  unsigned long long offset; // offset in bytes of entry from table_base
  unsigned long long * table_base_ptr = (unsigned long long *)table_base;
  offset = AArch64_get_offset(vaddress, level);
  
  // uintptr_t tbval = (uintptr_t) table_base;  
  // pte = *((unsigned long long*)(table_base + offset));
  pte = table_base_ptr[offset >> 3];
  /*
  pte = *((unsigned long long*)(((unsigned long long)table_base) + offset));
  */

//	hyp_putsp("AArch64_TranslationTableWalk_Level012: ");
//	hyp_putsxn("table_base",table_base,64);
//	hyp_putsxn("level",level,64);
//	hyp_putsxn("vaddress",vaddress,64);
//	hyp_putsxn("offset",offset,64);
//	hyp_putsxn("pte",pte,64);
//	hyp_putc('\n');

  
  switch (pte & GENMASK(1,0)) {
    case ENTRY_INVALID_0:
    case ENTRY_INVALID_2:
      return mkFaultLevel012(vaddress);
    case ENTRY_BLOCK:
      switch (level) {
        case 0:
          return mkFaultLevel012(vaddress);
        case 1:
          return mkTranslationLevel012(vaddress, (pte & GENMASK(47,30)) | (vaddress & GENMASK(29,0)));
        case 2:
          return mkTranslationLevel012(vaddress, (pte & GENMASK(47,21)) | (vaddress & GENMASK(20,0)));
      }
    case ENTRY_TABLE: // recurse
      {
        unsigned long long table_base_next_phys, table_base_next_virt;
	// XXX(JK) - How can we identify the following line?
	// XXX(JK) - we need to ensure that the result of the following GENMASK value
	// should be a valid pointer... 
	/*
        table_base_next_virt = 
          (unsigned long long)hyp_phys_to_virt
           ((phys_addr_t)table_base_next_phys);
	*/
        table_base_next_phys = pte & GENMASK(47,12);
        table_base_next_virt = (unsigned long long)hyp_phys_to_virt(table_base_next_phys);
        return mkIntermediateLevel012(table_base_next_virt); 
      }
  }

  return mkUnreachableLevel012(vaddress);
}

struct TLBRecord AArch64_TranslationTableWalk(unsigned long long table_base,
                             unsigned long long level,
                             unsigned long long vaddress) {
        // these declarations should really be combined with their
        // initialisations below, but the compiler complains that ISO C90
        // forbids mixed declations and code

//	hyp_putsp("AArch64_TranslationTableWalk: ");
//	hyp_putsxn("table_base",table_base,64);
//	hyp_putsxn("level",level,64);
//	hyp_putsxn("vaddress",vaddress,64);
//	hyp_putc('\n');
  switch (level) {
    case 0:
    case 1:
    case 2:
      {
	struct LEVEL012_result res = AArch64_TranslationTableWalk_Level012(table_base, level, vaddress);
        if (res.decision == TLB_REC) {
          return extractTLBRecord(res);
	  // return extractTLBRecord(0, 0, 0, 0, 0, 0);
        } else {
          /*
	  unsigned long long new_ptable_base
	    = (unsigned long long)copy_alloc_id(res.intermediate_address, (void*) res.intermediate_address);
            */
          unsigned long long new_ptable_base = res.intermediate_address;
          return AArch64_TranslationTableWalk(new_ptable_base, level + 1, vaddress); // PS: the JK version didn't actually return this; it just computed and discarded it
	  }
      }
    case 3:
      return AArch64_TranslationTableWalk_Level3(table_base, vaddress);
  }

  return mkUnreachable(vaddress);
}



/*********************************************
 * Top level function for the address translation
 * ******************************************/

// aarch64/translation/translation/AArch64.FirstStageTranslate
// =============================
// Perform a stage 1 translation walk. The function used by Address Translation operations is
// similar except it uses the translation regime specified for the instruction.
// AddressDescriptor AArch64.FirstStageTranslate(bits(64) vaddress, AccType acctype, boolean iswrite, boolean wasaligned, integer size)

struct
FaultRecord {
  enum Fault statuscode; // Fault Status
  //  AccType acctype; // Type of access that faulted
  //  FullAddress ipaddress; // Intermediate physical address
  //  boolean s2fs1walk; // Is on a Stage 1 page table walk
  //  boolean write; // TRUE for a write, FALSE for a read
  //  integer level; // For translation, access flag and permission faults
  //  bit extflag; // IMPLEMENTATION DEFINED syndrome for external aborts
  //  boolean secondstage; // Is a Stage 2 abort
  //  bits(4) domain; // Domain number, AArch32 only
  //  bits(2) errortype; // [Armv8.2 RAS] AArch32 AET or AArch64 SET
  //  bits(4) debugmoe; // Debug method of entry, from AArch32 only
};

struct
FullAddress {
  unsigned long long address; // bits(52) address;
  // Can we annotate it with 1
  int NS; // bit NS; // '0' = Secure, '1' = Non-secure
};

struct
AddressDescriptor {
  struct FaultRecord fault; // fault.statuscode indicates whether the address is valid
  //  MemoryAttributes memattrs;
  struct FullAddress paddress;
  unsigned long long vaddress; // bits(64) vaddress;
};

struct AddressDescriptor AArch64_FirstStageTranslate(uint64_t table_base, uint64_t vaddress /*, AccType acctype, boolean iswrite, boolean wasaligned, integer size*/) {

  struct AddressDescriptor S1;
  /* S1 = AArch64.TranslationTableWalk(ipaddress, TRUE, vaddress, acctype, iswrite, secondstage, s2fs1walk, size); */
  struct TLBRecord TLBValue = AArch64_TranslationTableWalk(table_base, 0, vaddress);

  S1.fault.statuscode = TLBValue.statuscode;
  S1.paddress.address = TLBValue.address;
  S1.paddress.NS = TLBValue.NS;
  S1.vaddress = TLBValue.vaddress;

//	hyp_putsp("AArch64_FirstStageTranslate returning: ");
//	hyp_putsxn("S1.fault.statuscode",(u64)S1.fault.statuscode,64);
//	hyp_putsxn("S1.paddress.address",(u64)S1.paddress.address,64);
//	hyp_putsxn("S1.vaddress",(u64)S1.vaddress,64);
//	hyp_putc('\n');


  return S1;
}

/**********************************************
 * End of address translation
**********************************************/







/* ************************************************************************** */
/* forwards check, that intended mapping_reqs are included in the actual page tables
 * ignoring prot for now
 */
/* check that a specific virt |-> (phys,prot) is included in the pagetables at pgd,
 * using the Armv8-A page-table walk function
 */
bool _check_hyp_mapping_fwd(u64 virt, phys_addr_t phys, enum kvm_pgtable_prot prot, kvm_pte_t *pgd)
{

        struct AddressDescriptor ad = AArch64_FirstStageTranslate((uint64_t)pgd, virt);

        switch (ad.fault.statuscode) {
        case Fault_None:
                if (ad.paddress.address == phys)
			return true;
		else
		hyp_putsp("_check_hyp_mapping_fwd failed: ");
                hyp_putsxn("virt",virt,64);
                hyp_putsxn("phys",phys,64);
		hyp_putsxn("translate-phys",ad.paddress.address,64);
                hyp_put_prot(prot);
		return false;

        default:
		hyp_putsp("_check_hyp_mapping_fwd failed for: ");
                hyp_putsxn("virt",virt,64);
                hyp_putsxn("phys",phys,64);
                hyp_put_prot(prot);
		hyp_putsxn("ad.fault.statuscode",(u32)ad.fault.statuscode,32);
		return false;
        }
}


/* check the `mapping` range of pages are included in the pagetables at `pgd` */
bool check_hyp_mapping_fwd(struct mapping *mapping, kvm_pte_t *pgd, bool noisy)
{
        u64 i;
        bool ret;

        ret = true;
        for (i=0; i<mapping->size; i++)
                ret = ret && _check_hyp_mapping_fwd(mapping->virt + i*PAGE_SIZE, mapping->phys + i*PAGE_SIZE, mapping->prot, pgd);

        if (noisy) {
                hyp_putsp("check_hyp_mapping_fwd ");
                hyp_putbool(ret);
                hyp_putc(' ');
                hyp_put_mapping(mapping);
                hyp_putc('\n');
        }
        return ret;
}

/* check that all the mappings recorded in `mappings` are included in the pagetables at `pgd` */
bool check_hyp_mappings_fwd(struct mappings *mappings, kvm_pte_t *pgd, bool noisy)
{
        bool ret;
        u64 i;
        ret = true;
	if (mappings->count == 0) return true;
        for (i=0; i < mappings->count; i++) {
                ret = ret && check_hyp_mapping_fwd(&mappings->m[i], pgd, noisy);
        }
        hyp_putsp("check_hyp_mappings_fwd "); hyp_putbool(ret); hyp_putc('\n'); 
        return ret;
}

/* **************************************************************************
 * reverse check, that  all the mappings in the pagetables at `pgd` are included in those recorded in `mappings`
 */

// Mathematically one would do this with a single quantification over
// all virtual addresses, using the Arm ASL translate function for
// each, but that would take too long to execute.  So we have to
// duplicate some of the walk code.  We could reuse pgtable.c here -
// but we want an independent definition that eventually we can prove
// relates to the Arm ASL.  For now, I'll just hack something up,
// adapting the above hacked-up version of the walk code.

// At a higher level, instead of doing two inclusion checks, we could
// compute a more explicit representation of the denotation of a page
// table and of the collection of mappings and check equality. That
// would be mathematically cleaner but more algorithmically complex,
// and involve more allocation.  We do that below.

// check (virt,phys) is in at least one of the `mappings`
bool _check_hyp_mappings_rev(struct mappings *mappings, u64 virt, phys_addr_t phys, bool noisy)
{
        int i;
        u64 occs;
        occs=0;
        for (i=0; i < mappings->count; i++) {
                if (virt >= mappings->m[i].virt && virt < mappings->m[i].virt + PAGE_SIZE*mappings->m[i].size && phys == mappings->m[i].phys + (virt - mappings->m[i].virt)) {
                        occs++;
                        if (noisy) {
                                hyp_put_mapping_kind(mappings->m[i].kind);
                                hyp_putc(' ');
                                if (occs > 1) hyp_putsp("duplicate ");
                        }
                }
        }
        if (noisy)
                if (occs == 0) hyp_putsp("not found ");
        return (occs >= 1);
}

// very crude recurse over the Armv8-A page tables at `pgd`, checking that each leaf
// (virt,phys) is in at least one of the mappings
bool check_hyp_mappings_rev(struct mappings *mappings, kvm_pte_t *pgd, u8 level, u64 va_partial, bool noisy);
bool check_hyp_mappings_rev(struct mappings *mappings, kvm_pte_t *pgd, u8 level, u64 va_partial, bool noisy)
{
        bool ret, entry;
        u64 idx;
        u64 va_partial_new;
        kvm_pte_t pte;
        enum entry_kind ek;
        u64 next_level_phys_address, next_level_virt_address;
        u64 oa;
        ret = true;
        for (idx = 0; idx < 512; idx++) {
                switch (level) {
                case 0: va_partial_new = va_partial | (idx << 39); break;
                case 1: va_partial_new = va_partial | (idx << 30); break;
                case 2: va_partial_new = va_partial | (idx << 21); break;
                case 3: va_partial_new = va_partial | (idx << 12); break;
                default: hyp_puts("unhandled level"); // cases are exhaustive
                }

                pte = pgd[idx];

                ek = entry_kind(pte, level);
                switch(ek) {
                case EK_INVALID:
                        entry = true; break;
                case EK_BLOCK:
                        check_assert_fail("unhandled EK_BLOCK");
                        entry = false; break;
                case EK_TABLE:
                        next_level_phys_address = pte & GENMASK(47,12);
                        next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
                        //hyp_putsxn("table phys", next_level_phys_address, 64);
                        //hyp_putsxn("table virt", next_level_virt_address, 64);
                        entry =check_hyp_mappings_rev(mappings, (kvm_pte_t *)next_level_virt_address, level+1, va_partial_new, noisy);
                        break;
                case EK_PAGE_DESCRIPTOR:
                        oa = pte & GENMASK(47,12);
                        // hyp_putsxn("oa", oa, 64);
                        // now check (va_partial, oa) is in one of the mappings
                        if (noisy) { check_assert_fail("check_hyp_mappings_rev "); hyp_putsxn("va", va_partial_new, 64); hyp_putsxn("oa", oa, 64); }
                        entry = _check_hyp_mappings_rev(mappings, va_partial_new, oa, noisy);
                        if (noisy) { hyp_putbool(entry); hyp_putc('\n'); }
                        break;
                case EK_BLOCK_NOT_PERMITTED:
                        check_assert_fail("unhandled EK_BLOCK_NOT_PERMITTED");
                        entry = false;
                        break;
                case EK_RESERVED:
                        check_assert_fail("unhandled EK_RESERVED");
                        entry = false;
                        break;
                case EK_DUMMY:
                        check_assert_fail("unhandled EK_DUMMY");
                        entry = false;
                        break;
                default:
                        check_assert_fail("unhandled default");
                        entry = false;
                        break;
                }
                ret = ret && entry;
        }
        if (level == 0) { hyp_putsp("check_hyp_mappings_rev "); hyp_putbool(ret); hyp_putc('\n'); }
        return ret;
}

/* **************************************************************************
 * check forward and reverse inclusions of the mappings in the pagetables at `pgd` and those recorded in `mappings`
 */

// call with hyp_pgtable.pgd to check putative mappings as described
// in hyp_pgtable, before the switch.  After the switch, we can do the
// same but using the then-current TTBR0_EL2 value instead of the
// hyp_pgtable.pgd


bool check_hyp_mappings_both(struct mappings *mappings, kvm_pte_t *pgd, bool noisy)
{
        bool ret, fwd, rev;
        fwd = check_hyp_mappings_fwd(mappings, pgd, noisy);
        rev = check_hyp_mappings_rev(mappings, pgd, 0, 0, noisy);

        // and we need to check disjointness of most of them. Disjointness
        // in a world with address translation is interesting... and there's
        // also read-only-ness and execute permissions to be taken into
        // account

        ret = fwd && rev;
        hyp_putsp("check_hyp_mappings_both: "); hyp_putbool(ret); hyp_putc('\n');
        return ret;
}
















/* *********************************************************** */
// compute interpretation of pagetables at `pgd`, ms = [[pgd]]

void _interpret_pgtable(struct list_head *maplets_list, struct maplets *maplets_pool, kvm_pte_t *pgd, u8 level, u64 va_partial, bool noisy)
{
        u64 idx;
        u64 va_partial_new;
        kvm_pte_t pte;
        enum entry_kind ek;
        u64 next_level_phys_address, next_level_virt_address;
        u64 oa;

        for (idx = 0; idx < 512; idx++) {
                switch (level) {
                case 0: va_partial_new = va_partial | (idx << 39); break;
                case 1: va_partial_new = va_partial | (idx << 30); break;
                case 2: va_partial_new = va_partial | (idx << 21); break;
                case 3: va_partial_new = va_partial | (idx << 12); break;
                default: check_assert_fail("unhandled level"); // cases are exhaustive
                }

                pte = pgd[idx];

                ek = entry_kind(pte, level);
                switch(ek)
                {
                case EK_INVALID:             break;
                case EK_BLOCK:             check_assert_fail("unhandled EK_BLOCK"); break;
                case EK_TABLE:
                        next_level_phys_address = pte & GENMASK(47,12);
                        next_level_virt_address = (u64)hyp_phys_to_virt((phys_addr_t)next_level_phys_address);
                        //hyp_putsxn("table phys", next_level_phys_address, 64);
                        //hyp_putsxn("table virt", next_level_virt_address, 64);
                        _interpret_pgtable(maplets_list, maplets_pool, (kvm_pte_t *)next_level_virt_address, level+1, va_partial_new, noisy); break;
                case EK_PAGE_DESCRIPTOR:
                        oa = pte & GENMASK(47,12);
                        // hyp_putsxn("oa", oa, 64);
                        // now add (va_partial, oa) to the mappings
                        if (noisy) { hyp_putsp("interpret_pgtable "); hyp_putsxn("va", va_partial_new, 64); hyp_putsxn("oa", oa, 64); }
                        extend_maplets(maplets_list, maplets_pool,va_partial_new, oa, 0);
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


void interpret_pgtable(struct list_head *maplets_list, struct maplets *maplets_pool, kvm_pte_t *pgd, bool noisy)
{
        _interpret_pgtable(maplets_list, maplets_pool, pgd, 0, 0, false);
}



/* *********************************************************** */
/* even newer abstraction - the page tables are now (2021-12) too big to conveniently look at every leaf, so glom together contiguous entries */


/* *********************************************************** */
// even newer abstraction - compute interpretation of pagetables at `pgd`, ms = [[pgd]]

u64 annotation;

