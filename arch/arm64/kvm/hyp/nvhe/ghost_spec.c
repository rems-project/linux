#include <asm/kvm_mmu.h>    // needed for debug-pl011.h ?
#include <../debug-pl011.h>
#include <../ghost_extra_debug-pl011.h>
//#include <nvhe/ghost_check_pgtables.h>
#include <nvhe/ghost_misc.h>
#include <../ghost_pgtable.h>
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#include <nvhe/spinlock.h>   
#include <nvhe/trap_handler.h>   // for DECLARE_REG
#include <nvhe/mem_protect.h>   // for DECLARE_REG
#include <asm/kvm_asm.h>    // for __KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp etc
#include <asm/kvm_hyp.h> // for read_sysreg_el2
#include <asm/sysreg.h> // for SYS_ESR_EL2
#include "nvhe/ghost_asm_ids.h"
#include "./ghost_spec.h"
#include "./ghost_compute_abstraction.h"
#include "../ghost_kvm_pgtable.h"



_Bool pkvm_prot_finalized_cpu[NR_CPUS];
_Bool pkvm_prot_finalized_all=false;
DEFINE_HYP_SPINLOCK(ghost_prot_finalized_lock);


struct ghost_state gs; // the "master" ghost state, shared but with its parts protected by the associated impl locks
DEFINE_PER_CPU(struct ghost_state, gs_recorded_pre);         // thread-local ghost state, of which only the relevant
DEFINE_PER_CPU(struct ghost_state, gs_recorded_post);        //  parts are used within each transition
DEFINE_PER_CPU(struct ghost_state, gs_computed_post);



//DEFINE_PER_CPU(struct ghost_state, g_recorded_backstop);
//DEFINE_PER_CPU(struct ghost_state, g_recorded_pre);
//DEFINE_PER_CPU(struct ghost_state, g_recorded_post);
//DEFINE_PER_CPU(bool, g_recorded_pre_present);

// __this_cpu_read(g_initial)
// __this_cpu_ptr(&g_initial)


/* are the specs of sub-functions wrt the global state, or wrt just that somehow accessible to the sub-functions? In other words, can the top-level-spec sub-functions be reused as executable specs of the implementation sub-functions?  What about their arguments? */


///* ***************************************************************************** */
///* ******   relational spec   ************************************************** */
///* ***************************************************************************** */
//
//
///*
//struct ghost_state spec_rel_handle_host_hcall(struct ghost_state *g1, struct ghost_state *g2) // pointer or value argument and result?
//{
//	// the function postcondition includes some things which are really implementation invariants, and some that are constraints on the resulting top-level spec.   How to organise?
//
//	// as far as the spec is concerned, we're assuming &kvm_protected_mode_initialized - how do we say that here?
//
//        // in the spec it's nice to do the initial dispatch with a switch or nested ifs, without that function-pointer array, so in fact we want to write it by hand anyway.
//	id -= KVM_HOST_SMCCC_ID(0);
//#pragma GCC diagnostic ignored "-Wunused-label" // not sure why the next lines trigger that
//	switch (id) {
//	__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp:
//		break;
//
//	__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp:
//		break;
//
//	__KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page:
//		break;
//
//		// TODO: and their bodies, and lots more
//	default:
//		goto inval;
//	}
//
//        return true; // TODO
//
//	inval:
//        return false; // TODO spec error?
//}
//*/
//
//
//bool spec_rel_handle_host_mem_abort(struct ghost_state *g1, struct ghost_state *g2)
//{
////	struct kvm_vcpu_fault_info fault;
////	u64 esr, addr;
////	int ret = -EPERM;
//	u64 addr;
////
//        bool ret;
//        int i=0;
//
//        bool is_memory;
//
//        struct maplet_target t;
//
//	mapping mapping_pre_annot, mapping_post_annot; // interpretation of pgtable on entry and exit, cut down to annot parts
//	mapping mapping_requested;
//	mapping mapping_post_nonannot;
//
////	esr = g->esr; // WAS read_sysreg_el2(SYS_ESR);
////	BUG_ON(!__get_fault_info(esr, &fault));
////	// defined in arch/arm64/kvm/hyp/include/hyp/fault.h
////	// interesting how to spec in several ways
////	// - checks cpus_have_final_cap(ARM64_WORKAROUND_834220), that reads some global state - mapped also at EL2, presumably?
////	// - reads another sysreg, PAR - that we should just read on entry and keep in the ghost state, I guess
////	// - does a __kvm_at("s1e1r", far)  defined in arch/arm64/include/asm/kvm_asm.h to futz with SPSR_EL2 and ELR_EL2 around an AT s1e1r
////	//     do we want to actually appeal to the h/w spec to do that stage 1 walk??  Or are we going to be so nondet about handle_host_mem_abort that it doesn't matter?  Or do we want to nondet out just the __translate_far_to_hpfar?   Used to think hopefully the second, but it seems that we're lucking out; now not sure.  Punt for now, just looking at the far_el2 and hpfar_el2.
////
////	addr = (fault.hpfar_el2 & HPFAR_MASK) << 8;  // [51:12] of faulting IPA, shifted back into proper place
////	addr |= fault.far_el2 & FAR_MASK;            // [11:0] of faulting VA
//	addr = (g1->sysregs[GHOST_HPFAR_EL2] & HPFAR_MASK) << 8;  // [51:12] of faulting IPA, shifted back into proper place
//	addr |= g1->sysregs[GHOST_FAR_EL2] & FAR_MASK;            // [11:0] of faulting VA
//
//        is_memory = mapping_in_domain(addr, g1->hyp_memory); /*just in range of a memblock*/
//
////
////	// WAS host_lock_component();
////
////	/* Check if an IOMMU device can handle the DABT. */
////	if (is_dabt(esr) /*just a pure-functional check of esr*/ && !addr_is_memory(addr) /*just in range of a memblock*/ &&
////	    pkvm_iommu_host_dabt_handler(host_ctxt, esr, addr)) // this has got a lot more complex since we last looked - punt for now on the internals
////		ret = 0;
//
//	if (is_dabt(g1->sysregs[GHOST_ESR_EL2]) /*just a pure-functional check of esr - should we make a ghost copy of that or expose the mem_protect.c version? For now, the latter*/ && !is_memory && false /* TODO:punting on pkvm_iommu_host_dabt_handler*/ ) {
//	};
//
////	/* If not handled, attempt to map the page. */
////	if (ret == -EPERM)
////		ret = host_stage2_idmap(addr);
//
//
//// in host_stage2_idmap
//
////	if (!is_memory) {
////		ret = pkvm_iommu_host_stage2_adjust_range(addr, &range.start,
////							  &range.end);
////		if (ret)
////			return ret;
////	}
//// punt on pkvm_iommu_host_stage2_adjust_range for now
//
//
////	ret = host_stage2_adjust_range(addr, &range);
////	if (ret)
////		return ret;
//// host_stage2_adjust_range uses kvm_pgtable_get_leaf and then finds the biggest granule size (lowest-numbered level) for which we could do a block mapping.  I think we should probably nondet-out the details of the latter, but we have to preserve the error cases of the former.  I've not looked into the errors that might be returned by kvm_pgtable_get_leaf for well-formed pagetables, though.
//
//// haven't followed the handle_host_perm_fault logic in handle_host_mem_abort - I'm a bit boggled by the overwriting of ret?  Ignoring that for now...
//
//
//// in  host_stage2_adjust_range
////	if (kvm_pte_valid(pte))
////		return -EAGAIN;
//// already mapped - handle_host_mem_abort just returns
////
////	if (pte)
//// non-value but non-zero case, i.e. something in annotation
////		return -EPERM;
//// handle_host_mem_abort calls host_inject_abort
//
//
//// the lack of generic option types is annoying here - in spec code we'd like to avoid the &t
//	if (mapping_lookup(addr, g1->host.host_mapping, &t)) {
//		if (t.k == MAPPED) { // mapped already
//			// TODO: do nothing
//		} else { // annotation already
//			// TODO: host_inject_abort
//		}
//	}
//	else { // new mapping called for
//
//		// if we ignore the "guessing" of addresses by __get_fault_info, we could require the following:
//		// postcondition: if addr is in memory and is not annotated in the stage 2 map, it's in mapping_post
//		mapping_requested = mapping_singleton(ALIGN_DOWN(addr,PAGE_SIZE), 1, maplet_target_mapped(ALIGN_DOWN(addr,PAGE_SIZE), DUMMY_ATTR, dummy_aal()));
//		ret = mapping_submapping(mapping_requested, g2->host.host_mapping, "spec_handle_host_mem_abort_rel", "mapping_requested", "g2->host.host_mapping", i+2);
//		//} else {
//		//	mapping_requested = mapping_empty_();
//		//	hyp_putspi("addr not in memory or annotated in stage 2, so nothing to check\n", i+2);
//		//}
//
//
//		// postcondition: mapping_post minus annotations included in hyp_memory minus annotations
//		mapping_pre_annot = mapping_annot(g1->host.host_mapping);
//		mapping_post_nonannot = mapping_nonannot(g2->host.host_mapping);
//		ret = ret && mapping_submapping(mapping_post_nonannot, g1->hyp_memory, "spec_handle_host_mem_abort_rel", "mapping_post_nonannot", "g1->hyp_memory", i+2);
//		ret = ret && mapping_disjoint(mapping_post_nonannot, mapping_pre_annot, "spec_handle_host_mem_abort_rel", "mapping_post_nonannot", "mapping_pre_annot", i+2);
//
//		// postcondition: mapping_post and mapping_pre have the same annotation part
//		mapping_post_annot = mapping_annot(g2->host.host_mapping);
//		ret = ret && mapping_equal(mapping_pre_annot, mapping_post_annot, "spec_handle_host_mem_abort_rel annot equal", "mapping_pre_annot", "mapping_post_annot", i+2);
//
//		free_mapping(mapping_requested);
//		free_mapping(mapping_pre_annot);
//		free_mapping(mapping_post_annot);
//		free_mapping(mapping_post_nonannot);
//
//		return ret;
//
//
//	}
//
//
////	// WAS host_unlock_component();
////
////	if ((esr & ESR_ELx_FSC_TYPE) == FSC_PERM)
////		ret = handle_host_perm_fault(host_ctxt, esr, addr);
////
////	if (ret == -EPERM)
////		host_inject_abort(host_ctxt);
////	else
////		BUG_ON(ret && ret != -EAGAIN);
//
//	return true; // TODO
//}
//
//
//
//bool spec_rel_handle_trap(struct ghost_state *g1, struct ghost_state *g2)
//	// pointer or struct arguments?  for more obvious correspondence to math, struct - but maybe too terrible for impl, and for idiomatic-readable-C?  But this code should never mutate them, in any case.
//{
//	switch (ESR_ELx_EC(g1->sysregs[GHOST_ESR_EL2])) {
//	case ESR_ELx_EC_HVC64:
//		return true; // TODO spec_rel_handle_host_hcall(g1,g2);
//	// TODO
//	//case ESR_ELx_EC_SMC64:
//	//	handle_host_smc(host_ctxt);
//	//	break;
//	//case ESR_ELx_EC_FP_ASIMD:
//	//case ESR_ELx_EC_SVE:
//	//	fpsimd_host_restore();
//	//	break;
//	case ESR_ELx_EC_IABT_LOW:
//	case ESR_ELx_EC_DABT_LOW:
//		return spec_rel_handle_host_mem_abort(g1,g2);
//	default:
//		return true; // TODO: really should return a spec error
//	}
//}
//
//
//
//
///* ***************************************************************************** */
///* ******   functional spec   ************************************************** */
///* ***************************************************************************** */
//
//// for the small-footprint version, this should really be just the host and hyp data, not a full ghost_state
//// pointer or value argument and result?   (values will probably blow the current pkvm stack, btw)
//// ...which also makes the top-level-spec spec closer to the function-local spec
////
////struct ghost_state spec___pkvm_host_share_hyp(struct ghost_state *g)
////{
//	//static void handle___pkvm_host_share_hyp(struct kvm_cpu_context *host_ctxt) // in hyp-main.c
//	//	DECLARE_REG(u64, pfn, host_ctxt, 1);                 // we should pull pfn from ghost_state ghost_ctxt
//	//      cpu_reg(host_ctxt, 1) = __pkvm_host_share_hyp(pfn);  // we should construct new ghost_state host_ctxt
//
//	//int __pkvm_host_share_hyp(u64 pfn) // in mem_protect.c
//
//	//u64 host_addr = hyp_pfn_to_phys(pfn);     // ((phys_addr_t)((pfn) << PAGE_SHIFT)) // pure
//	//u64 hyp_addr = (u64)__hyp_va(host_addr);  // ((void *)((phys_addr_t)(phys) - hyp_physvirt_offset)) // pure except uses hyp_physvirt_offset, which should be a constant-after-initialisation member of the ghost state
//
//	//struct pkvm_mem_share share = { ... } // lots of impl detail that the spec should abstract from
//	//struct pkvm_mem_share share = {       // morally, the proof should just partially evaluate the called fns w.r.t. this...?
//	//	.tx	= {
//	//		.nr_pages	= 1,
//	//		.initiator	= {
//	//			.id	= PKVM_ID_HOST,
//	//			.addr	= host_addr,
//	//			.host	= {
//	//				.completer_addr = hyp_addr,
//	//			},
//	//		},
//	//		.completer	= {
//	//			.id	= PKVM_ID_HYP,
//	//		},
//	//	},
//	//	.completer_prot	= PAGE_HYP,
//	//};
//
//	//host_lock_component();
//	//hyp_lock_component();
//	//
//	//ret = do_share(&share);
//	//
//	//hyp_unlock_component();
//	//host_unlock_component();
//        //return ret
//
//	//static int do_share(struct pkvm_mem_share *share) // in mem_protect.c
//	//	int ret;
//	//	ret = check_share(share);
//	//	if (ret)
//	//		return ret;
//	//	return WARN_ON(__do_share(share));
//
//	//static int check_share(struct pkvm_mem_share *share) // in mem_protect.c.   Specialising to the above value:
//	//u64 completer_addr;
//	//ret = host_request_owned_transition(&completer_addr, tx); if (ret) return ret;
//	//ret = hyp_ack_share(completer_addr, tx, share->completer_prot); return ret;
//
//	//First consider the first of those two: 	//ret = host_request_owned_transition(&completer_addr, tx); if (ret) return ret;
//
//		//static int host_request_owned_transition(u64 *completer_addr, const struct pkvm_mem_transition *tx)
//		//u64 size = tx->nr_pages * PAGE_SIZE;                                 // == 1*PAGE_SIZE
//		//u64 addr = tx->initiator.addr;                                       // == host_addr
//		//*completer_addr = tx->initiator.host.completer_addr;                 // == hyp_addr
//		//return __host_check_page_state_range(addr, size, PKVM_PAGE_OWNED);
//
//		//static int __host_check_page_state_range(u64 addr, u64 size, enum pkvm_page_state state)
//		//struct check_walk_data d = {
//		//	.desired	= state,                // == PKVM_PAGE_OWNED
//		//	.get_page_state	= host_get_page_state,  // the pure-ish C function that takes a pte and returns its state - depends on addr_is_memory(phys)
//		//};
//		//hyp_assert_lock_held(&host_mmu.lock);         // just a sanity check AFAICS - should always hold
//		//return check_page_state_range(&host_mmu.pgt, addr, size, &d);
//
//		//static int check_page_state_range(struct kvm_pgtable *pgt, u64 addr, u64 size, struct check_walk_data *data) // in mem_protect.c
//		//struct kvm_pgtable_walker walker = {
//		//	.cb	= __check_page_state_visitor,  // the function below
//		//	.arg	= data,
//		//	.flags	= KVM_PGTABLE_WALK_LEAF,
//		//};
//		//return kvm_pgtable_walk(pgt, addr, size, &walker);         // call the pgtable.c generic walk
//
//		//static int __check_page_state_visitor(u64 addr, u64 end, u32 level,   // in mem_protect.c
//		//				      kvm_pte_t *ptep,
//		//				      enum kvm_pgtable_walk_flags flag,
//		//				      void * const arg)
//		//{
//		//	struct check_walk_data *d = arg;
//		//	kvm_pte_t pte = *ptep;
//		//
//		//	if (kvm_pte_valid(pte) && !addr_is_allowed_memory(kvm_pte_to_phys(pte))) // TODO: can this ever happen?


// kvm_pte_valid(pte) 

//		//		return -EINVAL;
//		//
//		//	return d->get_page_state(pte) == d->desired ? 0 : -EPERM;
//		//}
//
//	// so it either returns true if the page state is PKVM_PAGE_OWNED or -EPERM if not (or maybe -EINVAL if !addr_is_allowed_memory)
//
//	// Second consider the second: 	//ret = hyp_ack_share(completer_addr, tx, share->completer_prot); return ret;
//
//		//static int hyp_ack_share(u64 addr, const struct pkvm_mem_transition *tx, enum kvm_pgtable_prot perms)
//		//	u64 size = tx->nr_pages * PAGE_SIZE;
//		//	if (perms != PAGE_HYP)                      // always true
//		//		return -EPERM;
//		//	if (__hyp_ack_skip_pgtable_check(tx))  // !(IS_ENABLED(CONFIG_NVHE_EL2_DEBUG) ||tx->initiator.id != PKVM_ID_HOST);
//		//		return 0;                      // == !(IS_ENABLED(CONFIG_NVHE_EL2_DEBUG) ==assumed false
//		//	return __hyp_check_page_state_range(addr, size, PKVM_NOPAGE);
//
//	// so it either returns true if the page state is PKVM_NOPAGE or -EPERM if not (or maybe -EINVAL if !addr_is_allowed_memor)y
//
//	// Now consider the return WARN_ON(__do_share(share));
//
//        // First 		ret = host_initiate_share(&completer_addr, tx);
//
//                // __host_set_page_state_range(addr, size, PKVM_PAGE_SHARED_OWNED);
//                //  host_stage2_idmap_locked(addr, size, pkvm_mkstate(PKVM_HOST_MEM_PROT, PKVM_PAGE_SHARED_OWNED), true);
//
//        // Second ret = hyp_complete_share(completer_addr, tx, share->completer_prot);
//
//                // pkvm_create_mappings_locked(start, end, pkvm_mkstate(PAGE_HYP, PKVM_PAGE_SHARED_BORROWED));
//
//		//int pkvm_create_mappings_locked(void *from, void *to, enum kvm_pgtable_prot prot) // in mm.c
//		//{
//		//	unsigned long start = (unsigned long)from;
//		//	unsigned long end = (unsigned long)to;
//		//	unsigned long virt_addr;
//		//	phys_addr_t phys;
//		//
//		//	hyp_assert_lock_held(&pkvm_pgd_lock);                   // always true
//		//
//		//	start = start & PAGE_MASK;
//		//	end = PAGE_ALIGN(end);
//		//
//		//	for (virt_addr = start; virt_addr < end; virt_addr += PAGE_SIZE) {
//		//		int err;
//		//
//		//		phys = hyp_virt_to_phys((void *)virt_addr);
//		//		err = kvm_pgtable_hyp_map(&pkvm_pgtable, virt_addr, PAGE_SIZE,
//		//					  phys, prot);
//		//		if (err)
//		//			return err;
//		//	}
//		//
//		//	return 0;
//		//}
//
//                // basically just a single call to kvm_pgtable_hyp_map
//
//// need to check any other errors from the pgtable.c calls that could escape out.
//// I guess no nondeterminism here except allocation failures from those calls.
//// So: snapshot host and pkvm abstractions at the lock points above (and record a serialisation point there too?)
//// subdivide host abstraction into the abstract-state part (exactly the annotation?) and the current-mapping part (exactly the rest?)
//// have these as separate C datastructures
//// have a new-spec-abstract-state function that takes the initial host and pkvm abstract states, and the arguments of handle___pkvm_host_share_hyp, and computes a new abstract state or (non-allocation-failure) error
//// wrap that to allow nondet allocation failures, in a function with the same type except that also takes the ret value
//// use that as the function spec for the above function
//// and (inside the appropriate dispatch and host_ctxt checking) in the top-level spec
//
////}
//

// adapted from memory.h to make it a pure function of the ghost state rather than depend on the impl global hyp_phys_virt_offset
#define ghost__hyp_va(g,phys)	((void *)((phys_addr_t)(phys) - g->hyp_physvirt_offset))

// adapted from mem_protect.c to use the hyp_memory map
bool ghost_addr_is_memory(struct ghost_state *g, phys_addr_t phys)
{
	struct maplet_target t;
	if ( !mapping_lookup(phys, g->hyp_memory, &t) ) {
		return false;
	}
	ghost_assert(t.k == MEMBLOCK);
	return true;
}


// adapted from mem_protect.c to use the hyp_memory map
bool ghost_addr_is_allowed_memory(struct ghost_state *g, phys_addr_t phys)
{
	struct maplet_target t;
	if (!mapping_lookup(phys, g->hyp_memory, &t))
		return false;
	ghost_assert(t.k == MEMBLOCK);
	return !(t.u.b.flags & MEMBLOCK_NOMAP);
}

static bool lookup_mapping_host_relinquished(const struct ghost_state *g, u64 addr, struct maplet_target *out)
{
	// this is to allow the caller to pass a NULL pointer if they do not care
	// about the entry
	struct maplet_target t;
	if (!out)
		out = &t;
	if ( !mapping_lookup(addr, g->host.host_abstract_pgtable_annot.mapping, out) ) {
		return false;
	}
	ghost_assert(out->k == ANNOT);
	return true;
}
#define is_in_mapping_host_relinquished(G, A) (lookup_mapping_host_relinquished(G, A, NULL))

static bool lookup_mapping_host_shared(const struct ghost_state *g, u64 addr, struct maplet_target *out)
{
	// this is to allow the caller to pass a NULL pointer if they do not care
	// about the entry
	struct maplet_target t;
	if (!out)
		out = &t;
	if ( !mapping_lookup(addr, g->host.host_abstract_pgtable_shared.mapping, out) ) {
		return false;
	}
	ghost_assert(out->k == MAPPED);
	return true;
}
#define is_in_mapping_host_shared(G, A) (lookup_mapping_host_shared(G, A, NULL))

static bool lookup_mapping_host_pkvm(const struct ghost_state *g, u64 addr, struct maplet_target *out)
{
	// this is to allow the caller to pass a NULL pointer if they do not care
	// about the entry
	struct maplet_target t;
	if (!out)
		out = &t;
	if ( !mapping_lookup(addr, g->pkvm.pkvm_abstract_pgtable.mapping, out) ) {
		return false;
	}
	ghost_assert(out->k == MAPPED);
	return true;
}
#define is_in_mapping_pkvm(G, A) (lookup_mapping_host_pkvm(G, A, NULL))


// horrible hack: copied unchanged from mem_protect.c, just to get in scope
static enum kvm_pgtable_prot ghost_default_host_prot(bool is_memory)
{
	return is_memory ? PKVM_HOST_MEM_PROT : PKVM_HOST_MMIO_PROT;
}



/* // adapted from mem_protect.c */
/* // kvm_pte_valid, kvm_pgtable_stage2_pte_prot, kvm_pte_to_phys, and default_host_prot are all pure functions, so a simple spec version just uses all those */
/* enum pkvm_page_state ghost_host_get_page_state(struct ghost_state *g, kvm_pte_t pte, u64 addr) */
/* { */
/* 	/1* enum pkvm_page_state state = 0; *1/ */
/* 	/1* enum kvm_pgtable_prot prot; *1/ */
/* 	/1* phys_addr_t phys; *1/ */

/* 	/1* if (!kvm_pte_valid(pte) && pte) *1/ */
/* 	/1* 	return PKVM_NOPAGE; *1/ */

/* 	/1* prot = kvm_pgtable_stage2_pte_prot(pte); *1/ */
/* 	/1* if (kvm_pte_valid(pte)) { *1/ */
/* 	/1* 	phys = kvm_pte_to_phys(pte); *1/ */
/* 	/1* 	if ((prot & KVM_PGTABLE_PROT_RWX) != ghost_default_host_prot(ghost_addr_is_memory(g,phys))) *1/ */
/* 	/1* 		state = PKVM_PAGE_RESTRICTED_PROT; *1/ */
/* 	/1* } *1/ */

/* 	/1* return state | pkvm_getstate(prot); *1/ */

/* 	if (!ghost_addr_is_allowed_memory(g, addr)) */
/* 		return PKVM_NOPAGE; */

/* 	if (!kvm_pte_valid(pte) && pte) */
/* 		return PKVM_NOPAGE; */

/* 	return pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte)); */
/* } */
// but for its usage in __host_check_page_state_range, we only care whether the result is equal to PKVM_PAGE_OWNED (as it gives -EPERM otherwise)

/* adapted from pgtable.c:stage2_set_prot_attr() */
/* TODO: handle device prot */
u64 arch_prot_of_prot(enum kvm_pgtable_prot prot)
{
	u64 attr=0;
	if (!(prot & KVM_PGTABLE_PROT_X))
		attr |= KVM_PTE_LEAF_ATTR_HI_S2_XN;
	if (prot & KVM_PGTABLE_PROT_R)
		attr |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R;
	if (prot & KVM_PGTABLE_PROT_W)
		attr |= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W;
	return attr;
}

void compute_new_abstract_state_handle___pkvm_host_share_hyp(struct ghost_state *g1, struct ghost_state *g0, u64 impl_return_value)
{
	u64 pfn = ghost_reg_gpr(g0, 1);
	u64 host_addr = hyp_pfn_to_phys(pfn); // ((phys_addr_t)((pfn) << PAGE_SHIFT)) // pure
	u64 phys_addr = host_addr; // TODO: isn't there a macro that we can use here?
	u64 hyp_addr = (u64)ghost__hyp_va(g0,phys_addr);
	int ret = 0;

	/* TODO: do some more thinking and if needed fix the following THEN branch
	 * ----
	 * BS and KM now think that ENOMEM cannot actually be an outcome of the hypercall
	 * as a result the __host_set_page_state_range() function (update of the HOST mapping)
	 * because of what comment preceding `host_stage2_try()` says and its code (which unmaps
	 * MMIO stuff if needed and retry updating the HOST mapping).
	 * KM: however I don't see the same in the code of `pkvm_create_mappings_locked()`,
	 *     so I think that the attempt at adding a new entry to the pKVM page table can
	 *     still cause a ENOMEM.
	 * ----
	 * NOTE: the rest of this comment is older than the previous TODO and may now be slightly wrong
	 * ----
	 * when the hypercall is adding entries to the host and hyp page tables
	 * it may run out of memory.
	 * we model this as a nondeterministic error (with two flavours) */
	if (impl_return_value == -ENOMEM) {
		ret = -ENOMEM;
		// TODO: it is not clear how to write the spec currently
		// because we 2 possible outcome:
		//   1. the error happened when attempting to add an entry
		//      to the host page table; then we don't copy anything to g1
		//   2. the error happened when attempting to add an entry
		//      to the pKVM page table; then we need to do
		//        copy_abstraction_host(g1, g0);
		goto out;
	}

	// __host_check_page_state_range(addr, size, PKVM_PAGE_OWNED);
	if (is_in_mapping_host_relinquished(g0, host_addr)) {
		ret = -EPERM;
		goto out;
	}
	if (is_in_mapping_host_shared(g0, host_addr)) {
		ret = -EPERM;
		goto out;
	}
	// checked in the pKVM code:
	// do_share() -> check_share() -> hyp_ack_share() -> __hyp_check_page_state_range()
	if (is_in_mapping_pkvm(g0, hyp_addr)) {
		ret = -EPERM;
		goto out;
	}

	u64 host_arch_prot = arch_prot_of_prot(ghost_default_host_prot(ghost_addr_is_memory(g0, phys_addr)));
	u64 hyp_arch_prot = host_arch_prot;

	/* the host annot mapping is unchanged (we have established that host_addr is NOT already in there) */
	g1->host.host_abstract_pgtable_annot.mapping = mapping_copy(g0->host.host_abstract_pgtable_annot.mapping);

	/* add a new host shared mapping, PKVM_PAGE_SHARED_OWNED */
	g1->host.host_abstract_pgtable_shared.mapping =
		mapping_plus(
			g0->host.host_abstract_pgtable_shared.mapping,
			mapping_singleton(host_addr, 1, maplet_target_mapped_ext(phys_addr, PKVM_PAGE_SHARED_OWNED, host_arch_prot)));

	/* add a new hyp mapping, PKVM_PAGE_SHARED_BORROWED */
	g1->pkvm.pkvm_abstract_pgtable.mapping =
		mapping_plus(
			g0->pkvm.pkvm_abstract_pgtable.mapping,
			mapping_singleton(hyp_addr, 1, maplet_target_mapped_ext(phys_addr, PKVM_PAGE_SHARED_BORROWED, hyp_arch_prot)));
out:
	ghost_reg_gpr(g1, 1) = ret;
}


/* pkvm_host_unshare_hyp(pfn) */
void compute_new_abstract_state_handle___pkvm_host_unshare_hyp(struct ghost_state *g1, struct ghost_state *g0, u64 impl_return_value)
{
	u64 pfn = ghost_reg_gpr(g0, 1);
	u64 host_addr = hyp_pfn_to_phys(pfn); // ((phys_addr_t)((pfn) << PAGE_SHIFT)) // pure
	u64 phys_addr = host_addr; // TODO: isn't there a macro that we can use here?
	u64 hyp_addr = (u64)ghost__hyp_va(g0,phys_addr);
	int ret = 0;

	// __host_check_page_state_range(addr, size, PKVM_PAGE_SHARED_OWNED);
	if (!is_in_mapping_host_shared(g0, host_addr)) {
		ret = -EPERM;
		goto out;
	}

	// check that pKVM is not using the page (otherwise EBUSY)
	// we model this as a non-deterministic choice that is determined
	// by the return code of the pKVM implementation
	if (impl_return_value == -EBUSY) {
		ret = -EBUSY;
		goto out;
	}

	// NOTE: we do not need a is_in_mapping_pkvm() corresponding to
	//   __hyp_check_page_state_range(hyp_addr, PAGE_SIZE, PKVM_PAGE_SHARED_BORROWED)
	// because this is a (possibly disabled) check that the host is not trying
	// to unshare a page it did NOT previously share with pKVM.
	// TODO BS: I don't understand why this is here. Re-read the pKVM code
	// more carefully and adapt or remove this comment accordingly

	/* remove 'host_addr' from the host shared finite map */
	// in pKVM code: __host_set_page_state_range(host_addr, PAGE_SIZE, PKVM_PAGE_OWNED);
	g1->host.host_abstract_pgtable_shared.mapping =
		mapping_minus(g0->host.host_abstract_pgtable_shared.mapping, host_addr, 1);

	// PKVM can non-deterministically fail to unmap the page in its page table
	// TODO: this may not be possible now that host_share_hyp cannot do a ENOMEM
	// TODO: check and remove this accordingly
	if (impl_return_value == -EFAULT) {
		ret = -EFAULT;
		goto out;
	}
	g1->pkvm.pkvm_abstract_pgtable.mapping =
		mapping_minus(g0->pkvm.pkvm_abstract_pgtable.mapping, hyp_addr, 1);
out:
	ghost_reg_gpr(g1, 1) = ret;
}

/**
 * compute the new abstract ghost_state from a u64 impl_return_value = pkvm_host_map_guest(host_pfn, guest_gfn)
 */
void compute_new_abstract_state_handle___pkvm_host_map_guest(struct ghost_state *g1, struct ghost_state *g0, u64 impl_return_value) {
	int ret;

	u64 pfn = ghost_reg_gpr(g0, 1);
	u64 gfn = ghost_reg_gpr(g0, 2);

	u64 phys_addr = (pfn << 12); // TODO: must be a macro for this, and depends on granule size?
	u64 host_virt = phys_addr;
	u64 guest_virt = (gfn << 12);

	// previous vcpu_load must have been done
	int this_cpu = get_cpu();
	struct ghost_loaded_vcpu hyp_loaded_vcpu = g0->loaded_hyp_vcpu[this_cpu];
	ghost_assert(hyp_loaded_vcpu.present);
	// `hyp_vcpu = pkvm_get_loaded_hyp_vcpu(); if (!hyp_vcpu) goto out;`
	if (!hyp_loaded_vcpu.loaded) {
		ret = -EINVAL;
		goto out;
	}

	u64 g0_vm_idx = ghost_vm_idx_from_handle(g0, hyp_loaded_vcpu.vm_handle);
	u64 g1_vm_idx = ghost_vm_idx_from_handle(g1, hyp_loaded_vcpu.vm_handle);
	ghost_assert(g0_vm_idx < KVM_MAX_PVMS);
	ghost_assert(g1_vm_idx < KVM_MAX_PVMS);

	// non-det failure on attempting to top-up guest memcache
	// resolved by dispatching on the implementations return value
	// TODO: check this case more carefully...
	if (impl_return_value == -ENOMEM) {
		ret = -ENOMEM;
		goto out;
	}

	// TODO: non-protected VM/VCPUs?

	// if this page is not accessible by the host, fail with -EPERM
	if (lookup_mapping_host_relinquished(g0, host_virt, NULL)) {
		ret = -EPERM;
		goto out;
	}

	// if this page is shared with/from the host, cannot give it away, so fail with -EPERM
	if (lookup_mapping_host_shared(g0, host_virt, NULL)) {
		ret = -EPERM;
		goto out;
	}

	// TODO: other error cases
	ret = 0;

	u64 guest_arch_prot = arch_prot_of_prot(ghost_default_host_prot(ghost_addr_is_memory(g0, phys_addr)));

	g1->host.host_abstract_pgtable_annot.mapping =
		mapping_plus(g0->host.host_abstract_pgtable_annot.mapping,
		             mapping_singleton(host_virt, 1, maplet_target_annot(PKVM_ID_GUEST)));

	g1->vms.vms[g1_vm_idx].vm_abstract_pgtable.mapping =
		mapping_plus(g0->vms.vms[g0_vm_idx].vm_abstract_pgtable.mapping,
		             mapping_singleton(guest_virt, 1, maplet_target_mapped_ext(phys_addr, PKVM_PAGE_OWNED, guest_arch_prot)));
out:
	ghost_reg_gpr(g1, 1) = ret;
}
void compute_new_abstract_state_handle___pkvm_vcpu_load(struct ghost_state *g1, struct ghost_state *g0, u64 impl_return_value) {
	int this_cpu = get_cpu();
	pkvm_handle_t vm_handle = ghost_reg_gpr(g0, 1);
	unsigned int vcpu_idx = ghost_reg_gpr(g0, 2);
	
	ghost_assert(g0->loaded_hyp_vcpu[this_cpu].present);
	// if another vcpu is already loaded on this CPU, then do nothing
	if (g0->loaded_hyp_vcpu[this_cpu].loaded)
		goto out;

	// if the vm is not present in the vm_table[] array, then do nothing
	if (!ghost_vm_is_valid_handle(g0, vm_handle))
		goto out;

	struct ghost_vm *vm = ghost_vm_from_handle(g0, vm_handle);
	ghost_assert(vm && vm->exists);  // just checked it was valid

	// if loading non-existent vcpu, do nothing.
	if (vcpu_idx > vm->nr_vcpus)
		goto out;

	struct ghost_vcpu *vcpu = &vm->vcpus[vcpu_idx];
	ghost_assert(vcpu_idx < KVM_MAX_VCPUS);
	ghost_assert(vcpu->exists);

	// if the vcpu is already loaded (potentially in another CPU), then do nothing
	if (vcpu->loaded)
		goto out;

	// record in the ghost state of the vcpu 'vcpu_idx' that is has been loaded
	u64 g1_vm_idx = ghost_vm_idx_from_handle(g1, vm_handle);
	ghost_assert(g1_vm_idx < KVM_MAX_PVMS);
	g1->vms.vms[g1_vm_idx].vcpus[vcpu_idx].loaded = true;

	// record in the ghost state that the current CPU has loaded
	// the vcpu 'vcpu_idx' of vm 'vm_idx'
	g1->loaded_hyp_vcpu[this_cpu] = (struct ghost_loaded_vcpu){
		.present = true,
		.loaded = true,
		.vm_handle = vm_handle,
		.vcpu_index = vcpu_idx,
	};
out:
	return;
}

void compute_new_abstract_state_handle___pkvm_vcpu_put(struct ghost_state *g1, struct ghost_state *g0, u64 impl_return_value) {
	int this_cpu = get_cpu();
	if (!g0->loaded_hyp_vcpu[this_cpu].loaded)
		goto out;

	pkvm_handle_t vm_handle = g0->loaded_hyp_vcpu[this_cpu].vm_handle;
	u64 vcpu_idx = g0->loaded_hyp_vcpu[this_cpu].vcpu_index;

	u64 g1_vm_idx = ghost_vm_idx_from_handle(g1, vm_handle);
	g1->vms.vms[g1_vm_idx].vcpus[vcpu_idx].loaded = false;

	g1->loaded_hyp_vcpu[this_cpu] = (struct ghost_loaded_vcpu){
		.present = true,
		.loaded = false,
	};
out:
	return;
}

void compute_new_abstract_state_handle___pkvm_init_vm(struct ghost_state *g1, struct ghost_state *g0, u64 impl_return_value) {
	int ret;
	if (impl_return_value <= 0)
	 	// TODO: set ret
		goto out;

	u64 handle = impl_return_value;
	u64 idx = ghost_vm_idx_from_handle(g1, handle);

	// TODO: error case on init'ing too many VMs?
	if (idx >= KVM_MAX_PVMS)
		goto out;

	g1->vms.present = true;
	g1->vms.vms[idx] = (struct ghost_vm) {
		.exists = true,
		.pkvm_handle = handle,
		// TODO: init pagetable and vcpus
	};
	ret = 0;
out:
	ghost_reg_gpr(g1, 1) = 0;
}

void compute_new_abstract_state_handle_host_hcall(struct ghost_state *g1, struct ghost_state *g0, u64 impl_return_value, bool *new_state_computed)
{
	int smccc_ret = SMCCC_RET_SUCCESS;
	// allow any hcall to fail with ENOMEM, with an otherwise-identity abstract state
	if (impl_return_value == -ENOMEM) {
		ghost_reg_gpr(g1, 1) = -ENOMEM;
		return;
	}

	unsigned long id = ghost_reg_gpr(g0, 0) - KVM_HOST_SMCCC_ID(0);
#pragma GCC diagnostic ignored "-Wunused-label" // not sure why the next lines trigger that
	switch (id) {
	__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp:
		compute_new_abstract_state_handle___pkvm_host_share_hyp(g1, g0, impl_return_value);
		*new_state_computed = true;
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp:
		compute_new_abstract_state_handle___pkvm_host_unshare_hyp(g1, g0, impl_return_value);
		*new_state_computed = true;
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page:
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest:
		compute_new_abstract_state_handle___pkvm_host_map_guest(g1, g0, impl_return_value);
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load:
		compute_new_abstract_state_handle___pkvm_vcpu_load(g1, g0, impl_return_value);
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put:
		compute_new_abstract_state_handle___pkvm_vcpu_put(g1, g0, impl_return_value);
		break;

	__KVM_HOST_SMCCC_FUNC___pkvm_init_vm:
		compute_new_abstract_state_handle___pkvm_init_vm(g1, g0, impl_return_value);
		break;

		// TODO: and their bodies, and all the other cases
	default:
		smccc_ret = SMCCC_RET_NOT_SUPPORTED;
		break;
	}
	ghost_reg_gpr(g1, 0) = smccc_ret;
}


void compute_new_abstract_state_handle_host_mem_abort(struct ghost_state *g1, struct ghost_state *g0, u64 impl_return_value, bool *new_state_computed)
{
	//TODO
}




void compute_new_abstract_state_handle_trap(struct ghost_state *g1 /*new*/, struct ghost_state *g0 /*old*/, u64 impl_return_value, bool *new_state_computed)
	// pointer or struct arguments and results?  For more obvious correspondence to math, struct - but that may be too terrible for executability, and distracting for those used to idiomatic C.  Doesn't matter too much.
{

	// assumes *g1 has been cleared
	ghost_assert(!g1->pkvm.present && !g1->host.present && !g1->regs.present);

	// copy the g0 regs to g1; we'll update them to make the final g1
	copy_abstraction_regs(g1, g0);

	// hyp_memory is supposed to be constant, so just copy the old one
	copy_abstraction_hyp_memory(g1, g0);

	switch (ESR_ELx_EC(ghost_reg_el2(g0,GHOST_ESR_EL2))) {
	case ESR_ELx_EC_HVC64:
		compute_new_abstract_state_handle_host_hcall(g1,g0,impl_return_value,new_state_computed);
		break;
	case ESR_ELx_EC_SMC64:
		//TODO compute_new_abstract_state_handle_host_smc(g1,g0);
		break;
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		//TODO compute_new_abstract_state_fpsimd_host_restore(g1,g0);
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		compute_new_abstract_state_handle_host_mem_abort(g1,g0,impl_return_value,new_state_computed);
		break;
	default:
		ghost_assert(false);
	}
}
