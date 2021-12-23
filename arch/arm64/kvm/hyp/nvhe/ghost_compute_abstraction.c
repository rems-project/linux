// computing the abstraction function from the pKVM concrete state to the abstract state



// these are the non-ghost headers from mem_protect.c - probably we only need some of them
#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>
#include <asm/stage2_pgtable.h>

#include <hyp/adjust_pc.h>
#include <hyp/fault.h>

#include <nvhe/gfp.h>
#include <nvhe/iommu.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
// end of mem_protect.c non-ghost headers


// and the ghost headers from mem_protect.c
#include <../debug-pl011.h>
#include <../ghost_extra_debug-pl011.h>
#include <../ghost_pgtable.h>
#include "./ghost_spec.h"
#include <nvhe/ghost_asm.h>
#include "nvhe/ghost_asm_ids.h"

//horrible hack for ghost code in nvhe/iommu/s2mpu.c
// but in the default build # CONFIG_KVM_S2MPU is not set
// and (looking in the Makefile) it seems that file isn't even linked in
// void __kvm_nvhe_ghost_dump_s2mpus(u64 indent);

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wunused-variable"
// end of mem_protect.c ghost headers


#include "./ghost_spec.h"
#include "./ghost_compute_abstraction.h"


// for all these, one needs to be in ghost_(un)lock_maplets()
// and, unless we make the memory management more automatic, the context must carefully free any pre-existing mappings

// should these return abstract-state structs or update a ghost_state struct?  We really need the latter, but (looking towards the functional spec) nicer to factor via the former?

mapping compute_abstraction_hyp_memory(void)
{
	mapping m;
	int cur;
        m = mapping_empty_();
	for (cur=0; cur<hyp_memblock_nr; cur++)
		extend_mapping_coalesce(&m, hyp_memory[cur].base, hyp_memory[cur].size / PAGE_SIZE, maplet_target_memblock(hyp_memory[cur].flags));
	return m;
}

// should this read from the mapping, or from our ghost record of the mapping requests?  From the mapping, as this is to specify what EL2 Stage 1 translation does - correctness of the initialisation w.r.t. the requests is a different question
// should this be usable only from a freshly initialised state, or from an arbitrary point during pKVM execution?  From an arbitrary point during execution.  (Do we have to remove any annot parts here?  not sure)
// need to hold the pkvm lock
struct ghost_pkvm compute_abstraction_pkvm(void)
{
	struct ghost_pkvm gp;
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	gp.pkvm_abstract_pgtable = ghost_record_pgtable_ap(&pkvm_pgtable, "pkvm_pgtable", i);
	gp.present = true;
	return gp;
}

struct ghost_host compute_abstraction_host(void)
{
	struct ghost_host gh;
	abstract_pgtable ap;
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	ap = ghost_record_pgtable_ap(&host_mmu.pgt, "host_mmu.pgt", i);
	gh.host_abstract_pgtable_annot = (abstract_pgtable){.root = ap.root, .mapping = mapping_annot(ap.mapping)};
	gh.host_abstract_pgtable_shared = (abstract_pgtable){.root = ap.root, .mapping = mapping_shared(ap.mapping)};
	gh.host_abstract_pgtable_nonannot = (abstract_pgtable){.root = ap.root, .mapping = mapping_nonannot(ap.mapping)};
	gh.present = true;
	free_mapping(ap.mapping);
	return gh;
}


bool abstraction_equals_hyp_memory(struct ghost_state *g1, struct ghost_state *g2)
{
	return mapping_equal(g1->hyp_memory, g2->hyp_memory, "abstraction_equals_hyp_memory", "g1.hyp_memory", "g2.hyp_memory", 4);
}

bool abstraction_equals_reg(struct ghost_state *g1, struct ghost_state *g2)
{
	u64 i;
	bool ret = true;
	u64 ghost_el2_regs[] = (u64[])GHOST_EL2_REGS;
	for (i=0; i<=30; i++)
		ret = ret && ghost_reg_gpr(g1,i) == ghost_reg_gpr(g2,i);
	for (i=0; i<sizeof(ghost_el2_regs); i++)
		ret = ret && ghost_reg_el2(g1,ghost_el2_regs[i]) == ghost_reg_el2(g2,ghost_el2_regs[i]);
	return ret;
	// TODO other regs
}

bool abstraction_equals_pkvm(struct ghost_pkvm gp1, struct ghost_pkvm gp2)
{
	ghost_assert(gp1.present && gp2.present);
	return mapping_equal(gp1.pkvm_abstract_pgtable.mapping, gp2.pkvm_abstract_pgtable.mapping, "abstraction_equals_pkvm", "gp1.pkvm_mapping", "gp2.pkvm_mapping", 4);
}

bool abstraction_equals_host(struct ghost_host gh1, struct ghost_host gh2)
{
	// note that this only checks the annot component
	ghost_assert(gh1.present && gh2.present);
	return (mapping_equal(gh1.host_abstract_pgtable_annot.mapping, gh2.host_abstract_pgtable_annot.mapping, "abstraction_equals_host", "gh1.host_mapping_annot", "gh2.host_mapping_annot", 4) &&
		mapping_equal(gh1.host_abstract_pgtable_shared.mapping, gh2.host_abstract_pgtable_shared.mapping, "abstraction_equals_host", "gh1.host_mapping_shared", "gh2.host_mapping_shared", 4));
}


//void abstraction_vms(struct ghost_state *g)
//{
//	// TODO
//}

// do we want these for an arbitrary g or for the global gs ?


bool abstraction_equals_all(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	bool ret_pkvm, ret_host;
	if (gc->pkvm.present && gr_post->pkvm.present) {
		ret_pkvm = abstraction_equals_pkvm(gc->pkvm, gr_post->pkvm);
	}
	else if (gc->pkvm.present && !gr_post->pkvm.present) {
		ghost_assert(false);
	}
	else if (!gc->pkvm.present && gr_post->pkvm.present) {
		ghost_assert(gr_pre->pkvm.present);
		ret_pkvm = abstraction_equals_pkvm(gr_post->pkvm, gr_pre->pkvm);
	}
	else
		ret_pkvm = true;

	if (gc->host.present && gr_post->host.present) {
		ret_host = abstraction_equals_host(gc->host, gr_post->host);
	}
	else if (gc->host.present && !gr_post->host.present) {
		ghost_assert(false);
	}
	else if (!gc->host.present && gr_post->host.present) {
		ghost_assert(gr_pre->host.present);
		ret_host = abstraction_equals_host(gr_post->host, gr_pre->host);
	}
	else
		ret_host = true;

	return abstraction_equals_hyp_memory(gc, gr_post) && abstraction_equals_reg(gc, gr_post) && gc->hyp_physvirt_offset==gr_post->hyp_physvirt_offset && ret_pkvm && ret_host;

}


void init_abstraction(struct ghost_state *g)
{
	g->pkvm.present = false;
	g->host.present = false;
	g->regs.present = false;
}

void init_abstraction_common(void)
{
	init_abstraction(&gs);
}

void init_abstraction_thread_local(void)
{
	init_abstraction(this_cpu_ptr(&gs_recorded_pre));
	init_abstraction(this_cpu_ptr(&gs_recorded_post));
	init_abstraction(this_cpu_ptr(&gs_computed_post));
}

void clear_abstraction_pkvm(struct ghost_state *g)
{
	if (g->pkvm.present) {
		free_mapping(g->pkvm.pkvm_abstract_pgtable.mapping);
		g->pkvm.present = false;
	}
}

void clear_abstraction_host(struct ghost_state *g)
{
	if (g->host.present) {
		free_mapping(g->host.host_abstract_pgtable_annot.mapping);
		free_mapping(g->host.host_abstract_pgtable_shared.mapping);
		free_mapping(g->host.host_abstract_pgtable_nonannot.mapping);
		g->host.present = false;
	}
}

void clear_abstraction_regs(struct ghost_state *g)
{
	g->regs.present = false;
}

void clear_abstraction_all(struct ghost_state *g)
{
	clear_abstraction_pkvm(g);
	clear_abstraction_host(g);
	clear_abstraction_regs(g);
}

void clear_abstraction_thread_local(void)
{
	ghost_lock_maplets();
	clear_abstraction_all(this_cpu_ptr(&gs_recorded_pre));
	clear_abstraction_all(this_cpu_ptr(&gs_recorded_post));
	clear_abstraction_all(this_cpu_ptr(&gs_computed_post));
	ghost_unlock_maplets();
}

void copy_abstraction_regs(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert(g_src->regs.present);
	ghost_assert(!g_tgt->regs.present);
	memcpy((void*) &(g_tgt->regs), (void*) &(g_src->regs), sizeof(struct ghost_register_state));
}

void copy_abstraction_hyp_memory(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	g_tgt->hyp_memory = mapping_copy(g_src->hyp_memory);
}

void copy_abstraction_pkvm(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert(g_src->pkvm.present);
	clear_abstraction_pkvm(g_tgt);
	g_tgt->pkvm.present = g_src->pkvm.present;
	g_tgt->pkvm.pkvm_abstract_pgtable.root = g_src->pkvm.pkvm_abstract_pgtable.root;
	g_tgt->pkvm.pkvm_abstract_pgtable.mapping = mapping_copy(g_src->pkvm.pkvm_abstract_pgtable.mapping);
}

void copy_abstraction_host(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert(g_src->host.present);
	clear_abstraction_host(g_tgt);
	g_tgt->host.present = g_src->host.present;
	g_tgt->host.host_abstract_pgtable_annot.root = g_src->host.host_abstract_pgtable_annot.root;
	g_tgt->host.host_abstract_pgtable_annot.mapping = mapping_copy(g_src->host.host_abstract_pgtable_annot.mapping);
	g_tgt->host.host_abstract_pgtable_shared.root = g_src->host.host_abstract_pgtable_shared.root;
	g_tgt->host.host_abstract_pgtable_shared.mapping = mapping_copy(g_src->host.host_abstract_pgtable_shared.mapping);
	g_tgt->host.host_abstract_pgtable_nonannot.root = g_src->host.host_abstract_pgtable_nonannot.root;
	g_tgt->host.host_abstract_pgtable_nonannot.mapping = mapping_copy(g_src->host.host_abstract_pgtable_nonannot.mapping);
}

void record_abstraction_hyp_memory(struct ghost_state *g)
{
	g->hyp_memory = compute_abstraction_hyp_memory();
}

void record_abstraction_pkvm(struct ghost_state *g)
{
	ghost_assert(!g->pkvm.present);
	g->pkvm = compute_abstraction_pkvm();
}

void record_abstraction_host(struct ghost_state *g)
{
	ghost_assert(!g->host.present);
	g->host = compute_abstraction_host();
}

void record_abstraction_vms(struct ghost_state *g)
{
	//g->vms = abstraction_vms(); TODO
}

void record_abstraction_regs(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	int i;

	g->regs.present = true;

	// copy GPR values from the ctxt saved by the exception vector
	for (i=0; i<=30; i++) {
		g->regs.ctxt.regs.regs[i] = ctxt->regs.regs[i];
	}
	// save EL2 registers
	ghost_get_sysregs(g->regs.el2_sysregs);
	// save EL1 registers comprising pKVM's view of the context
	// __sysreg_save_state_nvhe(ctxt);
}

void record_abstraction_regs_pre(struct kvm_cpu_context *ctxt)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_regs(g, ctxt);
}

void record_abstraction_regs_post(struct kvm_cpu_context *ctxt)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_regs(g, ctxt);
}

void record_abstraction_all(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	record_abstraction_hyp_memory(g);
	record_abstraction_pkvm(g);
	record_abstraction_host(g);
	//record_abstraction_vms(); TODO
	if (!ctxt) {
		record_abstraction_regs(g,ctxt);
	}
	g->hyp_physvirt_offset = hyp_physvirt_offset;
}

void record_abstraction_common(void)
{
	ghost_lock_maplets();
	record_abstraction_all(&gs, NULL);
	ghost_unlock_maplets();
}

void record_and_check_abstraction_pkvm_pre(void)
{
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_pkvm(g);
	abstraction_equals_pkvm(g->pkvm, gs.pkvm);
	ghost_unlock_maplets();
}

void record_and_copy_abstraction_pkvm_post(void)
{
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_pkvm(g);
	copy_abstraction_pkvm(&gs, g);
	ghost_unlock_maplets();
}

void record_and_check_abstraction_host_pre(void)
{
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_host(g);
	abstraction_equals_host(g->host, gs.host);
	ghost_unlock_maplets();
}

void record_and_copy_abstraction_host_post(void)
{
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_host(g);
	copy_abstraction_host(&gs, g);
	ghost_unlock_maplets();
}

