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


void abstraction_hyp_memory(struct ghost_state *g)
{
	int cur;
	g->hyp_memory = mapping_empty_();
	for (cur=0; cur<hyp_memblock_nr; cur++)
		extend_mapping_coalesce(&g->hyp_memory, hyp_memory[cur].base, hyp_memory[cur].size / PAGE_SIZE, maplet_target_mapped(hyp_memory[cur].base, DUMMY_ATTR, dummy_aal()));
	// TODO: the above should look at the memblock permissions or what-have-you
}



// should this read from the mapping, or from our ghost record of the mapping requests?  I guess the mapping
// should this be usable only from a freshly initialised state, or from an arbitrary point during pKVM execution?   not sure (for the second, we have to subtract any parts shared or donated by the host).  For now, I just do the first
// need to hold the pkvm lock
void abstraction_pkvm_mapping(struct ghost_state *g)
{
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	g->pkvm_mapping = ghost_record_pgtable(&pkvm_pgtable, "pkvm_pgtable", i);
}


// TODO: define these in ghost_maplets.{h,c}
mapping mapping_nonshare_nondonate(mapping map);
mapping mapping_shared_by_host(mapping map);
mapping mapping_donated_by_host(mapping map);
mapping mapping_nonshare_nondonate(mapping map) {return map;}
mapping mapping_shared_by_host(mapping map) {return map;}
mapping mapping_donated_by_host(mapping map) {return map;}


void abstraction_host(struct ghost_state *g)
{
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	g->host.host_mapping = ghost_record_pgtable(&host_mmu.pgt, "host_mmu.pgt", i);
	//	g->host.host_mapping_core            = mapping_nonshare_nondonate(mapping_host_all);
	//g->host.pkvm_mapping_shared_by_host  = mapping_shared_by_host(mapping_host_all);
	//g->host.pkvm_mapping_donated_by_host = mapping_donated_by_host(mapping_host_all);
	//free_mapping(mapping_host_all);
}


void abstraction_vms(struct ghost_state *g)
{
	// TODO
}

void abstraction_init(struct ghost_state *g)
{
	ghost_get_sysregs(g->sysregs);

	abstraction_hyp_memory(g);
	abstraction_pkvm_mapping(g);
	abstraction_host(g);
	abstraction_vms(g);
}

void record_abstraction(struct ghost_state *g)
{
	// abstraction_init(g);   // TODO maybe not exactly
}

void record_abstraction_shared_state(struct ghost_state *g)
{
	//abstraction_init(g);   // TODO maybe not exactly
}
