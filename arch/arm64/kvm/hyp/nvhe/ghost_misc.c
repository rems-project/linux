
#include <asm/kvm_mmu.h>
#include <../debug-pl011.h>
#include <../ghost_extra_debug-pl011.h>
#include "../ghost_pgtable.h"

#include <nvhe/ghost_misc.h>

#include <nvhe/ghost_asm.h>
#include "nvhe/ghost_asm_ids.h"

#include <asm/kvm_pkvm.h>
#include <linux/memblock.h>
#include <nvhe/mm.h>

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"




/* **************************************** */
/* print hyp_memory */


void ghost_dump_hyp_memory(u64 indent)
{
        u64 i;
	hyp_putspi("hyp_memory\n",indent);
	if (hyp_memblock_nr>0) {
		for (i = 0; i < hyp_memblock_nr; i++) {
			hyp_puti(indent);
			if (i>=1 && hyp_memory[i].base == hyp_memory[i-1].base+hyp_memory[i-1].size)
				hyp_putc('-');
			else
				hyp_putc(' ');
			hyp_putsxn("base",hyp_memory[i].base,64);
			hyp_putsxn("base'",hyp_memory[i].base+hyp_memory[i].size,64);
			hyp_putsxn("size",hyp_memory[i].size,64);
			hyp_putsp("flags:");
			if (hyp_memory[i].flags & MEMBLOCK_HOTPLUG)
				hyp_putsp("HOTPLUG ");
			if (hyp_memory[i].flags & MEMBLOCK_MIRROR)
				hyp_putsp("MIRROR ");
			if (hyp_memory[i].flags & MEMBLOCK_NOMAP)
				hyp_putsp("NOMAP ");
			hyp_putc('\n');
		}
	}
	return;
}



/* **************************************** */
/* print key system register values */
void dump_kvm_nvhe_init_params(struct kvm_nvhe_init_params *params)
{
        // ghastly hack to print start of section .hyp.text
	hyp_putsxn("__kvm_timer_set_cntvoff (start of section .hyp.text)",(u64)__kvm_timer_set_cntvoff,64);hyp_putc('\n');

        hyp_putsxn("mair_el2    ", params->mair_el2     , 64); hyp_putc('\n');
        hyp_putsxn("tcr_el2     ", params->tcr_el2      , 64); hyp_putc('\n');
        hyp_putsxn("tpidr_el2   ", params->tpidr_el2    , 64); hyp_putc('\n');
	//        hyp_putsxn("stack_hyp_va", params->stack_hyp_va , 64); hyp_putc('\n');
        hyp_putsxn("sp          ", params->stack_hyp_va , 64); hyp_putc('\n');
	//      hyp_putsxn("pgd_pa      ", (unsigned long)params->pgd_pa       , 64); hyp_putc('\n');
        hyp_putsxn("ttbr0_el2   ", (unsigned long)params->pgd_pa       , 64); hyp_putc('\n');
        hyp_putsxn("hcr_el2     ", params->hcr_el2      , 64); hyp_putc('\n');
        hyp_putsxn("vttbr_el2   ", params->vttbr        , 64); hyp_putc('\n');
        hyp_putsxn("vtcr_el2    ", params->vtcr         , 64); hyp_putc('\n');
}



void ghost_dump_sysregs(void)
{
	//struct kvm_nvhe_init_params params_snapshot;
	u64 regs[GHOST_NR_SYSREGS];
        //int i;

	//___kvm_get_sysregs(&params_snapshot);
	//dump_kvm_nvhe_init_params(&params_snapshot);

	ghost_get_sysregs(regs);

	hyp_putsxnl("SCTLR_EL2       ", regs[GHOST_SCTLR_EL2	   ], 64);
	hyp_putsxnl("HCR_EL2         ", regs[GHOST_HCR_EL2	   ], 64);
	// HCRX
	hyp_putsxnl("TCR_EL2         ", regs[GHOST_TCR_EL2	   ], 64);
	hyp_putsxnl("MAIR_EL2        ", regs[GHOST_MAIR_EL2	   ], 64);
	// AMAIR_EL2
	hyp_putsxnl("TTBR0_EL2       ", regs[GHOST_TTBR0_EL2	   ], 64);
	hyp_putsxnl("VTCR_EL2        ", regs[GHOST_VTCR_EL2	   ], 64);
	hyp_putsxnl("VTTBR_EL2       ", regs[GHOST_VTTBR_EL2	   ], 64);
	hyp_putsxnl("TPIDR_EL2       ", regs[GHOST_TPIDR_EL2	   ], 64);
	hyp_putsxnl("MDCR_EL2        ", regs[GHOST_MDCR_EL2	   ], 64);

	hyp_putsxnl("ELR_EL2         ", regs[GHOST_ELR_EL2	   ], 64);
	hyp_putsxnl("ESR_EL2         ", regs[GHOST_ESR_EL2	   ], 64);
	hyp_putsxnl("FAR_EL2         ", regs[GHOST_FAR_EL2	   ], 64);
	hyp_putsxnl("HPFAR_EL2       ", regs[GHOST_HPFAR_EL2	   ], 64);

	hyp_putsxnl("ID_AA64AFR0_EL1  ", regs[GHOST_ID_AA64AFR0_EL1  ], 64);
	hyp_putsxnl("ID_AA64AFR1_EL1  ", regs[GHOST_ID_AA64AFR1_EL1  ], 64);
	hyp_putsxnl("ID_AA64PFR0_EL1  ", regs[GHOST_ID_AA64PFR0_EL1  ], 64);
	hyp_putsxnl("ID_AA64PFR1_EL1  ", regs[GHOST_ID_AA64PFR1_EL1  ], 64);
	hyp_putsxnl("ID_AA64DFR0_EL1  ", regs[GHOST_ID_AA64DFR0_EL1  ], 64);
	hyp_putsxnl("ID_AA64DFR1_EL1  ", regs[GHOST_ID_AA64DFR1_EL1  ], 64);
	hyp_putsxnl("ID_AA64MMFR0_EL1 ", regs[GHOST_ID_AA64MMFR0_EL1 ], 64);
	hyp_putsxnl("ID_AA64MMFR1_EL1 ", regs[GHOST_ID_AA64MMFR1_EL1 ], 64);
	hyp_putsxnl("ID_AA64MMFR2_EL1 ", regs[GHOST_ID_AA64MMFR2_EL1 ], 64);
	hyp_putsxnl("ID_AA64ISAR0_EL1 ", regs[GHOST_ID_AA64ISAR0_EL1 ], 64);
	hyp_putsxnl("ID_AA64ISAR1_EL1 ", regs[GHOST_ID_AA64ISAR1_EL1 ], 64);

	//hyp_putsxnl("SCTLR_EL1       ", regs[GHOST_SCTLR_EL1	   ], 64);
	//hyp_putsxnl("TCR_EL1         ", regs[GHOST_TCR_EL1	   ], 64);
	hyp_putsxnl("SP              ", regs[GHOST_SP		   ], 64);
	//hyp_putsxnl("MDCR_EL3        ", regs[GHOST_MDCR_EL3	   ], 64);
	//hyp_putsxnl("MDSCR_EL1       ", regs[GHOST_MDSCR_EL1	   ], 64);
	//hyp_putsxnl("MPIDR_EL1       ", regs[GHOST_MPIDR_EL1	   ], 64);
	//hyp_putsxnl("OSDLR_EL1       ", regs[GHOST_OSDLR_EL1	   ], 64);
	//hyp_putsxnl("OSLSR_EL1       ", regs[GHOST_OSLSR_EL1	   ], 64);
	hyp_putsxnl("PSTATE_DAIF     ", regs[GHOST_PSTATE_DAIF	   ], 64);
	hyp_putsxnl("PSTATE_CURRENTEL", regs[GHOST_PSTATE_CURRENTEL], 64);
	hyp_putsxnl("PSTATE_SPSEL    ", regs[GHOST_PSTATE_SPSEL	   ], 64);
	//hyp_putsxnl("SCR_EL3         ", regs[GHOST_SCR_EL3	   ], 64);

}





/* **************************************** */
/* dump shadow vm and vcpu data */

#include <nvhe/pkvm.h>


void ghost_dump_shadow_table(void)
{
	//	u64 i;
	hyp_puts("\nshadow table");
        hyp_puts("\nghost instrumentation disabled for now\n");
	/*
	if (num_shadow_entries==0) {
		hyp_puts(" empty");
		return;
	}

	for (i=0; i<num_shadow_entries; i++) {
		hyp_putsxn("shadow_handle",(u64)(*shadow_table)[i].shadow_handle,64);
		hyp_putc('\n');
	}
	*/
}

/* **************************************** */
/* dump memory allocation from setup.c */

void ghost_dump_setup(void)
{

	hyp_putsxn("    ghost__pkvm_init_virt",     ghost__pkvm_init_virt, 64);
	hyp_putsxn("virt'",    ghost__pkvm_init_virt+ghost__pkvm_init_size, 64);
	hyp_putsxn("ghost__pkvm_init_phys",	ghost__pkvm_init_phys, 64);
	hyp_putsxn("phys'",	ghost__pkvm_init_phys+ghost__pkvm_init_size, 64);
	hyp_putsxn("size",     ghost__pkvm_init_size, 64);
	hyp_putc('\n');

	hyp_putsxn("    vmemmap_base    ", (u64)vmemmap_base, 64);
	hyp_putsxn("size",	ghost_vmemmap_size, 64);
	hyp_putc('\n');
	//	hyp_putsxn("shadow_table    ", (u64)shadow_table, 64);
	//	hyp_putsxn("size",	ghost_shadow_table_size	, 64);
	//	hyp_putc('\n');
	hyp_putsxn("    hyp_pgt_base    ",(u64)hyp_pgt_base,64);
	hyp_putsxn("size",	ghost_hyp_pgt_size, 64);
	hyp_putc('\n');
	hyp_putsxn("    host_s2_pgt_base", (u64)host_s2_pgt_base, 64);
	hyp_putsxn("size",	ghost_host_s2_pgt_size, 64);
	hyp_putc('\n');
}

