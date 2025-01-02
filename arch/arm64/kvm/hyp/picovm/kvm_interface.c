/* SPDX-License-Identifier: GPL-2.0-only */
#include <picovm/per-cpu.h>
#include <picovm/kvm_host.h>

#include <picovm/linux/types.h>
#include <picovm/linux/memblock.h>

#define __ro_after_init	__attribute__((__section__(".data..ro_after_init")))

/*
 * This file defines all the symbols needed to link kvm_nvhe.o with
 * the rest of the kernel.
 * For completeness we include as extern declarations symbols
 * we are defined in assembly somewhere else.
 */

// USED BY EXTERNAL arch/arm64/kvm/arm.c
// provided by reusing arch/arm64/kvm/hyp/hyp-entry.S
extern char __kvm_hyp_vector[];
extern unsigned char __bp_harden_hyp_vecs[];

// USED BY EXTERNAL arch/arm64/kvm/mmu.c
// provided by reusing arch/arm64/kvm/hyp/nvhe/hyp-init.S
extern char __kvm_hyp_init[];

// USED BY EXTERNAL arch/arm64/kvm/arm.c
// provided by reusing arch/arm64/kvm/hyp/nvhe/hyp-smp.c
// DEFINE_PER_CPU(int, hyp_cpu_number);
// u64 __ro_after_init hyp_cpu_logical_map[CONFIG_NR_CPUS];
// unsigned long __ro_after_init kvm_arm_hyp_percpu_base[CONFIG_NR_CPUS];

// USED BY EXTERNAL arch/arm64/kvm/arm.c
// provided by reusing arch/arm64/kvm/hyp/nvhe/psci-relay.c
// struct kvm_host_psci_config __ro_after_init kvm_host_psci_config;

// USED BY EXTERNAL arch/arm64/kvm/stacktrace.c
// provided by reusing arch/arm64/kvm/hyp/nvhe/stacktrace.c
// DEFINE_PER_CPU(unsigned long [OVERFLOW_STACK_SIZE/sizeof(long)], overflow_stack) __aligned(16);
// DEFINE_PER_CPU(struct kvm_nvhe_stacktrace_info, kvm_stacktrace_info);
// DEFINE_PER_CPU(unsigned long [NVHE_STACKTRACE_SIZE/sizeof(long)], pkvm_stacktrace);

/*****************************************************************************/

// NOTE: The definitions of these two were moved to the nvhe code by us for
// recording purpose. They were originally in arch/arm64/kvm/va_layout.c
u64 tag_val;
u8 tag_lsb;

// Initialised by arch/arm64/kvm/va_layout.c::init_hyp_physvirt_offset()
s64 __ro_after_init hyp_physvirt_offset;

// Initialised by arch/arm64/kvm/arm.c::kvm_hyp_init_symbols()
unsigned int __ro_after_init kvm_arm_vmid_bits;

// TODO: this comes from arch/arm64/include/asm/kvm_pkvm.h
// need to make sure this does not go out of sync somehow
#define HYP_MEMBLOCK_REGIONS	128
struct memblock_region hyp_memory[HYP_MEMBLOCK_REGIONS];
unsigned int hyp_memblock_nr;


// USED BY EXTERNAL arch/arm64/kvm/arm.c
// USED BY arch/arm64/kvm/hyp/entry.S
// USED BY arch/arm64/kvm/hyp/hyp-entry.S
// USED BY arch/arm64/kvm/hyp/picovm/host.S
// USED BY arch/arm64/kvm/hyp/picovm/setup.c
// USED BY arch/arm64/kvm/pmu.c
DEFINE_PER_CPU(struct kvm_host_data, kvm_host_data);


/*****************************************************************************/
// IN THE REMAINDER OF THIS FILE ARE SYMBOLS THAT ARE NOT USED BY PICOVM

// USED BY EXTERNAL arch/arm64/kvm/mmu.c
unsigned long arm64_kvm_hyp_debug_uart_addr;

// USED BY EXTERNAL arch/arm64/kvm/arm.c
unsigned long __icache_flags;

/*
 * Copies of the host's CPU features registers holding sanitized values at hyp.
 * 
 * In picovm we don't make use of these, but the symbols are expected by EL1,
 * which initialises them (see arch/arm64/kvm/arm.c::kvm_hyp_init_symbols()).
 */
u64 id_aa64pfr0_el1_sys_val;
u64 id_aa64pfr1_el1_sys_val;
u64 id_aa64isar0_el1_sys_val;
u64 id_aa64isar1_el1_sys_val;
u64 id_aa64isar2_el1_sys_val;
u64 id_aa64mmfr0_el1_sys_val;
u64 id_aa64mmfr1_el1_sys_val;
u64 id_aa64mmfr2_el1_sys_val;
u64 id_aa64smfr0_el1_sys_val;


// USED BY EXTERNAL arch/arm64/kvm/arm.c
DEFINE_PER_CPU(unsigned long, kvm_hyp_vector);
DEFINE_PER_CPU(struct kvm_nvhe_init_params, kvm_init_params);


// Some functions are referenced by arch/arm64/kernel/vmlinux.lds
// Except for __pi_memset (see lib/memset.c) we provide dummy definitions
// as we don't currently make use of them in picovm.
void __pi_clear_page(void *to)
{ }
void __pi_copy_page(void *to, const void *from)
{ }
void *__pi_memcpy(void *dst, const void *src, size_t size)
{
	return 0;
}

// USED BY EXTERNAL arch/arm64/kvm/mmu.c
// provided arch/arm64/kvm/hyp/picovm/mem_protect.c
// int __pkvm_host_share_hyp(u64 pfn);
// int __pkvm_host_unshare_hyp(u64 pfn);

// USED BY EXTERNAL arch/arm64/kvm/arm.c
// USED BY EXTERNAL arch/arm64/kvm/pkvm.c
// provided arch/arm64/kvm/hyp/picovm/setup.c
// int __pkvm_init(phys_addr_t phys, unsigned long size, unsigned long nr_cpus,
// 		unsigned long *per_cpu_base, u32 hyp_va_bits);

// USED BY EXTERNAL arch/arm64/kvm/pkvm.c
// provided arch/arm64/kvm/hyp/picovm/mem_protect.c
// int __pkvm_prot_finalize(void)


/******************************************************************************
 * TODO: remove all after this once the picovm code builds
 *****************************************************************************/

DEFINE_PER_CPU(struct kvm_cpu_context, kvm_hyp_ctxt);
void __noreturn hyp_panic(void){}
void __noreturn hyp_panic_bad_stack(void){}
void kvm_unexpected_el2_exception(void){}
