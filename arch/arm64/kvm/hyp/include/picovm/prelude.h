/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *	include/uapi/linux/const.h
 *	include/linux/cache.h
 *	include/linux/align.h
 *	include/asm/sections.h
 *	include/asm-generic/barrier.h
 *	arch/arm64/include/asm/kvm_emulate.h
 */
#ifndef __PICOVM_PRELUDE_H
#define __PICOVM_PRELUDE_H

/*
 * NOTE: List of header files external to PicoVM.
 * Completely detaching PicoVM from the Linux kernel presents some challenges:
 * - Many header files depend on low-level code, which ultimately relies on linux/types.
 * - CPU feature handling uses data structures initialized outside of KVM.
 */
#include <linux/types.h>
#include <linux/memblock.h>

#include <asm-generic/percpu.h>
#include <asm/cpufeature.h>
#include <asm/page.h>
#include <asm/memory.h>
#include <asm/mmu.h>
#include <asm/esr.h>
#include <asm/ptrace.h>
#include <asm/kvm_asm.h>

#include <picovm/linux/errno-base.h>
#include <picovm/linux/sys_regs.h>

#define BITS 64
#define BITS_PER_LONG 64

typedef uint8_t  BYTE;
typedef uint8_t  U8;
typedef int8_t   S8;
typedef uint16_t U16;
typedef int16_t  S16;
typedef uint32_t U32;
typedef int32_t  S32;
typedef uint64_t U64;
typedef int64_t  S64;


#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)

// TODO
static inline void picovm_assert(u64 x)
{

}

extern char __hyp_idmap_text_start[], __hyp_idmap_text_end[];
extern char __hyp_text_start[], __hyp_text_end[];
extern char __hyp_rodata_start[], __hyp_rodata_end[];
extern char __hyp_reloc_begin[], __hyp_reloc_end[];
extern char __hyp_bss_start[], __hyp_bss_end[];
extern char __idmap_text_start[], __idmap_text_end[];

/*
 * __ro_after_init is used to mark things that are read-only after init (i.e.
 * after mark_rodata_ro() has been called). These are effectively read-only,
 * but may get written to during init, so can't live in .rodata (via "const").
 */
#ifndef __ro_after_init
#define __ro_after_init __section(".data..ro_after_init")
#endif

/*
 * Raw TLBI operations.
 *
 * Where necessary, use the __tlbi() macro to avoid asm()
 * boilerplate. Drivers and most kernel code should use the TLB
 * management routines in preference to the macro below.
 *
 * The macro can be used as __tlbi(op) or __tlbi(op, arg), depending
 * on whether a particular TLBI operation takes an argument or
 * not. The macros handles invoking the asm with or without the
 * register argument as appropriate.
 */
// TODO: hardcoding in __TLBI_0 and __TLBI_1 the ARM64_WORKAROUND_REPEAT_TLBI
// patch to avoid depending on alternative in picovm
#define __TLBI_0(op, arg) asm (ARM64_ASM_PREAMBLE			       \
			       "tlbi " #op "\n"				       \
			       "dsb ish\n				       \
			       tlbi " #op	 			       \
			    : : )

#define __TLBI_1(op, arg) asm (ARM64_ASM_PREAMBLE			       \
			       "tlbi " #op ", %0\n"			       \
			       "dsb ish\n				       \
			       tlbi " #op ", %0"			       \
			    : : "r" (arg))

#define __TLBI_N(op, arg, n, ...) __TLBI_##n(op, arg)

#define __tlbi(op, ...)		__TLBI_N(op, ##__VA_ARGS__, 1, 0)
#define __tlbi_level(op, addr, level) do {				\
	u64 arg = addr;							\
	__tlbi(op, arg);						\
} while(0)

#define isb()		asm volatile("isb" : : : "memory")
#define dmb(opt)	asm volatile("dmb " #opt : : : "memory")
#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")
#define __smp_mb()	dmb(ish)

// TODO(note): this copy removes the call to kasan_check_write() and changes
// the occurences of types __uN to uN from picovm/prelude.h
#define __smp_store_release(p, v)					\
do {									\
	typeof(p) __p = (p);						\
	union { __unqual_scalar_typeof(*p) __val; char __c[1]; } __u =	\
		{ .__val = (__force __unqual_scalar_typeof(*p)) (v) };	\
	compiletime_assert_atomic_type(*p);				\
	switch (sizeof(*p)) {						\
	case 1:								\
		asm volatile ("stlrb %w1, %0"				\
				: "=Q" (*__p)				\
				: "rZ" (*(u8 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 2:								\
		asm volatile ("stlrh %w1, %0"				\
				: "=Q" (*__p)				\
				: "rZ" (*(u16 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 4:								\
		asm volatile ("stlr %w1, %0"				\
				: "=Q" (*__p)				\
				: "rZ" (*(u32 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 8:								\
		asm volatile ("stlr %x1, %0"				\
				: "=Q" (*__p)				\
				: "rZ" (*(u64 *)__u.__c)		\
				: "memory");				\
		break;							\
	}								\
} while (0)

#ifndef smp_store_release
#define smp_store_release(p, v) do { __smp_store_release(p, v); } while (0)
#endif

/// Exceptions

#define CURRENT_EL_SP_EL0_VECTOR	0x0
#define CURRENT_EL_SP_ELx_VECTOR	0x200
#define LOWER_EL_AArch64_VECTOR		0x400
#define LOWER_EL_AArch32_VECTOR		0x600

enum exception_type {
	except_type_sync	= 0,
	except_type_irq		= 0x80,
	except_type_fiq		= 0x100,
	except_type_serror	= 0x180,
};

#define picovm_exception_type_names		\
	{ except_type_sync,	"SYNC"   },	\
	{ except_type_irq,	"IRQ"    },	\
	{ except_type_fiq,	"FIQ"    },	\
	{ except_type_serror,	"SERROR" }

unsigned long get_except64_offset(unsigned long psr, unsigned long target_mode,
				  enum exception_type type)
{
	u64 mode = psr & (PSR_MODE_MASK | PSR_MODE32_BIT);
	u64 exc_offset;

	if      (mode == target_mode)
		exc_offset = CURRENT_EL_SP_ELx_VECTOR;
	else if ((mode | PSR_MODE_THREAD_BIT) == target_mode)
		exc_offset = CURRENT_EL_SP_EL0_VECTOR;
	else if (!(mode & PSR_MODE32_BIT))
		exc_offset = LOWER_EL_AArch64_VECTOR;
	else
		exc_offset = LOWER_EL_AArch32_VECTOR;

	return exc_offset + type;
}

unsigned long get_except64_cpsr(unsigned long old, bool has_mte,
				unsigned long sctlr, unsigned long target_mode)
{
	u64 new = 0;

	new |= (old & PSR_N_BIT);
	new |= (old & PSR_Z_BIT);
	new |= (old & PSR_C_BIT);
	new |= (old & PSR_V_BIT);

	if (has_mte)
		new |= PSR_TCO_BIT;

	new |= (old & PSR_DIT_BIT);

	// PSTATE.UAO is set to zero upon any exception to AArch64
	// See ARM DDI 0487E.a, page D5-2579.

	// PSTATE.PAN is unchanged unless SCTLR_ELx.SPAN == 0b0
	// SCTLR_ELx.SPAN is RES1 when ARMv8.1-PAN is not implemented
	// See ARM DDI 0487E.a, page D5-2578.
	new |= (old & PSR_PAN_BIT);
	if (!(sctlr & SCTLR_EL1_SPAN))
		new |= PSR_PAN_BIT;

	// PSTATE.SS is set to zero upon any exception to AArch64
	// See ARM DDI 0487E.a, page D2-2452.

	// PSTATE.IL is set to zero upon any exception to AArch64
	// See ARM DDI 0487E.a, page D1-2306.

	// PSTATE.SSBS is set to SCTLR_ELx.DSSBS upon any exception to AArch64
	// See ARM DDI 0487E.a, page D13-3258
	if (sctlr & SCTLR_ELx_DSSBS)
		new |= PSR_SSBS_BIT;

	// PSTATE.BTYPE is set to zero upon any exception to AArch64
	// See ARM DDI 0487E.a, pages D1-2293 to D1-2294.

	new |= PSR_D_BIT;
	new |= PSR_A_BIT;
	new |= PSR_I_BIT;
	new |= PSR_F_BIT;

	new |= target_mode;

	return new;
}


#endif /* __PICOVM_PRELUDE_H */
