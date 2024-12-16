/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

// TODO(standalone): replace this
#include <linux/linkage.h>
#undef ULL

#include <picovm/sysregs.h>


#ifdef CONFIG_PICOVM_STANDALONE

// TODO (from kvm_mmu.h)
/*
 * Convert a hypervisor VA to a PA
 * reg: hypervisor address to be converted in place
 * tmp: temporary register
 */
.macro hyp_pa reg, tmp
	ldr_l	\tmp, hyp_physvirt_offset
	add	\reg, \reg, \tmp
.endm

// TODO (from kvm_mmu.h)
/*
 * Convert a hypervisor VA to a kernel image address
 * reg: hypervisor address to be converted in place
 * tmp: temporary register
 *
 * The actual code generation takes place in kvm_get_kimage_voffset, and
 * the instructions below are only there to reserve the space and
 * perform the register allocation (kvm_get_kimage_voffset uses the
 * specific registers encoded in the instructions).
 */
.macro hyp_kimg_va reg, tmp
	/* Convert hyp VA -> PA. */
	hyp_pa	\reg, \tmp

	/* Load kimage_voffset. */
alternative_cb ARM64_ALWAYS_SYSTEM, kvm_get_kimage_voffset
	movz	\tmp, #0
	movk	\tmp, #0, lsl #16
	movk	\tmp, #0, lsl #32
	movk	\tmp, #0, lsl #48
alternative_cb_end

	/* Convert PA -> kimg VA. */
	add	\reg, \reg, \tmp
.endm


// TODO (from arch/arm64/include/asm/virt.h)
#define HVC_STUB_HCALL_NR	4

// TODO
// we always has KVM_MODE_PROTECTED to true, right? (if so remove the ARM64_KVM_PROTECTED_MODE alternative_if)

//TODO (from kvm_asm.h)
#define CPU_XREG_OFFSET(x)	(CPU_USER_PT_REGS + 8*x)
/*
 * We treat x18 as callee-saved as the host may use it as a platform
 * register (e.g. for shadow call stack).
 */
.macro save_callee_saved_regs ctxt
	str	x18,      [\ctxt, #CPU_XREG_OFFSET(18)]
	stp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	stp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	stp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	stp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	stp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	stp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm
.macro restore_callee_saved_regs ctxt
	// We require \ctxt is not x18-x28
	ldr	x18,      [\ctxt, #CPU_XREG_OFFSET(18)]
	ldp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	ldp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	ldp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	ldp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	ldp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	ldp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm


//TODO (from kvm_asm.h)
.macro get_host_ctxt reg, tmp
	adr_this_cpu \reg, kvm_host_data, \tmp
	add	\reg, \reg, #HOST_DATA_CONTEXT
.endm

//TODO (from kvm_asm.h)
.macro get_vcpu_ptr vcpu, ctxt
	get_host_ctxt \ctxt, \vcpu
	ldr	\vcpu, [\ctxt, #HOST_CONTEXT_VCPU]
.endm

//TODO (from kvm_asm.h)
.macro get_loaded_vcpu vcpu, ctxt
	adr_this_cpu \ctxt, kvm_hyp_ctxt, \vcpu
	ldr	\vcpu, [\ctxt, #HOST_CONTEXT_VCPU]
.endm

#else
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#endif /* CONFIG_PICOVM_STANDALONE */

// Copied and adapted from arch/arm64/include/asm/kvm_asm.h
//.macro picovm_get_host_ctxt reg, tmp
//	adr_this_cpu \reg, picovm_host_data, \tmp
//	add	\reg, \reg, #HOST_DATA_CONTEXT   TODO: this offset needs to be adapted to the picovm type
//.endm


	.text

SYM_FUNC_START(__host_exit)
	get_host_ctxt	x0, x1

	/* Store the host regs x2 and x3 */
	stp	x2, x3,   [x0, #CPU_XREG_OFFSET(2)]

	/* Retrieve the host regs x0-x1 from the stack */
	ldp	x2, x3, [sp], #16	// x0, x1

	/* Store the host regs x0-x1 and x4-x17 */
	stp	x2, x3,   [x0, #CPU_XREG_OFFSET(0)]
	stp	x4, x5,   [x0, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [x0, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [x0, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [x0, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [x0, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [x0, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [x0, #CPU_XREG_OFFSET(16)]

	/* Store the host regs x18-x29, lr */
	save_callee_saved_regs x0

	/* Save the host context pointer in x29 across the function call */
	mov	x29, x0
	bl	handle_trap

	/* Restore host regs x0-x17 */
__host_enter_restore_full:
	ldp	x0, x1,   [x29, #CPU_XREG_OFFSET(0)]
	ldp	x2, x3,   [x29, #CPU_XREG_OFFSET(2)]
	ldp	x4, x5,   [x29, #CPU_XREG_OFFSET(4)]
	ldp	x6, x7,   [x29, #CPU_XREG_OFFSET(6)]

	/* x0-7 are use for panic arguments */
__host_enter_for_panic:
	ldp	x8, x9,   [x29, #CPU_XREG_OFFSET(8)]
	ldp	x10, x11, [x29, #CPU_XREG_OFFSET(10)]
	ldp	x12, x13, [x29, #CPU_XREG_OFFSET(12)]
	ldp	x14, x15, [x29, #CPU_XREG_OFFSET(14)]
	ldp	x16, x17, [x29, #CPU_XREG_OFFSET(16)]

	/* Restore host regs x18-x29, lr */
	restore_callee_saved_regs x29

	/* Do not touch any register after this! */
__host_enter_without_restoring:
	eret
	sb
SYM_FUNC_END(__host_exit)

/*
 * void __noreturn __host_enter(struct kvm_cpu_context *host_ctxt);
 */
SYM_FUNC_START(__host_enter)
	mov	x29, x0
	b	__host_enter_restore_full
SYM_FUNC_END(__host_enter)

/*
 * void __noreturn __hyp_do_panic(struct kvm_cpu_context *host_ctxt, u64 spsr,
 * 				  u64 elr, u64 par);
 */
SYM_FUNC_START(__hyp_do_panic)
	/* Prepare and exit to the host's panic funciton. */
	mov	lr, #(PSR_F_BIT | PSR_I_BIT | PSR_A_BIT | PSR_D_BIT |\
		      PSR_MODE_EL1h)
	msr	spsr_el2, lr
	adr_l	lr, nvhe_hyp_panic_handler
	hyp_kimg_va lr, x6
	msr	elr_el2, lr

	mov	x29, x0

#ifdef CONFIG_NVHE_EL2_DEBUG
	/* Ensure host stage-2 is disabled */
	mrs	x0, hcr_el2
	bic	x0, x0, #HCR_VM
	msr	hcr_el2, x0
	isb
	tlbi	vmalls12e1
	dsb	nsh
#endif

	/* Load the panic arguments into x0-7 */
	mrs	x0, esr_el2
	mov	x4, x3
	mov	x3, x2
	hyp_pa	x3, x6
	get_vcpu_ptr x5, x6
	mrs	x6, far_el2
	mrs	x7, hpfar_el2

	/* Enter the host, conditionally restoring the host context. */
	cbz	x29, __host_enter_without_restoring
	b	__host_enter_for_panic
SYM_FUNC_END(__hyp_do_panic)

SYM_FUNC_START(__host_hvc)
	ldp	x0, x1, [sp]		// Don't fixup the stack yet

	/* No stub for you, sonny Jim */
alternative_if ARM64_KVM_PROTECTED_MODE
	b	__host_exit
alternative_else_nop_endif

	/* Check for a stub HVC call */
	cmp	x0, #HVC_STUB_HCALL_NR
	b.hs	__host_exit

	add	sp, sp, #16
	/*
	 * Compute the idmap address of __kvm_handle_stub_hvc and
	 * jump there.
	 *
	 * Preserve x0-x4, which may contain stub parameters.
	 */
	adr_l	x5, __kvm_handle_stub_hvc
	hyp_pa	x5, x6
	br	x5
SYM_FUNC_END(__host_hvc)

.macro host_el1_sync_vect
	.align 7
.L__vect_start\@:
	stp	x0, x1, [sp, #-16]!
	mrs	x0, esr_el2
	ubfx	x0, x0, #ESR_ELx_EC_SHIFT, #ESR_ELx_EC_WIDTH
	cmp	x0, #ESR_ELx_EC_HVC64
	b.eq	__host_hvc
	b	__host_exit
.L__vect_end\@:
.if ((.L__vect_end\@ - .L__vect_start\@) > 0x80)
	.error "host_el1_sync_vect larger than vector entry"
.endif
.endm

.macro invalid_host_el2_vect
	.align 7

	/*
	 * Test whether the SP has overflowed, without corrupting a GPR.
	 * nVHE hypervisor stacks are aligned so that the PAGE_SHIFT bit
	 * of SP should always be 1.
	 */
	add	sp, sp, x0			// sp' = sp + x0
	sub	x0, sp, x0			// x0' = sp' - x0 = (sp + x0) - x0 = sp
	tbz	x0, #PAGE_SHIFT, .L__hyp_sp_overflow\@
	sub	x0, sp, x0			// x0'' = sp' - x0' = (sp + x0) - sp = x0
	sub	sp, sp, x0			// sp'' = sp' - x0 = (sp + x0) - x0 = sp

	/* If a guest is loaded, panic out of it. */
	stp	x0, x1, [sp, #-16]!
	get_loaded_vcpu x0, x1
	cbnz	x0, __guest_exit_panic
	add	sp, sp, #16

	/*
	 * The panic may not be clean if the exception is taken before the host
	 * context has been saved by __host_exit or after the hyp context has
	 * been partially clobbered by __host_enter.
	 */
	b	hyp_panic

.L__hyp_sp_overflow\@:
	/* Switch to the overflow stack */
	adr_this_cpu sp, overflow_stack + OVERFLOW_STACK_SIZE, x0

	b	hyp_panic_bad_stack
	ASM_BUG()
.endm

.macro invalid_host_el1_vect
	.align 7
	mov	x0, xzr		/* restore_host = false */
	mrs	x1, spsr_el2
	mrs	x2, elr_el2
	mrs	x3, par_el1
	b	__hyp_do_panic
.endm

/*
 * The host vector does not use an ESB instruction in order to avoid consuming
 * SErrors that should only be consumed by the host. Guest entry is deferred by
 * __guest_enter if there are any pending asynchronous exceptions so hyp will
 * always return to the host without having consumerd host SErrors.
 *
 * CONFIG_KVM_INDIRECT_VECTORS is not applied to the host vectors because the
 * host knows about the EL2 vectors already, and there is no point in hiding
 * them.
 */
	.align 11
SYM_CODE_START(__kvm_hyp_host_vector)
	invalid_host_el2_vect			// Synchronous EL2t
	invalid_host_el2_vect			// IRQ EL2t
	invalid_host_el2_vect			// FIQ EL2t
	invalid_host_el2_vect			// Error EL2t

	invalid_host_el2_vect			// Synchronous EL2h
	invalid_host_el2_vect			// IRQ EL2h
	invalid_host_el2_vect			// FIQ EL2h
	invalid_host_el2_vect			// Error EL2h

	host_el1_sync_vect			// Synchronous 64-bit EL1/EL0
	invalid_host_el1_vect			// IRQ 64-bit EL1/EL0
	invalid_host_el1_vect			// FIQ 64-bit EL1/EL0
	invalid_host_el1_vect			// Error 64-bit EL1/EL0

	host_el1_sync_vect			// Synchronous 32-bit EL1/EL0
	invalid_host_el1_vect			// IRQ 32-bit EL1/EL0
	invalid_host_el1_vect			// FIQ 32-bit EL1/EL0
	invalid_host_el1_vect			// Error 32-bit EL1/EL0
SYM_CODE_END(__kvm_hyp_host_vector)

