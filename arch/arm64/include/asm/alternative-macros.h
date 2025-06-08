/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ALTERNATIVE_MACROS_H
#define __ASM_ALTERNATIVE_MACROS_H

#include <linux/const.h>
#include <vdso/bits.h>

#include <asm/cpucaps.h>
#include <asm/insn-def.h>

/*
 * Binutils 2.27.0 can't handle a 'UL' suffix on constants, so for the assembly
 * macros below we must use we must use `(1 << ARM64_CB_SHIFT)`.
 */
#define ARM64_CB_SHIFT	15
#define ARM64_CB_BIT	BIT(ARM64_CB_SHIFT)

#if ARM64_NCAPS >= ARM64_CB_BIT
#error "cpucaps have overflown ARM64_CB_BIT"
#endif

#ifndef BUILD_FIPS140_KO
#ifndef __ASSEMBLY__

#include <linux/stringify.h>

#define ALTINSTR_ENTRY(cpucap)					              \
	" .word 661b - .\n"				/* label           */ \
	" .word 663f - .\n"				/* new instruction */ \
	" .hword " __stringify(cpucap) "\n"		/* cpucap          */ \
	" .byte 662b-661b\n"				/* source len      */ \
	" .byte 664f-663f\n"				/* replacement len */

#define ALTINSTR_ENTRY_CB(cpucap, cb)					      \
	" .word 661b - .\n"				/* label           */ \
	" .word " __stringify(cb) "- .\n"		/* callback        */ \
	" .hword " __stringify(cpucap) "\n"		/* cpucap          */ \
	" .byte 662b-661b\n"				/* source len      */ \
	" .byte 664f-663f\n"				/* replacement len */

/*
 * alternative assembly primitive:
 *
 * If any of these .org directive fail, it means that insn1 and insn2
 * don't have the same length. This used to be written as
 *
 * .if ((664b-663b) != (662b-661b))
 * 	.error "Alternatives instruction length mismatch"
 * .endif
 *
 * but most assemblers die if insn1 or insn2 have a .inst. This should
 * be fixed in a binutils release posterior to 2.25.51.0.2 (anything
 * containing commit 4e4d08cf7399b606 or c1baaddf8861).
 *
 * Alternatives with callbacks do not generate replacement instructions.
 */
#define __ALTERNATIVE_CFG(oldinstr, newinstr, cpucap, cfg_enabled)	\
	".if "__stringify(cfg_enabled)" == 1\n"				\
	"661:\n\t"							\
	oldinstr "\n"							\
	"662:\n"							\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(cpucap)						\
	".popsection\n"							\
	".subsection 1\n"						\
	"663:\n\t"							\
	newinstr "\n"							\
	"664:\n\t"							\
	".org	. - (664b-663b) + (662b-661b)\n\t"			\
	".org	. - (662b-661b) + (664b-663b)\n\t"			\
	".previous\n"							\
	".endif\n"

#define __ALTERNATIVE_CFG_CB(oldinstr, cpucap, cfg_enabled, cb)	\
	".if "__stringify(cfg_enabled)" == 1\n"				\
	"661:\n\t"							\
	oldinstr "\n"							\
	"662:\n"							\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY_CB(cpucap, cb)					\
	".popsection\n"							\
	"663:\n\t"							\
	"664:\n\t"							\
	".endif\n"

#define _ALTERNATIVE_CFG(oldinstr, newinstr, cpucap, cfg, ...)	\
	__ALTERNATIVE_CFG(oldinstr, newinstr, cpucap, IS_ENABLED(cfg))

#define ALTERNATIVE_CB(oldinstr, cpucap, cb) \
	__ALTERNATIVE_CFG_CB(oldinstr, (1 << ARM64_CB_SHIFT) | (cpucap), 1, cb)
#else

#include <asm/assembler.h>

.macro altinstruction_entry orig_offset alt_offset cpucap orig_len alt_len
	.word \orig_offset - .
	.word \alt_offset - .
	.hword (\cpucap)
	.byte \orig_len
	.byte \alt_len
.endm

.macro alternative_insn insn1, insn2, cap, enable = 1
	.if \enable
661:	\insn1
662:	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663f, \cap, 662b-661b, 664f-663f
	.popsection
	.subsection 1
663:	\insn2
664:	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
	.previous
	.endif
.endm

/*
 * Alternative sequences
 *
 * The code for the case where the capability is not present will be
 * assembled and linked as normal. There are no restrictions on this
 * code.
 *
 * The code for the case where the capability is present will be
 * assembled into a special section to be used for dynamic patching.
 * Code for that case must:
 *
 * 1. Be exactly the same length (in bytes) as the default code
 *    sequence.
 *
 * 2. Not contain a branch target that is used outside of the
 *    alternative sequence it is defined in (branches into an
 *    alternative sequence are not fixed up).
 */

/*
 * Begin an alternative code sequence.
 */
.macro alternative_if_not cap
	.set .Lasm_alt_mode, 0
	.pushsection .altinstructions, "a"
	altinstruction_entry 661f, 663f, \cap, 662f-661f, 664f-663f
	.popsection
661:
.endm

.macro alternative_if cap
	.set .Lasm_alt_mode, 1
	.pushsection .altinstructions, "a"
	altinstruction_entry 663f, 661f, \cap, 664f-663f, 662f-661f
	.popsection
	.subsection 1
	.align 2	/* So GAS knows label 661 is suitably aligned */
661:
.endm

.macro alternative_cb cap, cb
	.set .Lasm_alt_mode, 0
	.pushsection .altinstructions, "a"
	altinstruction_entry 661f, \cb, (1 << ARM64_CB_SHIFT) | \cap, 662f-661f, 0
	.popsection
661:
.endm

/*
 * Provide the other half of the alternative code sequence.
 */
.macro alternative_else
662:
	.if .Lasm_alt_mode==0
	.subsection 1
	.else
	.previous
	.endif
663:
.endm

/*
 * Complete an alternative code sequence.
 */
.macro alternative_endif
664:
	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
	.if .Lasm_alt_mode==0
	.previous
	.endif
.endm

/*
 * Callback-based alternative epilogue
 */
.macro alternative_cb_end
662:
.endm

/*
 * Provides a trivial alternative or default sequence consisting solely
 * of NOPs. The number of NOPs is chosen automatically to match the
 * previous case.
 */
.macro alternative_else_nop_endif
alternative_else
	nops	(662b-661b) / AARCH64_INSN_SIZE
alternative_endif
.endm

#define _ALTERNATIVE_CFG(insn1, insn2, cap, cfg, ...)	\
	alternative_insn insn1, insn2, cap, IS_ENABLED(cfg)

#endif  /*  __ASSEMBLY__  */

/*
 * Usage: asm(ALTERNATIVE(oldinstr, newinstr, cpucap));
 *
 * Usage: asm(ALTERNATIVE(oldinstr, newinstr, cpucap, CONFIG_FOO));
 * N.B. If CONFIG_FOO is specified, but not selected, the whole block
 *      will be omitted, including oldinstr.
 */
#define ALTERNATIVE(oldinstr, newinstr, ...)   \
	_ALTERNATIVE_CFG(oldinstr, newinstr, __VA_ARGS__, 1)

#ifndef __ASSEMBLY__

#ifdef CONFIG_NVHE_EL2_O0
#include <linux/bug.h>
#endif /* CONFIG_NVHE_EL2_O0 */
#include <linux/types.h>

#ifdef CONFIG_NVHE_EL2_O0
#if ARM64_NCAPS != 117
#error "REMS -O0 hack need to be updated (ARM64_NCAPS changed)"
#endif

#define __REMS_O0_hack_LIKELY(N)						\
	asm goto(								\
	ALTERNATIVE_CB("b	%l[l_no]", N, alt_cb_patch_nops)		\
	:::: l_no)
#define REMS_O0_hack_LIKELY(N)							\
	switch (N) {								\
	case 0:									\
		__REMS_O0_hack_LIKELY(0);					\
		break;								\
	case 1:									\
		__REMS_O0_hack_LIKELY(1);					\
		break;								\
	case 2:									\
		__REMS_O0_hack_LIKELY(2);					\
		break;								\
	case 3:									\
		__REMS_O0_hack_LIKELY(3);					\
		break;								\
	case 4:									\
		__REMS_O0_hack_LIKELY(4);					\
		break;								\
	case 5:									\
		__REMS_O0_hack_LIKELY(5);					\
		break;								\
	case 6:									\
		__REMS_O0_hack_LIKELY(6);					\
		break;								\
	case 7:									\
		__REMS_O0_hack_LIKELY(7);					\
		break;								\
	case 8:									\
		__REMS_O0_hack_LIKELY(8);					\
		break;								\
	case 9:									\
		__REMS_O0_hack_LIKELY(9);					\
		break;								\
	case 10:								\
		__REMS_O0_hack_LIKELY(10);					\
		break;								\
	case 11:								\
		__REMS_O0_hack_LIKELY(11);					\
		break;								\
	case 12:								\
		__REMS_O0_hack_LIKELY(12);					\
		break;								\
	case 13:								\
		__REMS_O0_hack_LIKELY(13);					\
		break;								\
	case 14:								\
		__REMS_O0_hack_LIKELY(14);					\
		break;								\
	case 15:								\
		__REMS_O0_hack_LIKELY(15);					\
		break;								\
	case 16:								\
		__REMS_O0_hack_LIKELY(16);					\
		break;								\
	case 17:								\
		__REMS_O0_hack_LIKELY(17);					\
		break;								\
	case 18:								\
		__REMS_O0_hack_LIKELY(18);					\
		break;								\
	case 19:								\
		__REMS_O0_hack_LIKELY(19);					\
		break;								\
	case 20:								\
		__REMS_O0_hack_LIKELY(20);					\
		break;								\
	case 21:								\
		__REMS_O0_hack_LIKELY(21);					\
		break;								\
	case 22:								\
		__REMS_O0_hack_LIKELY(22);					\
		break;								\
	case 23:								\
		__REMS_O0_hack_LIKELY(23);					\
		break;								\
	case 24:								\
		__REMS_O0_hack_LIKELY(24);					\
		break;								\
	case 25:								\
		__REMS_O0_hack_LIKELY(25);					\
		break;								\
	case 26:								\
		__REMS_O0_hack_LIKELY(26);					\
		break;								\
	case 27:								\
		__REMS_O0_hack_LIKELY(27);					\
		break;								\
	case 28:								\
		__REMS_O0_hack_LIKELY(28);					\
		break;								\
	case 29:								\
		__REMS_O0_hack_LIKELY(29);					\
		break;								\
	case 30:								\
		__REMS_O0_hack_LIKELY(30);					\
		break;								\
	case 31:								\
		__REMS_O0_hack_LIKELY(31);					\
		break;								\
	case 32:								\
		__REMS_O0_hack_LIKELY(32);					\
		break;								\
	case 33:								\
		__REMS_O0_hack_LIKELY(33);					\
		break;								\
	case 34:								\
		__REMS_O0_hack_LIKELY(34);					\
		break;								\
	case 35:								\
		__REMS_O0_hack_LIKELY(35);					\
		break;								\
	case 36:								\
		__REMS_O0_hack_LIKELY(36);					\
		break;								\
	case 37:								\
		__REMS_O0_hack_LIKELY(37);					\
		break;								\
	case 38:								\
		__REMS_O0_hack_LIKELY(38);					\
		break;								\
	case 39:								\
		__REMS_O0_hack_LIKELY(39);					\
		break;								\
	case 40:								\
		__REMS_O0_hack_LIKELY(40);					\
		break;								\
	case 41:								\
		__REMS_O0_hack_LIKELY(41);					\
		break;								\
	case 42:								\
		__REMS_O0_hack_LIKELY(42);					\
		break;								\
	case 43:								\
		__REMS_O0_hack_LIKELY(43);					\
		break;								\
	case 44:								\
		__REMS_O0_hack_LIKELY(44);					\
		break;								\
	case 45:								\
		__REMS_O0_hack_LIKELY(45);					\
		break;								\
	case 46:								\
		__REMS_O0_hack_LIKELY(46);					\
		break;								\
	case 47:								\
		__REMS_O0_hack_LIKELY(47);					\
		break;								\
	case 48:								\
		__REMS_O0_hack_LIKELY(48);					\
		break;								\
	case 49:								\
		__REMS_O0_hack_LIKELY(49);					\
		break;								\
	case 50:								\
		__REMS_O0_hack_LIKELY(50);					\
		break;								\
	case 51:								\
		__REMS_O0_hack_LIKELY(51);					\
		break;								\
	case 52:								\
		__REMS_O0_hack_LIKELY(52);					\
		break;								\
	case 53:								\
		__REMS_O0_hack_LIKELY(53);					\
		break;								\
	case 54:								\
		__REMS_O0_hack_LIKELY(54);					\
		break;								\
	case 55:								\
		__REMS_O0_hack_LIKELY(55);					\
		break;								\
	case 56:								\
		__REMS_O0_hack_LIKELY(56);					\
		break;								\
	case 57:								\
		__REMS_O0_hack_LIKELY(57);					\
		break;								\
	case 58:								\
		__REMS_O0_hack_LIKELY(58);					\
		break;								\
	case 59:								\
		__REMS_O0_hack_LIKELY(59);					\
		break;								\
	case 60:								\
		__REMS_O0_hack_LIKELY(60);					\
		break;								\
	case 61:								\
		__REMS_O0_hack_LIKELY(61);					\
		break;								\
	case 62:								\
		__REMS_O0_hack_LIKELY(62);					\
		break;								\
	case 63:								\
		__REMS_O0_hack_LIKELY(63);					\
		break;								\
	case 64:								\
		__REMS_O0_hack_LIKELY(64);					\
		break;								\
	case 65:								\
		__REMS_O0_hack_LIKELY(65);					\
		break;								\
	case 66:								\
		__REMS_O0_hack_LIKELY(66);					\
		break;								\
	case 67:								\
		__REMS_O0_hack_LIKELY(67);					\
		break;								\
	case 68:								\
		__REMS_O0_hack_LIKELY(68);					\
		break;								\
	case 69:								\
		__REMS_O0_hack_LIKELY(69);					\
		break;								\
	case 70:								\
		__REMS_O0_hack_LIKELY(70);					\
		break;								\
	case 71:								\
		__REMS_O0_hack_LIKELY(71);					\
		break;								\
	case 72:								\
		__REMS_O0_hack_LIKELY(72);					\
		break;								\
	case 73:								\
		__REMS_O0_hack_LIKELY(73);					\
		break;								\
	case 74:								\
		__REMS_O0_hack_LIKELY(74);					\
		break;								\
	case 75:								\
		__REMS_O0_hack_LIKELY(75);					\
		break;								\
	case 76:								\
		__REMS_O0_hack_LIKELY(76);					\
		break;								\
	case 77:								\
		__REMS_O0_hack_LIKELY(77);					\
		break;								\
	case 78:								\
		__REMS_O0_hack_LIKELY(78);					\
		break;								\
	case 79:								\
		__REMS_O0_hack_LIKELY(79);					\
		break;								\
	case 80:								\
		__REMS_O0_hack_LIKELY(80);					\
		break;								\
	case 81:								\
		__REMS_O0_hack_LIKELY(81);					\
		break;								\
	case 82:								\
		__REMS_O0_hack_LIKELY(82);					\
		break;								\
	case 83:								\
		__REMS_O0_hack_LIKELY(83);					\
		break;								\
	case 84:								\
		__REMS_O0_hack_LIKELY(84);					\
		break;								\
	case 85:								\
		__REMS_O0_hack_LIKELY(85);					\
		break;								\
	case 86:								\
		__REMS_O0_hack_LIKELY(86);					\
		break;								\
	case 87:								\
		__REMS_O0_hack_LIKELY(87);					\
		break;								\
	case 88:								\
		__REMS_O0_hack_LIKELY(88);					\
		break;								\
	case 89:								\
		__REMS_O0_hack_LIKELY(89);					\
		break;								\
	case 90:								\
		__REMS_O0_hack_LIKELY(90);					\
		break;								\
	case 91:								\
		__REMS_O0_hack_LIKELY(91);					\
		break;								\
	case 92:								\
		__REMS_O0_hack_LIKELY(92);					\
		break;								\
	case 93:								\
		__REMS_O0_hack_LIKELY(93);					\
		break;								\
	case 94:								\
		__REMS_O0_hack_LIKELY(94);					\
		break;								\
	case 95:								\
		__REMS_O0_hack_LIKELY(95);					\
		break;								\
	case 96:								\
		__REMS_O0_hack_LIKELY(96);					\
		break;								\
	case 97:								\
		__REMS_O0_hack_LIKELY(97);					\
		break;								\
	case 98:								\
		__REMS_O0_hack_LIKELY(98);					\
		break;								\
	case 99:								\
		__REMS_O0_hack_LIKELY(99);					\
		break;								\
	case 100:								\
		__REMS_O0_hack_LIKELY(100);					\
		break;								\
	case 101:								\
		__REMS_O0_hack_LIKELY(101);					\
		break;								\
	case 102:								\
		__REMS_O0_hack_LIKELY(102);					\
		break;								\
	case 103:								\
		__REMS_O0_hack_LIKELY(103);					\
		break;								\
	case 104:								\
		__REMS_O0_hack_LIKELY(104);					\
		break;								\
	case 105:								\
		__REMS_O0_hack_LIKELY(105);					\
		break;								\
	case 106:								\
		__REMS_O0_hack_LIKELY(106);					\
		break;								\
	case 107:								\
		__REMS_O0_hack_LIKELY(107);					\
		break;								\
	case 108:								\
		__REMS_O0_hack_LIKELY(108);					\
		break;								\
	case 109:								\
		__REMS_O0_hack_LIKELY(109);					\
		break;								\
	case 110:								\
		__REMS_O0_hack_LIKELY(110);					\
		break;								\
	case 111:								\
		__REMS_O0_hack_LIKELY(111);					\
		break;								\
	case 112:								\
		__REMS_O0_hack_LIKELY(112);					\
		break;								\
	case 113:								\
		__REMS_O0_hack_LIKELY(113);					\
		break;								\
	case 114:								\
		__REMS_O0_hack_LIKELY(114);					\
		break;								\
	case 115:								\
		__REMS_O0_hack_LIKELY(115);					\
		break;								\
	case 116:								\
		__REMS_O0_hack_LIKELY(116);					\
		break;								\
	case 117:								\
		__REMS_O0_hack_LIKELY(117);					\
		break;								\
	default:								\
		BUG();								\
	}
#define __REMS_O0_hack_UNLIKELY(N)						\
	asm goto(								\
	ALTERNATIVE("nop", "b	%l[l_yes]", N)					\
	:::: l_yes)
#define REMS_O0_hack_UNLIKELY(N)						\
	switch (N) {								\
	case 0:									\
		__REMS_O0_hack_UNLIKELY(0);					\
		break;								\
	case 1:									\
		__REMS_O0_hack_UNLIKELY(1);					\
		break;								\
	case 2:									\
		__REMS_O0_hack_UNLIKELY(2);					\
		break;								\
	case 3:									\
		__REMS_O0_hack_UNLIKELY(3);					\
		break;								\
	case 4:									\
		__REMS_O0_hack_UNLIKELY(4);					\
		break;								\
	case 5:									\
		__REMS_O0_hack_UNLIKELY(5);					\
		break;								\
	case 6:									\
		__REMS_O0_hack_UNLIKELY(6);					\
		break;								\
	case 7:									\
		__REMS_O0_hack_UNLIKELY(7);					\
		break;								\
	case 8:									\
		__REMS_O0_hack_UNLIKELY(8);					\
		break;								\
	case 9:									\
		__REMS_O0_hack_UNLIKELY(9);					\
		break;								\
	case 10:								\
		__REMS_O0_hack_UNLIKELY(10);					\
		break;								\
	case 11:								\
		__REMS_O0_hack_UNLIKELY(11);					\
		break;								\
	case 12:								\
		__REMS_O0_hack_UNLIKELY(12);					\
		break;								\
	case 13:								\
		__REMS_O0_hack_UNLIKELY(13);					\
		break;								\
	case 14:								\
		__REMS_O0_hack_UNLIKELY(14);					\
		break;								\
	case 15:								\
		__REMS_O0_hack_UNLIKELY(15);					\
		break;								\
	case 16:								\
		__REMS_O0_hack_UNLIKELY(16);					\
		break;								\
	case 17:								\
		__REMS_O0_hack_UNLIKELY(17);					\
		break;								\
	case 18:								\
		__REMS_O0_hack_UNLIKELY(18);					\
		break;								\
	case 19:								\
		__REMS_O0_hack_UNLIKELY(19);					\
		break;								\
	case 20:								\
		__REMS_O0_hack_UNLIKELY(20);					\
		break;								\
	case 21:								\
		__REMS_O0_hack_UNLIKELY(21);					\
		break;								\
	case 22:								\
		__REMS_O0_hack_UNLIKELY(22);					\
		break;								\
	case 23:								\
		__REMS_O0_hack_UNLIKELY(23);					\
		break;								\
	case 24:								\
		__REMS_O0_hack_UNLIKELY(24);					\
		break;								\
	case 25:								\
		__REMS_O0_hack_UNLIKELY(25);					\
		break;								\
	case 26:								\
		__REMS_O0_hack_UNLIKELY(26);					\
		break;								\
	case 27:								\
		__REMS_O0_hack_UNLIKELY(27);					\
		break;								\
	case 28:								\
		__REMS_O0_hack_UNLIKELY(28);					\
		break;								\
	case 29:								\
		__REMS_O0_hack_UNLIKELY(29);					\
		break;								\
	case 30:								\
		__REMS_O0_hack_UNLIKELY(30);					\
		break;								\
	case 31:								\
		__REMS_O0_hack_UNLIKELY(31);					\
		break;								\
	case 32:								\
		__REMS_O0_hack_UNLIKELY(32);					\
		break;								\
	case 33:								\
		__REMS_O0_hack_UNLIKELY(33);					\
		break;								\
	case 34:								\
		__REMS_O0_hack_UNLIKELY(34);					\
		break;								\
	case 35:								\
		__REMS_O0_hack_UNLIKELY(35);					\
		break;								\
	case 36:								\
		__REMS_O0_hack_UNLIKELY(36);					\
		break;								\
	case 37:								\
		__REMS_O0_hack_UNLIKELY(37);					\
		break;								\
	case 38:								\
		__REMS_O0_hack_UNLIKELY(38);					\
		break;								\
	case 39:								\
		__REMS_O0_hack_UNLIKELY(39);					\
		break;								\
	case 40:								\
		__REMS_O0_hack_UNLIKELY(40);					\
		break;								\
	case 41:								\
		__REMS_O0_hack_UNLIKELY(41);					\
		break;								\
	case 42:								\
		__REMS_O0_hack_UNLIKELY(42);					\
		break;								\
	case 43:								\
		__REMS_O0_hack_UNLIKELY(43);					\
		break;								\
	case 44:								\
		__REMS_O0_hack_UNLIKELY(44);					\
		break;								\
	case 45:								\
		__REMS_O0_hack_UNLIKELY(45);					\
		break;								\
	case 46:								\
		__REMS_O0_hack_UNLIKELY(46);					\
		break;								\
	case 47:								\
		__REMS_O0_hack_UNLIKELY(47);					\
		break;								\
	case 48:								\
		__REMS_O0_hack_UNLIKELY(48);					\
		break;								\
	case 49:								\
		__REMS_O0_hack_UNLIKELY(49);					\
		break;								\
	case 50:								\
		__REMS_O0_hack_UNLIKELY(50);					\
		break;								\
	case 51:								\
		__REMS_O0_hack_UNLIKELY(51);					\
		break;								\
	case 52:								\
		__REMS_O0_hack_UNLIKELY(52);					\
		break;								\
	case 53:								\
		__REMS_O0_hack_UNLIKELY(53);					\
		break;								\
	case 54:								\
		__REMS_O0_hack_UNLIKELY(54);					\
		break;								\
	case 55:								\
		__REMS_O0_hack_UNLIKELY(55);					\
		break;								\
	case 56:								\
		__REMS_O0_hack_UNLIKELY(56);					\
		break;								\
	case 57:								\
		__REMS_O0_hack_UNLIKELY(57);					\
		break;								\
	case 58:								\
		__REMS_O0_hack_UNLIKELY(58);					\
		break;								\
	case 59:								\
		__REMS_O0_hack_UNLIKELY(59);					\
		break;								\
	case 60:								\
		__REMS_O0_hack_UNLIKELY(60);					\
		break;								\
	case 61:								\
		__REMS_O0_hack_UNLIKELY(61);					\
		break;								\
	case 62:								\
		__REMS_O0_hack_UNLIKELY(62);					\
		break;								\
	case 63:								\
		__REMS_O0_hack_UNLIKELY(63);					\
		break;								\
	case 64:								\
		__REMS_O0_hack_UNLIKELY(64);					\
		break;								\
	case 65:								\
		__REMS_O0_hack_UNLIKELY(65);					\
		break;								\
	case 66:								\
		__REMS_O0_hack_UNLIKELY(66);					\
		break;								\
	case 67:								\
		__REMS_O0_hack_UNLIKELY(67);					\
		break;								\
	case 68:								\
		__REMS_O0_hack_UNLIKELY(68);					\
		break;								\
	case 69:								\
		__REMS_O0_hack_UNLIKELY(69);					\
		break;								\
	case 70:								\
		__REMS_O0_hack_UNLIKELY(70);					\
		break;								\
	case 71:								\
		__REMS_O0_hack_UNLIKELY(71);					\
		break;								\
	case 72:								\
		__REMS_O0_hack_UNLIKELY(72);					\
		break;								\
	case 73:								\
		__REMS_O0_hack_UNLIKELY(73);					\
		break;								\
	case 74:								\
		__REMS_O0_hack_UNLIKELY(74);					\
		break;								\
	case 75:								\
		__REMS_O0_hack_UNLIKELY(75);					\
		break;								\
	case 76:								\
		__REMS_O0_hack_UNLIKELY(76);					\
		break;								\
	case 77:								\
		__REMS_O0_hack_UNLIKELY(77);					\
		break;								\
	case 78:								\
		__REMS_O0_hack_UNLIKELY(78);					\
		break;								\
	case 79:								\
		__REMS_O0_hack_UNLIKELY(79);					\
		break;								\
	case 80:								\
		__REMS_O0_hack_UNLIKELY(80);					\
		break;								\
	case 81:								\
		__REMS_O0_hack_UNLIKELY(81);					\
		break;								\
	case 82:								\
		__REMS_O0_hack_UNLIKELY(82);					\
		break;								\
	case 83:								\
		__REMS_O0_hack_UNLIKELY(83);					\
		break;								\
	case 84:								\
		__REMS_O0_hack_UNLIKELY(84);					\
		break;								\
	case 85:								\
		__REMS_O0_hack_UNLIKELY(85);					\
		break;								\
	case 86:								\
		__REMS_O0_hack_UNLIKELY(86);					\
		break;								\
	case 87:								\
		__REMS_O0_hack_UNLIKELY(87);					\
		break;								\
	case 88:								\
		__REMS_O0_hack_UNLIKELY(88);					\
		break;								\
	case 89:								\
		__REMS_O0_hack_UNLIKELY(89);					\
		break;								\
	case 90:								\
		__REMS_O0_hack_UNLIKELY(90);					\
		break;								\
	case 91:								\
		__REMS_O0_hack_UNLIKELY(91);					\
		break;								\
	case 92:								\
		__REMS_O0_hack_UNLIKELY(92);					\
		break;								\
	case 93:								\
		__REMS_O0_hack_UNLIKELY(93);					\
		break;								\
	case 94:								\
		__REMS_O0_hack_UNLIKELY(94);					\
		break;								\
	case 95:								\
		__REMS_O0_hack_UNLIKELY(95);					\
		break;								\
	case 96:								\
		__REMS_O0_hack_UNLIKELY(96);					\
		break;								\
	case 97:								\
		__REMS_O0_hack_UNLIKELY(97);					\
		break;								\
	case 98:								\
		__REMS_O0_hack_UNLIKELY(98);					\
		break;								\
	case 99:								\
		__REMS_O0_hack_UNLIKELY(99);					\
		break;								\
	case 100:								\
		__REMS_O0_hack_UNLIKELY(100);					\
		break;								\
	case 101:								\
		__REMS_O0_hack_UNLIKELY(101);					\
		break;								\
	case 102:								\
		__REMS_O0_hack_UNLIKELY(102);					\
		break;								\
	case 103:								\
		__REMS_O0_hack_UNLIKELY(103);					\
		break;								\
	case 104:								\
		__REMS_O0_hack_UNLIKELY(104);					\
		break;								\
	case 105:								\
		__REMS_O0_hack_UNLIKELY(105);					\
		break;								\
	case 106:								\
		__REMS_O0_hack_UNLIKELY(106);					\
		break;								\
	case 107:								\
		__REMS_O0_hack_UNLIKELY(107);					\
		break;								\
	case 108:								\
		__REMS_O0_hack_UNLIKELY(108);					\
		break;								\
	case 109:								\
		__REMS_O0_hack_UNLIKELY(109);					\
		break;								\
	case 110:								\
		__REMS_O0_hack_UNLIKELY(110);					\
		break;								\
	case 111:								\
		__REMS_O0_hack_UNLIKELY(111);					\
		break;								\
	case 112:								\
		__REMS_O0_hack_UNLIKELY(112);					\
		break;								\
	case 113:								\
		__REMS_O0_hack_UNLIKELY(113);					\
		break;								\
	case 114:								\
		__REMS_O0_hack_UNLIKELY(114);					\
		break;								\
	case 115:								\
		__REMS_O0_hack_UNLIKELY(115);					\
		break;								\
	case 116:								\
		__REMS_O0_hack_UNLIKELY(116);					\
		break;								\
	case 117:								\
		__REMS_O0_hack_UNLIKELY(117);					\
		break;								\
	default:								\
		BUG();								\
	}
#endif /* CONFIG_NVHE_EL2_O0 */

static __always_inline bool
alternative_has_cap_likely(const unsigned long cpucap)
{
	compiletime_assert(cpucap < ARM64_NCAPS,
			   "cpucap must be < ARM64_NCAPS");

#if defined(CONFIG_NVHE_EL2_O0) && defined(__KVM_NVHE_HYPERVISOR__)
	REMS_O0_hack_LIKELY(cpucap);
#else
	asm goto(
	ALTERNATIVE_CB("b	%l[l_no]", %[cpucap], alt_cb_patch_nops)
	:
	: [cpucap] "i" (cpucap)
	:
	: l_no);
#endif /* !(defined(CONFIG_NVHE_EL2_O0) && defined(__KVM_NVHE_HYPERVISOR__)) */

	return true;
l_no:
	return false;
}

static __always_inline bool
alternative_has_cap_unlikely(const unsigned long cpucap)
{
	compiletime_assert(cpucap < ARM64_NCAPS,
			   "cpucap must be < ARM64_NCAPS");

#if defined(CONFIG_NVHE_EL2_O0) && defined(__KVM_NVHE_HYPERVISOR__)
	REMS_O0_hack_UNLIKELY(cpucap);
#else
	asm goto(
	ALTERNATIVE("nop", "b	%l[l_yes]", %[cpucap])
	:
	: [cpucap] "i" (cpucap)
	:
	: l_yes);
#endif /* !(defined(CONFIG_NVHE_EL2_O0) && defined(__KVM_NVHE_HYPERVISOR__)) */

	return false;
l_yes:
	return true;
}

#endif /* __ASSEMBLY__ */

#else

/*
 * The FIPS140 module does not support alternatives patching, as this
 * invalidates the HMAC digest of the .text section. However, some alternatives
 * are known to be irrelevant so we can tolerate them in the FIPS140 module, as
 * they will never be applied in the first place in the use cases that the
 * FIPS140 module targets (Android running on a production phone). Any other
 * uses of alternatives should be avoided, as it is not safe in the general
 * case to simply use the default sequence in one place (the fips module) and
 * the alternative sequence everywhere else.
 *
 * Below is an allowlist of cpucaps that we can ignore, by simply taking the
 * safe default instruction sequence. Note that this implies that the FIPS140
 * module is not compatible with VHE, or with pseudo-NMI support.
 */

#define __ALT_ARM64_HAS_LDAPR			0,
#define __ALT_ARM64_HAS_VIRT_HOST_EXTN		0,
#define __ALT_ARM64_HAS_GIC_PRIO_MASKING	0,
#define __ALT_ARM64_HAS_GIC_PRIO_RELAXED_SYNC	0,

#define ALTERNATIVE(oldinstr, newinstr, cpucap, ...)   \
	_ALTERNATIVE(oldinstr, __ALT_ ## cpucap, #cpucap)

#define ALTERNATIVE_CB(oldinstr, cpucap, cb)	\
	_ALTERNATIVE(oldinstr, __ALT_ ## cpucap, #cpucap)

#define _ALTERNATIVE(oldinstr, cpucap, cpucap_str)   \
	__take_second_arg(cpucap oldinstr, \
		".err CPU capability " cpucap_str " not supported in fips140 module")

#ifndef __ASSEMBLY__

#include <linux/types.h>

static __always_inline bool
alternative_has_cap_likely(const unsigned long cpucap)
{
	return cpucap == ARM64_HAS_LDAPR ||
		cpucap == ARM64_HAS_VIRT_HOST_EXTN ||
		cpucap == ARM64_HAS_GIC_PRIO_MASKING ||
		cpucap == ARM64_HAS_GIC_PRIO_RELAXED_SYNC;
}

#define alternative_has_cap_unlikely alternative_has_cap_likely

#endif /* !__ASSEMBLY__ */

#endif /* BUILD_FIPS140_KO */

#endif /* __ASM_ALTERNATIVE_MACROS_H */
