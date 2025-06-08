/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 Huawei Ltd.
 * Author: Jiang Liu <liuj97@gmail.com>
 *
 * Based on arch/arm/include/asm/jump_label.h
 */
#ifndef __ASM_JUMP_LABEL_H
#define __ASM_JUMP_LABEL_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/insn.h>

#define HAVE_JUMP_LABEL_BATCH
#define JUMP_LABEL_NOP_SIZE		AARCH64_INSN_SIZE

#if defined(CONFIG_NVHE_EL2_O0) && defined(__KVM_NVHE_HYPERVISOR__)
#define __static_key_enabled(k)		(!!__READ_ONCE((k)->enabled.counter))
#define arch_static_branch(k,b)		(b ^ __static_key_enabled(k))
#define arch_static_branch_jump(k,b)	(b ^ __static_key_enabled(k))
#else

static __always_inline bool arch_static_branch(struct static_key * const key,
					       const bool branch)
{
	asm goto(
		"1:	nop					\n\t"
		 "	.pushsection	__jump_table, \"aw\"	\n\t"
		 "	.align		3			\n\t"
		 "	.long		1b - ., %l[l_yes] - .	\n\t"
		 "	.quad		%c0 - .			\n\t"
		 "	.popsection				\n\t"
		 :  :  "i"(&((char *)key)[branch]) :  : l_yes);

	return false;
l_yes:
	return true;
}

static __always_inline bool arch_static_branch_jump(struct static_key * const key,
						    const bool branch)
{
	asm goto(
		"1:	b		%l[l_yes]		\n\t"
		 "	.pushsection	__jump_table, \"aw\"	\n\t"
		 "	.align		3			\n\t"
		 "	.long		1b - ., %l[l_yes] - .	\n\t"
		 "	.quad		%c0 - .			\n\t"
		 "	.popsection				\n\t"
		 :  :  "i"(&((char *)key)[branch]) :  : l_yes);

	return false;
l_yes:
	return true;
}

#endif /* !(defined(CONFIG_NVHE_EL2_O0) && defined(__KVM_NVHE_HYPERVISOR__)) */
#endif  /* __ASSEMBLY__ */
#endif	/* __ASM_JUMP_LABEL_H */
