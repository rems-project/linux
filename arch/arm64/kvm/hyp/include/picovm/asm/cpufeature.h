/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on
 *   arch/arm64/include/asm/cpufeature.h
 *     Copyright (C) 2014 Linaro Ltd. <ard.biesheuvel@linaro.org>
 */
#ifndef __PICOVM_ASM_CPUFEATURE_H
#define __PICOVM_ASM_CPUFEATURE_H

#ifdef CONFIG_PICOVM_STANDALONE

#include <picovm/linux/types.h>
#include <picovm/sysregs.h>

static __always_inline unsigned int __attribute_const__
cpuid_feature_extract_unsigned_field_width(u64 features, int field, int width)
{
	return (u64)(features << (64 - width - field)) >> (64 - width);
}

static __always_inline unsigned int __attribute_const__
cpuid_feature_extract_unsigned_field(u64 features, int field)
{
	return cpuid_feature_extract_unsigned_field_width(features, field, 4);
}

static inline unsigned int get_vmid_bits(u64 mmfr1)
{
	int vmid_bits;

	vmid_bits = cpuid_feature_extract_unsigned_field(mmfr1,
						ID_AA64MMFR1_EL1_VMIDBits_SHIFT);
	if (vmid_bits == ID_AA64MMFR1_EL1_VMIDBits_16)
		return 16;

	/*
	 * Return the default here even if any reserved
	 * value is fetched from the system register.
	 */
	return 8;
}

#else
#include <asm/cpufeature.h>
#endif /* CONFIG_PICOVM_STANDALONE */

#endif /* __PICOVM_ASM_CPUFEATURE_H */
