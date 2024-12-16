/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on:
 *   * include/asm-generic/bitsperlong.h
 *   * include/vdso/bits.h
 *   * include/linux/bits.h
 */
#ifndef __PICOVM_LINUX_BITS_H
#define __PICOVM_LINUX_BITS_H

#ifdef CONFIG_PICOVM_STANDALONE

#include <picovm/linux/const.h>

#define BIT(nr)			(UL(1) << (nr))

#define BITS_PER_BYTE		8
#define BITS_PER_LONG 64
#define BITS_PER_LONG_LONG 	64

/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
/* K: I removed the clunky input checks */
#define GENMASK(h, l) \
	(((~UL(0)) - (UL(1) << (l)) + 1) & \
	 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))

#define GENMASK_ULL(h, l) \
	(((~ULL(0)) - (ULL(1) << (l)) + 1) & \
	 (~ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))

#else
#include <linux/bits.h>
#endif /* CONFIG_PICOVM_STANDALONE */

#endif /* __PICOVM_LINUX_BITS_H */
