/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on (very cutdown)
 *   include/linux/bitfield.h
 *     Copyright (C) 2014 Felix Fietkau <nbd@nbd.name>
 *     Copyright (C) 2004 - 2009 Ivo van Doorn <IvDoorn@gmail.com>
 */
#ifndef __PICOVM_BITFIELD_H
#define __PICOVM_BITFIELD_H

#ifdef CONFIG_PICOVM_STANDALONE

// Returns the index of the least significant 1-bit of x,
// or if x is zero, returns zero.
#ifdef CONFIG_PICOVM_CLIGHTPLUS
static inline int __bf_shf(unsigned long long x) {
    int shift = 0;
    while ((x & 1) == 0 && x != 0) {
        x >>= 1;
        shift++;
    }
    return shift;
}
#else
// __builtin_ffsll: GCC built-in
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#endif


#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define FIELD_GET(_mask, _reg) ((u64)(((_reg) & (_mask)) >> __bf_shf(_mask)))
#else
#define FIELD_GET(_mask, _reg)					\
	(typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask))
#endif

#else
#include <linux/bitfield.h>
#endif /* CONFIG_PICOVM_STANDALONE */
#endif /* __PICOVM_BITFIELD_H */
