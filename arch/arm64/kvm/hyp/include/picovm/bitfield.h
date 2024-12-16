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
#define __bf_shf(x) (__builtin_ffsll(x) - 1)

#define FIELD_GET(_mask, _reg)					\
	(typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask));	\

#else
#include <linux/bitfield.h>
#endif /* CONFIG_PICOVM_STANDALONE */
#endif /* __PICOVM_BITFIELD_H */
