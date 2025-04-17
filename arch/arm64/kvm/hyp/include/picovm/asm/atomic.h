/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm64/include/asm/atomic.h
 *
 * Copyright (C) 1996 Russell King.
 * Copyright (C) 2002 Deep Blue Solutions Ltd.
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __PICOVM_ASM_ATOMIC_H
#define __PICOVM_ASM_ATOMIC_H

#include <picovm/linux/types.h>
#include <picovm/asm/rwonce.h>

#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define atomic64_read(v) read_once(&((v)->counter))
#else
#define atomic64_read(v)	__READ_ONCE((v)->counter)
#endif

#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define atomic64_write(v, i)	write_once(&((v)->counter), i)
#else
#define atomic64_write(v, i)	__WRITE_ONCE((v)->counter, i)
#endif

#endif /* __PICOVM_ASM_ATOMIC_H */
