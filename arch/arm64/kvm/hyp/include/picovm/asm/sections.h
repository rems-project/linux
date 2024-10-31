/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2016 ARM Limited
 */

// NOTE: from linux/arch/arm64/include/asm/sections.h
#ifndef __PICOVM_ASM_SECTIONS_H
#define __PICOVM_ASM_SECTIONS_H

extern char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];

extern char __hyp_idmap_text_start[], __hyp_idmap_text_end[];
extern char __hyp_text_start[], __hyp_text_end[];
extern char __hyp_rodata_start[], __hyp_rodata_end[];
extern char __hyp_reloc_begin[], __hyp_reloc_end[];
extern char __hyp_bss_start[], __hyp_bss_end[];
extern char __idmap_text_start[], __idmap_text_end[];
extern char __initdata_begin[], __initdata_end[];


// NOTE: from compiler_attribute.h
#define __section(section)              __attribute__((__section__(section)))
/*
 * __ro_after_init is used to mark things that are read-only after init (i.e.
 * after mark_rodata_ro() has been called). These are effectively read-only,
 * but may get written to during init, so can't live in .rodata (via "const").
 */

// NOTE: from cache.h
#ifndef __ro_after_init
#define __ro_after_init __section(".data..ro_after_init")
#endif

#endif /* __PICOVM_ASM_SECTIONS_H */
