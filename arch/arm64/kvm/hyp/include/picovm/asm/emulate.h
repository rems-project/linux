/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Derived from arch/arm/include/kvm_emulate.h
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 * 
 * Partial copy of include/asm/kvm_emulate.h
 */

#ifndef __PICOVM_ARM64_EMULATE_H__
#define __PICOVM_ARM64_EMULATE_H__

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

#endif