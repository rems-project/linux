/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copied from arch/arm64/kvm/hyp/include/nvhe/trap_handler.h
 *
 * Copyright (C) 2020 - Google LLC
 * Author: Marc Zyngier <maz@kernel.org>
 */

#ifndef __PICOVM_TRAP_HANDLER_H__
#define __PICOVM_TRAP_HANDLER_H__

#include <picovm/kvm_host.h>

#define cpu_reg(ctxt, r)	(ctxt)->regs.regs[r]
#define DECLARE_REG(type, name, ctxt, reg)	\
				type name = (type)cpu_reg(ctxt, (reg))

#endif /* __PICOVM_TRAP_HANDLER_H__ */
