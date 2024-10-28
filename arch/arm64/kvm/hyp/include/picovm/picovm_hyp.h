/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Partial copy from include/asm/kvm_hyp.h
 */

#include <picovm/prelude.h>

#ifndef __PICOVM_HYP_H__
#define __PICOVM_HYP_H__

extern unsigned int __ro_after_init picovm_arm_vmid_bits;


DECLARE_PER_CPU(struct picovm_cpu_context, picovm_hyp_ctxt);
DECLARE_PER_CPU(unsigned long, picovm_hyp_vector);
DECLARE_PER_CPU(struct picovm_nvhe_init_params, picovm_init_params);

#endif /* __PICOVM_HYP_H__ */
