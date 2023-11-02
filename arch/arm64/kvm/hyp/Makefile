# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module, HYP part
#

incdir := $(srctree)/$(src)/include
subdir-asflags-y := -I$(incdir)
subdir-ccflags-y := -I$(incdir)

obj-$(CONFIG_KVM) += vhe/ nvhe/ pgtable.o

ghosts := \
	ghost_maplets.o ghost_pgtable.o ghost_pfn_set.o \
	ghost_control.o ghost_context.o ghost_extra_debug-pl011.o \
	ghost_alloc.o

obj-$(CONFIG_NVHE_GHOST_SPEC) += $(ghosts)
