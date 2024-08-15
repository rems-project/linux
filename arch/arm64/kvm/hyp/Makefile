# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module, HYP part
#

incdir := $(srctree)/$(src)/include
subdir-asflags-y := -I$(incdir)
subdir-ccflags-y := -I$(incdir)

# obj-$(CONFIG_KVM) += vhe/ nvhe/ pgtable.o
obj-$(CONFIG_KVM) += vhe/ picovm/ pgtable.o

ghosts := \
	ghost/ghost_maplets.o ghost/ghost_pgtable.o ghost/ghost_pfn_set.o \
	ghost/ghost_control.o ghost/ghost_context.o ghost/ghost_extra_debug-pl011.o \
	ghost/ghost_alloc.o ghost/ghost_status.o ghost/ghost_printer.o

obj-$(CONFIG_NVHE_GHOST_SPEC) += $(ghosts)
