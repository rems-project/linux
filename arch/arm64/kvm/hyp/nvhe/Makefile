# SPDX-License-Identifier: GPL-2.0

lib-objs := clear_page.o copy_page.o memcpy.o memset.o
lib-objs := $(addprefix ../../../lib/, $(lib-objs))

hyp-obj-y := timer-sr.o sysreg-sr.o debug-sr.o switch.o tlb.o hyp-init.o host.o \
	 hyp-main.o hyp-smp.o psci-relay.o alloc.o early_alloc.o page_alloc.o \
	 cache.o setup.o mm.o mem_protect.o sys_regs.o pkvm.o stacktrace.o ffa.o \
	 serial.o alloc_mgt.o
hyp-obj-y += ../vgic-v3-sr.o ../aarch32.o ../vgic-v2-cpuif-proxy.o ../entry.o \
	 ../fpsimd.o ../hyp-entry.o ../exception.o ../pgtable.o  iommu/iommu.o
hyp-obj-$(CONFIG_LIST_HARDENED) += list_debug.o
hyp-obj-$(CONFIG_TRACING) += clock.o events.o trace.o
hyp-obj-$(CONFIG_MODULES) += modules.o
hyp-obj-y += $(lib-objs)

#Only for built-in, not modules
ifeq ($(CONFIG_ARM_SMMU_V3_PKVM),y)
# There is no way to compile this separately as calling Makefile.nvhe again would
# create duplicate sections
hyp-obj-$(CONFIG_ARM_SMMU_V3_PKVM) += ../../../../../drivers/iommu/arm/arm-smmu-v3/pkvm/arm-smmu-v3.o
hyp-obj-$(CONFIG_ARM_SMMU_V3_PKVM) += ../../../../../drivers/iommu/arm/arm-smmu-v3/pkvm/io-pgtable-arm.o
hyp-obj-$(CONFIG_ARM_SMMU_V3_PKVM) += ../../../../../drivers/iommu/io-pgtable-arm-common.o
endif


ghosts-y += ghost/ghost_serial.o
ghosts-y += ghost/ghost_printer.o
ghosts-y += ghost/ghost_mapping_reqs.o
ghosts-y += ghost/ghost_misc.o
ghosts-y += ghost/ghost_asm.o
ghosts-y += ghost/ghost_sort_hack.o
ghosts-y += ghost/ghost_list_sort_hack.o
ghosts-y += ghost/ghost_maplets.o
ghosts-y += ghost/ghost_pgtable.o
ghosts-y += ghost/ghost_control.o
ghosts-y += ghost/ghost_pfn_set.o
ghosts-y += ghost/ghost_context.o
ghosts-y += ghost/ghost_status.o
ghosts-y += ghost/ghost_recording.o
ghosts-y += ghost/ghost_types_aux.o
ghosts-y += ghost/ghost_spec.o
ghosts-y += ghost/ghost_alloc.o
ghosts-y += ghost/ghost_control.o

ghosts-$(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL) += ghost/ghost_sm_driver.o
ghosts-$(CONFIG_NVHE_GHOST_DIFF) += ghost/ghost_abstraction_diff.o

# We define a macro for ghost translation units, so that headers can tell when
# they are included by ghost code.
$(foreach ghost,$(ghosts-y),$(eval CFLAGS_$(patsubst %.o,%.nvhe.o,$(ghost)) += -D__GHOST__))

hyp-obj-$(CONFIG_NVHE_GHOST_SPEC) += $(ghosts-y)

get-casemate:
	git clone https://github.com/rems-project/casemate ghost/casemate
.PHONY: get-casemate

ifneq ($(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL),)
  CASEMATELIB = ghost/casemate/src/lib
  GHOST_USES_SERIAL = 1
  include $(obj)/ghost/casemate/src/lib/Makefile.linux
endif

ghost-lib-objs := strcmp.o strlen.o
hyp-obj-$(CONFIG_NVHE_GHOST_SPEC) += $(addprefix ../../../lib/, $(ghost-lib-objs))
ccflags-$(CONFIG_NVHE_GHOST_SPEC) += -O1


hyp-obj-y += power/hvc.o

$(obj)/hyp.lds: $(src)/hyp.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

include $(srctree)/arch/arm64/kvm/hyp/nvhe/Makefile.nvhe
obj-y := kvm_nvhe.o
