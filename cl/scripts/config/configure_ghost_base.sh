#!/usr/bin/env sh
. ./cl/scripts/config/args.sh

# generic setup for all configurations
./scripts/config -d CONFIG_RANDOMIZE_BASE
./scripts/config -e CONFIG_NVHE_EL2_DEBUG
./scripts/config -d CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
./scripts/config -e CONFIG_DEBUG_INFO_DWARF4
./scripts/config -d CONFIG_PROTECTED_NVHE_STACKTRACE
./scripts/config --set-val CONFIG_NVHE_EL2_STACKSIZE 4
./scripts/config -e CONFIG_KVM_ARM_HYP_DEBUG_UART
./scripts/config --set-val CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR 0x09000000
./scripts/config --set-val CONFIG_NVHE_GHOST_MEM_LOG2 22

# ./scripts/config -e CONFIG_PKVM_PROXY

# actually enable nVHE ghost spec machinery
./scripts/config -e CONFIG_NVHE_GHOST_SPEC

# reset things back to a sensible default if they're not already defined
. ./cl/scripts/config/reset_undefs.sh