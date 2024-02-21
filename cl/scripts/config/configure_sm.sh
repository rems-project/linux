#!/usr/bin/env sh
# usage: ./cl/scripts/config/configure_sm.sh [-d|--disable]
#        enables/disables ghost simplified model checking

# should be ran from the linux source root directory

. ./cl/scripts/config/configure_ghost_base.sh

# CONFIG_NVHE_GHOST_SPEC_SAFETY_CHECKS is not set
./scripts/config $ENABLE CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL

#
# Inject errors
#
# CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR___kvm_tlb_flush_vmid_ipa_MISSING_TLBI is not set
# CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR_kvm_clear_pte_MISSING_WRITE is not set
# CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR_stage2_map_walker_try_leaf_MISSING_BREAK is not set
# CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR_stage2_try_break_pte_MISSING_TLBI is not set
# CONFIG_NVHE_GHOST_SPEC_INJECT_ERROR_stage2_put_pte_MISSING_INVALIDATE is not set
# end of Inject errors

#
# Inject fixes
#
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_INJECT_FIX_stage2_try_break_pte_MISSING_DSB
