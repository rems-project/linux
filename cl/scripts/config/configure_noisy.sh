#!/usr/bin/env sh
# usage: ./cl/scripts/config/configure_noisy.sh [-d|--disable]
#        enables/disables ghost printing

# should be ran from the linux source root directory

. ./cl/scripts/config/configure_ghost_base.sh

# enable ghost machinery prints, with colours
./scripts/config $ENABLE CONFIG_NVHE_GHOST_SPEC_NOISY
./scripts/config $ENABLE CONFIG_NVHE_GHOST_SPEC_COLOURS

# also for simplified model
./scripts/config $ENABLE CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_NOISY
# ... but condensed (no prints for "clean" ptes)
./scripts/config $ENABLE CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_NOISY_CONDENSED
# ... and don't dump the whole simplified model state each transition
./scripts/config $DISABLE CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_DUMP_ON_TRANS

# enable printing of diffs
./scripts/config $ENABLE CONFIG_NVHE_GHOST_DIFF
./scripts/config --set-val CONFIG_NVHE_GHOST_DIFF_MAX_DIFFS_PER_NODE 16

# print diffs
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_DIFF_post_computed
# ... but only between post and computed for exec spec
./scripts/config -k $DISABLE CONFIG_NVHE_GHOST_DIFF_pre_post_recorded
./scripts/config -k $DISABLE CONFIG_NVHE_GHOST_DIFF_post_host_pgtable
# ... and print diffs for simplified model
./scripts/config $ENABLE CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_DIFF_ON_TRANS