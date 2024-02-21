#!/usr/bin/env sh
# usage: ./cl/scripts/config/configure_noisy_mem_abort.sh [-d|--disable]
#        enables/disables noisy printing on mem aborts.
#        NOTE: should enable noisy generally for this to take effect

# should be ran from the linux source root directory

. ./cl/scripts/config/configure_ghost_base.sh

if [ ! $(./scripts/config -s CONFIG_NVHE_GHOST_SPEC_NOISY) = 'y' ]; then
    echo bad config: should enable noisy before making mem aborts noisy.
    exit 1
fi

./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_NOISY_handle_host_mem_abort
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_NOISY_handle_guest_mem_abort