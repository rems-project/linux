#!/usr/bin/env sh
# usage: ./cl/scripts/config/reset_config.sh [-d|--disable]
#        resets config back to base without ghost

# should be ran from the linux source root directory

./cl/scripts/config/configure_execspec.sh -d
./cl/scripts/config/configure_noisy_mem_abort.sh -d > /dev/null || true
./cl/scripts/config/configure_noisy.sh -d
./cl/scripts/config/configure_sm.sh -d
./cl/scripts/config/configure_ghost_base.sh -d