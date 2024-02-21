#!/usr/bin/env sh
# usage: ./cl/scripts/config/configure_execspec.sh [-d|--disable]
#        enables/disables execspec checking

# should be ran from the linux source root directory

. ./cl/scripts/config/configure_ghost_base.sh

#
# Hypercalls
#
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK_handle_host_mem_abort
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_host_share_hyp
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_host_unshare_hyp
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_host_reclaim_page
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_host_map_guest
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___kvm_vcpu_run
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_init_vm
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_init_vcpu
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_teardown_vm
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_vcpu_load
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_vcpu_put
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_guest_share_host
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_guest_unshare_host
./scripts/config -k $ENABLE CONFIG_NVHE_GHOST_SPEC_CHECK_handle_guest_mem_abort
# end of Hypercalls