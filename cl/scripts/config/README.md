Configure scripts for pKVM + ghost
==================================

All scripts should be ran from the Linux source root.

- `./cl/scripts/config/reset_config.sh` will reset the configuration back to have no ghost at all.
- `./cl/scripts/config/configure_ghost_base.sh` will turn on compilation (but not checking) of ghost machinery.
- `./cl/scripts/config/configure_execspec.sh` enables execspec checking.
- `./cl/scripts/config/configure_execspec.sh -d` disables execspec checking.
- `./cl/scripts/config/configure_sm.sh` enables simplified model checking.
- `./cl/scripts/config/configure_sm.sh -d` disables simplified model checking.
- `./cl/scripts/config/configure_noisy.sh` makes the ghost machinery be noisy
- `./cl/scripts/config/configure_noisy.sh -d` makes the ghost machinery be quiet
- `./cl/scripts/config/configure_noisy_mem_abort.sh` makes the ghost machinery be noisy on (host/guesT) mem aborts
- `./cl/scripts/config/configure_noisy_mem_abort.sh -d` makes the ghost machinery be quiet on (host/guest) mem aborts
