#include <asm/kvm_asm.h>
#include "nvhe/ghost_asm_ids.h"


/* unsigned long ghost_sysregs[GHOST_SYSREGS_MAX]; */




void ghost_get_sysregs(u64 *regs);
/* void ghost_get_sysregs(void); */

void ___kvm_get_sysregs(struct kvm_nvhe_init_params *params_snapshot);
