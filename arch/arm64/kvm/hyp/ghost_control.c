#include "./ghost_control.h"
#include <linux/types.h>

/* switches for various ghost-code checks and logging output.
   Currently the checks also produce (fairly noisy) logging output - we might add separate switches for that
*/

struct ghost_control ghost_control;

void init_ghost_control(void) {
	ghost_control.check_handle_host_mem_abort    = false;
	ghost_control.check_host_stage2_idmap        = false;
	ghost_control.check___pkvm_host_donate_guest = false;
	ghost_control.check___kvm_pgtable_walk       = false;
	ghost_control.check__kvm_pgtable_walk        = false;
	ghost_control.check_kvm_pgtable_stage2_map   = false;
	ghost_control.dump_handle_trap               = true;
	ghost_control.dump_handle_host_hcall         = true;
	ghost_control.dump_handle_host_hcall_verbose = false;
}
