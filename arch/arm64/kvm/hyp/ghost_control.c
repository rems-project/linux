#include "./ghost_control.h"
#include <stdbool.h>

/* switches for various ghost-code checks and logging output.
   Currently the checks also produce (fairly noisy) logging output - we might add separate switches for that
*/

struct ghost_control ghost_control = {
	.check_handle_host_mem_abort    = false,
	.check_host_stage2_idmap        = false,
	.check___pkvm_host_donate_guest = false,
	.check___kvm_pgtable_walk       = false,
	.check__kvm_pgtable_walk        = false,
	.check_kvm_pgtable_stage2_map   = false,
	.dump_handle_trap               = true,
	.dump_handle_host_hcall         = true,
	.dump_handle_host_hcall_verbose = false
};
