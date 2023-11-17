#include "linux/writeback.h"
#include <linux/types.h>
#include <linux/string.h>

#include <nvhe/ghost_control.h>

static const bool noisy_spec = IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_NOISY);
static const bool verbose_spec = IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_VERBOSE);
static const bool noisy_sm = IS_ENABLED(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_NOISY);

struct ghost_control_item {
	const char* name;
	bool check;
	bool print;
};

static struct ghost_control_item ghost_controls[] = {
	(struct ghost_control_item){.name="always", .check=true, .print=true},
	(struct ghost_control_item){.name="never", .check=false, .print=false},

	// top-level enable of immediate ghost shadow stack printing
	// even when false, still prints on error.
	(struct ghost_control_item){.name="ghost_context", .check=true, .print=false},

	/* whether to print out the ghost setup */
	(struct ghost_control_item){.name="dump_setup", .check=true, .print=noisy_spec},

	// printing simplified model (#define disables checking entirely);
	(struct ghost_control_item){.name="ghost_simplified_model_step", .check=true, .print=noisy_sm},
	(struct ghost_control_item){.name="initialise_ghost_simplified_model", .check=true, .print=noisy_sm},
	(struct ghost_control_item){.name="sm_dump_trans", .check=true, .print=IS_ENABLED(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_DUMP_ON_TRANS)},
	(struct ghost_control_item){.name="sm_diff_trans", .check=true, .print=IS_ENABLED(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_DIFF_ON_TRANS)},
	(struct ghost_control_item){.name="sm_condensed", .check=true, .print=IS_ENABLED(CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_NOISY_CONDENSED)},

	// verbose logs from the pre/post checkers
	(struct ghost_control_item){.name="ghost_record_pre", .check=true, .print=verbose_spec},
	(struct ghost_control_item){.name="ghost_post", .check=true, .print=verbose_spec},

	(struct ghost_control_item){.name="ghost_post_dump_recorded_concrete_host_pgtable_diff", .check=true, .print=IS_ENABLED(CONFIG_NVHE_GHOST_DIFF_post_host_pgtable)},
	(struct ghost_control_item){.name="ghost_post_dump_recorded_ghost_diff", .check=true, .print=IS_ENABLED(CONFIG_NVHE_GHOST_DIFF_pre_post_recorded)},
	(struct ghost_control_item){.name="ghost_post_dump_computed_ghost_diff", .check=true, .print=IS_ENABLED(CONFIG_NVHE_GHOST_DIFF_post_computed)},

	// hypercalls
	(struct ghost_control_item){.name="__pkvm_host_share_hyp", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_host_share_hyp), .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_init_vm", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_init_vm), .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_init_vcpu", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_init_vcpu), .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_vcpu_load", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_vcpu_load), .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_vcpu_put", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_vcpu_put), .print=noisy_spec},
	(struct ghost_control_item){.name="__kvm_vcpu_run", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___kvm_vcpu_run), .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_host_map_guest", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_host_map_guest), .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_teardown_vm", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_teardown_vm), .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_reclaim_page", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_reclaim_page), .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_host_unshare_hyp", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK___pkvm_host_unshare_hyp), .print=noisy_spec},
	(struct ghost_control_item){.name="handle_host_mem_abort", .check=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_CHECK_handle_host_mem_abort), .print=IS_ENABLED(CONFIG_NVHE_GHOST_SPEC_NOISY_handle_host_mem_abort)},

	// old
	(struct ghost_control_item){.name="handle_trap", .check=true, .print=verbose_spec},
	(struct ghost_control_item){.name="___kvm_pgtable_walk", .check=false, .print=verbose_spec},
	(struct ghost_control_item){.name="__kvm_pgtable_walk", .check=false, .print=verbose_spec},
	(struct ghost_control_item){.name="_kvm_pgtable_stage2_map", .check=false, .print=verbose_spec},
	(struct ghost_control_item){.name="handle_host_hcall", .check=true, .print=verbose_spec},
	(struct ghost_control_item){.name="handle_host_hcall_verbose", .check=true, .print=verbose_spec},
};
#define GHOST_CONTROLS_LEN (sizeof(ghost_controls)/sizeof(struct ghost_control_item))

bool ghost_control_is_controlled(const char* context)
{
	for (int i = 0; i < GHOST_CONTROLS_LEN; i++) {
		if (!strcmp(context, ghost_controls[i].name))
			return true;
	}

	return false;
}

bool ghost_control_print_enabled(const char* context)
{
	for (int i = 0; i < GHOST_CONTROLS_LEN; i++) {
		if (!strcmp(context, ghost_controls[i].name))
			return ghost_controls[i].print;
	}

	return false;
}

bool ghost_control_check_enabled(const char* context)
{
	for (int i = 0; i < GHOST_CONTROLS_LEN; i++) {
		if (!strcmp(context, ghost_controls[i].name)) {
			return ghost_controls[i].check;
		}
	}

	return false;
}

bool ghost_print_on(const char* context)
{
	return noisy_spec && (!ghost_control_is_controlled(context) || ghost_control_print_enabled(context));
}