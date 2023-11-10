#include "linux/writeback.h"
#include <linux/types.h>
#include <linux/string.h>

#include <nvhe/ghost_control.h>

#ifdef CONFIG_NVHE_GHOST_SPEC_NOISY
static const bool noisy_spec = true;
#else
static const bool noisy_spec = false;
#endif

#ifdef CONFIG_NVHE_GHOST_SPEC_VERBOSE
static const bool verbose_spec = true;
#else
static const bool verbose_spec = false;
#endif

#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_NOISY
static const bool noisy_sm = true;
#else
static const bool noisy_sm = false;
#endif

#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_VERBOSE
static const bool verbose_sm = true;
#else
static const bool verbose_sm = false;
#endif

static const bool check_host_hcalls = true;
static const bool check_mem_abort = true;

struct ghost_control_item {
	const char* name;
	bool check;
	bool print;
};

static struct ghost_control_item ghost_controls[] = {
	// top-level enable of immediate ghost shadow stack printing
	// even when false, still prints on error.
	(struct ghost_control_item){.name="ghost_context", .check=true, .print=false},

	// printing simplified model (#define disables checking entirely);
	(struct ghost_control_item){.name="ghost_simplified_model_step", .check=true, .print=noisy_sm},
	(struct ghost_control_item){.name="initialise_ghost_simplified_model", .check=true, .print=noisy_sm},

	// verbose logs from the pre/post checkers
	(struct ghost_control_item){.name="ghost_record_pre", .check=true, .print=verbose_spec},
	(struct ghost_control_item){.name="ghost_post", .check=true, .print=verbose_spec},

	// hypercalls
	(struct ghost_control_item){.name="__pkvm_host_share_hyp", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_init_vm", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_init_vcpu", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_vcpu_load", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_vcpu_put", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__kvm_vcpu_run", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_host_map_guest", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_teardown_vm", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_reclaim_page", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="__pkvm_host_unshare_hyp", .check=check_host_hcalls, .print=noisy_spec},
	(struct ghost_control_item){.name="host_handle_mem_abort", .check=check_mem_abort, .print=noisy_spec},

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