#include "linux/writeback.h"
#include <linux/types.h>
#include <linux/string.h>

#include <nvhe/ghost_control.h>

struct ghost_control_item {
	const char* context_name;
	bool check;
	bool noisy;
	bool verbose;
};


/**
 * struct ghost_control - Selectively enable/disable checks and prints
 */
struct ghost_control {
	u64 len;
	struct ghost_control_item items[20];
};

struct ghost_control ghost_control;

bool ghost_control_is_controlled(const char* context)
{
	for (int i = 0; i < ghost_control.len; i++) {
		if (!strcmp(context, ghost_control.items[i].context_name))
			return true;
	}

	return false;
}

bool ghost_control_print_enabled(const char* context)
{
	for (int i = 0; i < ghost_control.len; i++) {
		if (!strcmp(context, ghost_control.items[i].context_name))
			return ghost_control.items[i].noisy;
	}

	return false;
}

bool ghost_control_print_enabled_verbose(const char* context)
{
	for (int i = 0; i < ghost_control.len; i++) {
		if (!strcmp(context, ghost_control.items[i].context_name))
			return ghost_control.items[i].noisy && ghost_control.items[i].verbose;
	}

	return false;
}

bool ghost_control_check_enabled(const char* context)
{
	for (int i = 0; i < ghost_control.len; i++) {
		if (!strcmp(context, ghost_control.items[i].context_name)) {
			return ghost_control.items[i].check;
		}
	}

	return false;
}

static void ghost_control_create(const char *context, bool check, bool noisy, bool verbose)
{
	ghost_control.items[ghost_control.len++] = (struct ghost_control_item){
		.context_name = context,
		.check = check,
		.noisy = noisy,
	};
}


void init_ghost_control(void) {
	ghost_control_create("handle_trap", true, true, false);

	ghost_control_create("handle_host_mem_abort", true, false, false);
	ghost_control_create("handle_host_hcall", true, true, false);

	ghost_control_create("__pkvm_host_donate_guest", false, true, false);

	ghost_control_create("host_stage2_idmap", false, false, false);
	ghost_control_create("___kvm_pgtable_walk", false, true, false);
	ghost_control_create("__kvm_pgtable_walk", false, true, false);
	ghost_control_create("_kvm_pgtable_stage2_map", false, true, false);

	ghost_control_create("ghost_context", true, true, false);

	ghost_control_create("ghost_record_pre", true, false, false);
	ghost_control_create("ghost_post", true, false, false);

	ghost_control_create("ghost_simplified_model_step", true, false, false);
	ghost_control_create("initialise_ghost_simplified_model", true, false, false);
}
