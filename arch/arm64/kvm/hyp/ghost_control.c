#include "linux/writeback.h"
#include <linux/types.h>
#include <linux/string.h>

#include <nvhe/ghost_control.h>

struct ghost_control_item {
	const char* context_name;
	bool check;
	bool print;
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
			return ghost_control.items[i].print;
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

static void ghost_control_create(const char *context, bool check, bool print_enabled)
{
	ghost_control.items[ghost_control.len++] = (struct ghost_control_item){
		.context_name = context,
		.check = check,
		.print = print_enabled,
	};
}


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

void init_ghost_control(void) {

	ghost_control_create("ghost_context", true, noisy_spec);
	ghost_control_create("handle_trap", true, noisy_spec);

	ghost_control_create("___kvm_pgtable_walk", false, verbose_spec);
	ghost_control_create("__kvm_pgtable_walk", false, verbose_spec);
	ghost_control_create("_kvm_pgtable_stage2_map", false, verbose_spec);

	ghost_control_create("handle_host_hcall", true, noisy_spec);
	ghost_control_create("handle_host_hcall_verbose", true, verbose_spec);

	ghost_control_create("ghost_record_pre", true, noisy_spec);
	ghost_control_create("ghost_post", true, noisy_spec);

	ghost_control_create("ghost_simplified_model_step", true, noisy_sm);
	ghost_control_create("initialise_ghost_simplified_model", true, noisy_sm);

	ghost_control_create("traverse_pgtable_from", true, verbose_sm);
}
