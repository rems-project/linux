#include <asm/kvm_mmu.h>
#include <linux/types.h>

#include <hyp/ghost_extra_debug-pl011.h>

#include <nvhe/spinlock.h>
#include <nvhe/mem_protect.h>

#include <nvhe/ghost_asserts.h>
#include <nvhe/ghost_context.h>
#include <nvhe/ghost_control.h>

/**
 * GHOST_MAX_CONTEXT_FRAMES - Max depth of stack frames (per CPU)
 */
#define GHOST_MAX_CONTEXT_FRAMES 16

/**
 * GHOST_MAX_CONTEXT_DATA - Max count of log messages per stack frame
 *
 * Includes GHOST_LOG() vars as well as GHOST_WARN()/GHOST_MSG()
 */
#define GHOST_MAX_CONTEXT_DATA 16

struct ghost_context_data {
	const char *data_name;
	enum ghost_log_level level;
	bool has_data;
	void *data_ptr;
	ghost_printer_fn fn;
};

struct ghost_context_frame {
	const char *ctx_name;
	u64 nr_attached_data;
	u64 frame_id;
	struct ghost_context_data data[GHOST_MAX_CONTEXT_DATA];
};

struct ghost_context {
	u64 nr_frames;
	u64 count;
	struct ghost_context_frame frames[GHOST_MAX_CONTEXT_FRAMES];
};

DECLARE_PER_CPU(struct ghost_context, g_context);
DEFINE_PER_CPU(struct ghost_context, g_context);

static bool frame_should_print_immediately(void)
{
	struct ghost_context *ctx = this_cpu_ptr(&g_context);
	bool should_print_immediately;


	if (ghost_control_is_controlled("ghost_context") && !ghost_control_print_enabled("ghost_context")) {
		return false;
	}

	/*
	 * go down the stack, and find the inner-most defined control
	 * and return its print enabled
	 */
	should_print_immediately = true;

	for (int i = 0; i < ctx->nr_frames; i++) {
		const char *frame_name = ctx->frames[i].ctx_name;
		if (ghost_control_is_controlled(frame_name)) {
			should_print_immediately = ghost_control_print_enabled(frame_name);
		}
	}

	return should_print_immediately;
}

static void colour_open(enum ghost_log_level level)
{
	switch (level) {
	case GHOST_LOG_ERROR:
		hyp_putsp("! ");
		hyp_putsp(GHOST_WHITE_ON_RED);
		break;
	default:
		;
	}
}

static void colour_close(enum ghost_log_level level)
{
	switch (level) {
	case GHOST_LOG_ERROR:
		hyp_putsp(GHOST_NORMAL);
		break;
	default:
		;
	}
}

void ghost_log_enter_context(const char *s)
{
	u64 i;
	struct ghost_context_frame *frame;
	struct ghost_context *ctx;

	ctx = this_cpu_ptr(&g_context);
	ghost_assert(ctx->nr_frames < GHOST_MAX_CONTEXT_FRAMES);

	i = ctx->nr_frames++;
	++ctx->count;

	frame = &ctx->frames[i];
	frame->ctx_name = s;
	frame->nr_attached_data = 0;
	frame->frame_id = ctx->count;

	if (frame_should_print_immediately()) {
		ghost_print_begin();
		hyp_puti(i * 2);
		hyp_putsp("[enter ");
		hyp_putsp((char *)s);
		hyp_putsp("\n");
		ghost_print_end();
	}
}

void ghost_log_context_attach(const char *s, void *data, ghost_printer_fn printer)
{
	struct ghost_context *ctx;
	struct ghost_context_frame *frame;
	struct ghost_context_data *ctx_data;
	u64 framei, i;

	ctx = this_cpu_ptr(&g_context);

	framei = ctx->nr_frames - 1;
	frame = &ctx->frames[framei];

	ghost_assert(frame->nr_attached_data < GHOST_MAX_CONTEXT_DATA);

	i = frame->nr_attached_data++;

	ctx_data = &frame->data[i];
	ctx_data->level = GHOST_LOG_TRACE;
	ctx_data->has_data = true;
	ctx_data->data_name = s;
	ctx_data->data_ptr = data;
	ctx_data->fn = printer;

	if (frame_should_print_immediately()) {
		ghost_print_begin();
		hyp_putsp(".");
		hyp_putsp((char *)s);
		hyp_putsp(":");
		printer(data);
		hyp_putsp("\n");
		ghost_print_end();
	}
}

void ghost_log_context_log(const char *s, enum ghost_log_level level)
{
	struct ghost_context *ctx;
	struct ghost_context_frame *frame;
	struct ghost_context_data *ctx_data;
	u64 framei, i;

	ctx = this_cpu_ptr(&g_context);

	framei = ctx->nr_frames - 1;
	frame = &ctx->frames[framei];

	ghost_assert(frame->nr_attached_data < GHOST_MAX_CONTEXT_DATA);

	i = frame->nr_attached_data++;

	ctx_data = &frame->data[i];
	ctx_data->data_name = s;
	ctx_data->level = level;
	ctx_data->has_data = false;

	if (frame_should_print_immediately() || level == GHOST_LOG_ERROR) {
		ghost_print_begin();
		colour_open(level);
		hyp_putsp((char *)s);
		hyp_putsp("\n");
		colour_close(level);
		ghost_print_end();
	}
}

void ghost_log_exit_context(const char *s)
{
	struct ghost_context *ctx;
	struct ghost_context_frame *frame;

	ctx = this_cpu_ptr(&g_context);
	ghost_assert(ctx->nr_frames > 0);
	frame = &ctx->frames[ctx->nr_frames - 1];

	if (s && strcmp(s, frame->ctx_name)) {
		GHOST_WARN("Tried to pop shadow stack from wrong context");
		GHOST_LOG(frame->ctx_name, str);
		GHOST_LOG(s, str);
		ghost_assert(false);
	}

	if (frame_should_print_immediately()) {
		ghost_print_begin();
		hyp_puti(ctx->nr_frames * 2);
		hyp_putsp("... end ");
		hyp_putsp((char *)frame->ctx_name);
		hyp_putsp("] \n");
		ghost_print_end();
	}

	ctx->nr_frames--;
}

static void indent(u64 width)
{
	for (int i = 0; i < width; i++) {
		hyp_putsp(" ");
	}
}

// we want to use the pkvm pgtable walker to check validity of the VAs before trying to print them
extern int kvm_nvhe_sym(__hyp_check_page_state_range)(u64 addr, u64 size, enum pkvm_page_state state);
extern hyp_spinlock_t kvm_nvhe_sym(pkvm_pgd_lock);

void ghost_log_context_traceback(void)
{
	struct ghost_context *ctx;
	ghost_print_begin();

	ctx = this_cpu_ptr(&g_context);

	hyp_putsp("ghost context:\n");
	for (int i = 0; i < ctx->nr_frames; i++) {
		struct ghost_context_frame *frame = &ctx->frames[i];

		indent(i*4);
		hyp_putsp("in ");
		hyp_putsp((char *)frame->ctx_name);
		hyp_putsp("\n");

		for (int d = 0; d < frame->nr_attached_data; d++) {
			struct ghost_context_data *data = &frame->data[d];
			indent(i*4);
			hyp_putsp("| ");

			colour_open(data->level);

			hyp_putsp((char *)data->data_name);
			if (data->has_data) {
				u64 va;
				bool va_valid;

				hyp_putsp(":");

				// don't just dereference it, check if it's accessible first
				// ... by actually doing a pgtable walk!
				hyp_spin_lock(&kvm_nvhe_sym(pkvm_pgd_lock));
				va = (u64)data->data_ptr;
				va_valid = !kvm_nvhe_sym(__hyp_check_page_state_range)(va, sizeof(void*), PKVM_PAGE_OWNED);
				hyp_spin_unlock(&kvm_nvhe_sym(pkvm_pgd_lock));

				// don't try to dereference NULL pointers
				if (! data->data_ptr) {
					hyp_putsp("<inacessible>@NULL");
				// also check we can read it.
				} else if (! va_valid) {
					hyp_putsp("<inaccessible>@");
					hyp_putx64(va);
				} else {
					data->fn(data->data_ptr);
				}
			}
			colour_close(data->level);
			hyp_putsp("\n");
		}
	}
	ghost_print_end();
}
