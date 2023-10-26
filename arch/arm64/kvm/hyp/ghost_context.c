#include <asm/kvm_mmu.h>
#include <linux/types.h>

#include <hyp/ghost_extra_debug-pl011.h>

#include <nvhe/spinlock.h>
#include <nvhe/ghost_asserts.h>
#include <nvhe/ghost_context.h>

#define GHOST_MAX_CONTEXT_FRAMES 16
#define GHOST_MAX_CONTEXT_DATA 16

struct ghost_context_data {
	const char *data_name;
	void *data_ptr;
	ghost_printer_fn fn;
};

struct ghost_context_frame {
	const char *ctx_name;
	u64 nr_attached_data;
	struct ghost_context_data data[GHOST_MAX_CONTEXT_DATA];
};

struct ghost_context {
	u64 nr_frames;
	struct ghost_context_frame frames[GHOST_MAX_CONTEXT_FRAMES];
};

DECLARE_PER_CPU(struct ghost_context, g_context);
DEFINE_PER_CPU(struct ghost_context, g_context);

void ghost_log_enter_context(const char *s)
{
	u64 i;
	struct ghost_context_frame *frame;
	struct ghost_context *ctx;
	
	ctx = this_cpu_ptr(&g_context);
	ghost_assert(ctx->nr_frames < GHOST_MAX_CONTEXT_FRAMES);

	i = ctx->nr_frames++;

	frame = &ctx->frames[i];
	frame->ctx_name = s;
	frame->nr_attached_data = 0;

	ghost_print_begin();
	hyp_putsp("[enter ");
	hyp_putsp((char *)s);
	hyp_putsp("\n");
	ghost_print_end();
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
	ctx_data->data_name = s;
	ctx_data->data_ptr = data;
	ctx_data->fn = printer;

	ghost_print_begin();
	hyp_putsp(".");
	hyp_putsp((char *)s);
	hyp_putsp(":");
	printer(data);
	hyp_putsp("\n");
	ghost_print_end();
}

void ghost_log_exit_context(void)
{
	struct ghost_context *ctx;
	struct ghost_context_frame *frame;

	ctx = this_cpu_ptr(&g_context);
	ghost_assert(ctx->nr_frames > 0);
	frame = &ctx->frames[ctx->nr_frames - 1];

	ghost_print_begin();
	hyp_putsp("... end ");
	hyp_putsp((char *)frame->ctx_name);
	hyp_putsp("] \n");
	ghost_print_end();

	ctx->nr_frames--;
}

static void indent(u64 width)
{
	for (int i = 0; i < width; i++) {
		hyp_putsp(" ");
	}
}

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
			hyp_putsp((char *)data->data_name);
			hyp_putsp(":");
			data->fn(data->data_ptr);
			hyp_putsp("\n");
		}
	}
	ghost_print_end();
}