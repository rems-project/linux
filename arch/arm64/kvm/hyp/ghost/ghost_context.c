#include <asm/kvm_mmu.h>
#include <linux/types.h>

#include <hyp/ghost/ghost_extra_debug-pl011.h>

#include <nvhe/spinlock.h>
#include <nvhe/mem_protect.h>

#include <nvhe/ghost/ghost_asserts.h>
#include <nvhe/ghost/ghost_context.h>
#include <nvhe/ghost/ghost_control.h>

#include <nvhe/ghost/ghost_printer.h>


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

static const char *msg_open_for(enum ghost_log_level level)
{
	switch (level) {
	case GHOST_LOG_ERROR:
		return "! " GHOST_WHITE_ON_RED;
	case GHOST_LOG_WARN:
	  return "! " GHOST_WHITE_ON_YELLOW;
	default:
		return "";
	}
}

static const char *msg_close_for(enum ghost_log_level level)
{
	switch (level) {
	case GHOST_LOG_ERROR:
	case GHOST_LOG_WARN:
		return GHOST_NORMAL;
	default:
		return "";
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
		ghost_print_enter();
		ghost_printf("%I[enter %s]\n", i*2, (char*)s);
		ghost_print_exit();
	}
}

void ghost_log_context_attach(const char *current_frame_name, const char *s, void *data, ghost_printer_fn printer)
{
	struct ghost_context *ctx;
	struct ghost_context_frame *frame;
	struct ghost_context_data *ctx_data;
	u64 framei, i;

	ctx = this_cpu_ptr(&g_context);

	framei = ctx->nr_frames - 1;
	frame = &ctx->frames[framei];

	if (current_frame_name && strcmp(current_frame_name, frame->ctx_name)) {
		GHOST_WARN("Tried to attach to shadow stack from wrong context");
		GHOST_LOG_FORCE(NULL, frame->ctx_name, str);
		GHOST_LOG_FORCE(NULL, current_frame_name, str);
		ghost_assert(false);
	}

	ghost_assert(frame->nr_attached_data < GHOST_MAX_CONTEXT_DATA);

	i = frame->nr_attached_data++;

	ctx_data = &frame->data[i];
	ctx_data->level = GHOST_LOG_TRACE;
	ctx_data->has_data = true;
	ctx_data->data_name = s;
	ctx_data->data_ptr = data;
	ctx_data->fn = printer;

	if (frame_should_print_immediately()) {
		ghost_print_enter();
		/* TODO: make GHOST_LOG() take a ghost_printf %g(KIND) and use that here... */
		ghost_printf(".%s:", (char*)s);
		printer(data);
		ghost_printf("\n");
		ghost_print_exit();
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
		ghost_printf("%s%s%s\n", msg_open_for(level), (char *)s, msg_close_for(level));
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
		ghost_print_enter();
		ghost_printf("%I[exit %s]\n", ctx->nr_frames*2, frame->ctx_name);
		ghost_print_exit();
	}

	ctx->nr_frames--;
}

int gp_put_current_context_trace(gp_stream_t *out)
{
	int ret;
	struct ghost_context *ctx;

	ctx = this_cpu_ptr(&g_context);

	/* not in a context, nothing to do.*/
	if (ctx->nr_frames == 0)
		return 0;

	ret = ghost_sprintf(out, "%s", ctx->frames[0].ctx_name);
	if (ret)
		return ret;

	for (int i = 1; i < ctx->nr_frames; i++) {
		struct ghost_context_frame *frame = &ctx->frames[i];
		ret = ghost_sprintf(out, ":%s", frame->ctx_name);
		if (ret)
			return ret;
	}

	return 0;
}

void ghost_log_context_traceback(void)
{
	struct ghost_context *ctx;
	ghost_print_enter();

	ctx = this_cpu_ptr(&g_context);

	ghost_printf("ghost context:\n");
	for (int i = 0; i < ctx->nr_frames; i++) {
		struct ghost_context_frame *frame = &ctx->frames[i];

		ghost_printf("%Iin %s\n", i*4, frame->ctx_name);

		for (int d = 0; d < frame->nr_attached_data; d++) {
			struct ghost_context_data *data = &frame->data[d];

			if (data->has_data) {
				u64 va = (u64)data->data_ptr;

				// TODO: if context used %g() codes, we could do this in one...
				ghost_printf("%I|%s%s:", i*4, msg_open_for(data->level), data->data_name);

				// don't try to dereference NULL pointers
				if (! data->data_ptr) {
					ghost_printf("<inacessible>@NULL");
				// also check we can read it.
				} else {
					ghost_printf("[%p]=", va);
					data->fn(data->data_ptr);
				}
				ghost_printf("%s\n", msg_close_for(data->level));
			} else {
				ghost_printf("%I|%s%s%s\n", i*4, msg_open_for(data->level), data->data_name, msg_close_for(data->level));
			}
		}
	}

	ghost_print_exit();
}
