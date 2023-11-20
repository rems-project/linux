#ifndef GHOST_CONTEXT_H
#define GHOST_CONTEXT_H

#include <nvhe/ghost_printer.h>

/*
 * Useful logging stacked traceback builders
 * Allows attaching arbitrary data with printers,
 * and can be dumped at any time.
 */

// TODO: make this use the ghost_printf machinery.

typedef void (*ghost_printer_fn)(void *data);

enum ghost_log_level {
	GHOST_LOG_DEBUG = 0,
	GHOST_LOG_TRACE,
	GHOST_LOG_INFO,
	GHOST_LOG_WARN,
	GHOST_LOG_ERROR
};

void ghost_log_enter_context(
	const char *s
);
void ghost_log_context_attach(
	const char *current_frame_name,
	const char *s,
	void *data,
	ghost_printer_fn printer
);
void ghost_log_context_log(
	const char *s,
	enum ghost_log_level level
);
void ghost_log_exit_context(
	const char *s
);
void ghost_log_context_traceback(void);
int gp_put_current_context_trace(gp_stream_t *out);


#define __INNER_NAME(name) "inner " name

/**
 * GHOST_LOG_CONTEXT_ENTER() - Enter a shadow stack context
 *
 * Puts this function on the shadow stack,
 * must be paired with a sibling GHOST_LOG_CONTEXT_EXIT.
 */
#define GHOST_LOG_CONTEXT_ENTER() ghost_log_enter_context(__func__)

/**
 * GHOST_LOG_CONTEXT_EXIT() - Leave the current function's shadow stack context.
 *
 * Will fail if not in the same function as the current context.
 */
#define GHOST_LOG_CONTEXT_EXIT() ghost_log_exit_context(__func__)

/**
 * GHOST_LOG_CONTEXT_EXIT_FORCE() - Leave a shadow stack context.
 * @CONTEXT_NAME: name of context.
 *
 * Leaves a shadow stack context
 */
#define GHOST_LOG_CONTEXT_EXIT_FORCE(CONTEXT_NAME) ghost_log_exit_context(CONTEXT_NAME)

// Versions for inner contexts, too.
#define GHOST_LOG_CONTEXT_ENTER_INNER(name) ghost_log_enter_context(__INNER_NAME(name))
#define GHOST_LOG_CONTEXT_EXIT_INNER(name) ghost_log_exit_context(__INNER_NAME(name))

#define GHOST_LOG_P(context, var, printer) \
	ghost_log_context_attach(context, #var, (void*)&(var), printer)

#define GHOST_u64printer hyp_putx64ptr
#define GHOST_u32printer hyp_putx32ptr
#define GHOST_boolprinter hyp_putboolptr
#define GHOST_strprinter hyp_putsptr
#define __GHOST_PRINTER(ty) GHOST_##ty##printer

/**
 * GHOST_LOG() - Register a variable for logging.
 *
 * @VAR: lvalue
 * @TY: known ghost type (u64, u32, bool, str).
 *
 * Puts a reference to VAR on the shadow stack,
 * to be printed on any shadow traceback.
 *
 * Must be called from inside a same-function GHOST_LOG_CONTEXT_ENTER[_INNER] context.
 */
#define GHOST_LOG(VAR, TY) \
	GHOST_LOG_P((__func__), (VAR), __GHOST_PRINTER(TY))

/**
 * GHOST_LOG_FORCE() - GHOST_LOG() without the checking.
 * @CONTEXT: explicit name of context.
 * @VAR: lvalue.
 * @TY: ghost type.
 *
 * Like GHOST_LOG but can explicitly pass name of context.
 */
#define GHOST_LOG_FORCE(CONTEXT, VAR, TY) \
	GHOST_LOG_P((CONTEXT), (VAR), __GHOST_PRINTER(TY))

/**
 * GHOST_LOG_INNER() - GHOST_LOG() for inner contexts.
 * @NAME: explicit name of inner context.
 * @VAR: lvalue.
 * @TY: ghost type.
 *
 * Like GHOST_LOG but for inner contexts.
 */
#define GHOST_LOG_INNER(NAME, VAR, TY) \
	GHOST_LOG_P(__INNER_NAME(NAME), (VAR), __GHOST_PRINTER(TY))

/**
 * GHOST_ERROR_VAR() - Like GHOST_LOG() but for errors only.
 *
 * No checking on context frame.
 */
#define GHOST_ERROR_VAR(var, ty) \
	GHOST_LOG_P(NULL, (var), __GHOST_PRINTER(ty))

#define GHOST_WARN(msg) \
	ghost_log_context_log(msg, GHOST_LOG_WARN)

#define GHOST_INFO(msg) \
	ghost_log_context_log(msg, GHOST_LOG_INFO)

#define GHOST_TRACE(msg) \
	ghost_log_context_log(msg, GHOST_LOG_TRACE)

#endif /* GHOST_CONTEXT_H */
