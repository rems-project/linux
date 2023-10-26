#ifndef GHOST_CONTEXT_H
#define GHOST_CONTEXT_H

/*
 * Useful logging stacked traceback builders
 * Allows attaching arbitrary data with printers,
 * and can be dumped at any time.
 */

typedef void (*ghost_printer_fn)(void *data);

enum ghost_log_level {
	GHOST_LOG_TRACE,
	GHOST_LOG_ERROR
};

void ghost_log_enter_context(
	const char *s
);
void ghost_log_context_attach(
	const char *s,
	void *data,
	ghost_printer_fn printer
);
void ghost_log_context_log(
	const char *s,
	enum ghost_log_level level
);
void ghost_log_exit_context(void);
void ghost_log_context_traceback(void);


#define GHOST_LOG_CONTEXT_ENTER() ghost_log_enter_context(__func__)
#define GHOST_LOG_CONTEXT_EXIT() ghost_log_exit_context()

#define GHOST_LOG_P(var, printer) \
	ghost_log_context_attach(#var, &var, printer)

#define GHOST_u64printer hyp_putx64ptr
#define GHOST_u32printer hyp_putx32ptr
#define GHOST_boolprinter hyp_putboolptr
#define GHOST_strprinter hyp_putsptr

#define GHOST_PRINTER(ty) \
	GHOST_##ty##printer

#define GHOST_LOG(var, ty) \
	GHOST_LOG_P(var, GHOST_PRINTER(ty))

#define GHOST_WARN(msg) \
	ghost_log_context_log(msg, GHOST_LOG_ERROR)

#endif /* GHOST_CONTEXT_H */