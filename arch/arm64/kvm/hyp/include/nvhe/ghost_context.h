#ifndef GHOST_CONTEXT_H
#define GHOST_CONTEXT_H

/*
 * Useful logging stacked traceback builders
 * Allows attaching arbitrary data with printers,
 * and can be dumped at any time.
 */

typedef void (*ghost_printer_fn)(void *data);

void ghost_log_enter_context(
	const char *s
);
void ghost_log_context_attach(
	const char *s,
	void *data,
	ghost_printer_fn printer
);
void ghost_log_exit_context(void);
void ghost_log_context_traceback(void);


#define GHOST_LOG_CONTEXT_ENTER() ghost_log_enter_context(__func__)
#define GHOST_LOG_CONTEXT_EXIT() ghost_log_exit_context()

#define GHOST_LOG_P(var, printer) \
	ghost_log_context_attach(#var, &var, printer##ptr)

#define GHOST_u64printer hyp_putx64ptr
#define GHOST_u32printer hyp_putx32ptr
#define GHOST_boolprinter hyp_putboolptr
#define GHOST_PRINTER(ty) \
	GHOST_##ty##printer

#define GHOST_LOG(var, ty) \
	ghost_log_context_attach(#var, &var, GHOST_PRINTER(ty))

#endif /* GHOST_CONTEXT_H */