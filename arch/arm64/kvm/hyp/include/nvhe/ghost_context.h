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

#endif /* GHOST_CONTEXT_H */