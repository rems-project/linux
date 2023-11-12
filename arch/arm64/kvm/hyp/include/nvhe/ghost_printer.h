#ifndef GHOST_PRINTER_H
#define GHOST_PRINTER_H

#include <linux/types.h>
#include <linux/stdarg.h>

/*
 * A very minimal printf implementation, with extra features for ghost.
 *
 * Supported format codes:
 *  %c = char
 *  %b = boolean
 *  %s = string
 *  %p = pointer (as 0x1122334455667788)
 *  %d = decimal (u8, u16, and u32)
 *  %x = hex (u8, u16, and u32)
 *  %ld = long decimal (u64)
 *  %lx = long hex (u64)
 *  %I  = indent (u64)
 *  %g(KIND) = ghost object
 *      Where KIND one of:
 *      - maplet (pointer to)
 *      - maplet_target (pointer to)
 *      - ek (cast to u64)
 *  %g2(KIND) = ghost object (2 arg form, pointer then u64)
 *      - entry (u64, 2nd arg = level)
 *      - mapping (pointer to, 2nd arg = internal indent)
 *  (where %gL and %gI are aliases for %g2)
 *
 * Supported escapes:
 *  %% = literal %
 *  %$ = current shadow stack context
 */

enum gp_stream_kind {
	GP_STREAM_UART,
	GP_STREAM_BUF,
};

typedef struct gp_stream {
	enum gp_stream_kind kind;
	char *buf;
	u64 buf_rem;
} gp_stream_t;

#define STREAM_UART &__GHOST_UART
#define NEW_STREAM_BUFFERED(buffer, n) ((gp_stream_t){.kind=GP_STREAM_BUF, .buf=(buffer), .buf_rem=(n)})

int ghost_vsprintf(gp_stream_t *out, const char *fmt, va_list ap);

int ghost_snprintf(char *out, u64 n, const char *fmt, ...);
int ghost_sprintf(gp_stream_t *out, const char *fmt, ...);
void ghost_printf(const char *fmt, ...);

/*
 * Printer locks
 * These are re-entrant, so can be taken anywhere.
 *
 * NOTE: the pure UART dumpers do not respect these,
 *       so tracebacks and so on may be interleaved.
 */
void ghost_print_enter(void);
void ghost_print_exit(void);

#endif /* GHOST_PRINTER_H */