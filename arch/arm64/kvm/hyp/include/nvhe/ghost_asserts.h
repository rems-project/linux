#ifndef GHOST_ASSERTS_H
#define GHOST_ASSERTS_H

#include <asm-generic/bug.h>
#include <nvhe/ghost_context.h>

// assertion to check invariants of the ghost instrumentation, which should never fail
#define ghost_assert(c) { \
	if (!(c)) ghost_log_context_traceback(); \
	BUG_ON(!(c)); \
}

// assertion to check the spec
#define ghost_spec_assert(c) { \
	if (!(c)) ghost_log_context_traceback(); \
	BUG_ON(!(c)); \
}


/*
 * some spec assertion helpers
 */

#define ghost_spec_assert_equal(e1, e2) { \
	ghost_spec_assert((e1) == (e2)); \
}

#define ghost_spec_assert_not_equal(e1, e2) { \
	ghost_spec_assert((e1) != (e2)); \
}

#endif // GHOST_ASSERTS_H