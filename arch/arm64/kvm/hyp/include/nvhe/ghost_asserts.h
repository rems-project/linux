#ifndef GHOST_ASSERTS_H
#define GHOST_ASSERTS_H

#include <asm-generic/bug.h>

// assertion to check invariants of the ghost instrumentation, which should never fail
#define ghost_assert(c) BUG_ON(!(c));

// assertion to check the spec
#define ghost_spec_assert(c) BUG_ON(!(c));

#endif // GHOST_ASSERTS_H