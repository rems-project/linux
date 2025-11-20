#define __extension__
#define __signed__ signed
#define __typeof__(x) typeof(x)

/* XXX
 * Without `__attribute__((section(".data..percpu")))` on
 * hyp_allocator_errno, hyp_allocator_mc, and hyp_allocator_missing_donations,
 * pKVM absolutely crashes.
 *
 * `__attribute__((__aligned__(8)))` on chunk_hdr.data _seems_ non-essential..?
 */
#define __attribute__(x)

#define __builtin_offsetof(s, f) offsetof(s, f)

#define __auto_type long long int

#define __builtin_constant_p(x) 1
