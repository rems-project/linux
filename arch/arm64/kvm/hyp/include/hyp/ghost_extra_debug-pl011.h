#ifndef __ARM64_KVM_HYP_GHOST_EXTRA_DEBUG_PL011_H__
#define __ARM64_KVM_HYP_GHOST_EXTRA_DEBUG_PL011_H__

#include <linux/types.h>

#ifdef CONFIG_NVHE_GHOST_SPEC_COLOURS
#define GHOST_WHITE_ON_BLACK "\033[40;37;1m"
#define GHOST_WHITE_ON_RED "\033[41;37;1m"
#define GHOST_WHITE_ON_GREEN "\033[42;37;1m"
#define GHOST_WHITE_ON_YELLOW "\033[43;37;1m"
#define GHOST_WHITE_ON_BLUE "\033[44;37;1m"
#define GHOST_WHITE_ON_MAGENTA "\033[45;37;1m"
#define GHOST_WHITE_ON_CYAN "\033[46;37;1m"
#define GHOST_NORMAL "\033[0m"
#else
#define GHOST_WHITE_ON_BLACK  "***"
#define GHOST_WHITE_ON_RED    "***"
#define GHOST_WHITE_ON_GREEN  "***"
#define GHOST_WHITE_ON_YELLOW "***"
#define GHOST_WHITE_ON_BLUE   "***"
#define GHOST_WHITE_ON_MAGENTA "***"
#define GHOST_WHITE_ON_CYAN "***"
#define GHOST_NORMAL "***"
#endif

extern bool ghost_extra_debug_initialised;

/* hyp_put* are internally locked.
 */
void hyp_putc(char c);
void hyp_puts(char *s);
void hyp_putx32(unsigned int x);
void hyp_putx64(unsigned long x);

void hyp_puti(u64 i);
void hyp_putsp(char *s);
void hyp_putspi(char *s, u64 i);
void hyp_putbool(bool b);
void hyp_putsxn(char *s, unsigned long x, int n);
void hyp_putsxnl(char *s, unsigned long x, int n);
void check_assert_fail(char *s);

void hyp_putn(u64 n);

/* This lock can be taken around a larger printing block to prevent
 * interleaving.
 */
void ghost_print_begin(void);
void ghost_print_end(void);

/*
 * Helpers that duplicate the previous hyp_put* but that take pointers
 */

#define DECLARE_HYP_PTR_PRINTER(NAME) \
	void hyp_put##NAME##ptr(void *p);

#define DEFINE_HYP_PTR_PRINTER(NAME, TY, fn) \
	void hyp_put##NAME##ptr(void *p) { \
		fn(*(TY *)p); \
	}

DECLARE_HYP_PTR_PRINTER(c);
DECLARE_HYP_PTR_PRINTER(s);
DECLARE_HYP_PTR_PRINTER(x32);
DECLARE_HYP_PTR_PRINTER(x64);
DECLARE_HYP_PTR_PRINTER(bool);

#else /* __ARM64_KVM_HYP_GHOST_EXTRA_DEBUG_PL011_H__ */
//
//void hyp_putsp(char *s);
//void hyp_putbool(bool b);
//void hyp_putsxn(char *s, unsigned long x, int n);
//void check_assert_fail(char *s);
//
//
#endif        /* __ARM64_KVM_HYP_GHOST_EXTRA_DEBUG_PL011_H__ */
