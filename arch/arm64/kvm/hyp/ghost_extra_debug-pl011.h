// PS:






#ifndef __ARM64_KVM_HYP_GHOST_EXTRA_DEBUG_PL011_H__
#define __ARM64_KVM_HYP_GHOST_EXTRA_DEBUG_PL011_H__

#include "./debug-pl011.h"


extern bool ghost_extra_debug_initialised;

//// copied from debug-pl011.h as it's not in the new serial.h
//static inline void __hyp_putx4(unsigned int x)
//{
//	x &= 0xf;
//	if (x <= 9)
//		x += '0';
//	else
//		x += ('a' - 0xa);
//	hyp_putc(x);
//}
//// end

#define GHOST_WHITE_ON_BLACK "\033[40;37;1m"
#define GHOST_WHITE_ON_RED "\033[41;37;1m"
#define GHOST_WHITE_ON_GREEN "\033[42;37;1m"
#define GHOST_WHITE_ON_YELLOW "\033[43;37;1m"
#define GHOST_WHITE_ON_BLUE "\033[44;37;1m"
#define GHOST_WHITE_ON_MAGENTA "\033[45;37;1m"
#define GHOST_WHITE_ON_CYAN "\033[46;37;1m"
#define GHOST_NORMAL "\033[0m"


static inline void hyp_puti(u64 i)
{
        while (i > 0) {
		hyp_putc(' ');
		i--;
	}
}

static inline void hyp_putsp(char *s)
{
        if (s != NULL) {
		while (*s)
			hyp_putc(*s++);
	}
}

static inline void hyp_putspi(char *s, u64 i)
{
	hyp_puti(i);
	hyp_putsp(s);
}

static inline void hyp_putbool(bool b)
{
        if (b) hyp_putsp("true"); else hyp_putsp("false");
}


static inline void __hyp_putx4np(unsigned long x, int n)
{
        int i = n >> 2;

        hyp_putc('0');
        hyp_putc('x');

        while (i--) {
		if (i !=0 && x >> (4 * i) == 0)
			hyp_putc('.');
		else
			__hyp_putx4(x >> (4 * i));
	}

}

static inline void hyp_putsxn(char *s, unsigned long x, int n)
{
        hyp_putsp(s);
        hyp_putc(':');
        __hyp_putx4np(x,n);
        hyp_putc(' ');
}

static inline void hyp_putsxnl(char *s, unsigned long x, int n)
{
	hyp_putsp(s);
	hyp_putc(':');
	__hyp_putx4np(x, n);
	hyp_putc('\n');
}

static inline void check_assert_fail(char *s) 
{
        hyp_putsp("check_assert_fail: ");
        hyp_putsp(s);
        hyp_putc('\n');
}


#else /* __ARM64_KVM_HYP_GHOST_EXTRA_DEBUG_PL011_H__ */
//
//void hyp_putsp(char *s);
//void hyp_putbool(bool b);
//void hyp_putsxn(char *s, unsigned long x, int n);
//void check_assert_fail(char *s);
//
//
#endif        /* __ARM64_KVM_HYP_GHOST_EXTRA_DEBUG_PL011_H__ */
