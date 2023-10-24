#include <hyp/ghost_extra_debug-pl011.h>

#include <nvhe/pkvm.h>
#include <hyp/debug-pl011.h>

bool ghost_extra_debug_initialised = false;

static DEFINE_HYP_SPINLOCK(g_print_lock);  // Internal.

static DEFINE_HYP_SPINLOCK(g_public_print_lock); // Exported.

void ghost_print_begin(void) { hyp_spin_lock(&g_public_print_lock); }
void ghost_print_end(void) { hyp_spin_unlock(&g_public_print_lock); }

void hyp_putc(char c) { __hyp_putc(c); }

void hyp_puts(char *s) {
	hyp_spin_lock(&g_print_lock);
	__hyp_puts(s);
	hyp_spin_unlock(&g_print_lock);
}

void hyp_putx32(unsigned int x) { __hyp_putx32(x); }

void hyp_putx64(unsigned long x) { __hyp_putx64(x); }

static inline void __hyp_puti(u64 i)
{
	while (i-- > 0) __hyp_putc(' ');
}

void hyp_puti(u64 i) {
	hyp_spin_lock(&g_print_lock);
	__hyp_puti(i);
	hyp_spin_unlock(&g_print_lock);
}

static inline void __hyp_putsp(char *s)
{
	__hyp_puts(s ? s : "<NULL>");
}

void hyp_putsp(char *s)
{
	hyp_spin_lock(&g_print_lock);
	__hyp_putsp(s);
	hyp_spin_unlock(&g_print_lock);
}

void hyp_putspi(char *s, u64 i)
{
	hyp_spin_lock(&g_print_lock);
	__hyp_puti(i);
	__hyp_putsp(s);
	hyp_spin_unlock(&g_print_lock);
}

void hyp_putbool(bool b)
{
	hyp_spin_lock(&g_print_lock);
	__hyp_putsp(b ? "true" : "false");
	hyp_spin_unlock(&g_print_lock);
}


static void __hyp_putx4np(unsigned long x, int n)
{
	int i = n >> 2;

	__hyp_putc('0');
	__hyp_putc('x');

	while (i--) {
		if (i !=0 && x >> (4 * i) == 0)
			__hyp_putc('.');
		else
			__hyp_putx4(x >> (4 * i));
	}

}

void hyp_putsxn(char *s, unsigned long x, int n)
{
	hyp_spin_lock(&g_print_lock);
	__hyp_putsp(s);
	__hyp_putc(':');
	__hyp_putx4np(x,n);
	__hyp_putc(' ');
	hyp_spin_unlock(&g_print_lock);
}

void hyp_putsxnl(char *s, unsigned long x, int n)
{
	hyp_spin_lock(&g_print_lock);
	__hyp_putsp(s);
	__hyp_putc(':');
	__hyp_putx4np(x, n);
	__hyp_putc('\n');
	hyp_spin_unlock(&g_print_lock);
}

void check_assert_fail(char *s)
{
	hyp_spin_lock(&g_print_lock);
	__hyp_putsp("check_assert_fail: ");
	__hyp_putsp(s);
	__hyp_putc('\n');
	hyp_spin_unlock(&g_print_lock);
}

