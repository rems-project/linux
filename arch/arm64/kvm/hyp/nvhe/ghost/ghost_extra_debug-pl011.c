#include <nvhe/ghost/ghost_extra_debug-pl011.h>

#include <nvhe/pkvm.h>
#include <hyp/debug-pl011.h>


static DEFINE_HYP_SPINLOCK(g_print_lock);  // Internal.
static DEFINE_PER_CPU(int, g_print_lock_locked);

void ghost_print_begin(void)
{
	int p = *this_cpu_ptr(&g_print_lock_locked);

	if (!p)
		hyp_spin_lock(&g_print_lock);

	*this_cpu_ptr(&g_print_lock_locked) = p + 1;
}

void ghost_print_end(void)
{
	int p = *this_cpu_ptr(&g_print_lock_locked) - 1;
	*this_cpu_ptr(&g_print_lock_locked) = p;
	if (!p)
		hyp_spin_unlock(&g_print_lock);
}

void hyp_putc(char c) { __hyp_putc(c); }

void hyp_puts(char *s) {
	ghost_print_begin();
	__hyp_puts(s);
	ghost_print_end();
}

void hyp_putx32(unsigned int x) { __hyp_putx32(x); }

void hyp_putx64(unsigned long x) { __hyp_putx64(x); }

void __hyp_putn(u64 n)
{
	char digits[20] = {0};
	int i = 0;

	do {
		digits[i] = (n % 10) + '0';
		n /= 10;
		i++;
	} while (n > 0);

	i--;

	do {
		__hyp_putc(digits[i]);
	} while (i--);
}

static inline void __hyp_puti(u64 i)
{
	while (i-- > 0) __hyp_putc(' ');
}

void hyp_puti(u64 i) {
	ghost_print_begin();
	__hyp_puti(i);
	ghost_print_end();
}

static inline void __hyp_putsp(char *s)
{
	__hyp_puts(s ? s : "<NULL>");
}

void hyp_putsp(char *s)
{
	ghost_print_begin();
	__hyp_putsp(s);
	ghost_print_end();
}

void hyp_putspi(char *s, u64 i)
{
	ghost_print_begin();
	__hyp_puti(i);
	__hyp_putsp(s);
	ghost_print_end();
}

void hyp_putbool(bool b)
{
	ghost_print_begin();
	__hyp_putsp(b ? "true" : "false");
	ghost_print_end();
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
	ghost_print_begin();
	__hyp_putsp(s);
	__hyp_putc(':');
	__hyp_putx4np(x,n);
	__hyp_putc(' ');
	ghost_print_end();
}

void hyp_putsxnl(char *s, unsigned long x, int n)
{
	ghost_print_begin();
	__hyp_putsp(s);
	__hyp_putc(':');
	__hyp_putx4np(x, n);
	__hyp_putc('\n');
	ghost_print_end();
}

void hyp_putn(u64 n)
{
	ghost_print_begin();
	__hyp_putn(n);
	ghost_print_end();
}

void check_assert_fail(char *s)
{
	ghost_print_begin();
	__hyp_putsp("check_assert_fail: ");
	__hyp_putsp(s);
	__hyp_putc('\n');
	ghost_print_end();
}

DEFINE_HYP_PTR_PRINTER(c, char, hyp_putc);
DEFINE_HYP_PTR_PRINTER(s, char*, hyp_putsp);
DEFINE_HYP_PTR_PRINTER(x32, u32, hyp_putx32);
DEFINE_HYP_PTR_PRINTER(x64, u64, hyp_putx64);
DEFINE_HYP_PTR_PRINTER(bool, bool, hyp_putbool);
