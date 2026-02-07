#include <nvhe/ghost/ghost_serial.h>

#include <nvhe/pkvm.h>

static DEFINE_HYP_SPINLOCK(g_print_lock);  // Internal.
static DEFINE_PER_CPU(int, g_print_lock_locked);

static void ghost_print_begin(void)
{
	int p = *this_cpu_ptr(&g_print_lock_locked);

	if (!p)
		hyp_spin_lock(&g_print_lock);

	*this_cpu_ptr(&g_print_lock_locked) = p + 1;
}

static void ghost_print_end(void)
{
	int p = *this_cpu_ptr(&g_print_lock_locked) - 1;
	*this_cpu_ptr(&g_print_lock_locked) = p;
	if (!p)
		hyp_spin_unlock(&g_print_lock);
}

static inline void ghost_hyp_putx4(unsigned int x)
{
	x &= 0xf;
	if (x <= 9)
		x += '0';
	else
		x += ('a' - 0xa);
	hyp_putc(x);
}

static inline void ghost_hyp_putx4n(unsigned long x, int n)
{
	int i = n >> 2;

	hyp_putc('0');
	hyp_putc('x');

	while (i--)
		ghost_hyp_putx4(x >> (4 * i));

	hyp_putc('\n');
	hyp_putc('\r');
}

void hyp_putx32(unsigned int x)
{
	ghost_hyp_putx4n(x, 32);
}

static inline void __hyp_putx4(unsigned int x)
{
	x &= 0xf;
	if (x <= 9)
		x += '0';
	else
		x += ('a' - 0xa);
	hyp_putc(x);
}

static void __hyp_putn(u64 n)
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
		hyp_putc(digits[i]);
	} while (i--);
}

static inline void __hyp_puti(u64 i)
{
	while (i-- > 0) hyp_putc(' ');
}

void hyp_puti(u64 i) {
	ghost_print_begin();
	__hyp_puti(i);
	ghost_print_end();
}

static inline void __hyp_putsp(char *s)
{
	hyp_puts(s ? s : "<NULL>");
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

	hyp_putc('0');
	hyp_putc('x');

	while (i--) {
		if (i !=0 && x >> (4 * i) == 0)
			hyp_putc('.');
		else
			__hyp_putx4(x >> (4 * i));
	}

}

void hyp_putsxn(char *s, unsigned long x, int n)
{
	ghost_print_begin();
	__hyp_putsp(s);
	hyp_putc(':');
	__hyp_putx4np(x,n);
	hyp_putc(' ');
	ghost_print_end();
}

void hyp_putsxnl(char *s, unsigned long x, int n)
{
	ghost_print_begin();
	__hyp_putsp(s);
	hyp_putc(':');
	__hyp_putx4np(x, n);
	hyp_putc('\n');
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
	hyp_putc('\n');
	ghost_print_end();
}

DEFINE_HYP_PTR_PRINTER(c, char, hyp_putc);
DEFINE_HYP_PTR_PRINTER(s, char*, hyp_putsp);
DEFINE_HYP_PTR_PRINTER(x32, u32, hyp_putx32);
DEFINE_HYP_PTR_PRINTER(x64, u64, hyp_putx64);
DEFINE_HYP_PTR_PRINTER(bool, bool, hyp_putbool);
