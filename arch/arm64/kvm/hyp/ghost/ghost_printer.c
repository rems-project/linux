#include <linux/types.h>
#include <linux/stdarg.h>
#include <nvhe/ghost/ghost_printer.h>

#include <nvhe/pkvm.h>
#include <nvhe/spinlock.h>

#include <hyp/debug-pl011.h>
#include <hyp/ghost/ghost_extra_debug-pl011.h>
#include <nvhe/ghost/ghost_asserts.h> // can use asserts here since they dump right to UART without using this printer.

#include <nvhe/ghost/ghost_maplets.h>
#include <nvhe/ghost/ghost_pgtable.h>
#include <nvhe/ghost/ghost_pfn_set.h>
#include <nvhe/ghost/ghost_status.h>
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
#include <nvhe/ghost/ghost_simplified_model.h>
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

/*
 * The UART print stream
 */
gp_stream_t __GHOST_UART = {.kind=GP_STREAM_UART};

/*
 * Print locking
 * The underlying UART printers are not locked,
 * so we add a lock to the ghost_printfs,
 * but we expose this lock and make it reentrant so other code can also take it
 * without deadlocking the printer
 */
DEFINE_HYP_SPINLOCK(ghost_print_spinlock);
DEFINE_PER_CPU(int, ghost_print_lock_count);

void ghost_print_enter(void)
{
	int p = *this_cpu_ptr(&ghost_print_lock_count);

	if (!p)
		hyp_spin_lock(&ghost_print_spinlock);

	*this_cpu_ptr(&ghost_print_lock_count) = p + 1;
}

void ghost_print_exit(void)
{
	int p = *this_cpu_ptr(&ghost_print_lock_count) - 1;
	*this_cpu_ptr(&ghost_print_lock_count) = p;
	if (!p)
		hyp_spin_unlock(&ghost_print_spinlock);
}

int __putc(gp_stream_t *out, char c)
{
	switch (out->kind) {
	case GP_STREAM_UART:
		__hyp_putc(c);
		/* UART can't fail */
		return 0;
	case GP_STREAM_BUF:
		if (out->buf_rem == 0)
			return -ENOMEM;
		out->buf[0] = c;
		out->buf++;
		out->buf_rem -= 1;
		return 0;
	}
}

#define TRY(X) \
	do { int __ret = (X); \
	     if (__ret) return __ret; } while (0)

#define TRY_PUT(c) \
	TRY(__putc(out, (c)))


/*
 * Re-implement the put functions from the uart debug
 * but with failure cases.
 */

int __puts(gp_stream_t *out, char *s)
{
	while (*s)
		TRY_PUT(*s++);

	return 0;
}

int __puti(gp_stream_t *out, int width, char c)
{
	while (width--)
		TRY_PUT(c);

	return 0;
}

static int nr_decimal_digits(u64 n)
{
	int i = 0;

	do {
		n /= 10;
		i++;
	} while (n > 0);

	return i;
}

int __putn(gp_stream_t *out, u64 n)
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
		TRY_PUT(digits[i]);
	} while (i--);

	return 0;
}

int __putx(gp_stream_t *out, u32 x)
{
	x &= 0xf;
	if (x <= 9)
		x += '0';
	else
		x += ('a' - 0xa);

	return __putc(out, x);
}

int __putxn(gp_stream_t *out, u64 x, u32 n)
{
	int i = n >> 2;

	// always prefix hex with 0x
	TRY_PUT('0');
	TRY_PUT('x');

	while (i--) {
		/*
		 * write leading 0s as .s
		 */
		if (i > 0 && (x >> (4 * i)) == 0)
			TRY_PUT('.');
		else
			TRY(__putx(out, (x >> (4 * i)) & 0xf));
	}
	return 0;
}

/*
 * Dispatchers:
 * We have the major print codes:
 *  c: char
 *  s: string
 *  d: decimal
 *  x: hex
 *  p: pointer
 * Plus a custom ghost one:
 *  g: ghost object.
 *
 * The full printf format is %<width:digit*><length:LENGTH_CHAR*><print_code:(c|s|d|x|p|g)
 * for each print code, there is a dispatch function, which takes the padding as an int (-1 means no pad)
 * and the mode as a bitmap (pos 0 = first mode char in MODE_CHAR present, etc)
 * But for many they do nothing.
 */

enum arg_length {
	LENGTH_hh = 8,
	LENGTH_h = 16,
	LENGTH_none = 32,
	LENGTH_l = 64,
};

int put_char(gp_stream_t *out, char **p, int arg)
{
	/*
	 * Note that char/u8/etc gets promoted to 'int',
	 * so we pull out an `int` and it's safe to downcast it to a `char`.
	 */
	char c = (char)arg;
	return __putc(out, c);
}

int put_bool(gp_stream_t *out, char **p, int arg)
{
	bool b = (bool)arg;
	if (b)
		return __puts(out, "true");
	else
		return __puts(out, "false");
}


int put_str(gp_stream_t *out, char **p, int width, char *arg)
{
	int n;

	if (arg == NULL)
		arg = "<NULL>";

	// pad string with " " up to width
	n = strlen(arg);
	if (width > 0 && n < width)
		TRY(__puti(out, width - n, ' '));

	return __puts(out, arg);
}

int put_decimal(gp_stream_t *out, char **p, u64 width, enum arg_length len, u64 x)
{
	// pad the left-hand side with . up to width
	int n = nr_decimal_digits(x);
	if (n < width)
		TRY(__puti(out, width - n, '.'));

	return __putn(out,x);
}

int put_hex(gp_stream_t *out, char **p, u64 width, enum arg_length len, u64 x)
{
	// pad the left-hand side with . up to width
	int n = 2 + (len >> 2);
	if (n < width)
		TRY(__puti(out, width - n, '.'));

	return __putxn(out, x, len);
}

int put_raw_ptr(gp_stream_t *out, char **p, void *arg)
{
	u64 x = (u64)arg;
	return __putxn(out, x, 64);
}

int put_kern_ptr(gp_stream_t *out, char **p, void *arg)
{
	u64 x = (u64)arg;
	// kernel pointers are printed as RAW/HYP_VA
	TRY(__putxn(out, x, 64));
	TRY(__putc(out, '/'));
	return __putxn(out, hyp_virt_to_phys(arg), 64);
}

int put_phys_ptr(gp_stream_t *out, char **p, void *arg)
{
	u64 x = (u64)arg;
	// kernel pointers are printed as RAW/HYP_VA
	TRY(__putxn(out, x, 64));
	TRY(__putc(out, '/'));
	return __putxn(out, (u64)hyp_phys_to_virt(x), 64);
}

int put_indent(gp_stream_t *out, char **p, u64 arg)
{
	while (arg--)
		TRY_PUT(' ');
	return 0;
}

bool __matches(char *p, const char *kind)
{
	// zip until one runs out
	while (*kind && *p) {
		if (*kind++ != *p++)
			return false;
	}

	// if p ran out, then clearly didn't match.
	if (*kind)
		return false;

	return true;
}

// collect ghost printers from around the places.
extern int gp_put_maplet_target(gp_stream_t *out, struct maplet_target *target);
extern int gp_put_maplet(gp_stream_t *out, struct maplet *maplet);
extern int gp_put_mapping(gp_stream_t *out, mapping *mapp, u64 indent);
extern int gp_put_ek(gp_stream_t *out, enum entry_kind ek);
extern int gp_put_entry(gp_stream_t *out, u64 pte, u8 level);
extern int gp_print_pfn_set(gp_stream_t *out, struct pfn_set *set);
extern int gp_put_abstract_pgtable(gp_stream_t *out, abstract_pgtable *ap, u64 indent);
extern int gp_put_status(gp_stream_t *out, enum ghost_status s);
extern int gp_put_current_context_trace(gp_stream_t *out);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
extern int kvm_nvhe_sym(gp_print_sm_trans)(gp_stream_t *out, struct ghost_simplified_model_transition *trans);
extern int kvm_nvhe_sym(gp_print_sm_pte_state)(gp_stream_t *out, struct sm_pte_state *st);
extern int kvm_nvhe_sym(gp_print_sm_loc)(gp_stream_t *out, struct sm_location *loc);
extern int kvm_nvhe_sym(gp_print_sm_state)(gp_stream_t *out, struct ghost_simplified_model_state *s);
extern int kvm_nvhe_sym(gp_print_sm_locks)(gp_stream_t *out, struct owner_locks *locks);
extern int kvm_nvhe_sym(gp_print_sm_blob_info)(gp_stream_t *out, struct ghost_memory_blob *b);
extern int kvm_nvhe_sym(gp_print_sm_decoded_tlbi)(gp_stream_t *out, struct sm_tlbi_op *tlbi);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

static bool __gp_case(char **p, const char *name)
{
	if (__matches((*p)+1, name)) {
		*p += strlen(name);
		return true;
	} else {
		return false;
	}
}

#define GP_CASE(name) \
	__gp_case(p, "(" name ")")

int put_ghost_obj(gp_stream_t *out, char **p, u64 arg0, u64 arg1)
{
	// %g(KIND)

	if (GP_CASE("maplet")) {
		return gp_put_maplet(out, (struct maplet*) arg0);
	} else if (GP_CASE("maplet_target")) {
		return gp_put_maplet_target(out, (struct maplet_target*)arg0);
	} else if (GP_CASE("mapping")) {
		return gp_put_mapping(out, (mapping*)arg0, arg1);
	} else if (GP_CASE("ek")) {
		return gp_put_ek(out, (enum entry_kind)arg0);
	} else if (GP_CASE("entry")) {
		return gp_put_entry(out, arg0, (u8)arg1);
	} else if (GP_CASE("pfn_set")) {
		return gp_print_pfn_set(out, (struct pfn_set*)arg0);
	} else if (GP_CASE("pgtable")) {
		return gp_put_abstract_pgtable(out, (abstract_pgtable *)arg0, arg1);
	} else if (GP_CASE("status")) {
		return gp_put_status(out, (enum ghost_status)arg0);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
	} else if (GP_CASE("sm_trans")) {
		return kvm_nvhe_sym(gp_print_sm_trans)(out, (struct ghost_simplified_model_transition*)arg0);
	} else if (GP_CASE("sm_pte_state")) {
		return kvm_nvhe_sym(gp_print_sm_pte_state)(out, (struct sm_pte_state*)arg0);
	} else if (GP_CASE("sm_loc")) {
		return kvm_nvhe_sym(gp_print_sm_loc)(out, (struct sm_location*)arg0);
#ifndef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_LOG_ONLY
	} else if (GP_CASE("sm_blob")) {
		return kvm_nvhe_sym(gp_print_sm_blob_info)(out, (struct ghost_memory_blob*)arg0);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_LOG_ONLY */
	} else if (GP_CASE("sm_state")) {
		return kvm_nvhe_sym(gp_print_sm_state)(out, (struct ghost_simplified_model_state*)arg0);
	} else if (GP_CASE("sm_locks")) {
		return kvm_nvhe_sym(gp_print_sm_locks)(out, (struct owner_locks *) arg0);
	} else if (GP_CASE("sm_tlbi")) {
		return kvm_nvhe_sym(gp_print_sm_decoded_tlbi)(out, (struct sm_tlbi_op*)arg0);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */
	} else {
		return -EINVAL;
	}

	return 0;
}


/* Loop + dispatcher for print codes */

/*
 * given a reference to a string like "01234xyz"
 * slice off the leading digits (01234), update the pointer so it points to "xyz..."
 * and return the leading digits as an int.
 *
 * Returns -1 if missing.
 */
int slice_off_width(char **p)
{
	int d = 0;

	while (**p) {
		char c = **p;

		if ('0' <= c && c <= '9') {
			d *= 10;
			d += c - '0';
			++*p;
			continue;
		}

		return d;
	}

	return -1;
}

/*
 * given a reference to a string like "labcdef"
 * slice off the leading mode characters (e.g. "l")
 * update the pointer so it points to the remaining "abcdef..."
 * and return the mode as a bitmap of flags.
 */
enum arg_length slice_off_length(char **p)
{
	if (__matches(*p, "hh")) {
		*p += 2;
		return LENGTH_hh;
	}

	if (__matches(*p, "h")) {
		*p += 1;
		return LENGTH_h;
	}

	if (__matches(*p, "l")) {
		*p += 1;
		return LENGTH_l;
	}

	return LENGTH_none;
}

/*
 * given a string like "01234xyz" return the index of the first non-digit character
 */
int partition_padding(char *p)
{
	int i = 0;

	while (*p) {
		char c = *p++;

		if ('0' <= c && c <= '9') {
			i++;
			continue;
		}

		return i;
	}

	return -1;
}


/*
 * VA_INT_ARG(AP) is like va_arg(ap, int)
 * but substitutes `int` for whatever the `length` specifier says
 */
#define VA_INT_ARG(AP) (len == LENGTH_l ? va_arg(AP, u64) : (u64)va_arg(AP, int))

int ghost_vsprintf(gp_stream_t *out, const char *fmt, va_list ap)
{
	char* p = (char*)fmt;
	while (*p) {
		char c = *p;

		switch (c) {
		case '%': {
			int width;
			enum arg_length len;

			++p;

			// %<width><length><print_code>
			width = slice_off_width(&p);
			len = slice_off_length(&p);

			// get the print_code
			c = *p;

			switch (c) {
			case '%':
				TRY_PUT('%');
				break;
			case '$':
				TRY(gp_put_current_context_trace(out));
				break;
			case 'c':
				TRY(put_char(out, &p, va_arg(ap, int)));
				break;
			case 'b':
				TRY(put_bool(out, &p, va_arg(ap, int)));
				break;
			case 's':
				TRY(put_str(out, &p, width, va_arg(ap, char*)));
				break;
			case 'd':
				TRY(put_decimal(out, &p, width, len, VA_INT_ARG(ap)));
				break;
			case 'x':
				TRY(put_hex(out, &p, width, len, VA_INT_ARG(ap)));
				break;
			case 'p':
				switch (*(p+1)) {
				case 'K':
					++p;
					TRY(put_kern_ptr(out, &p, va_arg(ap, void*)));
					break;
				case 'P':
					++p;
					TRY(put_phys_ptr(out, &p, va_arg(ap, void*)));
					break;
				default:
					TRY(put_raw_ptr(out, &p, va_arg(ap, void*)));
					break;
				}
				break;
			case 'I':
				TRY(put_indent(out, &p, va_arg(ap, u64)));
				break;
			case 'g':
				switch (*(p+1)) {
				case '2':
				case 'I':  /* shorthand for (I)ndent*/
				case 'L':  /* shorthand for (L)evel*/
					++p;
					TRY(put_ghost_obj(out, &p, va_arg(ap, u64), va_arg(ap, u64)));
					break;
				case '(':
					TRY(put_ghost_obj(out, &p, va_arg(ap, u64), 0));
					break;
				default:
					/* unknown modifier */
					return -EINVAL;
				}
				break;
			default:
				/* unknown print code */
				return -EINVAL;
			}
			break;
		}
		default:
			TRY_PUT(c);
			break;
		}

		p++;
	}

	return 0;
}

/* User API */

int ghost_snprintf(char *out, u64 n, const char *fmt, ...)
{
	int ret;
	va_list ap;
	gp_stream_t stream = NEW_STREAM_BUFFERED(out, n);
	va_start(ap, fmt);
	ghost_print_enter();
	ret = ghost_vsprintf(&stream, fmt, ap);
	ghost_print_exit();
	va_end(ap);
	return ret;
}

void ghost_printf(const char *fmt, ...)
{
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ghost_print_enter();
	ret = ghost_vsprintf(STREAM_UART, fmt, ap);
	ghost_print_exit();
	va_end(ap);

	/* instead of returning error codes, really just fail,
	 * as no recovery on printing to UART. */
	if (ret)
		BUG();
}

int ghost_sprintf(gp_stream_t *out, const char *fmt, ...)
{
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ghost_print_enter();
	ret = ghost_vsprintf(out, fmt, ap);
	ghost_print_exit();
	va_end(ap);
	return ret;
}