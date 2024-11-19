/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on 
 *	include/linux/compiler.h,
 *	include/linux/compiler_types.h
 *	include/asm/compiler.h
 *	include/asm-generic/rwonce.h
 */

#ifndef __PICOVM_LINUX_COMPILER_H
#define __PICOVM_LINUX_COMPILER_H

#ifndef __ASSEMBLY__

/*
 * Skipped when running bindgen due to a libclang issue;
 * see https://github.com/rust-lang/rust-bindgen/issues/2244.
 */
#if defined(CONFIG_DEBUG_INFO_BTF) && defined(CONFIG_PAHOLE_HAS_BTF_TAG) && \
	__has_attribute(btf_type_tag) && !defined(__BINDGEN__)
# define BTF_TYPE_TAG(value) __attribute__((btf_type_tag(#value)))
#else
# define BTF_TYPE_TAG(value) /* nothing */
#endif

/* sparse defines __CHECKER__; see Documentation/dev-tools/sparse.rst */
#ifdef __CHECKER__
/* address spaces */
# define __kernel	__attribute__((address_space(0)))
# define __percpu	__attribute__((noderef, address_space(__percpu)))
#else /* __CHECKER__ */
/* address spaces */
# define __kernel
# define __percpu	BTF_TYPE_TAG(percpu)
#endif /* __CHECKER__ */

#ifndef RELOC_HIDE
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })
#endif

#ifdef ARM64_ASM_ARCH
#define ARM64_ASM_PREAMBLE ".arch " ARM64_ASM_ARCH "\n"
#else
#define ARM64_ASM_PREAMBLE
#endif

/*
 * Yes, this permits 64-bit accesses on 32-bit architectures. These will
 * actually be atomic in some cases (namely Armv7 + LPAE), but for others we
 * rely on the access being split into 2x32-bit accesses for a 32-bit quantity
 * (e.g. a virtual address) and a strong prevailing wind.
 */
#define compiletime_assert_rwonce_type(t)					\
	compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),	\
		"Unsupported access size for {READ,WRITE}_ONCE().")

/*
 * Use __READ_ONCE() instead of READ_ONCE() if you do not require any
 * atomicity. Note that this may result in tears!
 */
#ifndef __READ_ONCE
#define __READ_ONCE(x)	(*(const volatile __unqual_scalar_typeof(x) *)&(x))
#endif

#define READ_ONCE(x)							\
({									\
	compiletime_assert_rwonce_type(x);				\
	__READ_ONCE(x);							\
})

#define __WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)

#define WRITE_ONCE(x, val)						\
do {									\
	compiletime_assert_rwonce_type(x);				\
	__WRITE_ONCE(x, val);						\
} while (0)

#define __stringify_label(n) #n

#define __annotate_unreachable(c) ({					\
	asm volatile(__stringify_label(c) ":\n\t"			\
		     ".pushsection .discard.unreachable\n\t"		\
		     ".long " __stringify_label(c) "b - .\n\t"		\
		     ".popsection\n\t" : : "i" (c));			\
})
#define annotate_unreachable() __annotate_unreachable(__COUNTER__)

/* Annotate a C jump table to allow objtool to follow the code flow */
#define __annotate_jump_table __section(".rodata..c_jump_table")

#else /* !CONFIG_OBJTOOL */
#define annotate_unreachable()
#define __annotate_jump_table
#endif /* CONFIG_OBJTOOL */

#ifndef unreachable
# define unreachable() do {		\
	annotate_unreachable();		\
	__builtin_unreachable();	\
} while (0)

#define BUG() do {					\
	unreachable();					\
} while (0)


#endif /* __ASSEMBLY__ */

#endif /* __PICOVM_LINUX_COMPILER_H */
