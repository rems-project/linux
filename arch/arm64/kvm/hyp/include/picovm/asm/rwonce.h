/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on include/asm-generic/rwonce.h
 */
#ifndef __PICOVM_ASM_RWONCE_H
#define __PICOVM_ASM_RWONCE_H

#ifndef __ASSEMBLY__


#define compiletime_assert_rwonce_type(t)					\
	_Static_assert(__native_word(t) || sizeof(t) == sizeof(long long),	\
		"Unsupported access size for {READ,WRITE}_ONCE().")

/*
 * Use __READ_ONCE() instead of READ_ONCE() if you do not require any
 * atomicity. Note that this may result in tears!
 */
#ifndef __READ_ONCE
#define __READ_ONCE(x)	(*(const volatile __unqual_scalar_typeof(x) *)&(x))
#endif

#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define READ_ONCE(x) read_once(&x)
#else
#define READ_ONCE(x)							\
({									\
	compiletime_assert_rwonce_type(x);				\
	__READ_ONCE(x);							\
})
#endif

#define __WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)

#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define WRITE_ONCE(x, val) write_once(&x, val)
#else
#define WRITE_ONCE(x, val)						\
do {									\
	compiletime_assert_rwonce_type(x);				\
	__WRITE_ONCE(x, val);						\
} while (0)
#endif

#endif /* __ASSEMBLY__ */
#endif	/* __PICOVM_ASM_RWONCE_H */
