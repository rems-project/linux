/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on include/linux/compiler.h
 */
#ifndef __PICOVM_LINUX_COMPILER_H
#define __PICOVM_LINUX_COMPILER_H

#ifndef __ASSEMBLY__

#ifndef RELOC_HIDE
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })
#endif

#endif /* __ASSEMBLY__ */

#endif /* __PICOVM_LINUX_COMPILER_H */
