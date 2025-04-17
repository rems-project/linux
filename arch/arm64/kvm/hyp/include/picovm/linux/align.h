/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PICOVM_LINUX_ALIGN_H
#define __PICOVM_LINUX_ALIGN_H

#ifdef CONFIG_PICOVM_STANDALONE

#include <picovm/linux/const.h>

// From include/uapi/linux/const.h
#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define __ALIGN_KERNEL(x, a)        __ALIGN_KERNEL_MASK(x, (u64)(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)    (((x) + (mask)) & ~(mask))
#else
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#endif

// From include/linux/align.h
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#ifdef CONFIG_PICOVM_CLIGHTPLUS
#define IS_ALIGNED(x, a)	(((x) & ((u64)(a) - 1)) == 0)
#else
#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
#endif
#else
#include <linux/align.h>
#endif /* CONFIG_PICOVM_STANDALONE */

#endif /* __PICOVM_LINUX_ALIGN_H */
