#ifndef __PICOVM_LINUX_CONST_H
#define __PICOVM_LINUX_CONST_H

#ifdef CONFIG_PICOVM_STANDALONE

#ifdef __ASSEMBLY__
#undef UL
#define UL(X) 		(X)
#define ULL(X) 		(X)
#define _AT(T,X)	X
#else
#define UL(X) 		(X ## UL)
#define ULL(X)		(X ## ULL)
#define _AT(T,X)	((T)(X))
#endif

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#else
#include <linux/const.h>
#endif /* CONFIG_PICOVM_STANDALONE */

#endif /* __PICOVM_LINUX_CONST_H */
