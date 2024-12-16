#ifndef __PICOVM_LINUX_TYPES_H
#define __PICOVM_LINUX_TYPES_H

#ifdef CONFIG_PICOVM_STANDALONE

#undef NULL
#define NULL ((void *)0)

enum {
	false	= 0,
	true	= 1
};
typedef _Bool bool;

typedef unsigned char 		u8;
typedef unsigned short 		u16;
typedef unsigned int 		u32;
typedef unsigned long long 	u64;

// typedef signed short		s16;
typedef signed int		s32;
typedef signed long long	s64;

typedef unsigned long 		size_t;
typedef u64 			phys_addr_t;

typedef struct {
	s64 counter;
} atomic64_t;


#else
#include <linux/types.h>
#endif /* CONFIG_PICOVM_STANDALONE */

#endif /* __PICOVM_LINUX_TYPES_H */
