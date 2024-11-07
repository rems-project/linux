#ifndef __PICOVM_LINUX_TYPES_H
#define __PICOVM_LINUX_TYPES_H

typedef signed long long s64;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

// NOTE: from linux/types.h
typedef struct {
	s64 counter;
} atomic64_t;

#define U64(x)		(x ## ull)
#define BIT(nr)		(1UL << (nr))
#define NULL ((void *)0)
#define SZ_1G				0x40000000
#define ULONG_MAX (~0UL)

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

typedef u64 phys_addr_t;
typedef u64 size_t;

typedef _Bool bool;
#define true	1
#define false	0

#endif  /* __PICOVM_LINUX_TYPES_H */
