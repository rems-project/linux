#ifndef __PICOVM_LINUX_TYPES_H
#define __PICOVM_LINUX_TYPES_H

typedef signed long long s64;
typedef unsigned long long u64;
// typedef signed int s32;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
// _Static_assert(sizeof(s64) == 8, "sizeof(s64) must be 8 bytes");
// _Static_assert(sizeof(u64) == 8, "sizeof(u64) must be 8 bytes");
// _Static_assert(sizeof(u32) == 4, "sizeof(u32) must be 4 bytes");
// _Static_assert(sizeof(u16) == 2, "sizeof(u16) must be 2 bytes");

// NOTE: from linux/types.h
typedef struct {
	s64 counter;
} atomic64_t;

#define U64(x)		(x ## ull)
#define BIT(nr)		(1UL << (nr))
#define NULL ((void *)0)
#define SZ_1G				0x40000000

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

typedef u64 phys_addr_t;
typedef u64 size_t;

typedef _Bool bool;
#define true	1
#define false	0

#endif  /* __PICOVM_LINUX_TYPES_H */
