#ifndef __PICOVM_ASM_BUG_H
#define __PICOVM_ASM_BUG_H

#ifdef CONFIG_PICOVM_STANDALONE

// From arch/arm64/include/asm/brk-imm.h
#define BUG_BRK_IMM			"0x800"

#define BUG() do {					\
	asm volatile ("brk	" BUG_BRK_IMM);		\
	__builtin_unreachable();			\
} while (0)

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)

#else
#include <asm/bug.h>
#endif /* CONFIG_PICOVM_STANDALONE */

#endif /* __PICOVM_ASM_BUG_H */
