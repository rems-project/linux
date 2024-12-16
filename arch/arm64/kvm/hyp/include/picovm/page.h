#ifndef __PICOVM_PAGE_H
#define __PICOVM_PAGE_H

#include <picovm/linux/const.h>
#include <picovm/linux/align.h>

#define PAGE_SHIFT		CONFIG_ARM64_PAGE_SHIFT
#define PAGE_SIZE		(UL(1) << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))

#define PAGE_ALIGN(addr)	ALIGN(addr, PAGE_SIZE)

#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

#endif /* __PICOVM_PAGE_H */
