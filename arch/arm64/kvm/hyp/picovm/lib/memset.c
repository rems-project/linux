#include <picovm/linux/types.h>

void *__pi_memset(void *dst, int value, size_t size)
{
	unsigned char *ptr = dst;
	unsigned char val = (unsigned char)value;

	for (size_t i = 0; i < size; i++) {
		ptr[i] = val;
	}

	return dst;
}

void *memset(void*, int, size_t) __attribute__((alias ("__pi_memset")));
