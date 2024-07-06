#ifndef _NVHE_RING_BUFFER_
#define _NVHE_RING_BUFFER_

#include <linux/types.h>

struct r_buffer;

size_t r_buffer_getsize(struct r_buffer *buf);
size_t r_buffer_getcap(struct r_buffer *buf);
size_t r_buffer_getfill(struct r_buffer *buf);

void rb_init(struct r_buffer *buf, size_t struct_size);

int rb_write(struct r_buffer *dst, void *src, size_t size);
int rb_read(void *dst, struct r_buffer *src, size_t size);

#endif /* _NVHE_RING_BUFFER_ */
