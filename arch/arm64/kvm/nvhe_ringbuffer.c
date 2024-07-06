#include <linux/string.h>
#include <linux/minmax.h>
#include "hyp/include/nvhe/ringbuffer.h"

/* Writer progresses, reader follows.
 *
 * Invariant:
 * writer never catches up with the reader, but reader can catch up with the
 * writer.
 *   `reader` == `writer`                   →  empty
 *   `writer` == `reader` - 1 (mod `size`)  →  full
 * Thus, the available size is `size` - 1.
 *
 * Concurrency:
 * readers lock `reader`, writers lock `writer`.
 */
struct r_buffer {
	volatile size_t reader;
	volatile size_t writer;
	size_t size;
	char buffer[];
};

size_t r_buffer_getsize(struct r_buffer *buf)
{
	return buf->size;
}

/* The "write" distance — circular distance from writer to reader. 
 */
static inline size_t __w_distance(struct r_buffer *buf)
{
	size_t reader = buf->reader,
	       writer = buf->writer;
	size_t d = reader - writer;
	if(reader <= writer)
		d += buf->size;
	return d;
}

size_t r_buffer_getcap(struct r_buffer *buf)
{
	return __w_distance(buf) - 1;
}

size_t r_buffer_getfill(struct r_buffer *buf)
{
	return buf->size - __w_distance(buf);
}

/* Condition: sizeof(struct buffer) + 1 <= struct_size */
void rb_init(struct r_buffer *buf, size_t struct_size)
{
	*buf = (struct r_buffer) {
		.reader = 0,
		.writer = 0,
		.size = struct_size - sizeof(struct r_buffer),
	};
}

int rb_write(struct r_buffer *dst, void *src, size_t size)
{
	size_t writer = dst->writer;
	size_t to_edge = dst->size - writer;
	size = min(size, r_buffer_getcap(dst));
	if (size < to_edge) {
		memcpy(dst->buffer + writer, src, size);
		dst->writer = writer + size;
	} else {
		memcpy(dst->buffer + writer, src, to_edge);
		memcpy(dst->buffer, src + to_edge, size - to_edge);
		dst->writer = size - to_edge;
	}
	return size;
}

int rb_read(void *dst, struct r_buffer *src, size_t size)
{
	size_t reader = src->reader;
	size_t to_edge = src->size - reader;
	size = min(size, r_buffer_getfill(src));
	if (size < to_edge) {
		memcpy(dst, src->buffer + reader, size);
		src->reader = reader + size;
	} else {
		memcpy(dst, src->buffer + reader, to_edge);
		memcpy(dst + to_edge, src->buffer, size - to_edge);
		src->reader = size - to_edge;
	}
	return size;
}
