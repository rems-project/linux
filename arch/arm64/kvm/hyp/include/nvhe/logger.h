#ifndef _NVHE_LOGGER_
#define _NVHE_LOGGER_

#include <linux/types.h>

int pkvm_logger_is_initialised(void);
int pkvm_logger_buffer_init(u64 pages);
int pkvm_logger_buffer_add_page(u64 pfn);
int pkvm_logger_log(void *src, size_t size);
int pkvm_logger_log_unlocked(void *src, size_t size);

#endif /* _NVHE_LOGGER_ */
