#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <hyp/include/nvhe/ringbuffer.h>

#define PAGES (1 << CONFIG_NVHE_LOGGER_PAGES_ORDER)

static struct ctrl {
	struct r_buffer *buf;
	struct mutex mx;
} ctrl = {};

static int log_open(struct inode *inode, struct file *filep)
{
	return nonseekable_open(inode, filep);
}

static ssize_t log_read(struct file *filep, char __user *dst, size_t size, loff_t *off)
{
	size_t ret;
	mutex_lock(&ctrl.mx);
	// Since the EL2 cannot notify of new data, we essentially busy-loop,
	// but relinquishing the lock and allowing rescheduling.
	// XXX Not sure what is the proper way.
	while ((ret = rb_read(dst, ctrl.buf, size)) == 0) {
		mutex_unlock(&ctrl.mx);
		schedule();
		/* cond_resched(); */
		/* usleep_range(50, 50); */
		/* usleep_range(10000, 20000); */
		mutex_lock(&ctrl.mx);
	}
	mutex_unlock(&ctrl.mx);
	*off += ret;
	return ret;
}

static struct file_operations log_fops = {
	.open = log_open,
	.read = log_read,
};

static int __init nvhe_logger_init(void)
{
	int ret;

	mutex_init(&ctrl.mx);

	ctrl.buf = (void *) vmalloc(PAGES * PAGE_SIZE);
	if (ctrl.buf == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	ret = kvm_call_hyp_nvhe(__pkvm_logger_buffer_init, PAGES);
	if (ret)
		goto error;

	for (size_t i = 0; i < PAGES; ++i) {
		ret = kvm_call_hyp_nvhe(__pkvm_logger_buffer_add_page, vmalloc_to_pfn( ((void *) ctrl.buf) + i * PAGE_SIZE));
		if (ret)
			goto error;
	}

	debugfs_create_file("nvhe.log", 0400, NULL, NULL, &log_fops);

	printk(KERN_INFO "NVHE logger: initialised with %d pages", PAGES);
	return 0;

error:
	printk(KERN_ERR "NVHE logger: error initialising: %d", -ret);
	return ret;
}

device_initcall(nvhe_logger_init);
