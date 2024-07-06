#include <nvhe/pkvm.h>
#include <nvhe/mm.h>
#include <nvhe/mem_protect.h>
#include <nvhe/ringbuffer.h>
#include <nvhe/logger.h>

struct ctrl {
	struct r_buffer *buf;
	hyp_spinlock_t lock;
	size_t pages;
	size_t pending_pages;
};

static struct ctrl ctrl;

int pkvm_logger_is_initialised(void)
{
	return ctrl.buf && !ctrl.pending_pages;
}

int pkvm_logger_log_unlocked(void *src, size_t size)
{
	if (!pkvm_logger_is_initialised())
		return -EINVAL;
	return rb_write(ctrl.buf, src, size);
}

int pkvm_logger_log(void *src, size_t size)
{
	int res;
	if (!pkvm_logger_is_initialised())
		return -EINVAL;
	hyp_spin_lock(&ctrl.lock);
	res = rb_write(ctrl.buf, src, size);
	hyp_spin_unlock(&ctrl.lock);
	return res;
}

int pkvm_logger_buffer_init(u64 pages)
{
	int ret = 0;
	unsigned long vaddr;
	if (ctrl.buf || pages == 0)
		return -EINVAL;

	ret = pkvm_alloc_private_va_range(pages * PAGE_SIZE, &vaddr);
	if (ret)
		return ret;

	ctrl = (struct ctrl) {
		.buf = (void *) vaddr,
		.pages = 0,
		.pending_pages = pages,
	};

	hyp_spin_lock_init(&ctrl.lock);
	return 0;
}

int pkvm_logger_buffer_add_page(u64 pfn)
{
	int ret = 0;
	void *vaddr0 = (void *) __hyp_va(hyp_pfn_to_phys(pfn));
	void *vaddr = (void *) ctrl.buf + ctrl.pages * PAGE_SIZE;

	if (ctrl.pending_pages == 0)
		return -EINVAL;

	ret = __pkvm_host_share_hyp(pfn);
	if (ret)
		return ret;

	ret = hyp_pin_shared_mem(vaddr0, vaddr0 + PAGE_SIZE);
	if (ret)
		return ret;

	ret = kvm_pgtable_hyp_map(&pkvm_pgtable, (u64) vaddr, PAGE_SIZE, hyp_pfn_to_phys(pfn), PAGE_HYP);
	if (ret)
		return ret;

	++ctrl.pages;
	--ctrl.pending_pages;
	if (ctrl.pending_pages == 0)
		rb_init(ctrl.buf, ctrl.pages * PAGE_SIZE);

	return 0;
}
