// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/arm-smccc.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/kmsan-checks.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/anon_inodes.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kcov.h>
#include <linux/refcount.h>
#include <linux/log2.h>
#include <linux/uaccess.h>
#include <asm/setup.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_host.h>
#include <asm/kvm_pgtable.h>
#include <asm/pkvm_proxy.h>
#include <hyp_constants.h>

enum hprox_alloc_state {
	OWNED, // to be realeased on file closure
	RELEASED, // not owned by the kernel anymore
	FREED // freed back to kernel allocator
};

struct pkvm_proxy_alloc {
	enum hprox_alloc_type type;
	enum hprox_alloc_state state;
	uint size; // in bytes
	void* kaddr;
};

static void pkvm_proxy_alloc_free(struct pkvm_proxy_alloc *alloc)
{
	switch (alloc->type) {
	case HPROX_VMALLOC:
		vfree(alloc->kaddr);
		break;
	case HPROX_PAGES_EXACT:
		free_pages_exact(alloc->kaddr, alloc->size);
		break;
	}
}

static long pkvm_proxy_alloc_fd_ioctl(struct file *filep, unsigned int cmd,
				      unsigned long uarg)
{
	struct pkvm_proxy_alloc *alloc = filep->private_data;
	void** res;
	phys_addr_t phys;
	BUG_ON(!alloc);
	switch (cmd) {
	case HPROX_ALLOC_KADDR:
		res = (void **)uarg;
		if (copy_to_user(res, &alloc->kaddr, sizeof(void *)))
			return -EFAULT;
		return 0;
	case HPROX_ALLOC_PHYS:
		res = (void **)uarg;
		if (alloc->type != HPROX_PAGES_EXACT)
			return -ENOTSUPP;
		phys = virt_to_phys(alloc->kaddr);
		if (copy_to_user(res, &phys, sizeof(void *)))
			return -EFAULT;
		return 0;
	case HPROX_ALLOC_RELEASE:
		if (alloc->state != OWNED)
			return -EINVAL;
		alloc->state = RELEASED;
		return 0;
	case HPROX_ALLOC_FREE:
		if (alloc->state == FREED)
			return -EINVAL;
		pkvm_proxy_alloc_free(alloc);
		alloc->state = FREED;
		return 0;
	default:
		return -ENOSYS;
	}
}

static int pkvm_proxy_alloc_release(struct inode *inode, struct file *filep)
{
	struct pkvm_proxy_alloc *alloc = filep->private_data;
	if(!alloc) return -EBADFD;
	if (alloc->state == OWNED)
		pkvm_proxy_alloc_free(alloc);
	kfree(alloc);
	return 0;
}

static struct page* virt_to_page_fn(const void * addr)
{
	return virt_to_page(addr) ;
}

static int pkvm_proxy_alloc_mmap(struct file *filep,
				 struct vm_area_struct *vma)
{
	int res;
	struct pkvm_proxy_alloc *alloc = filep->private_data;
	unsigned long off;
	struct page *page;
	struct page* (*vtop) (const void*);

	if (vma->vm_pgoff != 0 || vma->vm_end - vma->vm_start != PAGE_ALIGN(alloc->size))
		return -EINVAL;
	BUG_ON(!alloc->kaddr);

	switch (alloc->type) {
	case HPROX_VMALLOC:
		vtop = vmalloc_to_page;
		break;
	case HPROX_PAGES_EXACT:
		vtop = virt_to_page_fn;
		break;
	}

	vm_flags_set(vma, VM_DONTEXPAND);

	for (off = 0; off < alloc->size; off += PAGE_SIZE) {
		page = vtop(alloc->kaddr + off);
		res = vm_insert_page(vma, vma->vm_start + off, page);
		if (res)
			return res;
	}
	return 0;

}

static int pkvm_proxy_open(struct inode *inode, struct file *filep)
{
	return nonseekable_open(inode, filep);
}

static const struct file_operations pkvm_proxy_alloc_fops = {
	.release = pkvm_proxy_alloc_release,
	.unlocked_ioctl = pkvm_proxy_alloc_fd_ioctl,
	.compat_ioctl = pkvm_proxy_alloc_fd_ioctl,
	.mmap = pkvm_proxy_alloc_mmap,
};

static long pkvm_proxy_alloc_ioctl(struct file *filep, unsigned int cmd,
					unsigned long uarg)
{
	int ret;
	struct pkvm_proxy_alloc *alloc;
	int fd;
	struct file *file;

	alloc = kmalloc(sizeof(struct pkvm_proxy_alloc), GFP_KERNEL);
	if(!alloc)
		return -ENOMEM;
	alloc->type = _IOC_NR(cmd);
	alloc->state = OWNED;
	alloc->size = uarg;

	if (alloc->type > HPROX_PAGES_EXACT) {
		ret = -EINVAL;
		goto alloc_struct_free;
	}
	switch(alloc->type){
	case HPROX_VMALLOC:
		alloc->kaddr = vmalloc_user(alloc->size);
		break;
	case HPROX_PAGES_EXACT:
		alloc->kaddr = alloc_pages_exact(alloc->size, GFP_KERNEL);
		break;
	}
	if (!alloc->kaddr) {
		ret = -ENOMEM;
		goto alloc_struct_free;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto main_free;
	}

	file = anon_inode_getfile("hprox-alloc", &pkvm_proxy_alloc_fops,
				  alloc, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto put_fd;
	}
	BUG_ON(file->private_data != alloc);
	fd_install(fd, file);
	return fd;

put_fd:
	put_unused_fd(fd);
main_free:
	pkvm_proxy_alloc_free(alloc);
alloc_struct_free:
	kfree(alloc);
	return ret;
}

static long pkvm_proxy_structs_ioctl(struct file *filep, unsigned int cmd,
					unsigned long uarg)
{
	u32 kvm_ipa_limit = get_kvm_ipa_limit();
	u64 mmfr0, mmfr1, vtcr;
	switch(cmd){
	case HPROX_STRUCT_KVM_GET_SIZE:
		return sizeof(struct kvm);
	case HPROX_STRUCT_KVM_GET_OFFSET:
		switch(uarg) {
		case HPROX_NR_MEM_SLOT_PAGES:
			return offsetof(struct kvm, nr_memslot_pages);
		case HPROX_VCPU_ARRAY:
			return offsetof(struct kvm, vcpu_array);
		case HPROX_MAX_VCPUS:
			return offsetof(struct kvm, max_vcpus);
		case HPROX_CREATED_VCPUS:
			return offsetof(struct kvm, created_vcpus);
		case HPROX_ARCH_PKVM_ENABLED:
			return offsetof(struct kvm, arch) +
				offsetof(struct kvm_arch, pkvm) +
				offsetof(struct kvm_protected_vm, enabled);
		case HPROX_ARCH_PKVM_TEARDOWN_MC:
			return offsetof(struct kvm, arch) +
				offsetof(struct kvm_arch, pkvm) +
				offsetof(struct kvm_protected_vm, teardown_mc);
		default:
			return -EINVAL;
		}
	case HPROX_HYP_VM_GET_SIZE:
		return PKVM_HYP_VM_SIZE;
	case HPROX_PGD_GET_SIZE:
		mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
		mmfr1 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR1_EL1);
		vtcr = kvm_get_vtcr(mmfr0, mmfr1, kvm_ipa_limit);
		return kvm_pgtable_stage2_pgd_size(vtcr);
	case HPROX_STRUCT_KVM_VCPU_GET_SIZE:
		return sizeof(struct kvm_vcpu);
	case HPROX_STRUCT_KVM_VCPU_GET_OFFSET:
		switch (uarg) {
		case HPROX_VCPU_ID:
			return offsetof(struct kvm_vcpu, vcpu_id);
		case HPROX_VCPU_IDX:
			return offsetof(struct kvm_vcpu, vcpu_idx);
		case HPROX_VCPU_CFLAGS:
			return offsetof(struct kvm_vcpu, arch.cflags);
		case HPROX_VCPU_IFLAGS:
			return offsetof(struct kvm_vcpu, arch.iflags);
		case HPROX_VCPU_FEATURES:
			return offsetof(struct kvm_vcpu, arch.features);
		case HPROX_VCPU_HCR_EL2:
			return offsetof(struct kvm_vcpu, arch.hcr_el2);
		case HPROX_VCPU_FAULT:
			return offsetof(struct kvm_vcpu, arch.fault);
		case HPROX_VCPU_REGS:
			return offsetof(struct kvm_vcpu, arch.ctxt.regs);
		case HPROX_VCPU_FP_REGS:
			return offsetof(struct kvm_vcpu, arch.ctxt.fp_regs);
		case HPROX_VCPU_MEMCACHE:
			return offsetof(struct kvm_vcpu, arch.pkvm_memcache);
		default:
			return -EINVAL;
		}

	case HPROX_HYP_VCPU_GET_SIZE:
		return PKVM_HYP_VCPU_SIZE;
	default:
		return -ENOSYS;
	}
}

static long pkvm_proxy_memcache_ioctl(struct file *filep, unsigned int cmd,
					unsigned long uarg)
{
	struct kvm_hyp_memcache* __user user_mc =
		(struct kvm_hyp_memcache* __user) uarg;
	struct kvm_hyp_memcache mc;
	uint minpages = _IOC_NR(cmd);

	if (copy_from_user(&mc, user_mc, sizeof(struct kvm_hyp_memcache)))
		return -EFAULT;

	if (minpages)
		topup_hyp_memcache(&mc, minpages);
	else
		free_hyp_memcache(&mc);

	if (copy_to_user(user_mc, &mc, sizeof(struct kvm_hyp_memcache)))
		return -EFAULT;

	return 0;
}

static long pkvm_proxy_hvc_ioctl(struct file *filep, unsigned int cmd,
				 unsigned long uarg)
{
	uint args_size;
	u64 args[7] = {};
	int id;
	struct arm_smccc_res res;
	id = _IOC_NR(cmd);
	args_size = ALIGN(_IOC_SIZE(cmd), sizeof(u64));
	if (args_size > 7 * sizeof(u64))
		return -EINVAL;
	if (args_size && copy_from_user(args, (void __user *)uarg, args_size))
		return -EACCES;
	arm_smccc_1_1_hvc(KVM_HOST_SMCCC_ID(id), args[0], args[1], args[2],
			  args[3], args[4], args[5], args[6], &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return -EINVAL;
	return res.a1;
}

static long pkvm_proxy_ioctl(struct file *filep, unsigned int cmd,
			     unsigned long uarg)
{
	switch (_IOC_TYPE(cmd)) {
	case HPROX_HVC_TYPE:
		return pkvm_proxy_hvc_ioctl(filep, cmd, uarg);
	case HPROX_STRUCTS_TYPE:
		return pkvm_proxy_structs_ioctl(filep, cmd, uarg);
	case HPROX_ALLOC_TYPE:
		return pkvm_proxy_alloc_ioctl(filep, cmd, uarg);
	case HPROX_MEMCACHE_TYPE:
		return pkvm_proxy_memcache_ioctl(filep, cmd, uarg);
	default:
		return -ENOSYS;
	}
}

static int pkvm_proxy_close(struct inode *inode, struct file *filep)
{
	return 0;
}

static const struct file_operations pkvm_proxy_fops = {
	.open = pkvm_proxy_open,
	.unlocked_ioctl = pkvm_proxy_ioctl,
	.compat_ioctl = pkvm_proxy_ioctl,
	/* .mmap = pkvm_proxy_mmap, */
	.release = pkvm_proxy_close,
};

static int __init pkvm_proxy_init(void)
{
	/*
	 * The pkvm_proxy debugfs file won't ever get removed and thus,
	 * there is no need to protect it against removal races. The
	 * use of debugfs_create_file_unsafe() is actually safe here.
	 */
	debugfs_create_file_unsafe("pkvm_proxy", 0600, NULL, NULL, &pkvm_proxy_fops);

	return 0;
}

device_initcall(pkvm_proxy_init);
