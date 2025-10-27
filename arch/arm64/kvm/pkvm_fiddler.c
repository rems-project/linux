#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>
#include <asm/kvm_asm.h>

static int hvc2f(const char *name, enum __kvm_host_smccc_func fn, u64 a1, u64 a2, u64 a3, u64 a4, int a_2_3[2]) {
	struct arm_smccc_res res = {};
	printk(KERN_INFO "-> HVC fn(%s %d) 0x%llx 0x%llx 0x%llx 0x%llx", name, fn, a1, a2, a3, a4);
	arm_smccc_1_1_hvc(KVM_HOST_SMCCC_ID(fn), a1, a2, a3, a4, &res);
	printk(KERN_INFO "<- HVC a0 = %d, a1 = %d, a2 = %d, a3 = %d", (int) res.a0, (int) res.a1, (int) res.a2, (int) res.a3);
	if (WARN_ON(res.a0 != SMCCC_RET_SUCCESS))
		return -EINVAL;
	if (a_2_3 != NULL) {
		a_2_3[0] = res.a2;
		a_2_3[1] = res.a3;
	}
	return (int) res.a1;
}

#define hvc2(fn, ...) hvc2f(#fn, __KVM_HOST_SMCCC_FUNC_ ## fn, __VA_ARGS__)

static int hvc_host_share_hyp(void *p, size_t size) {
	// assume p is page aligned
	u64 pfn = ((u64) virt_to_phys(p)) >> PAGE_SHIFT;
	size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	for (int i = 0; i < pages; i++) {
		int ret = hvc2(__pkvm_host_share_hyp, pfn + i, 0, 0, 0, NULL);
		if (WARN_ON(ret < 0))
			return ret;
	}
	return 0;
}

static int topup_hyp_alloc(unsigned long id, size_t nr_pages) {
	struct kvm_hyp_memcache mc = (struct kvm_hyp_memcache) {};
	for (int i = 0; i < nr_pages; i++) {
		phys_addr_t *page = (void *) __get_free_page(GFP_KERNEL);
		*page = mc.head;
		mc.head = virt_to_phys(page);
		mc.nr_pages++;
	}
	return hvc2(__pkvm_hyp_alloc_mgt_refill, id, mc.head, mc.nr_pages, 0, NULL);
}

#define PGD_SIZE (PAGE_SIZE * 8)

static int hvc_host_init_vm(struct kvm *kvm) {
	int ret;
	int a23[2] = {};
	void *pgd = alloc_pages_exact(PGD_SIZE, GFP_KERNEL);
	memset(kvm, 0, sizeof(struct kvm));
	kvm->arch.pkvm.enabled = true;
	kvm->created_vcpus = 2;
	ret = hvc_host_share_hyp(kvm, sizeof(struct kvm));
	if (ret < 0)
		return ret;
	ret = topup_hyp_alloc(HYP_ALLOC_MGT_HEAP_ID, 8);
	if (ret < 0)
		return ret;
	ret = hvc2(__pkvm_init_vm, (u64) kvm, (u64) pgd, 0, 0, a23);
	printk("init_vm -> %d, %d", ret, a23[1]);
	return ret;
}

static int hvc_host_init_vcpu(struct kvm_vcpu *vcpu, int handle, int idx) {
	int ret;
	int a23[2] = {};
	memset(vcpu, 0, sizeof(struct kvm_vcpu));
	vcpu->vcpu_idx = idx;
	ret = hvc_host_share_hyp(vcpu, sizeof(struct kvm_vcpu));
	if (ret < 0)
		return ret;
	ret = hvc2(__pkvm_init_vcpu, handle, (u64) vcpu, 0, 0, a23);
	printk("init_vcpu -> %d, %d", ret, a23[1]);
	return ret;
}

static int fiddle_open(struct inode *inode, struct file *filep)
{
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
	int handle, ret;
	printk(KERN_INFO "OPN ->");
	kvm = alloc_pages_exact(sizeof(struct kvm), GFP_KERNEL);
	ret = handle = hvc_host_init_vm(kvm);
	if (ret < 0) {
		free_pages_exact(kvm, sizeof(struct kvm));
		printk(KERN_WARNING "Cannot init_vm");
		return ret;
	}
	vcpu = alloc_pages_exact(sizeof(struct kvm_vcpu), GFP_KERNEL);
	ret = hvc_host_init_vcpu(vcpu, handle, 0);
	if (ret < 0) {
		free_pages_exact(vcpu, sizeof(struct kvm_vcpu));
		printk(KERN_WARNING "Cannot init_vcpu");
		return ret;
	}
	printk(KERN_INFO "OPN <-");
	return 0;
}

static int fiddle_release (struct inode *inode, struct file *filep)
{
	return 0;
}

static struct file_operations fiddle_fops = {
	.open = fiddle_open,
	.release = fiddle_release,
};

static int __init pkvm_fiddler_init(void)
{
	debugfs_create_file("fiddle", 0200, NULL, NULL, &fiddle_fops);
	printk(KERN_INFO "pKVM fiddler active");
	return 0;
}

static void __exit pkvm_fiddler_exit(void)
{
}

late_initcall(pkvm_fiddler_init);
module_exit(pkvm_fiddler_exit);

MODULE_AUTHOR("REMS Ninjas");
MODULE_DESCRIPTION("Fiddles pKVM");
MODULE_LICENSE("GPL");
