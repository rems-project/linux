#include <linux/debugfs.h>
#include <linux/namei.h>
#include <linux/kvm_host.h>
#include <hyp/include/nvhe/gcov.h>


#define EL2_SHARED_BUF_PAGES 4 /* "512 KB should be enough for everybody." */

/* Formatting
 *
 * Half nicked from gcov/fs.h - but those are not exported, and these use
 * slightly different GCOV structures.
 */

#define GCOV_DATA_MAGIC		((unsigned int) 0x67636461)
#define GCOV_TAG_FUNCTION	((unsigned int) 0x01000000)
#define GCOV_TAG_COUNTER_BASE	((unsigned int) 0x01a10000)

static size_t store_gcov_u32(void *buffer, size_t off, u32 v)
{
	u32 *data;

	if (buffer) {
		data = buffer + off;
		*data = v;
	}

	return sizeof(*data);
}

static size_t store_gcov_u64(void *buffer, size_t off, u64 v)
{
	u32 *data;

	if (buffer) {
		data = buffer + off;
		data[0] = (v & 0xffffffffUL);
		data[1] = (v >> 32);
	}

	return sizeof(*data) * 2;
}

static size_t convert_to_gcda(char *buffer, struct pkvm_gcov_info *info)
{
	struct pkvm_gcov_fn_info *f;
	size_t pos = 0;

	/* File header. */
	pos += store_gcov_u32(buffer, pos, GCOV_DATA_MAGIC);
	pos += store_gcov_u32(buffer, pos, info->version);
	pos += store_gcov_u32(buffer, pos, info->checksum);

	for (int fi = 0; fi < info->n_functions; ++fi) {
		f = &info->functions[fi];

		pos += store_gcov_u32(buffer, pos, GCOV_TAG_FUNCTION);
		pos += store_gcov_u32(buffer, pos, 3);
		pos += store_gcov_u32(buffer, pos, f->ident);
		pos += store_gcov_u32(buffer, pos, f->checksum);
		pos += store_gcov_u32(buffer, pos, f->cfg_checksum);
		pos += store_gcov_u32(buffer, pos, GCOV_TAG_COUNTER_BASE);
		pos += store_gcov_u32(buffer, pos, f->num_counters * 2);
		for (int i = 0; i < f->num_counters; i++)
			pos += store_gcov_u64(buffer, pos, f->counters[i]);
	}

	return pos;
}

/* ... */


static int init_pkvm_buffer(void *buf, size_t buf_n_pages) {
	int ret;
	if (!is_protected_kvm_enabled())
		return -ENOSYS;
	if (!IS_ALIGNED((u64)buf, PAGE_SIZE))
		return -EINVAL;
	if (WARN_ON(!is_vmalloc_addr(buf)))
		return -EINVAL;
	ret = kvm_call_hyp_nvhe(__pkvm_gcov_buffer_init, buf_n_pages);
	if (ret)
		return ret;
	for (size_t i = 0; i < buf_n_pages; ++i) {
		ret = kvm_call_hyp_nvhe(__pkvm_gcov_buffer_add_page, vmalloc_to_pfn(buf + i * PAGE_SIZE));
		if (ret)
			return ret;
	}
	return 0;
}

static struct ctrl {
	union {
		struct pkvm_gcov_info *info;
		void *buffer;
	} shared;
	struct mutex mx;
} ctrl = {};

static void unpack_gcov_info(struct pkvm_gcov_info *info)
{
	info->filename = rel_unpack_ptr(info, info->filename);
	for (int i = 0; i < info->n_functions; ++i)
		info->functions[i].counters = rel_unpack_ptr(info, info->functions[i].counters);
}

struct export_data {
	int index;    /* module index */
	size_t size;  /* GCDA size. */
};

struct export_file_data {
	size_t size;
	char buf[];
};

static int export_open(struct inode *inode, struct file *filep)
{
	struct export_data *data = inode->i_private;
	struct export_file_data *fdata;
	int ret = 0;

	mutex_lock(&ctrl.mx);

	ret = kvm_call_hyp_nvhe(__pkvm_gcov_export_module, data->index);
	if (ret)
		goto exit;
	unpack_gcov_info(ctrl.shared.info);

	/* Reuse the first computed GCDA size assuming it cannot change. */
	fdata = kzalloc(struct_size(fdata, buf, data->size), GFP_KERNEL);
	if (!fdata) {
		ret = -ENOMEM;
		goto exit;
	}
	fdata->size = data->size;
	convert_to_gcda(fdata->buf, ctrl.shared.info);
	filep->private_data = fdata;
	ret = generic_file_open(inode, filep);

exit:
	mutex_unlock(&ctrl.mx);
	return ret;
}

static int export_release (struct inode *inode, struct file *filep)
{
	kfree(filep->private_data);
	return 0;
}

static ssize_t export_read(struct file *filep, char __user *dst, size_t size, loff_t *off)
{
	int res;
	struct export_file_data *fdata = filep->private_data;
	if (*off >= fdata->size)
		return 0;
	size = min(size, (size_t) (fdata->size - *off));
	res = copy_to_user(dst, fdata->buf + *off, size);
	if (res)
		return res;
	*off += size;
	return size;
}

static struct file_operations export_fops = {
	.open = export_open,
	.read = export_read,
	.release = export_release,
};

static char *edit_suffix(const char *name, const char *suff, const char *newsuff)
{
	size_t len = strlen(name), s_len = strlen(suff), n_s_len = strlen(newsuff);
	char *res;
	if (len < s_len || strcmp(name + len - s_len, suff) != 0)
		return ERR_PTR(-EINVAL);
	res = kzalloc(len - s_len + n_s_len + 1, GFP_KERNEL);
	if (!res)
		return ERR_PTR(-ENOMEM);
	memcpy(res, name, len - s_len);
	memcpy(res + len - s_len, newsuff, n_s_len);
	return res;
}

static int create_related_symlink(const char *name, struct dentry *parent, const char *target, const char *ext, const char *newext)
{
	char *new_name, *new_target;
	new_name = edit_suffix(name, ext, newext);
	if (IS_ERR(new_name))
		return PTR_ERR(new_name);
	new_target = edit_suffix(target, ext, newext);
	if (IS_ERR(new_target)) {
		kfree(new_name);
		return PTR_ERR(new_target);
	}
	debugfs_create_symlink(new_name, parent, new_target);
	kfree(new_target);
	kfree(new_name);
	return 0;
}

#define PNEXT(p) (strchr(p, '/'))

static int create_node(struct dentry *parent, const char *name, int index, size_t size)
{

	int ret = 0;
	struct export_data *data;
	char *segment, *scratch = kstrdup(name, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	segment = scratch;
	for (char *next = PNEXT(scratch); next; segment = next, next = PNEXT(next)) {
		struct dentry *dentry;
		*(next++) = 0;
		if (strcmp(segment, "") == 0 || strcmp(segment, ".") == 0)
			continue;
		if (strcmp(segment, "..") == 0) {
			parent = parent->d_parent;
			continue;
		}
		dentry = lookup_one_len_unlocked(segment, parent, strlen(segment));
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
		if (d_really_is_negative(dentry))
			dentry = debugfs_create_dir(segment, parent);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
		parent = dentry;
	}

	data = kmalloc(sizeof(struct export_data), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto exit;
	}
	*data = (struct export_data) { .index = index, .size = size, };
	debugfs_create_file_size(segment, 0600, parent, data, &export_fops, size);

	create_related_symlink(segment, parent, name, ".gcda", ".gcno");
	create_related_symlink(segment, parent, name, ".nvhe.gcda", ".c");

exit:
	kfree(scratch);
	return ret;
}

static int create_export_files(struct dentry *parent)
{
	int index = 0;
	while (!(kvm_call_hyp_nvhe(__pkvm_gcov_export_module, index))) {
		unpack_gcov_info(ctrl.shared.info);
		create_node(parent, ctrl.shared.info->filename, index++, convert_to_gcda(NULL, ctrl.shared.info));
	}
	return index;
}

static ssize_t reset_write(struct file *filep, const char __user *src, size_t size, loff_t *off)
{
	int ret = kvm_call_hyp_nvhe(__pkvm_gcov_reset);
	if (ret)
		return ret;
	return size;
}

static struct file_operations reset_fops = {
	.open = nonseekable_open,
	.write = reset_write,
};

static int __init gcov_init(void)
{
	int ret;
	struct dentry *root = debugfs_create_dir("gcov_nvhe", NULL);

	mutex_init(&ctrl.mx);
	ctrl.shared.buffer = vmalloc(EL2_SHARED_BUF_PAGES * PAGE_SIZE);
	if (ctrl.shared.buffer == NULL)
		return -ENOMEM;
	ret = init_pkvm_buffer(ctrl.shared.buffer, EL2_SHARED_BUF_PAGES);
	if (ret)
		return ret;

        ret = create_export_files(root);
	debugfs_create_file("reset", 0200, root, NULL, &reset_fops);

	printk("NVHE GCOV: profiling %d modules, sharing %d pages\n", ret, EL2_SHARED_BUF_PAGES);
	return 0;
}

/* Must be ordered after __pkvm_prot_finalize, otherwise the Ghost breaks. */
late_initcall(gcov_init);
