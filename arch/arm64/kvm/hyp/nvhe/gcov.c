#include <nvhe/pkvm.h>
#include <nvhe/mm.h>
#include <nvhe/mem_protect.h>
#include <nvhe/gcov.h>


#define MAX_GCOV_MODULES 50

/* The story:
 *
 * Clang with "GCOV" (-fprofile-arcs -ftest-coverage) emits coverage
 * instrumentation. Its inner workings are private.
 *
 * It also emits one __llvm_gcov_init function per compilation unit, and marks
 * them as initialisers (.init_array section). We must arrange to call these
 * fairly early. Each of these, in turn, calls llvm_gcov_init, below, with
 * arguments specific to that module. The arguments are two function callbacks,
 * which are again specific to the compilation unit. The first (writeout), makes
 * a sequence of calls to the llvm_gcda_XXX functions, below, supplying the data
 * collected by the instrumentation.
 *
 * On init, we store the callbacks and let them be driven by hypercalls, writing
 * data into a buffer that was shared beforehand.
 */

typedef void (*llvm_gcov_callback)(void);

static struct modules {
	u32 n;
	struct gcov_cbs {
		llvm_gcov_callback writeout;
		llvm_gcov_callback reset;
	} cbs[MAX_GCOV_MODULES];
} modules;

static struct pkvm_gcov_info *curr;

void llvm_gcov_init(llvm_gcov_callback writeout, llvm_gcov_callback reset)
{
	BUG_ON(modules.n >= MAX_GCOV_MODULES);

	modules.cbs[modules.n++] = (struct gcov_cbs) {
		.writeout = writeout,
		.reset = reset,
	};
}

void llvm_gcda_start_file(const char *orig_filename, u32 version, u32 checksum)
{
	*curr = (struct pkvm_gcov_info) {
		.filename = orig_filename,
		.version = version,
		.checksum = checksum,
	};
}

void llvm_gcda_emit_function(u32 ident, u32 func_checksum, u32 cfg_checksum)
{
	curr->n_functions++;
	curr->functions[curr->n_functions - 1] = (struct pkvm_gcov_fn_info) {
		.ident = ident,
		.checksum = func_checksum,
		.cfg_checksum = cfg_checksum,
	};
}

void llvm_gcda_emit_arcs(u32 num_counters, u64 *counters)
{
	struct pkvm_gcov_fn_info *info = &curr->functions[curr->n_functions - 1];
	info->num_counters = num_counters;
	info->counters = counters;
}

void llvm_gcda_summary_info(void)
{
}

void llvm_gcda_end_file(void)
{
}

static void pack_gcov_info(void *buf)
{
	struct pkvm_gcov_info *info = buf;
	struct pkvm_gcov_fn_info *f_info;

	buf += sizeof(struct pkvm_gcov_info) + sizeof(struct pkvm_gcov_fn_info) * info->n_functions;
	info->filename = rel_pack_ptr(&buf, info, info->filename, strlen(info->filename) + 1);

	for (u32 i = 0; i < info->n_functions; ++i) {
		f_info = &info->functions[i];
		f_info->counters = rel_pack_ptr(&buf, info, f_info->counters, f_info->num_counters * sizeof(u64));
	}
}

static struct shared {
	void *buf;
	u64 size;
	u64 mapped;
	hyp_spinlock_t lock;
} shared;

static inline int is_initialised(void)
{
	return shared.size > 0 && shared.mapped == shared.size;
}

int pkvm_gcov_buffer_init(u64 pages) {
	int ret;
	unsigned long vaddr;
	if (shared.buf)
		return -EINVAL;
	ret = pkvm_alloc_private_va_range(pages * PAGE_SIZE, &vaddr);
	if (ret)
		return ret;
	shared = (struct shared) {
		.buf = (void *) vaddr,
		.size = pages * PAGE_SIZE,
		.mapped = 0
	};
	return ret;
}

int pkvm_gcov_buffer_add_page(u64 pfn)
{
	int ret;
	u64 phys_addr = hyp_pfn_to_phys(pfn);
	void *hyp_addr = __hyp_va(phys_addr);

	hyp_spin_lock(&shared.lock);

	if (shared.size <= shared.mapped) {
		ret = -EINVAL;
		goto exit;
	}

	ret = __pkvm_host_share_hyp(pfn);
	if (ret)
		goto exit;

	ret = hyp_pin_shared_mem(hyp_addr, hyp_addr + PAGE_SIZE);
	if (ret)
		goto exit;

	hyp_spin_lock(&pkvm_pgd_lock);
	ret = kvm_pgtable_hyp_map(&pkvm_pgtable, (u64)shared.buf + shared.mapped, PAGE_SIZE, phys_addr, PAGE_HYP);
	hyp_spin_unlock(&pkvm_pgd_lock);
	if (ret)
		goto exit;

	shared.mapped += PAGE_SIZE;

exit:
	hyp_spin_unlock(&shared.lock);
	return ret;
}

int pkvm_gcov_export_module(unsigned int index)
{
	int ret = 0;
	hyp_spin_lock(&shared.lock);
	if (modules.n <= index || !is_initialised()) {
		ret = -EINVAL;
		goto exit;
	}
	curr = shared.buf;
	modules.cbs[index].writeout();
	curr = NULL;
	// XXX At this point, kernel can fiddle with the buffer and crash us.
	pack_gcov_info(shared.buf);
exit:
	hyp_spin_unlock(&shared.lock);
	return ret;
}

int pkvm_gcov_reset(void)
{
	hyp_spin_lock(&shared.lock);
        for (int i = 0; i < modules.n; ++i)
		modules.cbs[i].reset();
	hyp_spin_unlock(&shared.lock);
	return 0;
}
