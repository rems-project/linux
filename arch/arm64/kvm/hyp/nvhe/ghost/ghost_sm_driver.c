#include <linux/stdarg.h>

#include <nvhe/mm.h>
#include <nvhe/mem_protect.h>

#include <nvhe/ghost/ghost_alloc.h>
#include <nvhe/ghost/ghost_context.h>
#include <nvhe/ghost/ghost_control.h>
#include <nvhe/ghost/ghost_printer.h>
#include <nvhe/ghost/ghost_simplified_model.h>

/*
 * Driver functions for the simplified model
 */

u64 casemate_cpu_id(void)
{
	return hyp_smp_processor_id();
}

static void ghost_cm_abort(const char *msg)
{
	ghost_printf("! casemate: error: %s\n", msg);
	ghost_log_context_traceback();
	BUG();
}

static u64 ghost_cm_read_physmem(u64 phys)
{
	return *(u64*)hyp_phys_to_virt(phys);
}

u64 ghost_cm_read_sysreg(enum ghost_sysreg_kind sysreg)
{
	switch (sysreg) {
	case SYSREG_VTCR_EL2:
		return read_sysreg(vtcr_el2);
	case SYSREG_TCR_EL2:
		return read_sysreg(tcr_el2);
	case SYSREG_MAIR_EL2:
		return read_sysreg(mair_el2);

	/* casemate should never try read the TTBRs at runtime */
	case SYSREG_VTTBR:
	case SYSREG_TTBR_EL2:
		BUG();

	default:
		BUG();
	}
}

static int ghost_cm_print(void *arg, const char *fmt, va_list ap)
{
	gp_stream_t *stream = (gp_stream_t*)arg;

	if (stream == NULL) {
		stream = STREAM_UART;
	}

	return ghost_vsprintf(stream, fmt, ap);
}

static void ghost_cm_trace(const char *record)
{
	ghost_printf_ext(GHOST_WHITE_ON_CYAN "%s" GHOST_NORMAL "\n", record);
}

void *ghost_cm_make_buffer(char* arg, u64 n)
{
	gp_stream_t *buf = malloc_or_die(ALLOC_CASEMATE, sizeof(gp_stream_t));
	buf->buf = arg;
	buf->buf_rem = n;
	buf->kind = GP_STREAM_BUF;
	return buf;
}

void ghost_cm_free_buffer(void *buf)
{
	g_free(ALLOC_CASEMATE, buf);
}

/*
 * Simplified model initialisation
 */
extern struct host_mmu host_mmu;
extern hyp_spinlock_t pkvm_pgd_lock;
extern struct hyp_pool hpool;
extern struct hyp_pool host_s2_pool;

static int pool_init(struct hyp_pool *pool)
{
	casemate_model_step_init(pool->range_start, pool->range_end - pool->range_start);
	for (u64 p = pool->range_start; p < pool->range_end; p += 8) {
		u64 val = *(u64*)hyp_phys_to_virt(p);
		if (val)
			casemate_model_step_write(WMO_plain, p, val);
	}
	return 0;
}

void ghost_initialise_sm(u64 phys, u64 size)
{
	struct casemate_options opts = CASEMATE_DEFAULT_OPTS;
	u64 sm_size = PAGE_ALIGN(2 * sizeof(struct casemate_model_state));
	unsigned long sm_virt;
	struct ghost_driver sm_driver = {
		.read_physmem = NULL, // ghost_cm_read_physmem,
		.read_sysreg = ghost_cm_read_sysreg,
		.abort = ghost_cm_abort,
		.print = ghost_cm_print,
		.sprint_create_buffer = ghost_cm_make_buffer,
		.sprint_destroy_buffer = ghost_cm_free_buffer,
		.trace = ghost_cm_trace,
	};

	opts.enable_checking = ghost_control_check_enabled("casemate_model_step");

	opts.check_opts.enable_printing = ghost_control_print_enabled("casemate_model_step");
	opts.check_opts.print_opts = CM_PRINT_NONE;

	if (ghost_control_print_enabled("sm_dump_trans"))
		opts.check_opts.print_opts |= CM_PRINT_WHOLE_STATE_ON_STEP;
	if (ghost_control_print_enabled("sm_diff_trans"))
		opts.check_opts.print_opts |= CM_PRINT_DIFF_TO_STATE_ON_STEP;
	if (ghost_control_print_enabled("sm_condensed"))
		opts.check_opts.print_opts |= CM_PRINT_ONLY_UNCLEAN;

	opts.enable_tracing = ghost_control_print_enabled("casemate_model_step");

	GHOST_LOG_CONTEXT_ENTER();

	/* have to do the initial simplified model setup before recording the global pKVM pgtable state */
	GHOST_LOG(pkvm_pgtable.start_level, u32);
	// carve out some space just for us at the end, and hope it doesn't prevent the host making progress too much
	BUG_ON(__pkvm_create_private_mapping(phys+size-sm_size, sm_size, PAGE_HYP, &sm_virt, HYP_WORKSPACE));

	ghost_printf("initialisating casemate\n");
	initialise_casemate_model(&opts, phys, size, sm_virt, sm_size);
	initialise_ghost_driver(&sm_driver);

	/* Initialise the memory */
	pool_init(&hpool);
	pool_init(&host_s2_pool);

	/* pKVM's Stage 1 is already loaded (we're using it right now!),
	 * so tell the model about it post-hoc */
	casemate_model_step_hint(GHOST_HINT_SET_ROOT_LOCK, hyp_virt_to_phys(pkvm_pgtable.pgd), hyp_virt_to_phys(&pkvm_pgd_lock));
	casemate_model_step_msr(SYSREG_TTBR_EL2, read_sysreg(ttbr0_el2));

	/* we've already created the host's pgtable and will switch to it soon
	 * so initialise it now */
	casemate_model_step_hint(GHOST_HINT_SET_ROOT_LOCK, hyp_virt_to_phys(host_mmu.pgt.pgd), hyp_virt_to_phys(&host_mmu.lock));

	GHOST_LOG_CONTEXT_EXIT();
}
