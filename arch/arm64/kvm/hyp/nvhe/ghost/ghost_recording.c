#include <nvhe/mm.h> // for pkvm_pgtable

#include <nvhe/ghost/ghost_alloc.h>
#include <nvhe/ghost/ghost_state.h>
#include <nvhe/ghost/ghost_misc.h>

#include <nvhe/ghost/ghost_spec.h>
#include <nvhe/ghost/ghost_types_aux.h>

#include <nvhe/ghost/ghost_tracing.h>

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

/* from nvhe/pkvm.c */
extern struct pkvm_hyp_vm **vm_table;

/**
 * these are here to make __kvm_nvhe_ versions of them that are accessible in both the nvhe and non-nvhe code
 * as they were static in va_layout.c but now we need to access them in the ghost spec.
 *
 * TODO: Ben will move these (or fix it or something)
 */
u8 tag_lsb;
u64 tag_val;

/* from setup.c */
extern unsigned long hyp_nr_cpus;


static void init_abstraction(struct ghost_state *g)
{
	g->pkvm.present = false;
	g->host.present = false;
	g->vms.present = false;

	/* the pointers in the local state are never NULL
	 * but for some threads might not be valid to read.
	 */
	for (int idx=0; idx<hyp_nr_cpus; idx++) {
		struct ghost_local_state *st = malloc_or_die(ALLOC_LOCAL_STATE, sizeof(struct ghost_local_state));
		st->present = false;
		g->cpu_local_state[idx] = st;

		/* allocate a vCPU to sit in the per-CPU loaded state */
		struct ghost_vcpu *loaded_vcpu = malloc_or_die(ALLOC_VCPU, sizeof(struct ghost_vcpu));
		g->cpu_local_state[idx]->loaded_vcpu_status.loaded_vcpu = loaded_vcpu;
	}
}

// EXPORTED ghost_recording.h
void init_abstraction_common(void)
{
	init_abstraction(&gs);
}

// EXPORTED ghost_recording.h
void init_abstraction_thread_local(void)
{
	init_abstraction(this_cpu_ptr(&gs_recorded_pre));
	init_abstraction(this_cpu_ptr(&gs_recorded_post));
	init_abstraction(this_cpu_ptr(&gs_computed_post));
}

static mapping compute_abstraction_hyp_memory(void)
{
	mapping m;
	int cur;
	m = mapping_empty_();
	for (cur=0; cur<hyp_memblock_nr; cur++)
		extend_mapping_coalesce(&m, GHOST_STAGE_NONE, hyp_memory[cur].base, hyp_memory[cur].size / PAGE_SIZE, maplet_target_memblock(hyp_memory[cur].flags));
	return m;
}

// Recording of the set of reclaimable/need_poisoning pages by walking
// all pages of all hyp_memory memblocks.
// This is very slow, but only look at the concrete pKVM state.
static void compute_reclaimable_and_need_poisoning_slow(struct ghost_host *dest)
{
	for (int i=0; i<hyp_memblock_nr; i++) {
		struct memblock_region block = hyp_memory[i];
		for (int j=0; j<block.size; j+=PAGE_SIZE) {
			phys_addr_t addr = block.base + j;
			struct hyp_page *page = hyp_phys_to_page(addr);
			if (page->flags & HOST_PAGE_PENDING_RECLAIM)
				ghost_pfn_set_insert(&dest->reclaimable_pfn_set, hyp_phys_to_pfn(addr));
			if (page->flags & HOST_PAGE_NEED_POISONING)
				ghost_pfn_set_insert(&dest->need_poisoning_pfn_set, hyp_phys_to_pfn(addr));
		}
	}
}

// This version is much starter, but looks at the ghost host annot and shared mappings
// instead of looking at the concrete pKVM state.
static void compute_reclaimable_and_need_poisoning_faster(struct ghost_host *dest)
{
	struct glist_node *pos;
	struct maplet *m;
	// if (glist_empty(&dest->host_abstract_pgtable_annot))
	// 	return;
	glist_for_each(pos, &dest->host_abstract_pgtable_annot) {
		m = glist_entry(pos, struct maplet, list);
		ghost_assert(m->target.kind == MAPLET_UNMAPPED);
		if (MAPLET_OWNER_ANNOT_OWNED_GUEST == m->target.annot.owner) {
			for (int i = 0; i < m->ia_range_nr_pages; i++) {
				// NOTE: using the input address because the target is MAPLET_UNMAPPED,
				// but we know that host is identity mapped so it is fine.
				phys_addr_t addr = m->ia_range_start + i*PAGE_SIZE;
				struct hyp_page *page = hyp_phys_to_page(addr);
				if (page->flags & HOST_PAGE_PENDING_RECLAIM) {
					ghost_pfn_set_insert(&dest->reclaimable_pfn_set, hyp_phys_to_pfn(addr));
				}
				if (page->flags & HOST_PAGE_NEED_POISONING) {
					ghost_pfn_set_insert(&dest->need_poisoning_pfn_set, hyp_phys_to_pfn(addr));
				}
			}
		}
	}
	// NOTE: it is not enough to just look at the annot mapping, because guests may have shared pages with the host.
	glist_for_each(pos, &dest->host_abstract_pgtable_shared) {
		m = glist_entry(pos, struct maplet, list);
		ghost_assert(m);
		for (int i = 0; i < m->ia_range_nr_pages; i++) {
			phys_addr_t addr = m->target.map.oa_range_start + i*PAGE_SIZE;
			struct hyp_page *page = hyp_phys_to_page(addr);
			ghost_assert(page);
			if (page->flags & HOST_PAGE_PENDING_RECLAIM) {
				ghost_pfn_set_insert(&dest->reclaimable_pfn_set, hyp_phys_to_pfn(addr));
			}
			if (page->flags & HOST_PAGE_NEED_POISONING) {
				ghost_pfn_set_insert(&dest->need_poisoning_pfn_set, hyp_phys_to_pfn(addr));
			}
		}
	}

}


static void compute_abstraction_host(struct ghost_host *dest)
{
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	u64 pool_range_start = (u64)hyp_virt_to_phys(host_s2_pgt_base);
	u64 pool_range_end = pool_range_start + ghost_host_s2_pgt_size * PAGE_SIZE;
	ghost_record_pgtable_ap(&dest->host_concrete_pgtable, &host_mmu.pgt, pool_range_start, pool_range_end, "host_mmu.pgt", i);
	dest->host_abstract_pgtable_annot = mapping_annot(dest->host_concrete_pgtable.mapping);
	dest->host_abstract_pgtable_shared = mapping_shared(dest->host_concrete_pgtable.mapping);
	// TODO: maybe add a build config switch?
	if (true)
		compute_reclaimable_and_need_poisoning_faster(dest);
	else
		compute_reclaimable_and_need_poisoning_slow(dest);
	dest->present = true;
}

// should this read from the mapping, or from our ghost record of the mapping requests?  From the mapping, as this is to specify what EL2 Stage 1 translation does - correctness of the initialisation w.r.t. the requests is a different question
// should this be usable only from a freshly initialised state, or from an arbitrary point during pKVM execution?  From an arbitrary point during execution.  (Do we have to remove any annot parts here?  not sure)
// need to hold the pkvm lock
static void compute_abstraction_pkvm(struct ghost_pkvm *dest)
{
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	u64 pool_range_start = (u64)hyp_virt_to_phys(hyp_pgt_base);
	u64 pool_range_end = pool_range_start + ghost_hyp_pgt_size * PAGE_SIZE;
	ghost_record_pgtable_ap(&dest->pkvm_abstract_pgtable, &pkvm_pgtable, pool_range_start, pool_range_end, "pkvm_pgtable", i);
	dest->present = true;
}


inline void make_abstract_register(struct ghost_register *reg, u64 value)
{
	reg->status = GHOST_PRESENT;
	reg->value = value;
}

static void ghost_registers_copy_sysregs_from_context(const struct kvm_cpu_context* ctxt, struct ghost_register out_sysregs[NR_GHOST_SYSREGS])
{
	for (int i=__INVALID_SYSREG__ + 1; i<NR_SYS_REGS; i++) {
		u32 idx = ghost_registers_mapping[i];
		if (!(BIT(31) & idx)) {
			ghost_assert(idx < NR_GHOST_SYSREGS);
			make_abstract_register(&out_sysregs[idx], ctxt->sys_regs[i]);
		}
	}
}

static void ghost_registers_copy_el2_sysregs_from_context(const struct kvm_cpu_context* ctxt, struct ghost_register out_el2_sysregs[NR_GHOST_EL2_SYSREGS])
{
	for (int i=__INVALID_SYSREG__ + 1; i<NR_SYS_REGS; i++) {
		u32 idx = ghost_registers_mapping[i];
		if (BIT(31) & idx) {
			ghost_assert(~idx < NR_GHOST_EL2_SYSREGS);
			make_abstract_register(&out_el2_sysregs[~idx], ctxt->sys_regs[i]);
		}
	}
}

static void compute_abstract_registers(struct ghost_registers *regs, struct kvm_cpu_context *ctxt, bool copy_el2_sysregs)
{
	regs->present = true;
	make_abstract_register(&regs->pc, ctxt->regs.pc);

	for (int i=0; i<31; i++)
		make_abstract_register(&regs->gprs[i], ctxt->regs.regs[i]);

	ghost_registers_copy_sysregs_from_context(ctxt, regs->sysregs);

	if (copy_el2_sysregs)
		ghost_registers_copy_el2_sysregs_from_context(ctxt, regs->el2_sysregs);
	else for (int i=0; i<NR_GHOST_EL2_SYSREGS; i++)
		regs->el2_sysregs[i].status = GHOST_ABSENT;
}

#define RECORD_EL2_SYSREG(R, NAME) \
	make_abstract_register(&R[GHOST_SYSREG(NAME)], read_sysreg(NAME))
static void record_abstraction_el2_sysregs(struct ghost_registers *gr)
{
	for (int i=0; i<NR_GHOST_EL2_SYSREGS; i++)
		gr->el2_sysregs[i].status = GHOST_ABSENT;

	RECORD_EL2_SYSREG(gr->el2_sysregs, CNTVOFF_EL2);
	if (  (read_sysreg(ID_AA64PFR0_EL1) >> ID_AA64PFR0_EL1_EL1_SHIFT)
	    & ID_AA64PFR0_EL1_EL1_AARCH32) {
		// Accessing these registers is undefined if EL1 doesn't
		// support AArch32.
		// TODO: do we actually care about these registers?
		RECORD_EL2_SYSREG(gr->el2_sysregs, DACR32_EL2);
		RECORD_EL2_SYSREG(gr->el2_sysregs, IFSR32_EL2);
		RECORD_EL2_SYSREG(gr->el2_sysregs, DBGVCR32_EL2);
	}
	RECORD_EL2_SYSREG(gr->el2_sysregs, VPIDR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, VMPIDR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, SCTLR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, ACTLR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, HCR_EL2);

	// TODO: if EL3 is implemented, accessing these registers can be
	// undefined or trap to EL3 (depending on the configuration of
	// an EL3 register).
	// pKVM does access these two.
	RECORD_EL2_SYSREG(gr->el2_sysregs, MDCR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, CPTR_EL2);

	RECORD_EL2_SYSREG(gr->el2_sysregs, HSTR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, HACR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, TTBR0_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, TCR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, VTTBR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, VTCR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, SPSR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, ELR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, AFSR0_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, AFSR1_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, ESR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, FAR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, HPFAR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, MAIR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, AMAIR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, VBAR_EL2);

	// TODO: if EL3 is implemented, accessing this register
	// is undefined, and pKVM does not access it.
	RECORD_EL2_SYSREG(gr->el2_sysregs, RVBAR_EL2);

	RECORD_EL2_SYSREG(gr->el2_sysregs, TPIDR_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, CNTHCTL_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, CNTHP_CTL_EL2);
	RECORD_EL2_SYSREG(gr->el2_sysregs, CNTHP_CVAL_EL2);

	// TODO: reading this sysreg gives a "Trapped access to SVE, Advanced SIMD or floating point"
	// RECORD_EL2_SYSREG(gr->el2_sysregs, FPEXC32_EL2);

	// TODO: these are not permitted by the compiler
	// RECORD_EL2_SYSREG(gr->el2_sysregs, TTBR1_EL2);
	// RECORD_EL2_SYSREG(gr->el2_sysregs, CONTEXTIDR_EL2);
	// RECORD_EL2_SYSREG(gr->el2_sysregs, CNTHV_CTL_EL2);
	// RECORD_EL2_SYSREG(gr->el2_sysregs, CNTHV_CVAL_EL2);

	// RECORD_EL2_SYSREG(gr->el2_sysregs, SP_EL2);
}

static void record_abstraction_regs(struct ghost_registers *gr, struct kvm_cpu_context *ctxt)
{
	gr->present = true;
	struct kvm_cpu_context *myctxt = malloc_or_die(ALLOC_KVM_CPU_CONTEXT, sizeof(struct kvm_cpu_context));
	memcpy(myctxt, ctxt, sizeof(struct kvm_cpu_context));
	__sysreg_save_state_nvhe(myctxt);
	compute_abstract_registers(gr, myctxt, false/*we do not copy the EL2 sysregs*/);
	free(ALLOC_KVM_CPU_CONTEXT, myctxt);

	record_abstraction_el2_sysregs(gr);
}

static void compute_abstraction_vcpu(struct ghost_vcpu *dest, struct pkvm_hyp_vcpu *vcpu, u64 vcpu_index)
{
	memset(dest, 0, sizeof(struct ghost_vcpu));
	dest->vcpu_index = vcpu_index;
	if (vcpu) {
		dest->regs.present = true;
		compute_abstract_registers(&dest->regs, &vcpu->vcpu.arch.ctxt, true/*we also copy EL2 sysregs*/);
		// TODO(check): guest trap registers seem to be stored in separated fields
		make_abstract_register(&dest->regs.el2_sysregs[GHOST_SYSREG(HCR_EL2)], vcpu->vcpu.arch.hcr_el2);
		make_abstract_register(&dest->regs.el2_sysregs[GHOST_SYSREG(MDCR_EL2)], vcpu->vcpu.arch.mdcr_el2);
		make_abstract_register(&dest->regs.el2_sysregs[GHOST_SYSREG(CPTR_EL2)], vcpu->vcpu.arch.cptr_el2);
		phys_addr_t* p = hyp_phys_to_virt(vcpu->vcpu.arch.pkvm_memcache.head);
		for (int i=0; i<vcpu->vcpu.arch.pkvm_memcache.nr_pages; i++) {
			ghost_pfn_set_insert(&dest->recorded_memcache_pfn_set, hyp_virt_to_pfn(p));
			p = hyp_phys_to_virt(*p);
		}
	}
}

static void compute_abstraction_vm_partial(struct ghost_vm *dest, struct pkvm_hyp_vm *hyp_vm, enum vm_field_owner owner)
{
	ghost_assert(hyp_vm);

	dest->protected = hyp_vm->kvm.arch.pkvm.enabled;
	dest->pkvm_handle = hyp_vm->kvm.arch.pkvm.handle;

	dest->vm_teardown_data.host_mc = hyp_virt_to_phys(&hyp_vm->host_kvm->arch.pkvm.teardown_mc);
	dest->vm_teardown_data.hyp_vm_struct_addr = hyp_virt_to_phys(hyp_vm);
	dest->vm_teardown_data.last_ran_addr = hyp_virt_to_phys(hyp_vm->kvm.arch.mmu.last_vcpu_ran);

	dest->lock = &hyp_vm->lock;

	if (owner & VMS_VM_OWNED) {
		/* really do need to hold this lock */
		hyp_assert_lock_held(&hyp_vm->lock);
		dest->vm_locked.present = true;
		ghost_record_pgtable_ap(&dest->vm_locked.vm_abstract_pgtable, &hyp_vm->pgt, hyp_vm->pool.range_start, hyp_vm->pool.range_end, "guest_mmu.pgt", 0);
	}


	if (owner & VMS_VM_TABLE_OWNED) {
		/* can't assert the lock held, as it might be that we're in a loaded vcpu
		 * so don't need the lock at all. */
		dest->vm_table_locked.present = true;
		dest->vm_table_locked.nr_vcpus = hyp_vm->kvm.created_vcpus;
		dest->vm_table_locked.nr_initialised_vcpus = hyp_vm->nr_vcpus;

		/* the pKVM hyp_vm .vcpus field is only defined up to created_vcpus */
		for (int vcpu_idx=0; vcpu_idx < KVM_MAX_PVMS; vcpu_idx++) {
			struct ghost_vcpu_reference *vcpu_ref = &dest->vm_table_locked.vcpu_refs[vcpu_idx];
			if (vcpu_idx < hyp_vm->kvm.created_vcpus) {
				struct pkvm_hyp_vcpu *vcpu = hyp_vm->vcpus[vcpu_idx];
				vcpu_ref->initialised = vcpu_idx < hyp_vm->nr_vcpus;
				if (vcpu_ref->initialised) {
					dest->vm_table_locked.vm_teardown_vcpu_addrs[vcpu_idx] =
						vcpu_ref->initialised ? hyp_virt_to_phys(hyp_vm->vcpus[vcpu_idx]) : 0;
					if (vcpu->loaded_hyp_vcpu) {
						vcpu_ref->loaded_somewhere = true;
						ghost_assert(vcpu_ref->vcpu == NULL);
						vcpu_ref->vcpu = NULL;
					} else {
						vcpu_ref->loaded_somewhere = false;
						struct ghost_vcpu *g_vcpu = malloc_or_die(ALLOC_VCPU, sizeof (struct ghost_vcpu));
						compute_abstraction_vcpu(g_vcpu, vcpu, vcpu_idx);
						ghost_assert(vcpu_ref->vcpu == NULL);
						vcpu_ref->vcpu = g_vcpu;

					}
				}
			}
		}
	}
}

static void record_abstraction_pkvm(struct ghost_state *g)
{
	ghost_assert(!g->pkvm.present);
	compute_abstraction_pkvm(&g->pkvm);
}

// EXPORTED ghost_recording.h
void record_and_check_abstraction_pkvm_pre(void)
{
	trace_ghost_enter(GHOST_TRACE_record_and_check_abstraction_pkvm_pre);
	if (ghost_machinery_enabled()) {
		GHOST_LOG_CONTEXT_ENTER();
		ghost_lock_maplets();
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
		// For pKVM and Host we believe there is no single synchronisation point during a hypercall
		// because the hypercalls may take and release the locks on these multiple times.
		//
		// For now we just record the pre for the very first lock, and assume no interference.
		// ... but later on we'll have to do some this-thread-diff/trajectory tracking instead
		if (!g->pkvm.present) {
			record_abstraction_pkvm(g);
			check_abstraction_equals_pkvm(&g->pkvm, &gs.pkvm);
		}
		ghost_unlock_maplets();
		GHOST_LOG_CONTEXT_EXIT();
	}
	trace_ghost_exit(GHOST_TRACE_record_and_check_abstraction_pkvm_pre);
}

// EXPORTED ghost_recording.h
void record_and_copy_abstraction_pkvm_post(void)
{
	trace_ghost_enter(GHOST_TRACE_record_and_copy_abstraction_pkvm_post);
	if (ghost_machinery_enabled()) {
		GHOST_LOG_CONTEXT_ENTER();
		ghost_lock_maplets();
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
		// TODO: for pKVM and Host we believe there is no single synchronisation point
		// (see comment in record_and_check_abstraction_pkvm_pre)
		// so on the post we must clear if there was a previous recorded post
		if (g->pkvm.present)
			clear_abstraction_pkvm(g);
		record_abstraction_pkvm(g);
		copy_abstraction_pkvm(&gs, g);
		ghost_unlock_maplets();
		GHOST_LOG_CONTEXT_EXIT();
	}
	trace_ghost_exit(GHOST_TRACE_record_and_copy_abstraction_pkvm_post);
}

static void record_abstraction_host(struct ghost_state *g)
{
	ghost_assert(!g->host.present);
	compute_abstraction_host(&g->host);
}

// EXPORTED ghost_recording.h
void record_and_check_abstraction_host_pre(void)
{
	trace_ghost_enter(GHOST_TRACE_record_and_check_abstraction_host_pre);
	if (ghost_machinery_enabled()) {
		GHOST_LOG_CONTEXT_ENTER();
		ghost_lock_maplets();
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
		// TODO: see comment in record_and_check_abstraction_pkvm_pre
		if (!g->host.present) {
			record_abstraction_host(g);
			check_abstraction_equals_host(&g->host, &gs.host);
		}
		ghost_unlock_maplets();
		GHOST_LOG_CONTEXT_EXIT();
	}
	trace_ghost_exit(GHOST_TRACE_record_and_check_abstraction_host_pre);
}

// EXPORTED ghost_recording.h
void record_and_copy_abstraction_host_post(void)
{
	trace_ghost_enter(GHOST_TRACE_record_and_copy_abstraction_host_post);
	if (ghost_machinery_enabled()) {
		GHOST_LOG_CONTEXT_ENTER();
		ghost_lock_maplets();
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
		// TODO: for pKVM and Host we believe there is no single synchronisation point
		// (see comment in record_and_check_abstraction_pkvm_pre)
		// so on the post we must clear if there was a previous recorded post
		if (g->host.present)
			clear_abstraction_host(g);
		record_abstraction_host(g);
		copy_abstraction_host(&gs, g);
		ghost_unlock_maplets();
		GHOST_LOG_CONTEXT_EXIT();
	}
	trace_ghost_exit(GHOST_TRACE_record_and_copy_abstraction_host_post);
}

static void record_abstraction_constants(struct ghost_state *g)
{
	g->globals.hyp_nr_cpus = hyp_nr_cpus;
	g->globals.hyp_physvirt_offset = hyp_physvirt_offset;
	g->globals.tag_lsb = tag_lsb;
	g->globals.tag_val = tag_val;
	g->globals.hyp_memory = compute_abstraction_hyp_memory();
}

// EXPORTED ghost_recording.h
void record_abstraction_constants_pre(void)
{
	trace_ghost_enter(GHOST_TRACE_record_abstraction_constants_pre);
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_constants(g);
	trace_ghost_exit(GHOST_TRACE_record_abstraction_constants_pre);
}

// EXPORTED ghost_recording.h
void record_abstraction_constants_post(void)
{
	trace_ghost_enter(GHOST_TRACE_record_abstraction_constants_post);
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_constants(g);
	trace_ghost_exit(GHOST_TRACE_record_abstraction_constants_post);
}

static void record_abstraction_vm_partial(struct ghost_state *g, struct pkvm_hyp_vm *hyp_vm, enum vm_field_owner owner)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_vms_locked();

	pkvm_handle_t handle = hyp_vm->kvm.arch.pkvm.handle;

	// if recording the first vm, make an empty dictionary.
	if (!g->vms.present)
		make_abstraction_vms(&g->vms);

	/*
	* It may be that we're taking or releasing a vm_table_lock
	* when a VM lock was already taken
	* so it might already exist
	*/
	struct ghost_vm *vm = ghost_vms_get(&g->vms, handle);
	if (!vm) {
		/* if not: safe to just create one as we hold all the locks */
		vm = ghost_vms_alloc(&g->vms, handle);
		ghost_assert(vm);
	}

	compute_abstraction_vm_partial(vm, hyp_vm, owner);
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_recording.h
void record_and_check_abstraction_vm_pre(struct pkvm_hyp_vm *vm)
{
	trace_ghost_enter(GHOST_TRACE_record_and_check_abstraction_vm_pre);
	if (ghost_machinery_enabled()) {
		GHOST_LOG_CONTEXT_ENTER();
		// TODO: (and for the others) maplets are already locked by the top-level hcall
		// but this isn't right (e.g. for vpu_run), and it should be at least this
		// (if not more!) fine-grained locking for maplets and the vms.vms table.
		ghost_lock_maplets();
		ghost_lock_vms();
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
		pkvm_handle_t handle = vm->kvm.arch.pkvm.handle;

		// If this is __init_vm, then the lock was taken after a vm was partially initialised
		// and we shouldn't try record it.
		if (!THIS_HCALL_IS("__pkvm_init_vm")) {
			record_abstraction_vm_partial(g, vm, VMS_VM_OWNED);
			enum vm_field_owner owner = VMS_VM_OWNED | VMS_VM_TABLE_OWNED;

			if (THIS_HCALL_IS("__pkvm_teardown_vm")) {
				// If this is __pkvm_teardown_vm, then
				// the VM has already been removed from the table
				// so we only record the VM_OWNED part.
				owner ^= VMS_VM_TABLE_OWNED;
			}

			check_abstraction_vm_in_vms_and_equal(handle, g, &gs.vms, owner);
		}

		ghost_unlock_vms();
		ghost_unlock_maplets();
		GHOST_LOG_CONTEXT_EXIT();
	}
	trace_ghost_exit(GHOST_TRACE_record_and_check_abstraction_vm_pre);
}

// EXPORTED ghost_recording.h
void record_and_copy_abstraction_vm_post(struct pkvm_hyp_vm *vm)
{
	trace_ghost_enter(GHOST_TRACE_record_and_copy_abstraction_vm_post);
	if (ghost_machinery_enabled()) {
		GHOST_LOG_CONTEXT_ENTER();
		ghost_lock_maplets();
		ghost_lock_vms();
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
		record_abstraction_vm_partial(g, vm, VMS_VM_OWNED);
		copy_abstraction_vm_partial(&gs, g, vm->kvm.arch.pkvm.handle, VMS_VM_OWNED);
		ghost_unlock_vms();
		ghost_unlock_maplets();
		GHOST_LOG_CONTEXT_EXIT();
	}
	trace_ghost_exit(GHOST_TRACE_record_and_copy_abstraction_vm_post);
}

static void record_abstraction_vms_partial(struct ghost_state *g, enum vm_field_owner owner)
{
	GHOST_LOG_CONTEXT_ENTER();

	/* Make empty table if not already there */
	if (!g->vms.present) {
		make_abstraction_vms(&g->vms);
	}

	if (owner & VMS_VM_TABLE_OWNED) {
		g->vms.table_data.present = true;
		g->vms.table_data.nr_vms = 0;
	}

	for (int idx=0; idx<KVM_MAX_PVMS; idx++) {
		struct pkvm_hyp_vm *hyp_vm = vm_table[idx];
		/* If we only have the table lock, not the entire vm lock
		 * then can't record the pgtable right now,
		 * so only take a partial view of it.
		 */
		if (hyp_vm) {
			record_abstraction_vm_partial(g, hyp_vm, owner);

			if (owner & VMS_VM_TABLE_OWNED)
				g->vms.table_data.nr_vms++;
		}
	}
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_recording.h
void record_and_check_abstraction_vms_pre(void)
{
	trace_ghost_enter(GHOST_TRACE_record_and_check_abstraction_vms_pre);

	if (ghost_machinery_enabled()) {
		GHOST_LOG_CONTEXT_ENTER();
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
		ghost_lock_vms();
		record_abstraction_vms_partial(g, VMS_VM_TABLE_OWNED);
		check_abstraction_vms_subseteq(&g->vms, &gs.vms);
		ghost_unlock_vms();
		GHOST_LOG_CONTEXT_EXIT();
	}

	trace_ghost_exit(GHOST_TRACE_record_and_check_abstraction_vms_pre);
}

// EXPORTED ghost_recording.h
void record_and_copy_abstraction_vms_post(void)
{
	trace_ghost_enter(GHOST_TRACE_record_and_copy_abstraction_vms_post);

	if (ghost_machinery_enabled()) {
		GHOST_LOG_CONTEXT_ENTER();
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
		ghost_lock_vms();
		record_abstraction_vms_partial(g, VMS_VM_TABLE_OWNED);
		copy_abstraction_vms_partial(&gs, g, VMS_VM_TABLE_OWNED);
		ghost_unlock_vms();
		GHOST_LOG_CONTEXT_EXIT();
	}

	trace_ghost_exit(GHOST_TRACE_record_and_copy_abstraction_vms_post);
}

static void ghost_cpu_running_state_copy(struct ghost_running_state *run_tgt, struct ghost_running_state *g_src)
{
	run_tgt->guest_running = g_src->guest_running;
	run_tgt->vm_handle = g_src->vm_handle;
	run_tgt->vcpu_index = g_src->vcpu_index;
	run_tgt->guest_exit_code = g_src->guest_exit_code;
}

static void record_abstraction_loaded_vcpu(struct ghost_state *g, struct pkvm_hyp_vcpu *loaded_vcpu)
{
	struct ghost_loaded_vcpu_status *g_loaded_vcpu_status;

	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert(ghost_this_cpu_local_state(g)->present);
	g_loaded_vcpu_status = &ghost_this_cpu_local_state(g)->loaded_vcpu_status;

	if (loaded_vcpu) {
		u64 vcpu_index = loaded_vcpu->vcpu.vcpu_idx;

		/* The vm_table lock is still protecting us, ensuring the vcpu is only on one core
		 * it's just that we 'forgot' about that on the hypercall
		 * so just re-compute the vm-table-owned data. */
		g_loaded_vcpu_status->loaded = true;
		g_loaded_vcpu_status->vm_handle = loaded_vcpu->vcpu.kvm->arch.pkvm.handle;
		compute_abstraction_vcpu(g_loaded_vcpu_status->loaded_vcpu, loaded_vcpu, vcpu_index);
	} else {
		g_loaded_vcpu_status->loaded = false;
	}

	GHOST_LOG_CONTEXT_EXIT();
}

static void record_abstraction_local_state(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	struct ghost_local_state *local = ghost_this_cpu_local_state(g);
	struct ghost_running_state *cpu_run_state = this_cpu_ptr(&ghost_cpu_run_state);

	if (ctxt)
		record_abstraction_regs(&local->regs, ctxt);

	ghost_cpu_running_state_copy(&local->cpu_state, cpu_run_state);

	local->host_regs.present = true;
	record_abstraction_regs(&local->host_regs.regs, &this_cpu_ptr(&kvm_host_data)->host_ctxt);

	local->present = true;

	/* no loaded_vcpu state, as that is read separately */
	struct pkvm_hyp_vcpu *loaded_vcpu = pkvm_get_loaded_hyp_vcpu();
	record_abstraction_loaded_vcpu(g, loaded_vcpu);
}

// EXPORTED ghost_recording.h
void record_and_check_abstraction_local_state_pre(struct kvm_cpu_context *ctxt)
{
	trace_ghost_enter(GHOST_TRACE_record_and_check_abstraction_local_state_pre);
	if (ghost_machinery_enabled()) {
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
		GHOST_LOG_CONTEXT_ENTER();
		record_abstraction_local_state(g, ctxt);

		if (this_cpu_ghost_registers(&gs)->present) {
			GHOST_TRACE("expected:gs");
			GHOST_TRACE("impl:gr_pre");
			check_abstraction_equals_local_state(&gs, g);
		}
		GHOST_LOG_CONTEXT_EXIT();
	}
	trace_ghost_exit(GHOST_TRACE_record_and_check_abstraction_local_state_pre);
}

// EXPORTED ghost_recording.h
void record_and_copy_abstraction_local_state_post(struct kvm_cpu_context *ctxt)
{
	trace_ghost_enter(GHOST_TRACE_record_and_copy_abstraction_local_state_post);
	if (ghost_machinery_enabled()) {
		struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
		record_abstraction_local_state(g, ctxt);
		copy_abstraction_local_state(ghost_this_cpu_local_state(&gs), ghost_this_cpu_local_state(g));
	}
	trace_ghost_exit(GHOST_TRACE_record_and_copy_abstraction_local_state_post);
}

// EXPORTED ghost_recording.h
void record_abstraction_loaded_vcpu_and_check_none(void)
{
	trace_ghost_enter(GHOST_TRACE_record_abstraction_loaded_vcpu_and_check_none);
	struct pkvm_hyp_vcpu *loaded_vcpu = pkvm_get_loaded_hyp_vcpu();
	// this cpu should have a loaded vcpu yet
	ghost_spec_assert(!loaded_vcpu);
	this_cpu_ghost_loaded_vcpu_status(&gs)->loaded = false;
	ghost_assert(!this_cpu_ghost_loaded_vcpu_status(&gs)->loaded);
	trace_ghost_exit(GHOST_TRACE_record_abstraction_loaded_vcpu_and_check_none);
}

static void record_abstraction_vms_and_check_none(struct ghost_state *g)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_assert_vms_locked();
	ghost_assert_pkvm_vm_table_locked();

	// empty the dictionary first;
	// then set it to be present, but empty.
	clear_abstraction_vms(g);
	make_abstraction_vms(&g->vms);

	// make there be a vm_table_data but make it empty.
	g->vms.table_data.present = true;
	g->vms.table_data.nr_vms = 0;

	for (int vm_index = 0; vm_index < KVM_MAX_PVMS; vm_index++) {
		struct pkvm_hyp_vm *hyp_vm = vm_table[vm_index];
		if (hyp_vm) {
			// should be that there were no vms at this point.
			ghost_assert(false);
		}
	}
	GHOST_LOG_CONTEXT_EXIT();
}

static void record_abstraction_all(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	GHOST_LOG_CONTEXT_ENTER();
	record_abstraction_pkvm(g);
	record_abstraction_host(g);
	record_abstraction_vms_and_check_none(g);
	/* dont record local state right at start,
	 * as the registers and other CPU local state aren't valid until
	 * the start of the first real hypercall after __pkvm_prot_finalize */
	// record_abstraction_local_state(g, ctxt);
	record_abstraction_constants(g);
	GHOST_LOG_CONTEXT_EXIT();
}

// EXPORTED ghost_recording.h
void record_abstraction_common(void)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_lock_pkvm_vm_table();
	ghost_lock_maplets();
	ghost_lock_vms();
	record_abstraction_all(&gs, NULL);
	ghost_unlock_vms();
	ghost_unlock_maplets();
	ghost_unlock_pkvm_vm_table();
	GHOST_LOG_CONTEXT_EXIT();
}
