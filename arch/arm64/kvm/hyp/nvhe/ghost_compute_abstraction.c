// computing the abstraction function from the pKVM concrete state to the abstract state



// these are the non-ghost headers from mem_protect.c - probably we only need some of them
#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>
#include <asm/stage2_pgtable.h>

#include <hyp/adjust_pc.h>
#include <hyp/fault.h>

#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/spinlock.h>
// end of mem_protect.c non-ghost headers


// and the ghost headers from mem_protect.c
#include <../debug-pl011.h>
#include <../ghost_extra_debug-pl011.h>
#include <../ghost_pgtable.h>
#include "./ghost_spec.h"
#include <nvhe/ghost_asm.h>
#include "nvhe/ghost_asm_ids.h"

//horrible hack for ghost code in nvhe/iommu/s2mpu.c
// but in the default build # CONFIG_KVM_S2MPU is not set
// and (looking in the Makefile) it seems that file isn't even linked in
// void __kvm_nvhe_ghost_dump_s2mpus(u64 indent);

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wunused-variable"
// end of mem_protect.c ghost headers


#include "./ghost_spec.h"
#include "./ghost_compute_abstraction.h"

/* from nvhe/pkvm.c */
extern struct pkvm_hyp_vm **vm_table;
extern hyp_spinlock_t vm_table_lock;

// for all these, one needs to be in ghost_(un)lock_maplets()
// and, unless we make the memory management more automatic, the context must carefully free any pre-existing mappings

// should these return abstract-state structs or update a ghost_state struct?  We really need the latter, but (looking towards the functional spec) nicer to factor via the former?

mapping compute_abstraction_hyp_memory(void)
{
	mapping m;
	int cur;
        m = mapping_empty_();
	for (cur=0; cur<hyp_memblock_nr; cur++)
		extend_mapping_coalesce(&m, hyp_memory[cur].base, hyp_memory[cur].size / PAGE_SIZE, maplet_target_memblock(hyp_memory[cur].flags));
	return m;
}

// should this read from the mapping, or from our ghost record of the mapping requests?  From the mapping, as this is to specify what EL2 Stage 1 translation does - correctness of the initialisation w.r.t. the requests is a different question
// should this be usable only from a freshly initialised state, or from an arbitrary point during pKVM execution?  From an arbitrary point during execution.  (Do we have to remove any annot parts here?  not sure)
// need to hold the pkvm lock
struct ghost_pkvm compute_abstraction_pkvm(void)
{
	struct ghost_pkvm gp;
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	gp.pkvm_abstract_pgtable = ghost_record_pgtable_ap(&pkvm_pgtable, "pkvm_pgtable", i);
	gp.present = true;
	return gp;
}

struct ghost_host compute_abstraction_host(void)
{
	struct ghost_host gh;
	abstract_pgtable ap;
	u64 i=0; /* base indent */ /* though we'll mostly want this to be quiet, later */
	ap = ghost_record_pgtable_ap(&host_mmu.pgt, "host_mmu.pgt", i);
	gh.host_abstract_pgtable_annot = (abstract_pgtable){.root = ap.root, .mapping = mapping_annot(ap.mapping)};
	gh.host_abstract_pgtable_shared = (abstract_pgtable){.root = ap.root, .mapping = mapping_shared(ap.mapping)};
	gh.host_abstract_pgtable_nonannot = (abstract_pgtable){.root = ap.root, .mapping = mapping_nonannot(ap.mapping)};
	gh.present = true;
	free_mapping(ap.mapping);
	return gh;
}

static struct ghost_vm_slot *__ghost_vm_or_free_slot_from_handle(struct ghost_vms *vms, pkvm_handle_t handle) {
	ghost_assert_vms_table_locked();
	ghost_assert(vms->present);

	struct ghost_vm_slot *free_slot = NULL;

	for (int i=0; i<KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *this = &vms->table[i];

		if (this->exists && this->handle == handle) {
			// sanity check: the included vm has the same handle as the slot marker
			// they should always match for slots that exist, but are technically owned by separate locks.
			ghost_assert(this->vm.pkvm_handle == this->handle);
			return this;
		} else if (!this->exists) {
			free_slot = this;
		}
	}

	return free_slot;
}

struct ghost_vm *ghost_vms_get(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_table_locked();
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	if (slot->exists)
		return &slot->vm;
	return NULL;
}

struct ghost_vm *ghost_vms_alloc(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_table_locked();
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	if (!slot->exists) {
		return &slot->vm;
	}

	return NULL;
}

static void ghost_vm_clear_slot(struct ghost_vm_slot *slot)
{
	if (slot->exists) {
		slot->exists = false;
		free_mapping(slot->vm.vm_abstract_pgtable.mapping);
	}
}

void ghost_vms_free(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_table_locked();
	struct ghost_vm_slot *slot = __ghost_vm_or_free_slot_from_handle(vms, handle);
	// can only free something that exists in the table
	ghost_assert(slot);
	ghost_vm_clear_slot(slot);
}

bool ghost_vms_is_valid_handle(struct ghost_vms *vms, pkvm_handle_t handle)
{
	ghost_assert_vms_table_locked();
	ghost_assert(vms->present);
	struct ghost_vm *vm = ghost_vms_get(vms, handle);
	return vm != NULL;
}

/// from a vm_table index compute the abstract ghost VM
struct ghost_vm compute_abstraction_vm(struct pkvm_hyp_vm *vm) {
	int i;
	struct ghost_vm abstract_vm;
	ghost_assert(vm);
	hyp_assert_lock_held(&vm->lock);
	abstract_vm.pkvm_handle = vm->kvm.arch.pkvm.handle;
	abstract_vm.nr_vcpus = vm->nr_vcpus;
	for (i=0; i<KVM_MAX_VCPUS; i++) {
		abstract_vm.vcpus[i] = (struct ghost_vcpu){
			.exists = false,
		};

		// if the vm has this vcpu, then
		if (i < abstract_vm.nr_vcpus) {
			abstract_vm.vcpus[i].exists = true;
			abstract_vm.vcpus[i].loaded = vm->vcpus[i]->loaded_hyp_vcpu ? true : false;
		}
	}
	abstract_vm.vm_abstract_pgtable = ghost_record_pgtable_ap(&vm->pgt, "guest_mmu.pgt", 0);
	abstract_vm.lock = &vm->lock;
	return abstract_vm;
}

bool abstract_pgtable_equal(char *cmp_name, abstract_pgtable ap1, abstract_pgtable ap2,
	char *ap1_name, char* ap2_name, u64 indent)
{
	return (   ap1.root == ap2.root
		&& mapping_equal(ap1.mapping, ap2.mapping, cmp_name, ap1_name, ap2_name, indent));
}

bool abstraction_equals_hyp_memory(struct ghost_state *g1, struct ghost_state *g2)
{
	return mapping_equal(g1->hyp_memory, g2->hyp_memory, "abstraction_equals_hyp_memory", "g1.hyp_memory", "g2.hyp_memory", 4);
}

bool abstraction_equals_reg(struct ghost_state *g1, struct ghost_state *g2)
{
	u64 i;
	bool ret = true;
	u64 ghost_el2_regs[] = (u64[])GHOST_EL2_REGS;
	for (i=0; i<=30; i++)
		ret = ret && ghost_reg_gpr(g1,i) == ghost_reg_gpr(g2,i);
	for (i=0; i<sizeof(ghost_el2_regs)/sizeof(u64); i++)
		ret = ret && ghost_reg_el2(g1,ghost_el2_regs[i]) == ghost_reg_el2(g2,ghost_el2_regs[i]);
	return ret;
	// TODO other regs
}

bool abstraction_equals_pkvm(struct ghost_pkvm gp1, struct ghost_pkvm gp2)
{
	ghost_assert(gp1.present && gp2.present);
	return abstract_pgtable_equal("abstraction_equals_pkvm", gp1.pkvm_abstract_pgtable, gp2.pkvm_abstract_pgtable, "gp1.pkvm_mapping", "gp2.pkvm_mapping", 4);
}

bool abstraction_equals_host(struct ghost_host gh1, struct ghost_host gh2)
{
	// note that this only checks the annot component
	ghost_assert(gh1.present && gh2.present);
	return (abstract_pgtable_equal("abstraction_equals_host", gh1.host_abstract_pgtable_annot, gh2.host_abstract_pgtable_annot, "gh1.host_mapping_annot", "gh2.host_mapping_annot", 4) &&
		abstract_pgtable_equal("abstraction_equals_host", gh1.host_abstract_pgtable_shared, gh2.host_abstract_pgtable_shared, "gh1.host_mapping_shared", "gh2.host_mapping_shared", 4));
}

bool abstraction_equals_loaded_vcpu(struct ghost_loaded_vcpu loaded_vcpu1, struct ghost_loaded_vcpu loaded_vcpu2) 
{
	ghost_assert(loaded_vcpu1.present && loaded_vcpu2.present);
	if (loaded_vcpu1.loaded == loaded_vcpu2.loaded) {
		return    loaded_vcpu1.vm_handle == loaded_vcpu2.vm_handle
		       && loaded_vcpu1.vcpu_index == loaded_vcpu2.vcpu_index;
	} else {
	  return false;
	}
}

bool abstraction_equals_loaded_vcpus(struct ghost_state *g1, struct ghost_state *g2)
{
	bool ret = true;
	for (int i=0; i<NR_CPUS; i++) {
		if (g1->loaded_hyp_vcpu[i].present && g2->loaded_hyp_vcpu[i].present) {
			ret = ret && abstraction_equals_loaded_vcpu(g1->loaded_hyp_vcpu[i], g2->loaded_hyp_vcpu[i]);
		} else if (g1->loaded_hyp_vcpu[i].present && !g2->loaded_hyp_vcpu[i].present) {
			ghost_assert(false);
		}
	}
	return ret;
}

bool abstraction_equals_vcpu(struct ghost_vcpu vcpu1, struct ghost_vcpu vcpu2)
{
	if (vcpu1.exists == vcpu2.exists) {
		return vcpu1.loaded == vcpu2.loaded;
	} else {
		return false;
	}
}

bool abstraction_equals_vm(struct ghost_vm vm1, struct ghost_vm vm2)
{
	// need to hold the vms lock to make sure the vm doesn't change out under us.
	ghost_assert_vms_table_locked();

	hyp_assert_lock_held(vm1.lock);

	// if not for the same guest VM, then not equal
	// technically the handles are fields on the vm and protected by the vm
	// but if we hold the ghost vms lock they can't change out from under us
	// and we don't want to lock vm2 if it's not the same guest as vm1
	if (vm1.pkvm_handle != vm2.pkvm_handle)
		return false;

	ghost_assert(vm1.lock == vm2.lock);
	
	bool vcpus_are_equal;
	for (int i=0; i<KVM_MAX_VCPUS; i++) {
		vcpus_are_equal = vcpus_are_equal && abstraction_equals_vcpu(vm1.vcpus[i], vm2.vcpus[i]);
	}

	return (   abstract_pgtable_equal("abstraction_equals_vm", vm1.vm_abstract_pgtable, vm2.vm_abstract_pgtable, "vm1.vm_abstract_pgtable", "vm2.vm_abstract_pgtable", 4)
		&& vm1.nr_vcpus == vm2.nr_vcpus
		&& vcpus_are_equal);
}

/// Check that `vm` is found in `vms` and that the two ghost vms are equal
bool abstraction_vm_in_vms_and_equal(pkvm_handle_t vm_handle, struct ghost_state *g, struct ghost_vms *vms) {
	int i;	
	ghost_assert_vms_table_locked();

	struct ghost_vm *g_vm = ghost_vms_get(&g->vms, vm_handle);
	struct ghost_vm *found_vm = ghost_vms_get(vms, vm_handle);

	ghost_assert(g_vm != NULL);
	if (found_vm == NULL)
		return false;

	return abstraction_equals_vm(*g_vm, *found_vm);
}

bool __abstraction_vm_contained_in(struct ghost_vm *vm, struct ghost_vms *vms) {
	struct ghost_vm *vm2 = ghost_vms_get(vms, vm->pkvm_handle);

	if (vm2) {
		return abstraction_equals_vm(*vm, *vm2);
	} else {
		return false;
	}
}

bool __abstraction_vm_all_contained_in(struct ghost_vms *vms1, struct ghost_vms *vms2) {
	bool all_found;
	int i;
	// just iterate over the whole table of slots
	// and check, for each VM that exists in vms1 whether that vm can be found in vms2
	for (i=0; i<KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &vms1->table[i];
		if (slot->exists) {
			all_found = all_found && __abstraction_vm_contained_in(&slot->vm, vms2);
		}
	}
	return all_found;
}

bool abstraction_equals_vms(struct ghost_vms gc, struct ghost_vms gr_post)
{
	ghost_assert(gc.present && gr_post.present);
	// the computed and recorded post states should have exactly the same set of touched VMs
	return (
		   __abstraction_vm_all_contained_in(&gc, &gr_post)
		&& __abstraction_vm_all_contained_in(&gr_post, &gc)
	);
}


// do we want these for an arbitrary g or for the global gs ?


bool abstraction_equals_all(struct ghost_state *gc, struct ghost_state *gr_post, struct ghost_state *gr_pre)
{
	bool ret_pkvm, ret_host, ret_vms, ret_loaded_vcpus;
	if (gc->pkvm.present && gr_post->pkvm.present) {
		ret_pkvm = abstraction_equals_pkvm(gc->pkvm, gr_post->pkvm);
	}
	else if (gc->pkvm.present && !gr_post->pkvm.present) {
		ghost_assert(false);
	}
	else if (!gc->pkvm.present && gr_post->pkvm.present) {
		ghost_assert(gr_pre->pkvm.present);
		ret_pkvm = abstraction_equals_pkvm(gr_post->pkvm, gr_pre->pkvm);
	}
	else
		ret_pkvm = true;

	if (gc->host.present && gr_post->host.present) {
		hyp_putsp("case 1\n");
		ret_host = abstraction_equals_host(gc->host, gr_post->host);
	}
	else if (gc->host.present && !gr_post->host.present) {
		ghost_assert(false);
	}
	else if (!gc->host.present && gr_post->host.present) {
		hyp_putsp("case 3\n");
		ghost_assert(gr_pre->host.present);
		ret_host = abstraction_equals_host(gr_post->host, gr_pre->host);
	}
	else
		ret_host = true;

	// TODO: ensure we actually own the locks of any VMs we touched in the hypercall before doing this...
	if (gc->vms.present && gr_post->vms.present) {
		ret_vms = abstraction_equals_vms(gc->vms, gr_post->vms);
	} else if (gc->vms.present && !gr_post->vms.present) {
		ghost_assert(false);
	} else if (!gc->vms.present && gr_post->vms.present) {
		ghost_assert(gr_pre->vms.present);
		ret_vms = abstraction_equals_vms(gr_post->vms, gr_pre->vms);
	} else {
		ret_vms = true;
	}


	ret_loaded_vcpus = abstraction_equals_loaded_vcpus(gc, gr_post);

	return abstraction_equals_hyp_memory(gc, gr_post) && abstraction_equals_reg(gc, gr_post) && gc->hyp_physvirt_offset==gr_post->hyp_physvirt_offset && ret_pkvm && ret_host && ret_vms && ret_loaded_vcpus;
}


void init_abstraction(struct ghost_state *g)
{
	g->pkvm.present = false;
	g->host.present = false;
	g->regs.present = false;
	g->vms.present = false;
	for (int cpu=0; cpu<NR_CPUS; cpu++) {
		g->loaded_hyp_vcpu[cpu].present = false;
	}
}

void init_abstraction_common(void)
{
	init_abstraction(&gs);
}

void init_abstraction_thread_local(void)
{
	init_abstraction(this_cpu_ptr(&gs_recorded_pre));
	init_abstraction(this_cpu_ptr(&gs_recorded_post));
	init_abstraction(this_cpu_ptr(&gs_computed_post));
}

void clear_abstraction_pkvm(struct ghost_state *g)
{
	if (g->pkvm.present) {
		free_mapping(g->pkvm.pkvm_abstract_pgtable.mapping);
		g->pkvm.present = false;
	}
}

void clear_abstraction_host(struct ghost_state *g)
{
	if (g->host.present) {
		free_mapping(g->host.host_abstract_pgtable_annot.mapping);
		free_mapping(g->host.host_abstract_pgtable_shared.mapping);
		free_mapping(g->host.host_abstract_pgtable_nonannot.mapping);
		g->host.present = false;
	}
}

void clear_abstraction_regs(struct ghost_state *g)
{
	g->regs.present = false;
}

void clear_abstraction_vm(struct ghost_state *g, pkvm_handle_t handle)
{
	ghost_assert_vms_table_locked();
	ghost_vms_free(&g->vms, handle);
}

void clear_abstraction_vms(struct ghost_state *g)
{
	int i;
	ghost_assert_vms_table_locked();
	g->vms.present = false;
	for (i=0; i<KVM_MAX_PVMS; i++) {
		ghost_vm_clear_slot(&g->vms.table[i]);
	}
}

void clear_abstraction_all(struct ghost_state *g)
{
	clear_abstraction_pkvm(g);
	clear_abstraction_host(g);
	clear_abstraction_regs(g);
	clear_abstraction_vms(g);
	for (int i=0; i<NR_CPUS; i++) {
		g->loaded_hyp_vcpu[i].present = false;
	}
}

void clear_abstraction_thread_local(void)
{
	ghost_lock_maplets();
	clear_abstraction_all(this_cpu_ptr(&gs_recorded_pre));
	clear_abstraction_all(this_cpu_ptr(&gs_recorded_post));
	clear_abstraction_all(this_cpu_ptr(&gs_computed_post));
	ghost_unlock_maplets();
}

void copy_abstraction_regs(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert(g_src->regs.present);
	ghost_assert(!g_tgt->regs.present);
	memcpy((void*) &(g_tgt->regs), (void*) &(g_src->regs), sizeof(struct ghost_register_state));
}

void copy_abstraction_hyp_memory(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	g_tgt->hyp_memory = mapping_copy(g_src->hyp_memory);
}

void copy_abstraction_pkvm(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert_maplets_locked();
	ghost_assert(g_src->pkvm.present);
	clear_abstraction_pkvm(g_tgt);
	g_tgt->pkvm.present = g_src->pkvm.present;
	g_tgt->pkvm.pkvm_abstract_pgtable.root = g_src->pkvm.pkvm_abstract_pgtable.root;
	g_tgt->pkvm.pkvm_abstract_pgtable.mapping = mapping_copy(g_src->pkvm.pkvm_abstract_pgtable.mapping);
}

void copy_abstraction_host(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert_maplets_locked();
	ghost_assert(g_src->host.present);
	clear_abstraction_host(g_tgt);
	g_tgt->host.present = true;
	g_tgt->host.host_abstract_pgtable_annot.root = g_src->host.host_abstract_pgtable_annot.root;
	g_tgt->host.host_abstract_pgtable_annot.mapping = mapping_copy(g_src->host.host_abstract_pgtable_annot.mapping);
	g_tgt->host.host_abstract_pgtable_shared.root = g_src->host.host_abstract_pgtable_shared.root;
	g_tgt->host.host_abstract_pgtable_shared.mapping = mapping_copy(g_src->host.host_abstract_pgtable_shared.mapping);
	g_tgt->host.host_abstract_pgtable_nonannot.root = g_src->host.host_abstract_pgtable_nonannot.root;
	g_tgt->host.host_abstract_pgtable_nonannot.mapping = mapping_copy(g_src->host.host_abstract_pgtable_nonannot.mapping);
}

void copy_abstraction_vms(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	ghost_assert_maplets_locked();
	ghost_assert_vms_table_locked();
	ghost_assert(g_src->vms.present);

	clear_abstraction_vms(g_tgt);

	// since we just cleared the whole table in tgt, can just copy the src one over.
	for (int i=0; i<KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *src_slot = &g_src->vms.table[i];
		struct ghost_vm_slot *tgt_slot = &g_tgt->vms.table[i];
		bool exists = src_slot->exists;
		tgt_slot->exists = src_slot->exists;
		if (exists) {
			ghost_vm_clone_into(&tgt_slot->vm, &src_slot->vm);
		}
	}
}

void ghost_vm_clone_into_nomappings(struct ghost_vm *dest, struct ghost_vm *src)
{
	ghost_assert_vms_table_locked();
	hyp_assert_lock_held(src->lock);

	dest->nr_vcpus = src->nr_vcpus;
	ghost_assert(src->nr_vcpus <= KVM_MAX_VCPUS);
	for (int vcpu_idx=0; vcpu_idx<src->nr_vcpus; vcpu_idx++) {
		dest->vcpus[vcpu_idx] = src->vcpus[vcpu_idx];
	}
	dest->pkvm_handle = src->pkvm_handle;
	dest->lock = src->lock;
}

void ghost_vm_clone_into(struct ghost_vm *dest, struct ghost_vm *src)
{
	ghost_assert_vms_table_locked();
	ghost_vm_clone_into_nomappings(dest, src);
	dest->vm_abstract_pgtable = abstract_pgtable_copy(src->vm_abstract_pgtable);
}

void copy_abstraction_vm(struct ghost_state *g_tgt, struct ghost_state *g_src, pkvm_handle_t handle)
{
	ghost_assert_maplets_locked();
	ghost_assert_vms_table_locked();

	struct ghost_vm *src_vm = ghost_vms_get(&g_src->vms, handle);
	ghost_assert(src_vm);

	hyp_assert_lock_held(src_vm->lock);

	clear_abstraction_vm(g_tgt, handle);
	struct ghost_vm *tgt_vm = ghost_vms_alloc(&g_tgt->vms, handle);

	ghost_vm_clone_into(tgt_vm, src_vm);
}

void copy_abstraction_loaded_vcpus(struct ghost_state *g_tgt, struct ghost_state *g_src)
{
	for (int i=0; i<NR_CPUS; i++) {
		if (g_src->loaded_hyp_vcpu[i].present) {
			g_tgt->loaded_hyp_vcpu[i] = g_src->loaded_hyp_vcpu[i];
		}
	}
}

void record_abstraction_hyp_memory(struct ghost_state *g)
{
	g->hyp_memory = compute_abstraction_hyp_memory();
}

void record_abstraction_pkvm(struct ghost_state *g)
{
	ghost_assert(!g->pkvm.present);
	g->pkvm = compute_abstraction_pkvm();
}

/* from nvhe/pkvm.c */
extern DEFINE_PER_CPU(struct pkvm_hyp_vcpu *, loaded_hyp_vcpu);

/*
 * record the currently loaded vcpu on this core
 * this must be called after loading pkvm
 */
void record_abstraction_loaded_vcpu(struct ghost_state *g)
{
	bool loaded = false;
	pkvm_handle_t vm_handle = 0;
	u64 vcpu_index = 0;
	struct pkvm_hyp_vcpu *loaded_vcpu = this_cpu_ptr(loaded_hyp_vcpu);
	if (loaded_vcpu) {
		// Now we dereference the vcpu struct, even though we're not protected by a lock
		// this is somehow ok?
		vm_handle = loaded_vcpu->vcpu.kvm->arch.pkvm.handle;
		vcpu_index = loaded_vcpu->vcpu.vcpu_idx;
		loaded = true;
	}
	// TODO: get_cpu() causes a linker error "undefined reference to `__kvm_nvhe_cpu_number'"
	g->loaded_hyp_vcpu[get_cpu()] = (struct ghost_loaded_vcpu){
		.present = true,
		.loaded = loaded,
		.vm_handle = vm_handle,
		.vcpu_index = vcpu_index,
	};
}

void record_abstraction_host(struct ghost_state *g)
{
	ghost_assert(!g->host.present);
	g->host = compute_abstraction_host();
}

void record_abstraction_vm(struct ghost_state *g, struct pkvm_hyp_vm *vm)
{
	ghost_assert_vms_table_locked();
	if (!g->vms.present) {
		// this creates an empty table of vm slots (where all .exists are false)
		g->vms = (struct ghost_vms){ 0 };
		g->vms.present = true;
	}

	// we really should only call record_abstraction_vm to record a vm that actually exists
	// and that we own
	ghost_assert(vm);
	hyp_assert_lock_held(&vm->lock);

	pkvm_handle_t handle = vm->kvm.arch.pkvm.handle;
	struct ghost_vm ghost_vm = compute_abstraction_vm(vm);

	// get, and if it doesn't exist, create one
	struct ghost_vm *slot = ghost_vms_get(&g->vms, handle);
	if (!slot) {
		slot = ghost_vms_alloc(&g->vms, handle);
	}

	// just copy in, this should be safe
	*slot = ghost_vm;
}

void record_abstraction_regs(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	int i;
	g->regs.present = true;

	// copy GPR values from the ctxt saved by the exception vector
	for (i=0; i<=30; i++) {
		g->regs.ctxt.regs.regs[i] = ctxt->regs.regs[i];
	}
	// save EL2 registers
	ghost_get_sysregs(g->regs.el2_sysregs);
	// save EL1 registers comprising pKVM's view of the context
	// __sysreg_save_state_nvhe(ctxt);
}

void record_abstraction_regs_pre(struct kvm_cpu_context *ctxt)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_regs(g, ctxt);
}

void record_abstraction_regs_post(struct kvm_cpu_context *ctxt)
{
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_regs(g, ctxt);
}

void record_abstraction_all(struct ghost_state *g, struct kvm_cpu_context *ctxt)
{
	record_abstraction_hyp_memory(g);
	record_abstraction_pkvm(g);
	record_abstraction_host(g);
	if (ctxt) {
		record_abstraction_regs(g,ctxt);
	}
	g->hyp_physvirt_offset = hyp_physvirt_offset;
}

void record_abstraction_common(void)
{
	ghost_lock_maplets();
	record_abstraction_all(&gs, NULL);
	ghost_unlock_maplets();
}

void record_and_check_abstraction_pkvm_pre(void)
{
	hyp_putsp("record_and_check_abstraction_pkvm_pre\n");
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_pkvm(g);
	ghost_spec_assert(abstraction_equals_pkvm(g->pkvm, gs.pkvm));
	ghost_unlock_maplets();
}

void record_and_copy_abstraction_pkvm_post(void)
{
	hyp_putsp("record_and_copy_abstraction_pkvm_post\n");
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_pkvm(g);
	copy_abstraction_pkvm(&gs, g);
	ghost_unlock_maplets();
}

void record_and_check_abstraction_host_pre(void)
{
	hyp_putsp("record_and_check_abstraction_host_pre\n");
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	record_abstraction_host(g);
	hyp_putsp("a-e-h: record_and_check_abstraction_host_pre\n");
	ghost_spec_assert(abstraction_equals_host(g->host, gs.host));
	ghost_unlock_maplets();
}

void record_and_copy_abstraction_host_post(void)
{
	hyp_putsp("record_and_copy_abstraction_host_post\n");
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_host(g);
	copy_abstraction_host(&gs, g);
	ghost_unlock_maplets();
}

void record_and_check_abstraction_loaded_hyp_vcpu_pre(void)
{
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_loaded_vcpu(g);
	ghost_spec_assert(abstraction_equals_loaded_vcpus(g, &gs));
	ghost_unlock_maplets();
}

void record_and_copy_abstraction_loaded_hyp_vcpu_post(void)
{
	ghost_lock_maplets();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_loaded_vcpu(g);
	copy_abstraction_loaded_vcpus(&gs, g);
	ghost_unlock_maplets();
}

void record_and_check_abstraction_vm_pre(struct pkvm_hyp_vm *vm)
{
	// TODO: (and for the others) maplets are already locked by the top-level hcall
	// but this isn't right (e.g. for vpu_run), and it should be at least this
	// (if not more!) fine-grained locking for maplets and the vms.vms table.
	ghost_lock_maplets();
	ghost_lock_vms_table();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_pre);
	pkvm_handle_t handle = vm->kvm.arch.pkvm.handle;
	record_abstraction_vm(g, vm);
	ghost_spec_assert(abstraction_vm_in_vms_and_equal(handle, g, &gs.vms));
	ghost_unlock_vms_table();
	ghost_unlock_maplets();
}

void record_and_copy_abstraction_vm_post(struct pkvm_hyp_vm *vm)
{
	ghost_lock_maplets();
	ghost_lock_vms_table();
	struct ghost_state *g = this_cpu_ptr(&gs_recorded_post);
	record_abstraction_vm(g, vm);
	copy_abstraction_vm(&gs, g, vm->kvm.arch.pkvm.handle);
	ghost_unlock_vms_table();
	ghost_unlock_maplets();
}


/****************************************/
// locking

DEFINE_HYP_SPINLOCK(ghost_vms_lock);

void ghost_lock_vms_table(void) {
	hyp_spin_lock(&ghost_vms_lock);
}

void ghost_unlock_vms_table(void) {
	hyp_spin_unlock(&ghost_vms_lock);
}

inline void ghost_assert_vms_table_locked(void) {
	hyp_assert_lock_held(&ghost_vms_lock);
}

/****************************************/
// ghost_call_data helpers

void ghost_relaxed_reads_insert(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width, u64 value)
{
	rs->read_slots[rs->len++] = (struct ghost_read){
		.phys_addr = phys_addr,
		.width = width,
		.value = value,
	};
	BUG_ON(rs->len > GHOST_MAX_RELAXED_READS);
}

u64 ghost_relaxed_reads_get(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width)
{
	int i;
	for (i=0; i<rs->len; i++) {
		struct ghost_read *r = &rs->read_slots[i];
		if (r->phys_addr == phys_addr && r->width == width)
			return r->value;
	}

	/* If the spec tries to read a relaxed read which wasn't read during the call
	 * then the spec is clearly incorrect. */
	ghost_spec_assert(false);
	unreachable();
}