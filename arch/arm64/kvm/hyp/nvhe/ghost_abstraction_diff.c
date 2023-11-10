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

#include <hyp/ghost_extra_debug-pl011.h>
#include <nvhe/ghost_pgtable.h>
#include <nvhe/ghost_spec.h>
#include <nvhe/ghost_asm.h>
#include <nvhe/ghost_asm_ids.h>

#include <nvhe/ghost_abstraction_diff.h>

DEFINE_HYP_SPINLOCK(ghost_diff_lock);

struct ghost_diff_memory {
	u64 len;
	struct ghost_diff *free_list;
	struct ghost_diff nodes[100];
};

/***********************/
// Awful Allocation

struct ghost_diff_memory the_memory;

struct ghost_diff *__alloc_diff(void)
{
	struct ghost_diff *node;
	if (the_memory.free_list) {
		node = the_memory.free_list;
		the_memory.free_list = *(struct ghost_diff**)node;
	} else {
		ghost_assert(the_memory.len < 100);
		node = &the_memory.nodes[the_memory.len++];
	}
	memset(node, 0, sizeof(struct ghost_diff));
	return node;
}

static void __free_node(struct ghost_diff *container)
{
	struct ghost_diff *free_list;
	free_list = the_memory.free_list;
	the_memory.free_list = container;
	memcpy((void*)container, &free_list, sizeof(struct ghost_diff *));
}

struct ghost_diff *alloc_diff(void)
{
	struct ghost_diff *node;
	hyp_spin_lock(&ghost_diff_lock);
	node = __alloc_diff();
	hyp_spin_unlock(&ghost_diff_lock);
	return node;
}

void free_node(struct ghost_diff *node)
{
	hyp_spin_lock(&ghost_diff_lock);
	__free_node(node);
	hyp_spin_unlock(&ghost_diff_lock);
}

void free_container(struct ghost_diff *node)
{
	ghost_assert(node->kind == GHOST_DIFF_CONTAINER);

	for (int c = 0; c < node->container.nr_children; c++) {
		free_diff(node->container.children[c]);
	}

	free_node(node);
}

void free_diff(struct ghost_diff *node)
{
	ghost_assert(node);
	switch (node->kind) {
	case GHOST_DIFF_CONTAINER:
		free_container(node);
		break;
	default:
		free_node(node);
		break;
	}
}


struct ghost_diff *normalise(struct ghost_diff *node)
{
	if (node->kind != GHOST_DIFF_CONTAINER)
		return node;

	if (node->container.nr_children > 0)
		return node;

	free_container(node);
	return NULL;
}

/****************************/
// Creation


struct ghost_diff *container(void)
{
	struct ghost_diff *node = alloc_diff();
	node->key = TSTR(NULL);
	node->kind = GHOST_DIFF_CONTAINER;
	node->container.nr_children = 0;
	return node;
}

static bool val_equal(struct diff_val lhs, struct diff_val rhs)
{
	switch (lhs.kind) {
	case Tbool:
		return lhs.b == rhs.b;
	case Tu64:
		return lhs.n == rhs.n;
	case Tstr:
		return !strcmp(lhs.s, rhs.s);
	case Tmaplet:
		return false;
	default:
		BUG();
	}
}

/**
 * Compare two Tval and if not equal, return a diff.
 */
struct ghost_diff *diff_pair(struct diff_val lhs, struct diff_val rhs)
{
	if (val_equal(lhs, rhs))
		return NULL;

	struct ghost_diff *node = alloc_diff();
	node->key = TSTR(NULL);
	node->kind = GHOST_DIFF_PAIR;
	node->pair.lhs = lhs;
	node->pair.rhs = rhs;
	return node;
}

struct ghost_diff *diff_pm(bool add, struct diff_val val)
{
	struct ghost_diff *node = alloc_diff();
	node->key = TSTR(NULL);
	node->kind = GHOST_DIFF_PM;
	node->pm.add = add;
	node->pm.val = val;
	return node;
}

static void __attach(struct ghost_diff *container, struct diff_val key, struct ghost_diff *child)
{
	ghost_assert(container->kind == GHOST_DIFF_CONTAINER);
	ghost_assert(container->container.nr_children < DIFF_MAX_CHILDREN);

	if (child != NULL) {
		child->key = key;
		container->container.children[container->container.nr_children++] = child;
	}
}

void ghost_diff_field(struct ghost_diff *container, char *key, struct ghost_diff *child)
{
	__attach(container, TSTR(key), child);
}

void ghost_diff_index(struct ghost_diff *container, u64 key, struct ghost_diff *child)
{
	__attach(container, TU64(key), child);
}

void ghost_diff_attach(struct ghost_diff *container, struct ghost_diff *child)
{
	__attach(container, TSTR(NULL), child);
}

/****************/
// Differ!

struct ghost_diff *ghost_diff_pfns_array(struct pfn_set *s1, struct pfn_set *s2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "len", diff_pair(TU64(s1->len), TU64(s2->len)));

	for (int i = 0; i < s2->len; i++) {
		u64 pfn = s2->external_pfns[i];

		if (! ghost_pfn_set_contains(s1, pfn))
			ghost_diff_field(node, "pfn", diff_pm(true, TU64(pfn)));
	}

	for (int i = 0; i < s1->len; i++) {
		u64 pfn = s1->external_pfns[i];

		if (! ghost_pfn_set_contains(s2, pfn))
			ghost_diff_field(node, "pfn", diff_pm(false, TU64(pfn)));
	}

	return normalise(node);
}

struct ghost_diff *ghost_diff_pfns(struct pfn_set *s1, struct pfn_set *s2) {
	struct ghost_diff *node = container();
	ghost_diff_field(node, "pool_range_start", diff_pair(TU64(s1->pool_range_start), TU64(s2->pool_range_start)));
	ghost_diff_field(node, "pool_range_end", diff_pair(TU64(s1->pool_range_end), TU64(s2->pool_range_end)));
	ghost_diff_field(node, "external_pfns", ghost_diff_pfns_array(s1, s2));
	return normalise(node);
}

struct ghost_diff *ghost_diff_mappings(mapping *mp1, mapping *mp2)
{
	struct ghost_diff *node = container();
	struct glist_head head1 = *(struct glist_head*)mp1;
	struct glist_head head2 = *(struct glist_head*)mp2;
	struct glist_node *pos1, *pos2;
	struct maplet *m1, *m2;

	ghost_assert_maplets_locked();

	if (glist_empty(&head1) && glist_empty(&head2)) {
		return NULL;
	}

	if (glist_empty(&head1)) {
		ghost_diff_attach(node, diff_pm(true, TMAPLET(glist_entry(head2.first, struct maplet, list))));
	}

	if (glist_empty(&head2)) {
		ghost_diff_attach(node, diff_pm(false, TMAPLET(glist_entry(head1.first, struct maplet, list))));
	}

	pos1 = head1.first;
	pos2 = head2.first;
	while (pos1 != NULL || pos2 != NULL) {
		if (pos1 != NULL)
			m1 = glist_entry(pos1, struct maplet, list);

		if (pos2 != NULL)
			m2 = glist_entry(pos2, struct maplet, list);

		if (pos1 == NULL) {
			ghost_diff_attach(node, diff_pm(true, TMAPLET(m2)));
			pos2 = pos2->next;
	 	} else if (pos2 == NULL) {
			ghost_diff_attach(node, diff_pm(false, TMAPLET(m1)));
			pos1 = pos1->next;
		} else if ( !(maplet_eq(m1, m2)) ) {
			if (m1->virt < m2->virt) {
				ghost_diff_attach(node, diff_pm(false, TMAPLET(m1)));
				pos1=pos1->next;
			} else if (m1->virt > m2->virt) {
				ghost_diff_attach(node, diff_pm(true, TMAPLET(m2)));
				pos2=pos2->next;
			} else {
				ghost_diff_attach(node, diff_pair(TMAPLET(m1), TMAPLET(m2)));
				pos1 = pos1->next;
				pos2 = pos2->next;
			}
		} else {
			pos1 = pos1->next;
			pos2 = pos2->next;
		}

		if (pos1 == NULL && pos2 == NULL)
			break;
	}

	return normalise(node);
}



struct ghost_diff *ghost_diff_pgtable(abstract_pgtable *ap1, abstract_pgtable *ap2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "pfns", ghost_diff_pfns(&ap1->table_pfns, &ap2->table_pfns));
	ghost_diff_field(node, "mapping", ghost_diff_mappings(&ap1->mapping, &ap2->mapping));
	return normalise(node);
}

struct ghost_diff *ghost_diff_pkvm(struct ghost_pkvm *p1, struct ghost_pkvm *p2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "present", diff_pair(TBOOL(p1->present), TBOOL(p2->present)));
	if (p1->present && p2->present)
		ghost_diff_field(node, "pgtable", ghost_diff_pgtable(&p1->pkvm_abstract_pgtable, &p2->pkvm_abstract_pgtable));
	return normalise(node);
}

struct ghost_diff *ghost_diff_host(struct ghost_host *h1, struct ghost_host *h2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "present", diff_pair(TBOOL(h1->present), TBOOL(h2->present)));
	if (h1->present && h2->present) {
		ghost_diff_field(node, "pfns", ghost_diff_pfns(&h1->host_pgtable_pages, &h2->host_pgtable_pages));
		ghost_diff_field(node, "annot", ghost_diff_mappings(&h1->host_abstract_pgtable_annot, &h2->host_abstract_pgtable_annot));
		ghost_diff_field(node, "shared", ghost_diff_mappings(&h1->host_abstract_pgtable_shared, &h2->host_abstract_pgtable_shared));
	}
	return normalise(node);
}

struct ghost_diff *ghost_diff_registers(struct ghost_register_state *r1, struct ghost_register_state *r2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "present", diff_pair(TBOOL(r1->present), TBOOL(r2->present)));
	if (r1->present && r2->present) {
		int i;
		struct ghost_diff *gprs = container();
		struct ghost_diff *el1_sysregs = container();
		struct ghost_diff *el2_sysregs = container();

		u64 ghost_el2_regs[] = (u64[])GHOST_EL2_REGS;
		for (i=0; i<=30; i++) {
			ghost_diff_index(gprs, i, diff_pair(TU64(r1->ctxt.regs.regs[i]), TU64(r2->ctxt.regs.regs[i])));
		}
		for (i=0; i<NR_SYS_REGS; i++) {
			const char *name = GHOST_VCPU_SYSREG_NAMES[i];
			ghost_diff_field(el1_sysregs, (char *)name, diff_pair(TU64(r1->ctxt.sys_regs[i]), TU64(r2->ctxt.sys_regs[i])));
		}
		for (i=0; i<sizeof(ghost_el2_regs)/sizeof(u64); i++) {
			u64 r = ghost_el2_regs[i];
			const char *name = GHOST_EL2_REG_NAMES[r];
			ghost_diff_field(el1_sysregs, (char *)name, diff_pair(TU64(r1->el2_sysregs[r]), TU64(r2->el2_sysregs[r])));
		}
		ghost_diff_field(node, "gprs", normalise(gprs));
		ghost_diff_field(node, "el1_sysregs", normalise(el1_sysregs));
		ghost_diff_field(node, "el2_sysregs", normalise(el2_sysregs));
	}
	return normalise(node);
}

struct ghost_diff *ghost_diff_vcpu(struct ghost_vcpu *vcpu1, struct ghost_vcpu *vcpu2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "vcpu_handle", diff_pair(TU64(vcpu1->vcpu_handle), TU64(vcpu2->vcpu_handle)));
	ghost_diff_field(node, "loaded", diff_pair(TBOOL(vcpu1->loaded), TBOOL(vcpu2->loaded)));
	ghost_diff_field(node, "initialised", diff_pair(TBOOL(vcpu1->initialised), TBOOL(vcpu2->initialised)));
	ghost_diff_field(node, "regs", ghost_diff_registers(&vcpu1->regs, &vcpu2->regs));
	return normalise(node);
}

struct ghost_diff *ghost_diff_vm(struct ghost_vm *vm1, struct ghost_vm *vm2)
{
	struct ghost_diff *node = container();
	// in theory: handle should be the same...
	ghost_diff_field(node, "handle", diff_pair(TU64((u64)vm1->pkvm_handle), TU64((u64)vm2->pkvm_handle)));
	if (vm1->pkvm_handle == vm2->pkvm_handle) {
		ghost_diff_field(node, "nr_vcpus", diff_pair(TU64(vm1->nr_vcpus), TU64(vm2->nr_vcpus)));
		ghost_diff_field(node, "nr_initialised_vcpus", diff_pair(TU64(vm1->nr_initialised_vcpus), TU64(vm2->nr_initialised_vcpus)));
		ghost_diff_field(node, "vm_abstract_pgtable", ghost_diff_pgtable(&vm1->vm_abstract_pgtable, &vm2->vm_abstract_pgtable));

		for (u64 i = 0; i < KVM_MAX_VCPUS; i++) {
			struct ghost_vcpu *vcpu1 = vm1->vcpus[i];
			struct ghost_vcpu *vcpu2 = vm1->vcpus[i];

			if (vcpu1 && vcpu2) {
				ghost_diff_index(node, i, ghost_diff_vcpu(vcpu1, vcpu2));
			} else if (!vcpu1 && !vcpu2) {
				continue;
			} else if (vcpu1) {
				ghost_diff_index(node, i, diff_pm(false, TU64(i)));
			} else {
				ghost_diff_index(node, i, diff_pm(true, TU64(i)));
			}
		}
	}

	return normalise(node);
}

struct ghost_diff *ghost_diff_vms(struct ghost_vms *vms1, struct ghost_vms *vms2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "present", diff_pair(TBOOL(vms1->present), TBOOL(vms2->present)));
	if (!vms1->present || !vms2->present)
		goto cleanup;

	// find those that were removed from vms2
	for (int i = 0; i < KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &vms1->table[i];
		if (slot->exists) {
			pkvm_handle_t handle = slot->handle;
			struct ghost_vm *vm2 = ghost_vms_get(vms2, handle);
			if (! vm2) {
				ghost_diff_index(node, (u64)handle, diff_pm(false, TU64((u64)handle)));
			}
		}
	}

	// now find those added or changed
	for (int i = 0; i < KVM_MAX_PVMS; i++) {
		struct ghost_vm_slot *slot = &vms2->table[i];
		if (slot->exists) {
			pkvm_handle_t handle = slot->handle;
			struct ghost_vm *vm2 = slot->vm;
			struct ghost_vm *vm1 = ghost_vms_get(vms1, handle);
			if (! vm1) {
				ghost_diff_index(node, (u64)handle, diff_pm(true, TU64((u64)handle)));
			} else {
				ghost_diff_index(node, (u64)handle, ghost_diff_vm(vm1, vm2));
			}
		}
	}
	ghost_diff_field(node, "present", diff_pair(TBOOL(vms1->present), TBOOL(vms2->present)));

cleanup:
	return normalise(node);
}


struct ghost_diff *ghost_diff_globals(struct ghost_constant_globals *g1, struct ghost_constant_globals *g2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "hyp_nr_cpus", diff_pair(TU64(g1->hyp_nr_cpus), TU64(g2->hyp_nr_cpus)));
	ghost_diff_field(node, "hyp_physvirt_offset", diff_pair(TU64(g1->hyp_physvirt_offset), TU64(g2->hyp_physvirt_offset)));
	ghost_diff_field(node, "tag_lsb", diff_pair(TU64(g1->tag_lsb), TU64(g2->tag_lsb)));
	ghost_diff_field(node, "tag_val", diff_pair(TU64(g1->tag_val), TU64(g2->tag_val)));
	return normalise(node);
}

struct ghost_diff *ghost_diff_loaded_vcpu(struct ghost_loaded_vcpu *vcpu1, struct ghost_loaded_vcpu *vcpu2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "present", diff_pair(TBOOL(vcpu1->present), TBOOL(vcpu2->present)));
	if (vcpu1->present && vcpu2->present) {
		ghost_diff_field(node, "loaded", diff_pair(TBOOL(vcpu1->loaded), TBOOL(vcpu2->loaded)));
		if (vcpu1->loaded && vcpu2->loaded) {
			ghost_diff_field(node, "vm_handle", diff_pair(TU64(vcpu1->vm_handle), TU64(vcpu2->vm_handle)));
			ghost_diff_field(node, "vcpu_index", diff_pair(TU64(vcpu1->vcpu_index), TU64(vcpu2->vcpu_index)));
		}
	}
	return normalise(node);
}

struct ghost_diff *ghost_diff_running_state(struct ghost_running_state *r1, struct ghost_running_state *r2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "guest_running", diff_pair(TBOOL(r1->guest_running), TU64(r2->guest_running)));
	if (r1->guest_running && r2->guest_running) {
		ghost_diff_field(node, "vm_handle", diff_pair(TU64(r1->vm_handle), TU64(r2->vm_handle)));
		ghost_diff_field(node, "vcpu_index", diff_pair(TU64(r1->vcpu_index), TU64(r2->vcpu_index)));
	}
	return normalise(node);
}

struct ghost_diff *ghost_diff_state(struct ghost_state *s1, struct ghost_state *s2)
{
	struct ghost_diff *node = container();
	ghost_diff_field(node, "pkvm", ghost_diff_pkvm(&s1->pkvm, &s2->pkvm));
	ghost_diff_field(node, "host", ghost_diff_host(&s1->host, &s2->host));
	ghost_diff_field(node, "vms", ghost_diff_vms(&s1->vms, &s2->vms));
	ghost_diff_field(node, "regs", ghost_diff_registers(this_cpu_ghost_register_state(s1), this_cpu_ghost_register_state(s2)));
	ghost_diff_field(node, "globals", ghost_diff_globals(&s1->globals, &s2->globals));
	ghost_diff_field(node, "loaded_vcpu", ghost_diff_loaded_vcpu(this_cpu_ghost_loaded_vcpu(s1), this_cpu_ghost_loaded_vcpu(s2)));
	ghost_diff_field(node, "running_state", ghost_diff_running_state(this_cpu_ghost_run_state(s1), this_cpu_ghost_run_state(s2)));
	return normalise(node);
}

/************************************/
// Printing

static void __put_val(struct diff_val val, u64 indent)
{
	switch (val.kind) {
	case Tu64:
		hyp_putx64(val.n);
		break;
	case Tstr:
		if (val.s)
			hyp_putsp(val.s);
		break;
	case Tbool:
		hyp_putbool(val.b);
		break;
	case Tmaplet:
		hyp_put_maplet(val.m, indent);
		break;
	}
}


static void __hyp_dump_diff(struct ghost_diff *diff, u64 indent)
{
	if (! (diff->key.kind == Tstr && diff->key.s == NULL)) {
		hyp_puti(indent);
		__put_val(diff->key, indent);
		hyp_puts(": ");
	}

	switch (diff->kind) {
	case GHOST_DIFF_CONTAINER:
		hyp_puts("\n");
		for (int i = 0; i < diff->container.nr_children; i++) {
			__hyp_dump_diff(diff->container.children[i], indent + 2);
		};
		break;
	case GHOST_DIFF_PM:
		if (diff->pm.add)
			hyp_puts(GHOST_WHITE_ON_GREEN "+");
		else
			hyp_puts(GHOST_WHITE_ON_RED "-");

		__put_val(diff->pm.val, indent+2);

		hyp_puts(GHOST_NORMAL);
		break;
	case GHOST_DIFF_PAIR:
		hyp_puts("\n");
		hyp_puts(GHOST_WHITE_ON_RED "-");
		__put_val(diff->pair.lhs, indent + 2);
		hyp_puts(GHOST_NORMAL);

		hyp_puts("\n");

		hyp_puts(GHOST_WHITE_ON_GREEN "+");
		__put_val(diff->pair.rhs, indent + 2);
		hyp_puts(GHOST_NORMAL);
		break;
	}
}

void hyp_dump_diff(struct ghost_diff *diff)
{
	if (!diff)
		hyp_puts("<identical>");
	else
		__hyp_dump_diff(diff, 0);
}