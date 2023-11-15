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

#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
#include <nvhe/ghost_simplified_model.h>
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

#define MAX_PRINT_DIFF_PER_SUBFIELDS CONFIG_NVHE_GHOST_DIFF_MAX_DIFFS_PER_NODE

/*
 * Ghost state diffs:
 * The whole ghost state is arranged as a tree
 * so we duplicate that tree structure by walking the state
 */

enum ghost_diff_kind {
	/**
	 * A pair that matched (no diff)
	 */
	GHOST_DIFF_NONE,

	/**
	 * A pair that didn't match.
	 */
	GHOST_DIFF_PAIR,

	/**
	 * An element that was or wasn't there.
	 */
	GHOST_DIFF_PM,
};

/*
 * I Hate C, so let's just wrap up the common values (u64, bool, char* etc)
 * so can write some half-generic functions.
 */
enum ghost_diff_val_kind {
	/* suitable for keys */
	Tu64,
	Tstr,
	Tgpr,

	/* Plus some more */
	Tbool,

	/* A pair of a format string and u64
	 * ("%...", u64)
	 * which can be passed to ghost_snprintf
	 * to generate a string to diff */
	Tgprint,
};

struct diff_val {
	enum ghost_diff_val_kind kind;
	union {
		bool b;
		u64 n;
		char *s;

		// this is okay to be a reference since the diff is only alive if the two diff'd objects are.
		struct gprint_data {
			const char *fmt;
			void *ptr;
	 	} gp;
	};
};
#define TBOOL(value) (struct diff_val){.kind=Tbool, .b=(value)}
#define TU64(value) (struct diff_val){.kind=Tu64, .n=(value)}
#define TSTR(value) (struct diff_val){.kind=Tstr, .s=(value)}
#define TGPREG(value) (struct diff_val){.kind=Tgpr, .n=(value)}
#define TGPRINT(FMT, VAL) (struct diff_val){.kind=Tgprint, .gp=(struct gprint_data){.fmt=FMT, .ptr=(VAL)}}

#define TMAPLET(M) TGPRINT("%g(maplet)", M)

#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
#define TSMLOC(LOC) TGPRINT("%g(sm_loc)", LOC)
#define TSMBLOB(BLOB) TGPRINT("%g(sm_blob)", BLOB)
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

#define EMPTY_KEY TSTR(NULL)

struct ghost_diff {
	enum ghost_diff_kind kind;
	union {
		struct diff_pair_data {
			struct diff_val lhs;
			struct diff_val rhs;
		} pair;

		struct diff_pm_data {
			/**
			 * whether this is an addition or deletion...
			 */
			bool add;
			struct diff_val val;
		} pm;
	};
};

#define DIFF_NONE ((struct ghost_diff){.kind=GHOST_DIFF_NONE})
#define MAX_CONTAINER_PATH 32

struct diff_container {
	int depth;
	int clean_prefix;
	const char *path[MAX_CONTAINER_PATH];
	bool saw_diff;
	u64 nr_subfield_diffs;
};

/*********/
// Differ

static int __put_val_string(struct diff_val val, char *buf, u64 n)
{
	switch (val.kind) {
	case Tu64:
		return ghost_snprintf(buf, n, "%lx", val.n);
	case Tstr:
		return ghost_snprintf(buf, n, "%s", val.s);
	case Tbool:
		if (val.b)
			return ghost_snprintf(buf, n, "true");
		else
			return ghost_snprintf(buf, n, "false");
	case Tgpr:
		return ghost_snprintf(buf, n, "r%ld", val.n);
	case Tgprint:
		return ghost_snprintf(buf, n, val.gp.fmt, val.gp.ptr);
	default:
		BUG();
	}
}

static bool val_equal(struct diff_val lhs, struct diff_val rhs)
{
	if (lhs.kind != rhs.kind)
		return false;

	switch (lhs.kind) {
	case Tbool:
		return lhs.b == rhs.b;
	case Tu64:
	case Tgpr:
		return lhs.n == rhs.n;
	case Tstr:
		if (!lhs.s || !rhs.s)
			return lhs.s == rhs.s;
		else
			return !strcmp(lhs.s, rhs.s);
	case Tgprint: {
		/* 256 should be long enough for any of our ghost-y prints.
		 * by construction */
		char buf1[256];
		char buf2[256];
		int r1 = __put_val_string(lhs, buf1, 256);
		int r2 = __put_val_string(rhs, buf2, 256);
		if (r1 || r2) {
			GHOST_ERROR_VAR(r1, u32);
			GHOST_ERROR_VAR(r2, u32);
			ghost_assert(false);
		}
		return !strcmp(buf1, buf2);
	}
	default:
		BUG();
	}
}

static void __put_val(struct diff_val val, u64 indent)
{
	switch (val.kind) {
	case Tu64:
		ghost_printf("%lx", val.n);
		break;
	case Tstr:
		ghost_printf("%s", val.s);
		break;
	case Tbool:
		if (val.b)
			ghost_printf("true");
		else
			ghost_printf("false");
		break;
	case Tgpr:
		ghost_printf("r%ld", val.n);
		break;
	case Tgprint:
		ghost_printf(val.gp.fmt, val.gp.ptr);
		break;
	default:
		BUG();
	}
}



static void __put_dirty_string(char *s, bool *dirty, bool negate)
{
	while (*s) {
		char c = *s++;
		bool d = *dirty++;

		if (!d)
			ghost_printf("%c", c);
		else if (negate)
			ghost_printf("%s%c%s", GHOST_WHITE_ON_RED, c, GHOST_NORMAL);
		else
			ghost_printf("%s%c%s", GHOST_WHITE_ON_GREEN, c, GHOST_NORMAL);
	}
}

#define GHOST_STRING_DUMP_LEN 256
static void __hyp_dump_string_diff(struct diff_val lhs, struct diff_val rhs)
{
	char lhs_s[GHOST_STRING_DUMP_LEN] = {0};
	char rhs_s[GHOST_STRING_DUMP_LEN] = {0};

	bool dirty[GHOST_STRING_DUMP_LEN] = {0};

	__put_val_string(lhs, lhs_s, GHOST_STRING_DUMP_LEN);
	__put_val_string(rhs, rhs_s, GHOST_STRING_DUMP_LEN);

	// now, we find those that differ
	// TODO: do something more clever, and find inserted/removed text.
	//       so far, everything is constant-width and consistent so it's ok
	for (int i = 0; i < GHOST_STRING_DUMP_LEN; i++) {
		if (lhs_s[i] != rhs_s[i])
			dirty[i] = true;
	}

	ghost_printf("\n");
	ghost_printf("-");
	__put_dirty_string(lhs_s, dirty, true);

	ghost_printf("\n");
	ghost_printf("+");
	__put_dirty_string(rhs_s, dirty, false);
}

static void __ghost_print_diff(struct ghost_diff *diff, u64 indent)
{
	switch (diff->kind) {
	case GHOST_DIFF_NONE:
		break;
	case GHOST_DIFF_PM:
		if (diff->pm.add)
			ghost_printf(GHOST_WHITE_ON_GREEN "+");
		else
			ghost_printf(GHOST_WHITE_ON_RED "-");

		__put_val(diff->pm.val, 0);

		ghost_printf(GHOST_NORMAL);
		break;
	case GHOST_DIFF_PAIR:
		__hyp_dump_string_diff(diff->pair.lhs, diff->pair.rhs);
		break;
	}
}


static void __put_key(struct diff_container *node, struct diff_val key)
{
	if (! val_equal(key, EMPTY_KEY)) {
		ghost_printf("\n%I", node->depth*4);
		__put_val(key, 0);
		ghost_printf(":");
	}

	ghost_printf("\n");
}

/**
 * Compare two Tval and if not equal, return a diff.
 */
static struct ghost_diff diff_pair(struct diff_val lhs, struct diff_val rhs)
{
	if (val_equal(lhs, rhs))
		return DIFF_NONE;

	struct ghost_diff n = {
		.kind = GHOST_DIFF_PAIR,
		.pair = (struct diff_pair_data){
			.lhs = lhs,
			.rhs = rhs,
		},
	};

	return n;
}

static struct ghost_diff diff_pm(bool add, struct diff_val val)
{
	struct ghost_diff n = {
		.kind = GHOST_DIFF_PM,
		.pm = (struct diff_pm_data){
			.add = add,
			.val = val,
		},
	};
	return n;
}

static void __attach(struct diff_container *node, struct diff_val key, struct ghost_diff diff)
{
	switch (diff.kind) {
	case GHOST_DIFF_NONE:
		break;
	default:
		node->nr_subfield_diffs++;

		// print out the part of the path we've not printed before.
		for (int i = node->clean_prefix; i < node->depth; i++) {
			ghost_printf("\n%I%s:", i*4, node->path[i]);
		};
		if (node->clean_prefix != node->depth && node->nr_subfield_diffs >= MAX_PRINT_DIFF_PER_SUBFIELDS)
			ghost_printf(GHOST_WHITE_ON_YELLOW "<skip diff>" GHOST_NORMAL "\n");

		node->clean_prefix = node->depth;
		node->saw_diff = true;

		if (node->nr_subfield_diffs < MAX_PRINT_DIFF_PER_SUBFIELDS) {
			__put_key(node, key);
			__ghost_print_diff(&diff, 0);
		} else if (node->nr_subfield_diffs == MAX_PRINT_DIFF_PER_SUBFIELDS) {
			// only once, not too noisy...
			ghost_printf("\n");
			ghost_printf(GHOST_WHITE_ON_YELLOW "<skipping diffs>" GHOST_NORMAL "\n");
		}
	}
}

static void ghost_diff_enter_subfield(struct diff_container *container, const char *name)
{
	container->path[container->depth++] = name;
}

static void ghost_diff_pop_subfield(struct diff_container *container)
{
	container->depth--;

	if (container->depth < container->clean_prefix)
		container->clean_prefix = container->depth;

	container->nr_subfield_diffs = 0;
}

static void ghost_diff_field(struct diff_container *container, char *key, struct ghost_diff child)
{
	__attach(container, TSTR(key), child);
}

static void ghost_diff_index(struct diff_container *container, u64 key, struct ghost_diff child)
{
	__attach(container, TU64(key), child);
}

static void ghost_diff_attach(struct diff_container *container, struct ghost_diff child)
{
	__attach(container, EMPTY_KEY, child);
}

static void ghost_diff_gpr(struct diff_container *container, u64 reg, struct ghost_diff child)
{
	__attach(container, TGPREG(reg), child);
}

/****************/
// Differ!

static void ghost_diff_registers(struct diff_container *node, struct ghost_register_state *r1, struct ghost_register_state *r2);

static void ghost_diff_pfns_array(struct diff_container *node, struct pfn_set *s1, struct pfn_set *s2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "external_pfns");
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

	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_pfns(struct diff_container *node, struct pfn_set *s1, struct pfn_set *s2) {
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "pfns");
	ghost_diff_field(node, "pool_range_start", diff_pair(TU64(s1->pool_range_start), TU64(s2->pool_range_start)));
	ghost_diff_field(node, "pool_range_end", diff_pair(TU64(s1->pool_range_end), TU64(s2->pool_range_end)));
	ghost_diff_pfns_array(node, s1, s2);
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_mappings(struct diff_container *node, const char *name, mapping *mp1, mapping *mp2)
{
	GHOST_LOG_CONTEXT_ENTER();
	struct glist_head head1 = *(struct glist_head*)mp1;
	struct glist_head head2 = *(struct glist_head*)mp2;
	struct glist_node *pos1, *pos2;
	struct maplet *m1, *m2;

	ghost_diff_enter_subfield(node, name);

	ghost_assert_maplets_locked();

	if (glist_empty(&head1) && glist_empty(&head2))
		goto cleanup_exit;

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
			if (m1->ia_range_start < m2->ia_range_start) {
				ghost_diff_attach(node, diff_pm(false, TMAPLET(m1)));
				pos1=pos1->next;
			} else if (m1->ia_range_start > m2->ia_range_start) {
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
cleanup_exit:
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}



static void ghost_diff_pgtable(struct diff_container *node, const char *name, abstract_pgtable *ap1, abstract_pgtable *ap2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, name);

	ghost_diff_pfns(node, &ap1->table_pfns, &ap2->table_pfns);
	ghost_diff_mappings(node, "mapping", &ap1->mapping, &ap2->mapping);

	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_pkvm(struct diff_container *node, struct ghost_pkvm *p1, struct ghost_pkvm *p2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "pkvm");
	ghost_diff_field(node, "present", diff_pair(TBOOL(p1->present), TBOOL(p2->present)));
	if (p1->present && p2->present)
		ghost_diff_pgtable(node, "pgtable", &p1->pkvm_abstract_pgtable, &p2->pkvm_abstract_pgtable);
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_host(struct diff_container *node, struct ghost_host *h1, struct ghost_host *h2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "host");
	ghost_diff_field(node, "present", diff_pair(TBOOL(h1->present), TBOOL(h2->present)));
	if (h1->present && h2->present) {
		ghost_diff_pfns(node, &h1->host_pgtable_pages, &h2->host_pgtable_pages);
		ghost_diff_mappings(node, "annot", &h1->host_abstract_pgtable_annot, &h2->host_abstract_pgtable_annot);
		ghost_diff_mappings(node, "shared", &h1->host_abstract_pgtable_shared, &h2->host_abstract_pgtable_shared);
	}
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_registers(struct diff_container *node, struct ghost_register_state *r1, struct ghost_register_state *r2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "regs");
	ghost_diff_field(node, "present", diff_pair(TBOOL(r1->present), TBOOL(r2->present)));
	if (r1->present && r2->present) {
		int i;

		u64 ghost_el2_regs[] = (u64[])GHOST_EL2_REGS;
		for (i=0; i<=30; i++) {
			GHOST_LOG_CONTEXT_ENTER_INNER("loop gpr");
			ghost_diff_gpr(node, i, diff_pair(TU64(r1->ctxt.regs.regs[i]), TU64(r2->ctxt.regs.regs[i])));
			GHOST_LOG_CONTEXT_EXIT_INNER("loop gpr");
		}
		for (i=0; i<NR_SYS_REGS; i++) {
			GHOST_LOG_CONTEXT_ENTER_INNER("loop sysreg");
			const char *name = GHOST_VCPU_SYSREG_NAMES[i];
			ghost_diff_field(node, (char *)name, diff_pair(TU64(r1->ctxt.sys_regs[i]), TU64(r2->ctxt.sys_regs[i])));
			GHOST_LOG_CONTEXT_EXIT_INNER("loop sysreg");
		}
		for (i=0; i<sizeof(ghost_el2_regs)/sizeof(u64); i++) {
			GHOST_LOG_CONTEXT_ENTER_INNER("loop el2_regs");
			u64 r = ghost_el2_regs[i];
			const char *name = GHOST_EL2_REG_NAMES[r];
			ghost_diff_field(node, (char *)name, diff_pair(TU64(r1->el2_sysregs[r]), TU64(r2->el2_sysregs[r])));
			GHOST_LOG_CONTEXT_EXIT_INNER("loop el2_regs");
		}
	}
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_vcpu(struct diff_container *node, struct ghost_vcpu *vcpu1, struct ghost_vcpu *vcpu2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "vcpu");
	ghost_diff_field(node, "vcpu_handle", diff_pair(TU64(vcpu1->vcpu_handle), TU64(vcpu2->vcpu_handle)));
	ghost_diff_field(node, "loaded", diff_pair(TBOOL(vcpu1->loaded), TBOOL(vcpu2->loaded)));
	ghost_diff_field(node, "initialised", diff_pair(TBOOL(vcpu1->initialised), TBOOL(vcpu2->initialised)));
	if (vcpu1->initialised && vcpu2->initialised)
		ghost_diff_registers(node, &vcpu1->regs, &vcpu2->regs);
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_vm(struct diff_container *node, pkvm_handle_t handle, struct ghost_vm *vm1, struct ghost_vm *vm2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "vm");
	// in theory: handle should be the same...
	ghost_diff_field(node, "handle", diff_pair(TU64((u64)vm1->pkvm_handle), TU64((u64)vm2->pkvm_handle)));
	if (vm1->pkvm_handle == vm2->pkvm_handle) {
		ghost_diff_field(node, "nr_vcpus", diff_pair(TU64(vm1->vm_table_locked.nr_vcpus), TU64(vm2->vm_table_locked.nr_vcpus)));
		ghost_diff_field(node, "nr_initialised_vcpus", diff_pair(TU64(vm1->vm_table_locked.nr_initialised_vcpus), TU64(vm2->vm_table_locked.nr_initialised_vcpus)));
		ghost_diff_pgtable(node, "vm_abstract_pgtable", &vm1->vm_locked.vm_abstract_pgtable, &vm2->vm_locked.vm_abstract_pgtable);

		for (u64 i = 0; i < KVM_MAX_VCPUS; i++) {
			struct ghost_vcpu *vcpu1 = vm1->vm_table_locked.vcpus[i];
			struct ghost_vcpu *vcpu2 = vm2->vm_table_locked.vcpus[i];

			if (vcpu1 && vcpu2) {
				ghost_diff_vcpu(node, vcpu1, vcpu2);
			} else if (!vcpu1 && !vcpu2) {
				continue;
			} else if (vcpu1) {
				ghost_diff_index(node, i, diff_pm(false, TU64(i)));
			} else {
				ghost_diff_index(node, i, diff_pm(true, TU64(i)));
			}
		}
	}
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_vms(struct diff_container *node, struct ghost_vms *vms1, struct ghost_vms *vms2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "vms");
	ghost_diff_field(node, "present", diff_pair(TBOOL(vms1->present), TBOOL(vms2->present)));
	if (!vms1->present || !vms2->present)
		goto cleanup;
	ghost_diff_field(node, "nr_vms", diff_pair(TU64(vms1->nr_vms), TU64(vms2->nr_vms)));

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
				ghost_diff_vm(node, handle, vm1, vm2);
			}
		}
	}

cleanup:
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}


static void ghost_diff_globals(struct diff_container *node, struct ghost_constant_globals *g1, struct ghost_constant_globals *g2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "globals");
	ghost_diff_field(node, "hyp_nr_cpus", diff_pair(TU64(g1->hyp_nr_cpus), TU64(g2->hyp_nr_cpus)));
	ghost_diff_field(node, "hyp_physvirt_offset", diff_pair(TU64(g1->hyp_physvirt_offset), TU64(g2->hyp_physvirt_offset)));
	ghost_diff_field(node, "tag_lsb", diff_pair(TU64(g1->tag_lsb), TU64(g2->tag_lsb)));
	ghost_diff_field(node, "tag_val", diff_pair(TU64(g1->tag_val), TU64(g2->tag_val)));
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_loaded_vcpu(struct diff_container *node, struct ghost_loaded_vcpu *vcpu1, struct ghost_loaded_vcpu *vcpu2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "globals");
	ghost_diff_field(node, "present", diff_pair(TBOOL(vcpu1->present), TBOOL(vcpu2->present)));
	if (vcpu1->present && vcpu2->present) {
		ghost_diff_field(node, "loaded", diff_pair(TBOOL(vcpu1->loaded), TBOOL(vcpu2->loaded)));
		if (vcpu1->loaded && vcpu2->loaded) {
			ghost_diff_field(node, "vm_handle", diff_pair(TU64(vcpu1->vm_handle), TU64(vcpu2->vm_handle)));
			ghost_diff_field(node, "vcpu_index", diff_pair(TU64(vcpu1->vcpu_index), TU64(vcpu2->vcpu_index)));
		}
	}
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_running_state(struct diff_container *node, struct ghost_running_state *r1, struct ghost_running_state *r2)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_diff_enter_subfield(node, "run_state");
	ghost_diff_field(node, "guest_running", diff_pair(TBOOL(r1->guest_running), TBOOL(r2->guest_running)));
	if (r1->guest_running && r2->guest_running) {
		ghost_diff_field(node, "vm_handle", diff_pair(TU64((u64)r1->vm_handle), TU64((u64)r2->vm_handle)));
		ghost_diff_field(node, "vcpu_index", diff_pair(TU64(r1->vcpu_index), TU64(r2->vcpu_index)));
	}
	ghost_diff_pop_subfield(node);
	GHOST_LOG_CONTEXT_EXIT();
}

static void ghost_diff_state(struct diff_container *node, struct ghost_state *s1, struct ghost_state *s2)
{
	ghost_diff_pkvm(node, &s1->pkvm, &s2->pkvm);
	ghost_diff_host(node, &s1->host, &s2->host);
	ghost_diff_vms(node, &s1->vms, &s2->vms);
	ghost_diff_registers(node, this_cpu_ghost_register_state(s1), this_cpu_ghost_register_state(s2));
	ghost_diff_globals(node, &s1->globals, &s2->globals);
	ghost_diff_loaded_vcpu(node, this_cpu_ghost_loaded_vcpu(s1), this_cpu_ghost_loaded_vcpu(s2));
	ghost_diff_running_state(node, this_cpu_ghost_run_state(s1), this_cpu_ghost_run_state(s2));
}

/************************************/
// Simplified model diffing

#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL

#define TSMLOC_TRACK(LOC) TGPRINT("track %g(sm_loc)", (LOC))

static void one_way_diff_blob_slots(struct diff_container *container, struct ghost_memory_blob *b1, struct ghost_memory_blob *b2, bool add)
{
	bool saw_unclean = false;

	for (u64 i = 0; i < SLOTS_PER_PAGE; i++) {
		struct sm_location *loc1 = &b1->slots[i];
		struct sm_location *loc2 = &b2->slots[i];

		// only show the diffs if one side is unclean
		if (loc1->state.kind == STATE_PTE_INVALID_UNCLEAN || loc2->state.kind == STATE_PTE_INVALID_UNCLEAN) {
			if (loc1->is_pte && loc2->is_pte)
				ghost_diff_attach(container, diff_pair(TSMLOC(loc1), TSMLOC(loc2)));
			else if (loc1->is_pte)
				ghost_diff_attach(container, diff_pm(add, TSMLOC_TRACK(loc1)));
			else if (loc2->is_pte)
				ghost_diff_attach(container, diff_pm(!add, TSMLOC_TRACK(loc2)));
			saw_unclean = true;
		}
	}
}

static void one_way_diff_blobs(struct diff_container *container, struct ghost_simplified_memory *m1, struct ghost_simplified_memory *m2, bool add, bool skip_eq)
{
	bool found;
	for (u64 bi = 0; bi < m1->nr_allocated_blobs; bi++) {
		struct ghost_memory_blob *b1 = blob_of(m1, bi);
		struct ghost_memory_blob *b2 = find_blob(m2, b1->phys);

		if (b2) {
			found = true;

			// only in one direction should we try diff the blobs themselves
			if (!skip_eq) {
				one_way_diff_blob_slots(container, b1, b2, add);
			}
		} else if (blob_unclean(b1)) {
			ghost_diff_attach(container, diff_pm(add, TSMBLOB(b1)));
		}
	}
}

static void ghost_diff_sm_mem(struct diff_container *node, struct ghost_simplified_memory *m1, struct ghost_simplified_memory *m2)
{
	ghost_diff_enter_subfield(node, "mem");
	one_way_diff_blobs(node, m1, m2, false, false);
	one_way_diff_blobs(node, m2, m1, true, true);
	ghost_diff_pop_subfield(node);
}

static void one_way_diff_roots(struct diff_container *container, u64 len, u64 *lhs, u64 *rhs, bool add)
{
	bool found;
	for (u64 i = 0; i < len; i++) {
		u64 r = lhs[i];
		found = false;
		for (u64 j = 0; j < len; j++) {
			if (rhs[j] == r)
				found = true;
		}

		// something was removed
		if (!found)
			ghost_diff_attach(container, diff_pm(add, TU64(r)));
	}
}

static void ghost_diff_sm_roots(struct diff_container *node, const char *name, u64 len, u64 *roots1, u64 *roots2)
{
	ghost_diff_enter_subfield(node, name);
	// roots are unordered
	one_way_diff_roots(node, len, roots1, roots2, false);
	one_way_diff_roots(node, len, roots2, roots1, true);
	ghost_diff_pop_subfield(node);
}

static void ghost_diff_sm_state(struct diff_container *node, struct ghost_simplified_model_state *s1, struct ghost_simplified_model_state *s2)
{
	ghost_diff_field(node, "base", diff_pair(TU64(s1->base_addr), TU64(s2->base_addr)));
	ghost_diff_field(node, "size", diff_pair(TU64(s1->size), TU64(s2->size)));

	ghost_diff_sm_roots(node, "s1_roots", s1->nr_s1_roots, s1->s1_roots, s2->s1_roots);
	ghost_diff_sm_roots(node, "s2_roots", s1->nr_s2_roots, s1->s2_roots, s2->s2_roots);

	ghost_diff_sm_mem(node, &s1->memory, &s2->memory);
}

#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

static struct diff_container container(void)
{
	struct diff_container n;
	n.depth = 0;
	n.clean_prefix = 0;
	n.saw_diff = false;
	n.nr_subfield_diffs = 0;
	return n;
}

void ghost_diff_and_print_state(struct ghost_state *s1, struct ghost_state *s2)
{
	struct diff_container node = container();
	ghost_print_enter();
	ghost_diff_state(&node, s1, s2);
	if (!node.saw_diff)
		ghost_printf("<identical>");
	ghost_print_exit();
}

void ghost_diff_and_print_pgtable(abstract_pgtable *ap1, abstract_pgtable *ap2)
{
	struct diff_container node = container();
	ghost_print_enter();
	ghost_diff_pgtable(&node, "pgtable", ap1, ap2);
	if (!node.saw_diff)
		ghost_printf("<identical>");
	ghost_print_exit();
}

#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_DIFF_ON_TRANS
void ghost_diff_and_print_sm_state(struct ghost_simplified_model_state *s1, struct ghost_simplified_model_state *s2)
{
	struct diff_container node = container();
	ghost_print_enter();
	ghost_diff_sm_state(&node, s1, s2);
	if (!node.saw_diff)
		ghost_printf("<identical>");
	ghost_print_exit();
}
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL_DIFF_ON_TRANS */