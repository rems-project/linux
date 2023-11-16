#include <asm/kvm_mmu.h>

#include <nvhe/ghost_asserts.h>
#include <nvhe/ghost_pfn_set.h>
#include <nvhe/ghost_context.h>

#include <nvhe/ghost_printer.h>

void ghost_pfn_set_init(struct pfn_set *set, u64 pool_range_start, u64 pool_range_end)
{
	set->len = 0;
	set->pool_range_start = pool_range_start;
	set->pool_range_end = pool_range_end;
}

void ghost_pfn_set_insert(struct pfn_set *set, u64 pfn)
{
	u64 idx;
	u64 phys_page_addr = pfn << PAGE_SHIFT;
	if (!(set->pool_range_start <= phys_page_addr && phys_page_addr < set->pool_range_end)) {
		idx = set->len++;
		ghost_assert(idx < GHOST_MAX_PFN_SET_LEN);
		set->external_pfns[idx] = pfn;
	}
}

bool ghost_pfn_set_contains(struct pfn_set *set, u64 pfn)
{
	ghost_assert(set->len < GHOST_MAX_PFN_SET_LEN);
	for (int idx=0; idx < set->len; idx++) {
		if (set->external_pfns[idx] == pfn)
			return true;
	}
	return false;
}

int gp_print_pfn_set(gp_stream_t *out, struct pfn_set *set)
{
	int ret;
	ghost_assert(set->len < GHOST_MAX_PFN_SET_LEN);
	ret = ghost_sprintf(out, "pfns range:(%p..%p) external_pages:[", set->pool_range_start, set->pool_range_end);

	for (int idx=0; idx < set->len; idx++) {
		ret = ghost_sprintf(out, "%p", set->external_pfns[idx]);
		if (ret)
			return ret;

		if (idx < set->len - 1) {
			ret = ghost_sprintf(out, ", ");
		}
	}
	return ghost_sprintf(out, "]\n");
}

void ghost_pfn_set_copy(struct pfn_set *dst, struct pfn_set *src)
{
	dst->len = src->len;
	dst->pool_range_start = src->pool_range_start;
	dst->pool_range_end = src->pool_range_end;
	for (int idx=0; idx<GHOST_MAX_PFN_SET_LEN; idx++) {
		dst->external_pfns[idx] = src->external_pfns[idx];
	}
}

static bool range_equal(struct pfn_set *lhs, struct pfn_set *rhs)
{
	return (   (lhs->pool_range_start == rhs->pool_range_start)
	        && (lhs->pool_range_end   == rhs->pool_range_end));
}

void ghost_pfn_set_assert_equal(struct pfn_set *lhs, struct pfn_set *rhs)
{
	GHOST_LOG_CONTEXT_ENTER();
	ghost_pfn_set_assert_subseteq(lhs, rhs);
	GHOST_LOG_CONTEXT_ENTER_INNER("subseteq flipped");
	ghost_pfn_set_assert_subseteq(rhs, lhs);
	GHOST_LOG_CONTEXT_EXIT_INNER("subseteq flipped");
	GHOST_LOG_CONTEXT_EXIT();
}

static void print_set(void *set)
{
	struct pfn_set *s = *(struct pfn_set**)set;
	ghost_printf("%g(pfn_set)\n", s);
}

void ghost_pfn_set_assert_subseteq(struct pfn_set *lhs, struct pfn_set *rhs)
{
	GHOST_LOG_CONTEXT_ENTER();

	GHOST_LOG_P(__func__, lhs, print_set);
	GHOST_LOG_P(__func__, rhs, print_set);

	ghost_spec_assert(range_equal(lhs, rhs));
	ghost_spec_assert(lhs->len == rhs->len);

	for (int i=0; i<lhs->len; i++) {
		ghost_spec_assert(ghost_pfn_set_contains(rhs, lhs->external_pfns[i]));
	}

	GHOST_LOG_CONTEXT_EXIT();
}

void ghost_pfn_set_clear(struct pfn_set *set)
{
	set->len = 0;
}
