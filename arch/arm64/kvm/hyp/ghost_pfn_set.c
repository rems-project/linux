#include <asm/kvm_mmu.h>

#include <nvhe/ghost_asserts.h>
#include <nvhe/ghost_pfn_set.h>

#include <hyp/ghost_extra_debug-pl011.h>

void ghost_pfn_set_init(struct pfn_set *set, u64 pool_range_start, u64 pool_range_end)
{
	set->len = 0;
	set->pool_range_start = pool_range_start;
	set->pool_range_end = pool_range_end;
}

void ghost_pfn_set_insert(struct pfn_set *set, u64 pfn)
{
	u64 idx;
	if (!(set->pool_range_start <= pfn && pfn < set->pool_range_end)) {
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

void ghost_pfn_set_dump(struct pfn_set *set)
{
	ghost_assert(set->len < GHOST_MAX_PFN_SET_LEN);
	hyp_putsp("BEGIN PFNS[pool_range: ");
	hyp_putx64(set->pool_range_start);
	hyp_putsp(" ... ");
	hyp_putx64(set->pool_range_end);
	hyp_putsp("]\n");
	for (int idx=0; idx < set->len; idx++) {
		hyp_putsxn("  pfs", set->external_pfns[idx], 64);
		hyp_putsp("\n");
	}
	hyp_putsp("END PFNS\n");
}

void ghost_pfn_set_copy(struct pfn_set *dst, struct pfn_set *src)
{
	dst->len = src->len;
	for (int idx=0; idx<GHOST_MAX_PFN_SET_LEN; idx++) {
		dst->external_pfns[idx] = src->external_pfns[idx];
	}
}

static bool range_equal(struct pfn_set *lhs, struct pfn_set *rhs)
{
	return (   (lhs->pool_range_start == rhs->pool_range_start)
	        && (lhs->pool_range_end   == rhs->pool_range_end));
}

bool ghost_pfn_set_equal(struct pfn_set *lhs, struct pfn_set *rhs)
{
	bool ret;
	GHOST_LOG_CONTEXT_ENTER();
	ret = (
		   ghost_pfn_set_subseteq(lhs, rhs)
		&& ghost_pfn_set_subseteq(rhs, lhs)
	);
	GHOST_LOG_CONTEXT_EXIT();
	return ret;
}

bool ghost_pfn_set_subseteq(struct pfn_set *lhs, struct pfn_set *rhs)
{
	bool ret, all_external_pfns_contained;
	GHOST_LOG_CONTEXT_ENTER();

	if (!range_equal(lhs, rhs)) {
		ret = false;
		goto out;
	}

	if (lhs->len != rhs->len) {
		ret = false;
		goto out;
	}

	all_external_pfns_contained = true;
	for (int i=0; i<lhs->len; i++) {
		if (!ghost_pfn_set_contains(rhs, lhs->external_pfns[i])) {
			ret = false;
			goto out;
		}
	}

	ret = true;
out:
	GHOST_LOG_CONTEXT_EXIT();
	return ret;
}

void ghost_pfn_set_clear(struct pfn_set *set)
{
	set->len = 0;
}
