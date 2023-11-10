
#ifndef __KVM_HYP_GHOST_PFN_SET
#define __KVM_HYP_GHOST_PFN_SET

#include <linux/types.h>

#define GHOST_MAX_PFN_SET_LEN 64

/**
 * struct pfn_set - A set of pagetable table addresses
 * @pool_range_start: the (physical) address the contiguous hyp_pool for this pagetable starts at.
 * @pool_range_end: the (physical) address the contiguous hyp_pool for this pagetable ends at.
 * @len: the count of extra-pool pages are in the pagetable.
 * @external_pfns: the underlying buffer (up to `len`) of table page frame numbers.
 *
 * The pfn_set is split in two:
 * - the hyp_pool range, which are (by the spec) required to always be mapped and owned by pKVM and no other.
 * - an arbitrary set of other pages, once owned by the host, now stolen by pKVM for purposes of storing pagetables.
 */
struct pfn_set {
	u64 pool_range_start;
	u64 pool_range_end;
	u64 len;
	phys_addr_t external_pfns[GHOST_MAX_PFN_SET_LEN];
};

void ghost_pfn_set_init(struct pfn_set *set, u64 pool_range_start, u64 pool_range_end);
void ghost_pfn_set_clear(struct pfn_set *set);
void ghost_pfn_set_insert(struct pfn_set *set, u64 pfn);
bool ghost_pfn_set_contains(struct pfn_set *set, u64 pfn);
void ghost_pfn_set_dump(struct pfn_set *set, u64 indent);
void ghost_pfn_set_copy(struct pfn_set *dst, struct pfn_set *src);

void ghost_pfn_set_assert_equal(struct pfn_set *lhs, struct pfn_set *rhs);
void ghost_pfn_set_assert_subseteq(struct pfn_set *lhs, struct pfn_set *rhs);

#endif /* __KVM_HYP_GHOST_PFN_SET */