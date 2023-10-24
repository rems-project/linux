
#ifndef __KVM_HYP_GHOST_PFN_SET
#define __KVM_HYP_GHOST_PFN_SET

#include <linux/types.h>

#define GHOST_MAX_PFN_SET_LEN 64

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
void ghost_pfn_set_dump(struct pfn_set *set);
void ghost_pfn_set_copy(struct pfn_set *dst, struct pfn_set *src);
bool ghost_pfn_set_equal(struct pfn_set *lhs, struct pfn_set *rhs);
bool ghost_pfn_set_subseteq(struct pfn_set *lhs, struct pfn_set *rhs);

#endif /* __KVM_HYP_GHOST_PFN_SET */