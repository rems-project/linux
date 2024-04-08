#ifndef GHOST_CALL_DATA_H
#define GHOST_CALL_DATA_H

#include <linux/types.h>
#include <asm/kvm_asm.h>    // DECLARE_PER_CPU

/**
 * ghost_clear_call_data - Resets this CPU's recorded hypercall data back to empty
 */
void ghost_clear_call_data(void);


/**
 * max number of recorded READ_ONCEs
 */
#define GHOST_MAX_RELAXED_READS 512

/**
 * struct ghost_read - A single relaxed read
 *
 * @phys_addr: the physical address read from.
 * @value: the actual value that was read.
 * @width: the size of the read, in bytes.
 */
struct ghost_read {
	u64 phys_addr;
	u64 value;
	u8 width;
};

/**
 * struct ghost_relaxed_reads - List of previously seen relaxed reads
 *
 * @len: count of stored relaxed reads.
 * @read_slots: the underlying buffer of ghost reads.
 *
 * The read_slots field contains an array of non-overlapping ghost_read objects, up to index len.
 * ghost_relaxed_reads_insert appends to this, and ghost_reads_get gets the corresponding read value
 */
struct ghost_relaxed_reads {
	size_t len;
	struct ghost_read read_slots[GHOST_MAX_RELAXED_READS];
};

void ghost_relaxed_reads_insert(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width, u64 value);
u64 ghost_relaxed_reads_get(struct ghost_relaxed_reads *rs, u64 phys_addr, u8 width);

#define GHOST_MAX_MEMCACHE_DONATIONS 16

/**
 * struct ghost_memcache_donations - List of memcache pages donated to hypervisor during call
 *
 * @len: count of donations
 * @pages: the underlying buffer of donated addresses.
 *
 * The slots field contains an array of donated pfns, up to index len.
 * ghost_memcache_donations_insert appends to this
 */
struct ghost_memcache_donations {
	size_t len;
	u64 pages[GHOST_MAX_MEMCACHE_DONATIONS];
};

void ghost_memcache_donations_insert(struct ghost_memcache_donations *ds, u64 pfn);

#define GHOST_MAX_AT_TRANSLATIONS 16

/**
 * struct ghost_at_translation - A single recorded `AT s1e1` result.
 * @va: the input host (potentially non-kernel) virtual address.
 * @success: whether the `AT` instruction succeeded.
 * @ipa: if success, the resulting host IPA.
 */
struct ghost_at_translation {
	u64 va;
	bool success;
	u64 ipa;
};

/**
 * struct ghost_at_translations - List of recorded AT translations.
 * @len: count of AT instructions recorded.
 * @translations: the underlying buffer of translations.
 */
struct ghost_at_translations {
	size_t len;
	struct ghost_at_translation translations[GHOST_MAX_AT_TRANSLATIONS];
};

void ghost_at_translations_insert_fail(struct ghost_at_translations *translations, u64 va);
void ghost_at_translations_insert_success(struct ghost_at_translations *translations, u64 va, u64 ipa);

/**
 * ghost_at_translations_get() - Retrieve an attempted AT s1e1r from the translations.
 * @translations: the recorded list of AT translations.
 * @va: the input host (but not necessarily kernel) virtual address.
 *
 * Returns NULL if the specified AT translation was not found in the list.
 */
struct ghost_at_translation *ghost_at_translations_get(struct ghost_at_translations *translations, u64 va);

/**
 * struct ghost_call_data - Ghost copies of values seen by implementation
 *
 * @return_value: The final value (usually an errno) returned by the real implementation.
 * @relaxed_reads: The list of relaxed READ_ONCE()s performed by the implementation.
 * @memcache_donations: list of donated addresses
 * @at_translations: list of performed AT instructions
 *
 * The spec contains two forms of non-determinism:
 *  - nondet by internal choice, this makes the spec truly non-deterministic
 *    and only arises (so far) from out-of-memory errors on the internal allocators
 *    and so can be totally resolved by reading the returned errno
 *  - externally chosen nondet, these arise when the implementation has to read
 *    memory shared by/with the host or guests, where the spec is deterministic once
 *    the choice of value has been made.
 *
 * to resolve both kinds of non-determinism in the spec,
 * we record the choices the implementation actually saw for each.
 */
struct ghost_call_data {
	u64 return_value;
	struct ghost_relaxed_reads relaxed_reads;
	struct ghost_memcache_donations memcache_donations;
	struct ghost_at_translations at_translations;
};

/**
 * gs_call_data - per-thread storage of data collected during the hypercall
 */
DECLARE_PER_CPU(struct ghost_call_data, gs_call_data);

/**
 * READ_ONCE_GHOST_RECORD(ptr) - Perform a READ_ONCE(ptr) but remember the address and value in the ghost state.
 */
#define READ_ONCE_GHOST_RECORD(x) \
	({ \
		typeof(x) v = READ_ONCE(x); \
		ghost_relaxed_reads_insert( \
			&this_cpu_ptr(&gs_call_data)->relaxed_reads, \
			(u64)&x, \
			sizeof(typeof(x)), \
			v \
		); \
		v; \
	})

/**
 * GHOST_READ_ONCE(x) - Behaves like READ_ONCE(x) but recalls the previously read value from the ghost state
 */
#define GHOST_READ_ONCE(gcd, x) \
	({ \
		ghost_relaxed_reads_get(&gcd->relaxed_reads, (u64)&x, sizeof(typeof(x))); \
	})


/**
 * GHOST_SPEC_DECLARE_REG()
 */
#define GHOST_SPEC_DECLARE_REG(type, name, ctxt, reg)	\
	type name = (type)ghost_reg_gpr(ctxt, (reg))


/**
 * GHOST_RECORD_MEMCACHE_DONATION()
 */
#define GHOST_RECORD_MEMCACHE_DONATION(pfn) \
	ghost_memcache_donations_insert(&this_cpu_ptr(&gs_call_data)->memcache_donations, (u64)pfn)

/**
 * GHOST_RECORD_AT_SUCCESS() - Record a successfull `AT s1e1r`
 */
#define GHOST_RECORD_AT_SUCCESS(va, ipa) \
	ghost_at_translations_insert_success(&this_cpu_ptr(&gs_call_data)->at_translations, (u64)(va), (u64)(ipa))
/**
 * GHOST_RECORD_AT_FAIL() - Record a failed `AT s1e1r`
 */
#define GHOST_RECORD_AT_FAIL(va) \
	ghost_at_translations_insert_fail(&this_cpu_ptr(&gs_call_data)->at_translations, (u64)(va))

#endif /* GHOST_CALL_DATA_H */