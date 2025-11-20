// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC
 * Author: Vincent Donnefort <vdonnefort@google.com>
 */

#ifdef STANDALONE
#include <prelude.h>
#include <alloc.h>
#include <fulminate.h>
#include "shim.c"
extern unsigned long hyp_nr_cpus;
#else
#include <nvhe/alloc.h>
#include <nvhe/alloc_mgt.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/spinlock.h>

#include <linux/build_bug.h>
#include <linux/hash.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#endif /* STANDALONE */

#define MIN_ALLOC 8UL

/*@
function (u64) MIN_ALLOC () {
        8u64
}
@*/

static DEFINE_PER_CPU(int, hyp_allocator_errno);
static DEFINE_PER_CPU(struct kvm_hyp_memcache, hyp_allocator_mc);
static DEFINE_PER_CPU(u8, hyp_allocator_missing_donations);

static struct hyp_allocator {
        struct list_head        chunks;
        unsigned long           start;
        u32                     size;
        hyp_spinlock_t          lock;
} hyp_allocator;

/* HK: Why "explicit padding"?

First, the original `chunk_hdr`'s data access is a bit unusual: the `data` field
is located at the end of the struct and is only one byte in size.
In `pkvm-hyp-allocator`, the macro `chunk_data` is used to access this field.
However, if you use `struct chunk_hdr` to represent ownership, you
unintentionally also own the first byte of the data.

Note that changing `char data` to `char data[]` doesn’t work, because CN does not
support this kind of array.

To avoid this, I introduced `chunk_hdr_only`, which omits the `data` field.

Then we encounter a second issue: padding.
The size of `chunk_hdr` up to (but not including) `data` is 4 + 4 + 8 + 8 + 4 =
28 bytes.  Some tool (Cerberus?) implicitly adds 4 bytes of padding to align the
total size to 32 bytes. As a result, if you directly use `struct chunk_hdr_only`,
there will be a 4-byte overlap between the header and the data.

That’s why I added 4 bytes of explicit padding to the struct.
I’m not sure if this is the best solution, but it works for now.
*/
struct chunk_hdr {
        u32                     alloc_size;
        u32                     mapped_size;
        struct list_head        node;
        u32                     hash;
        /*CN*/ u32              explicit_padding;
        char                    data __aligned(8);
};
// HK: having char data at the end of the struct is very annoying
// If we write RW<struct chunk_hdr>, a single byte of the data is going to be owned
// unintentionally.
// TODO: rewrite the spec to use chunk_hdr_only instead of chunk_hdr
struct chunk_hdr_only {
        u32                     alloc_size;
        u32                     mapped_size;
        struct list_head        node;
        u32                     hash;
        /* CN */ u32            explicit_padding;
};
#ifdef __CN_VERIFY
[[cerb::byte]]
#endif
typedef unsigned char byte;


// Auxiliary functions for chunk_hdr
/*@
type_synonym cn_chunk_hdr_raw = {
        u32 alloc_size,
        u32 mapped_size,
        struct list_head node,
        u32 hash
}
datatype chunk_hdr_option {
  ChunkHdr_none {},
  ChunkHdr_some { cn_chunk_hdr_raw hdr }
}
datatype chunk_hdr_u_option {
  ChunkHdr_u_none {},
  ChunkHdr_u_some { u32 alloc_size, u32 mapped_size, struct list_head node }
}

function (boolean) bind_hash_change_only_u (datatype chunk_hdr_u_option pre, datatype chunk_hdr_option post)
{
        match (pre) {
                ChunkHdr_u_none {} => {
                        match (post) {
                                ChunkHdr_none {} => {
                                        true
                                }
                                ChunkHdr_some {hdr:hdr} => {
                                        false
                                }
                        }
                }
                ChunkHdr_u_some {alloc_size: x2, mapped_size: y2, node: z2 } => {
                        match (post) {
                                ChunkHdr_none {} => {
                                        false
                                }
                                ChunkHdr_some {hdr: hdr } => {
                                        hdr.alloc_size == x2 && hdr.mapped_size == y2 && hdr.node == z2
                                }
                        }
                }
        }
}
@*/

/*@
function (u64) MergeU32s(u32 x, u32 y)
{
        shift_left((u64)y, 32u64) | (u64)x
}

@*/

#ifdef __CN_VERIFY
void LemmaTurnU32sToU64(unsigned *a, unsigned *b)
/*@
requires
    !is_null(a);
    take X = RW<unsigned>(a);
    take Y = RW<unsigned>(b);
    ptr_eq(array_shift<unsigned>(a, 1u32), b);
ensures
    take Z = RW<unsigned long long>(a);
    Z == MergeU32s(X, Y);
@*/
{
        /*@ to_bytes RW<unsigned>(a); @*/
        /*@ to_bytes RW<unsigned>(b); @*/

        /*@ focus RW<byte>, 0u64; @*/
        /*@ focus RW<byte>, 1u64; @*/
        /*@ focus RW<byte>, 2u64; @*/
        /*@ focus RW<byte>, 3u64; @*/
        /*@ focus RW<byte>, 4u64; @*/
        /*@ focus RW<byte>, 5u64; @*/
        /*@ focus RW<byte>, 6u64; @*/
        /*@ focus RW<byte>, 7u64; @*/
        /*@ from_bytes RW<unsigned long long>(a); @*/
}

void LemmaTurnU64ToU32s(unsigned *a, unsigned *b)
/*@
requires
    take Z = RW<unsigned long long>(a);
    ptr_eq(array_shift<unsigned>(a, 1u32), b);
ensures
    take X = RW<unsigned>(a);
    take Y = RW<unsigned>(b);
    Z == MergeU32s(X, Y);
@*/
{
        /*@ to_bytes RW<unsigned long long>(a); @*/

        /*@ focus RW<byte>, 0u64; @*/
        /*@ focus RW<byte>, 1u64; @*/
        /*@ focus RW<byte>, 2u64; @*/
        /*@ focus RW<byte>, 3u64; @*/
        /*@ focus RW<byte>, 4u64; @*/
        /*@ focus RW<byte>, 5u64; @*/
        /*@ focus RW<byte>, 6u64; @*/
        /*@ focus RW<byte>, 7u64; @*/
        /*@ from_bytes RW<unsigned>(a); @*/
        /*@ from_bytes RW<unsigned>(b); @*/
}

void LemmaPtrToU64(struct list_head **a)
/*@
requires
    take P = RW<struct list_head*>(a);
ensures
    take Q = RW<unsigned long long>(a);
    (u64)P == Q;
@*/
{
        /*@ to_bytes RW<struct list_head*>(a); @*/
        /*@ from_bytes RW<unsigned long long>(a); @*/
}

void LemmaU64ToPtr(struct list_head **a)
/*@
requires
    take Q = RW<unsigned long long>(a);
ensures
    take P = RW<struct list_head*>(a);
    (u64)P == Q;
@*/
{
        /*@ to_bytes RW<unsigned long long>(a); @*/
        /*@ from_bytes RW<struct list_head*>(a); @*/
}
#endif

// HK: This requires CN to have a normal conjunction in addition to the
// separating conjunction.
static u32 chunk_hash_compute(struct chunk_hdr *chunk)
/*@
    requires
        !is_null(chunk);
        let alloc_size = member_shift<struct chunk_hdr>(chunk, alloc_size);
        let mapped_size = member_shift<struct chunk_hdr>(chunk, mapped_size);
        let node = member_shift<struct chunk_hdr>(chunk, node);
        take alloc_size_pre = RW<unsigned>(alloc_size);
        take mapped_size_pre = RW<unsigned>(mapped_size);
        take node_pre = RW<struct list_head>(node);
        !is_null(node_pre.next) && (u64)node_pre.next != 0u64;
        !is_null(node_pre.prev) && (u64)node_pre.prev != 0u64;
    ensures
        take alloc_size_post = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, alloc_size));
        take mapped_size_post = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, mapped_size));
        take node_post = RW<struct list_head>(member_shift<struct chunk_hdr>(chunk, node));
        alloc_size_pre == alloc_size_post;
        mapped_size_pre == mapped_size_post;
        node_pre == node_post;

@*/
{

        size_t len = offsetof(struct chunk_hdr, hash);
        // HK: How do I handle this cast while having the ownership to chunk??
        u64 *data = (u64 *)chunk;

        u32 hash = 0;
#ifdef __CN_VERIFY
        LemmaTurnU32sToU64(&chunk->alloc_size, &chunk->mapped_size);
#endif

        BUILD_BUG_ON(!IS_ALIGNED(offsetof(struct chunk_hdr, hash), sizeof(u32)));
        /*@ assert(ptr_eq(data, alloc_size)); @*/
#ifdef __CN_VERIFY
        LemmaPtrToU64(&chunk->node.next);
        LemmaPtrToU64(&chunk->node.prev);
#endif

    while (len >= sizeof(u64))
    /*@
        inv
        {chunk} unchanged;
        !is_null(data);
        (u64)chunk <= (u64)data;
        let size = offsetof(chunk_hdr, hash);
        len <= size;
        (u64)data + len == (u64)chunk + size;
        (u64)data & 7u64 == 0u64;
        take X1 = RW<unsigned long long>(alloc_size);
        MergeU32s(alloc_size_pre, mapped_size_pre) == X1;

        take X2 = RW<unsigned long long>(member_shift<struct list_head>(node, next));
        (u64)X2 == (u64)node_pre.next;
        take X3 = RW<unsigned long long>(member_shift<struct list_head>(node, prev));
        (u64)X3 == (u64)node_pre.prev;
        //take L = each(u64 i; i < 3u64) { RW<unsigned long long>(array_shift<unsigned long long>(alloc_size, i))};
    @*/
    {
            /*@ split_case(ptr_eq(alloc_size, data));@*/
            /*@ split_case(ptr_eq(member_shift<struct list_head>(node, next), data));@*/
            ///*@ split_case(ptr_eq(alloc_size, data));@*/
            hash ^= hash_64(*data, 32);
            len -= sizeof(u64);
            data++;
    }

        if (len)
                hash ^= hash_32(*(u32 *)data, 32);
#ifdef __CN_VERIFY
        LemmaU64ToPtr(&chunk->node.next);
        LemmaU64ToPtr(&chunk->node.prev);
        LemmaTurnU64ToU32s(&chunk->alloc_size, &chunk->mapped_size);
#endif

        return hash;
}

static inline void chunk_hash_update(struct chunk_hdr *chunk)
/*@
    requires
        take C_pre = MaybeChunkHdrU(chunk, !is_null(chunk));
    ensures
        take C_post = MaybeChunkHdr(chunk, !is_null(chunk));
        bind_hash_change_only_u(C_pre, C_post);
@*/
{
        if (chunk) {
	        /*@ unpack MaybeChunkHdrU(...); @*/
                chunk->hash = chunk_hash_compute(chunk);
        }
	/*@ unpack MaybeChunkHdrU(...); @*/
}

static inline void chunk_hash_validate(struct chunk_hdr *chunk)
/*@
    requires
        take C_pre = MaybeChunkHdr(chunk, !is_null(chunk));
    ensures
        take C_post = MaybeChunkHdr(chunk, !is_null(chunk));
        C_post == C_pre;
@*/
{
        if (chunk) {
	        /*@ unpack MaybeChunkHdr(chunk, !is_null(chunk)); @*/
                WARN_ON(chunk->hash != chunk_hash_compute(chunk));
        }
}

#ifdef __cerb__
/*@
function (u64) Cn_chunk_hdr_size ()
{
        (u64) offsetof(chunk_hdr, data)
}
// HK: size_t cast is removed. Macro requires cast because it does not know what the
// argument type is.
function (u64) Cn_chunk_size (u64 size)
{
        Cn_chunk_hdr_size() + (size > MIN_ALLOC() ? size : MIN_ALLOC())
        //(u64) member_shift<struct chunk_hdr>(NULL, data) + (size > MIN_ALLOC() ? size : MIN_ALLOC())
}
function (pointer) Cn_chunk_data (struct chunk_hdr chunk)
{
    (pointer)chunk.data
}
function (u64) Cn_chunk_unmapped_region(pointer chunk_p, struct chunk_hdr chunk)
{
    (u64)chunk_p + (u64)chunk.mapped_size
}


@*/
#endif

#ifdef __cerb__
#include "spec.c"
#endif

#define chunk_is_used(chunk) \
	(!!(chunk)->alloc_size)
#define chunk_hdr_size() \
	offsetof(struct chunk_hdr, data)

#ifdef NO_STATEMENT_EXPRS
#define chunk_size(size) \
        (chunk_hdr_size() + max_u64((unsigned long)(size), MIN_ALLOC))
#else /* NO_STATEMENT_EXPRS */
#define chunk_size(size) \
	(chunk_hdr_size() + max((size_t)(size), MIN_ALLOC))
#endif

#define chunk_data(chunk) \
	((void *)(&(chunk)->data))
#define __chunk_next(chunk, allocator)				\
({								\
	list_is_last(&(chunk)->node, &(allocator)->chunks) ?	\
		NULL : list_next_entry(chunk, node);		\
})
#define __chunk_prev(chunk, allocator)				\
({								\
	list_is_first(&(chunk)->node, &(allocator)->chunks) ?	\
		NULL : list_prev_entry(chunk, node);		\
})
#define chunk_get_next(chunk, allocator)			\
({								\
	struct chunk_hdr *next = __chunk_next(chunk, allocator);\
	chunk_hash_validate(next);				\
	next;							\
})
#define chunk_get_prev(chunk, allocator)			\
({								\
	struct chunk_hdr *prev = __chunk_prev(chunk, allocator);\
	chunk_hash_validate(prev);				\
	prev;							\
})
#define chunk_get(addr)						\
({								\
	struct chunk_hdr *chunk = (struct chunk_hdr *)addr;	\
	chunk_hash_validate(chunk);				\
	chunk;							\
})
#define chunk_unmapped_region(chunk) \
	((unsigned long)(chunk) + chunk->mapped_size)
#define chunk_unmapped_size(chunk, allocator)				\
({									\
	struct chunk_hdr *next = chunk_get_next(chunk, allocator);	\
	unsigned long allocator_end = (allocator)->start +		\
				      (allocator)->size;		\
	next ? (unsigned long)next - chunk_unmapped_region(chunk) :	\
		allocator_end - chunk_unmapped_region(chunk);		\
})

/*@
function (boolean) Cn_list_is_first(struct list_head node, pointer chunks)
{
        ptr_eq(node.prev, chunks)
}
function (boolean) Cn_list_is_last(struct list_head node, pointer chunks)
{
        ptr_eq(node.next, chunks)
}
function (pointer) Cn_chunk_get_next(struct chunk_hdr chunk, pointer allocator)
{
        Cn_list_is_last(chunk.node, member_shift<struct hyp_allocator>(allocator, chunks)) ?
        NULL : my_container_of_chunk_hdr(chunk.node.next)
}
function (u32) Cn_chunk_unmapped_size(cn_chunk_hdr hdr)
{
        hdr.va_size - hdr.mapped_size
}

function [rec] (cn_chunk_hdrs) SnocHdr(cn_chunk_hdrs hdrs, cn_chunk_hdr hdr)
{
        match (hdrs) {
                Chunk_nil {} => {
                        Chunk_cons {hd:hdr, tl:Chunk_nil {}}
                }
                Chunk_cons {hd:hd, tl:tl} => {
                        Chunk_cons {hd:hd, tl:SnocHdr(tl, hdr)}
                }
        }
}


@*/
#ifdef __CN_VERIFY
void LemmaNextChunk(struct chunk_hdr *chunk,
                    struct hyp_allocator *allocator)
/*@
    requires
        !is_null(chunk);
        take X = Cn_hyp_allocator_focusing_on(allocator, chunk);
        let ha_full = X.ha;
        let ha = {head: ha_full.head, start: ha_full.start, size: ha_full.size, first: ha_full.first};
        let C_pre = X.lseg.chunk;
        X.lseg.after != Chunk_nil{};
        let next = match (X.lseg.after) {
            Chunk_nil {} => {
                // dummy
                {hdr: X.lseg.chunk, tl: Chunk_nil {}}
            }
            Chunk_cons {hd:hdr, tl:tl} => {
                {hdr: hdr, tl: tl}
            }
        };
    ensures
        take Y = Cn_hyp_allocator_focusing_on(allocator, (pointer)next.hdr.header_address);
        Y.lseg.before == Chunk_cons{hd: X.lseg.chunk, tl: X.lseg.before};
        Y.lseg.chunk == next.hdr;
        Y.lseg.after == next.tl;
        Y.ha == X.ha;
@*/
{
        /*@ split_case(ptr_eq(
                member_shift<struct chunk_hdr>(chunk, node),
                member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        /*@ split_case(ptr_eq(
                member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        /*@ split_case(!is_null(member_shift<struct chunk_hdr>(chunk, node)));@*/
        /*@ split_case(!is_null(member_shift<struct chunk_hdr>(chunk, node)->next));@*/
        /*@ unpack Cn_chunk_hdrs(member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct chunk_hdr>(chunk, node), X.ha.last, ha); @*/
}


void LemmaPrevChunk(struct chunk_hdr *chunk,
                            struct hyp_allocator *allocator)
/*@
    requires
        !is_null(chunk);
        take X = Cn_hyp_allocator_focusing_on(allocator, chunk);
        X.lseg.before != Chunk_nil{};
        let prev = match (X.lseg.before) {
            Chunk_nil {} => {
                // dummy
                {hdr: X.lseg.chunk, tl: Chunk_nil {}}
            }
            Chunk_cons {hd:hdr, tl:tl} => {
                {hdr: hdr, tl: tl}
            }
        };
    ensures
        take Y = Cn_hyp_allocator_focusing_on(allocator, (pointer)prev.hdr.header_address);
        Y.lseg.after == Chunk_cons{hd: X.lseg.chunk, tl: X.lseg.after};
        Y.lseg.chunk == prev.hdr;
        Y.lseg.before == prev.tl;
        Y.ha == X.ha;

@*/
{
        /*@ split_case(ptr_eq(
                member_shift<struct chunk_hdr>(chunk, node),
                member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        /*@ split_case(ptr_eq(
                member_shift<struct chunk_hdr>(chunk, node)->prev,
                member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        /*@ split_case(!is_null(member_shift<struct chunk_hdr>(chunk, node)));@*/
        /*@ split_case(!is_null(member_shift<struct chunk_hdr>(chunk, node)->prev));@*/
        /*@ unpack Cn_chunk_hdrs_rev(member_shift<struct chunk_hdr>(chunk, node)->prev,
                member_shift<struct chunk_hdr>(chunk, node), X.ha.first, Cn_hyp_allocator_core(X.ha)); @*/
}

#endif


// This function takes
//   - a chunk *not in the chunk list*
//   - a chunk *in the chunk list*, which will be the previous chunk of the new chunk
//   - the allocator
// and inserts the new chunk into the chunk list after the previous chunk.

// HK: This is the point where raw pointer manipulations and beautiful list
// specifications meet, which is one of the most difficult parts of the whole
// spec writing.
// Currently, I "believe" that the spec I wrote is correct, but it is not
// automatically verified by CN.
static inline void chunk_list_insert(struct chunk_hdr *chunk,
                                     struct chunk_hdr *prev,
                                     struct hyp_allocator *allocator)
/*

1. chunk list in allocator
-> xx -> ... -> prev -> next -> ...
2. chunk is not in the list
==>
-> xx -> ... -> prev -> chunk -> next -> ...

*/

/*@
    requires
        !is_null(chunk);
        !is_null(prev);
        take HA_pre = Cn_hyp_allocator_focusing_on_for_install(allocator, prev, chunk, Option_u64_none{}, true);
        let lseg_pre = HA_pre.lseg;
        let Prev_pre = lseg_pre.chunk;

        // chunk is not constructed yet
        take alloc_size = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, alloc_size));
        take mapped_size = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, mapped_size));
        take node = W<struct list_head>(member_shift<struct chunk_hdr>(chunk, node));
        take hash = W<unsigned>(member_shift<struct chunk_hdr>(chunk, hash));
        take explicit_padding = W<unsigned>(member_shift<struct chunk_hdr>(chunk, explicit_padding));

        //  [prev]    [+alloc_size]             [chunk]     [+(old)va_size]
        //    ------- ------------------------- ----------- -------------
        (u64)alloc_size + Cn_chunk_hdr_size() <= (u64)mapped_size;
        (u64)mapped_size <= HA_pre.va_size;
        (u64)prev + Cn_chunk_hdr_size() +  (u64)Prev_pre.alloc_size <= (u64)chunk;

        let start = array_shift<char>(chunk, Cn_chunk_hdr_size() + (u64)alloc_size);
        let owned_by_ha =  (u64)HA_pre.va_size - (u64)alloc_size - Cn_chunk_hdr_size();
        take X = Cn_char_array(start, owned_by_ha);

    ensures
        take HA_post = Cn_hyp_allocator_focusing_on(allocator, prev);
        let lseg_post = HA_post.lseg;
        let Prev_post = lseg_post.chunk;
        let ha = HA_pre.ha;
        HA_post.ha.size == ha.size && HA_post.ha.start == ha.start && ptr_eq(HA_post.ha.head, ha.head);
        lseg_pre.before == lseg_post.before;
        let Chunk = {
                header_address: (u64)chunk,
                va_size: (u32)HA_pre.va_size,
                alloc_size: alloc_size,
                mapped_size: mapped_size
        };
        lseg_post.after == Chunk_cons {hd: Chunk, tl: HA_pre.lseg.after};
        lseg_pre.chunk == Prev_post;
@*/
{
        // HK: non-rust ownership type part
        // This is also why we cannot directly apply the idea of
        // [Hermes&Krebbers ITP 2024] to this program.
        // In p9, the specification for inserting a node into a list is
        // defined as:
        // { DCycle c L ∗ l ↦ [ _, _ ] } insert c l { DCycle c (l :: L) }
        // but we cannot give up the ownership of l just after the insertion.

        // HK: Proof for the ownership of RW<struct list_head*>(&(&prev->node)->next)
        //  - If prev->node is the last node, then prev->node.next == allocator->chunks,
        //    which is in H_pre.ha
        //  - If prev->node is not the last node, then prev->node.next is in Next_Chunk.

        // HK: Proof for the ownership of prev
        //   - prev must be in the chunk list from the precondition
        //   - that implies we have the ownership of prev

        /*@ split_case(ptr_eq(
                member_shift<struct chunk_hdr>(prev, node)->next,
                member_shift<struct hyp_allocator>(allocator, chunks)));
        unpack Cn_chunk_hdrs(member_shift<struct chunk_hdr>(prev, node)->next,
                member_shift<struct chunk_hdr>(prev, node), HA_pre.ha.last, Cn_hyp_allocator_core(HA_pre.ha));
        split_case(ptr_eq(
                member_shift<struct chunk_hdr>(prev, node)->prev,
                member_shift<struct hyp_allocator>(allocator, chunks)));
        unpack Cn_chunk_hdrs_rev(member_shift<struct chunk_hdr>(prev, node)->prev,
                member_shift<struct chunk_hdr>(prev, node), HA_pre.ha.first, Cn_hyp_allocator_core(HA_pre.ha));
        @*/
        list_add(&chunk->node, &prev->node);
#ifdef __CN_VERIFY
        /*@ unpack CondListHead(...); @*/
#endif

        /*@ split_case(ptr_eq(
                member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        chunk_hash_update(prev);
	/*@ unpack MaybeChunkHdr(prev, !is_null(prev)); @*/
        chunk_hash_update(__chunk_next(chunk, allocator));
        chunk_hash_update(chunk);
	/*@ unpack MaybeChunkHdr(...); @*/
}

#ifdef __CN_VERIFY
void LemmaMergeArrays(
        char *p, unsigned long size1, unsigned long size2
)
/*@
requires
        let size = size1 + size2;
        let owned_by_ha = array_shift<byte>(p, size1);
        take X1 = Cn_char_array(p, size1);
        take X2 = Cn_char_array(owned_by_ha, size2);
        size1 <= (u64)MAXu32();
        size2 <= (u64)MAXu32();
        size <= (u64)MAXu32();
ensures
        take X = Cn_char_array(p, size);
@*/
{
        /*@
        unpack Cn_char_array(...);
        @*/
        unsigned long i;
        for (i = 0; i < size2; i++)
        /*@
        inv
                take L0 = Cn_char_array(p, size1 + i);
                take L1 = Cn_char_array_with_offset(owned_by_ha, size2 - i, i);
                {p} unchanged;
                {size1} unchanged;
                {size2} unchanged;
                i <= size2;
        @*/
        {
                /*@
                  unpack Cn_char_array(...);
                  focus W<byte>, i;
                  focus W<byte>, (size1 + i);
                @*/
        }
}

void LemmaMergeChunk(char *start, unsigned long size1, unsigned long size2)
/*@
requires
        take X = Cn_char_array(start, size1);
        take Hdr = Own_chunk_hdr(array_shift<char>(start, size1));
        take Y = Cn_char_array(array_shift<char>(start, size1 + Cn_chunk_hdr_size()), size2);
        size1 <= (u64)MAXu32();
        size2 <= (u64)MAXu32();
        let size_all = size1 + size2 + Cn_chunk_hdr_size();
        size_all <= (u64)MAXu32();
ensures
        take X_post = Cn_char_array(start, size_all);
@*/
{
        /*@
        to_bytes W<struct chunk_hdr_only>(array_shift<char>(start, size1));
        @*/
        LemmaMergeArrays(start, size1, chunk_hdr_size());
        LemmaMergeArrays(start, size1 + chunk_hdr_size(), size2);
}
#endif


static inline void chunk_list_del(struct chunk_hdr *chunk,
                                  struct hyp_allocator *allocator)
/*@
    requires
    take ha_full = Cn_hyp_allocator_only(allocator);
    let ha = {head: ha_full.head, start: ha_full.start, size: ha_full.size, first: ha_full.first};
    let end = ha.start + (u64)ha.size;

    // own this chunk
    take cn_hdr = Cn_chunk_hdr(chunk, ha);
    !is_null(cn_hdr.Node.next);
    !is_null(cn_hdr.Node.prev);
    cn_hdr.Hdr.alloc_size == 0u32;

    let prev = cn_hdr.Node.prev;
    !ptr_eq(prev, member_shift<struct hyp_allocator>(allocator, chunks));

    let prev_hdr_addr = array_shift<char>(prev, -offsetof(chunk_hdr, node));
    take prev_hdr = Cn_chunk_hdr_inner(prev_hdr_addr, ha, Option_u64_none {}, true, Option_u64_none {}, false);
    !is_null(prev_hdr.Node.next);
    !is_null(prev_hdr.Node.prev);
    (u64)prev_hdr.Hdr.alloc_size + Cn_chunk_hdr_size() <= (u64)prev_hdr.Hdr.mapped_size;
    (u64)prev_hdr.Hdr.mapped_size <= (u64)cn_hdr.Hdr.va_size + (u64)prev_hdr.Hdr.va_size;

    (u64)prev_hdr.Hdr.alloc_size + Cn_chunk_hdr_size() <= (u64)prev_hdr.Hdr.va_size;
    (u64)prev_hdr.Hdr.va_size <= (u64)cn_hdr.Hdr.va_size + (u64)prev_hdr.Hdr.va_size;

    // let chunk_end = prev_hdr.Hdr.header_address + (u64) prev_hdr.Hdr.mapped_size;
    // chunk_end <= end;
    // chunk_end >= prev_hdr.Hdr.header_address;
    let chunk_node = member_shift<struct chunk_hdr>(chunk, node);
    ptr_eq(prev_hdr.Node.next, chunk_node);

    // chunk must be a valid chunk in the allocator
    take hdrs1 = Cn_chunk_hdrs_rev(prev_hdr.Node.prev, prev, ha_full.first, ha);
    take hdrs2 = Cn_chunk_hdrs(cn_hdr.Node.next, chunk_node, ha_full.last, ha);

    ensures
        take HA_post = Cn_hyp_allocator_focusing_on(allocator, prev_hdr_addr);
        ha == Cn_hyp_allocator_core(HA_post.ha);
        HA_post.lseg.before == hdrs1;
        HA_post.lseg.chunk.mapped_size == prev_hdr.Hdr.mapped_size;
        HA_post.lseg.chunk.alloc_size == prev_hdr.Hdr.alloc_size;
        HA_post.lseg.chunk.header_address == prev_hdr.Hdr.header_address;
@*/
{
        /*@
        split_case(ptr_eq(
                member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct hyp_allocator>(allocator, chunks)));
        unpack Cn_chunk_hdrs(...);
        @*/
        struct chunk_hdr *prev = __chunk_prev(chunk, allocator);
        struct chunk_hdr *next = __chunk_next(chunk, allocator);

        // non-rust ownership type part
        list_del(&chunk->node);
        chunk_hash_update(prev);
        chunk_hash_update(next);
        /*@ unpack MaybeChunkHdr(...); @*/
#ifdef __CN_VERIFY
        unsigned long prev_va_size = (unsigned long)chunk - (unsigned long)prev;
        unsigned long cn_va_size = (next ?
                (unsigned long)next :
                allocator->start + allocator->size) - (unsigned long)chunk;
        /*@ assert(prev_va_size == (u64)prev_hdr.Hdr.va_size); @*/
        /*@ assert(cn_va_size == (u64)cn_hdr.Hdr.va_size); @*/
        LemmaMergeChunk((char *)chunk_data(prev) + prev->alloc_size,
                        prev_va_size - (chunk_hdr_size() + prev->alloc_size),
                        cn_va_size - chunk_hdr_size());
#endif
}

static void hyp_allocator_unmap(struct hyp_allocator *allocator,
                                unsigned long va, size_t size)
{
        struct kvm_hyp_memcache *mc = this_cpu_ptr(&hyp_allocator_mc);
        int nr_pages = size >> PAGE_SHIFT;
        unsigned long __va = va;

        WARN_ON(!PAGE_ALIGNED(va));
        WARN_ON(!PAGE_ALIGNED(size));

        while (nr_pages--) {
                phys_addr_t pa = __pkvm_private_range_pa((void *)__va);
                void *page = hyp_phys_to_virt(pa);

                push_hyp_memcache(mc, page, hyp_virt_to_phys, 0);
                __va += PAGE_SIZE;
        }

        pkvm_remove_mappings((void *)va, (void *)(va + size));
}

static int hyp_allocator_map(struct hyp_allocator *allocator,
                             unsigned long va, size_t size)
#ifdef __CN_VERIFY
/*@
        requires
                take HA_pre = Cn_hyp_allocator_only(allocator);

        ensures
                take HA_post = Cn_hyp_allocator_only(allocator);
                HA_post == HA_pre;
                let va_end = va + size;
                return == 0i32 implies
                (va <= va_end && va_end <= (HA_pre.start + (u64)HA_pre.size));
@*/
#endif
// HK: Hyp_allocator_map mines a new memory from memcache and maps it.
// This means that it returns an ownership of this mined memory out of thin air.
{
        struct kvm_hyp_memcache *mc = this_cpu_ptr(&hyp_allocator_mc);
        unsigned long va_end = va + size;
        int ret, nr_pages = 0;

        if (!PAGE_ALIGNED(va) || !PAGE_ALIGNED(size))
                return -EINVAL;

        if (va_end < va || va_end > (allocator->start + allocator->size))
                return -E2BIG;

        if (mc->nr_pages < (size >> PAGE_SHIFT)) {
                u8 *missing_donations = this_cpu_ptr(&hyp_allocator_missing_donations);
                u32 delta = (size >> PAGE_SHIFT) - mc->nr_pages;

/* CN DIFF */
// originally `*missing_donations = (u8)min(delta, (u32) ~((u8)0));`
#ifdef NO_STATEMENT_EXPRS
                *missing_donations = min_u32(delta, U8_MAX);
#else  /* NO_STATEMENT_EXPRS*/
                *missing_donations = min(delta, U8_MAX);
#endif /* NO_STATEMENT_EXPRS */

                return -ENOMEM;
        }

        while (nr_pages < (size >> PAGE_SHIFT)) {
                void *page;
                unsigned long order;

                page = pop_hyp_memcache(mc, hyp_phys_to_virt, &order);
                /* We only expect 1 page at a time for now. */
                WARN_ON(!page || order);

                ret = __hyp_allocator_map(va, hyp_virt_to_phys(page));
                if (ret) {
                        push_hyp_memcache(mc, page, hyp_virt_to_phys, 0);
                        break;
                }
                va += PAGE_SIZE;
                nr_pages++;
        }

        if (ret && nr_pages) {
                va -= PAGE_SIZE * nr_pages;
                hyp_allocator_unmap(allocator, va, nr_pages << PAGE_SHIFT);
        }

        return ret;
}

/*@
// no first chunk && no EINVAL in check_install
function (boolean) chunk_install_sanity_check(pointer prev_p, pointer chunk_p, struct chunk_hdr prev)
{
    !is_null(prev_p)
           && !(Cn_chunk_unmapped_region(prev_p, prev) < (u64)chunk_p)
           && !((u64)Cn_chunk_data(prev) + (u64)prev.alloc_size > (u64)chunk_p)
}

predicate (datatype chunk_hdr_u_option) MaybeChunkHdrU(pointer chunk, boolean condition)
{
        if (condition)
        {
                assert(!is_null(chunk));
                take alloc_size = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, alloc_size));
                take mapped_size = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, mapped_size));
                take node = RW<struct list_head>(member_shift<struct chunk_hdr>(chunk, node));
                assert((u64)node.next != 0u64);
                assert((u64)node.prev != 0u64);
                take hash = W<unsigned>(member_shift<struct chunk_hdr>(chunk, hash));
                take pad = W<unsigned>(member_shift<struct chunk_hdr>(chunk, explicit_padding));
                return ChunkHdr_u_some { alloc_size: alloc_size, mapped_size: mapped_size, node: node };
        }
        else
        {
                return ChunkHdr_u_none {};
        }
}

predicate (datatype chunk_hdr_option) MaybeChunkHdr(pointer chunk, boolean condition)
{
        if (condition)
        {
                take v = Own_chunk_hdr(chunk);
                return ChunkHdr_some { hdr: v };
        }
        else
        {
                return ChunkHdr_none {};
        }
}
@*/

/*@
// provably rewrite this by using lseg
predicate ({cn_hyp_allocator ha, cn_lseg lseg}) ChunkInstallPre(pointer chunk, u64 size, pointer prev, pointer allocator)
{
        if (is_null(prev))
        {
                assert(!is_null(chunk));
                take a_in=Cn_hyp_allocator(allocator);
                let ha = a_in.ha;
                assert(ptr_eq(ha.head,ha.first));

                assert(size <= (u64)ha.size);
                assert(PAGE_ALIGN(Cn_chunk_size(size)) <= (u64)a_in.ha.size);
                assert(ha.start == (u64)chunk);

                let dummy = {
                        header_address: 0u64,
                        mapped_size: 0u32,
                        alloc_size: 0u32,
                        va_size: 0u32
                };
                return {ha: a_in.ha, lseg: {before: Chunk_nil {}, after: Chunk_nil {}, chunk: dummy }};
        }
        else
        {
                take HA_pre = Cn_hyp_allocator_focusing_on(allocator, prev);
                let allocator_end = (u64)HA_pre.ha.start + (u64)HA_pre.ha.size;

                let P_pre = HA_pre.lseg.chunk;
                // order
                // (i) prev <= prev_alloc_end
                // (ii)      <= chunk
                // (iii)     <= chunk_alloc_end
                // (iv)      <= prev_old_mapped_size
                // (v)       <= prev old_va_size
                // (v)       <= prev old_va_size
                // (vi)      <= allocator_end
                let prev_alloc_end = (u64)prev + (u64)P_pre.alloc_size;
                let chunk_alloc_end = (u64)chunk + size + Cn_chunk_hdr_size();
                let prev_old_mapped_size = (u64)prev + (u64)P_pre.mapped_size;
                let prev_old_va_size = (u64)prev + (u64)P_pre.va_size;
                assert((u64)prev <= prev_alloc_end); // (i)
                assert(prev_alloc_end <= (u64)chunk); // (ii)
                assert((u64)chunk < (u64)chunk + Cn_chunk_hdr_size()); // (iii')
                assert((u64)chunk + Cn_chunk_hdr_size() <= chunk_alloc_end); // (iii'')
                assert(chunk_alloc_end <= prev_old_mapped_size); // (iv)
                assert(prev_old_mapped_size <= prev_old_va_size); // (v)
                assert(prev_old_va_size <= allocator_end); // (vi)

                return {ha: HA_pre.ha, lseg: HA_pre.lseg};
        }
}
predicate (void) ChunkInstallPost(pointer chunk, u64 size, pointer prev, pointer allocator, cn_hyp_allocator ha, cn_lseg lseg, i32 ret)
{
        if (is_null(prev))
        {
                assert(!is_null(chunk));
                take HA_post = Cn_hyp_allocator_focusing_on(allocator, chunk);
                let allocator_end = (u64)ha.start + (u64)ha.size;
                let first_chunk = {
                        header_address: (u64)chunk,
                        mapped_size: (u32)PAGE_ALIGN(Cn_chunk_size(size)),
                        alloc_size: (u32) size,
                        va_size: (u32) (allocator_end - (u64)chunk)
                };
                assert(HA_post.lseg.after == Chunk_nil {});
                assert(HA_post.lseg.chunk == first_chunk);
                assert(HA_post.lseg.before == Chunk_nil {} );
                let ha_post = {
                        head: ha.head,
                        size: ha.size,
                        start: ha.start,
                        first: member_shift<struct chunk_hdr_only>(chunk, node),
                        last: member_shift<struct chunk_hdr_only>(chunk, node)
                };
                assert(HA_post.ha == ha_post);
                assert(ret == 0i32);
                take U = Cn_char_array(array_shift<byte>(chunk, Cn_chunk_hdr_size()), size);
                return;
        }
        else
        { if (ret == 0i32)
        {
                take HA_post =Cn_hyp_allocator_focusing_on(allocator, prev);
                assert(HA_post.ha.size == ha.size && HA_post.ha.start == ha.start && ptr_eq(HA_post.ha.head, ha.head));
                assert(HA_post.lseg.before == lseg.before);

                assert(!is_null(chunk));

                let P_pre = lseg.chunk;
                let P_post = HA_post.lseg.chunk;



                let prev_mapped_size = P_pre.mapped_size;
                let prev_va_size = (u32)((u64)chunk - (u64)prev);
                assert(P_post == {
                        header_address: (u64)prev,
                        mapped_size: prev_va_size,
                        alloc_size: (u32)P_pre.alloc_size,
                        va_size: prev_va_size
                });

                let C_post = {
                        header_address: (u64)chunk,
                        mapped_size: prev_mapped_size - P_post.mapped_size,
                        alloc_size: (u32)size,
                        va_size: (u32)((u64)P_pre.va_size - (u64)P_post.va_size)
                };
                assert(HA_post.lseg.after == Chunk_cons {hd: C_post, tl: lseg.after});

                take U = Cn_char_array(array_shift<byte>(chunk, Cn_chunk_hdr_size()), size);

                return;
        }
        else {
                take HA_post =Cn_hyp_allocator_focusing_on(allocator, prev);
                let P_pre = lseg.chunk;
                assert(ha == HA_post.ha);
                assert(HA_post.lseg == lseg);

                let prev_u = (u64)prev + (u64)P_pre.mapped_size;
                let prev_cd = (u64)prev + (u64)offsetof(chunk_hdr, data);
                let cond = prev_u < (u64)chunk;
                let cond2 = (u64)prev_cd + (u64)P_pre.alloc_size > (u64)chunk;
                assert(cond || cond2);

                return;
        }
        }
}
@*/

#ifdef __CN_VERIFY
void LemmaSplitAndNewChunk(
        char *p, unsigned int size1, unsigned int size2
)
/*@
requires
        let size = (u64)size1 + (u64)size2;
        take X = Cn_char_array(p, size);
        let owned_by_ha = array_shift<byte>(p, (u64)size1);
ensures
        take X1 = Cn_char_array(p, (u64)size1);
        take X2 = Cn_char_array(owned_by_ha, (u64)size2);
@*/
{
        /*@
        unpack Cn_char_array(p, (u64)size1 + (u64)size2);
        @*/
        unsigned long i;
        for (i = 0; i < (unsigned long)size2; i++)
        /*@
        inv
                take L0 = Cn_char_array(p, (u64)size1);
                take L1 = Cn_char_array_with_offset(p, (u64)size2 - i, (u64)size1 + (u64)i);
                take L2 = Cn_char_array(owned_by_ha, i);
                {p} unchanged;
                {size1} unchanged;
                {size2} unchanged;
                i <= (u64)size2;
        @*/
        {
                /*@
                  unpack Cn_char_array(owned_by_ha, i);
                  focus W<byte>, i;
                  focus W<byte>, ((u64)size1 + i);
                @*/
        }
}

void LemmaCreateChunkHdr(char *chunk_data)
/*@
    requires
        !is_null(chunk_data);
        take X = Cn_char_array(chunk_data, Cn_chunk_hdr_size());
        let p = chunk_data;
    ensures
        take Y = W<struct chunk_hdr_only>(p);
@*/
{
        //LemmaSplitAndNewChunk(chunk_data, sizeof(unsigned), cur_size);
        /*@ unpack Cn_char_array(chunk_data, Cn_chunk_hdr_size()); @*/
        /*@
        from_bytes W<struct chunk_hdr_only>(chunk_data);
        @*/

}

void LemmaCreateNewChunkAux(char *chunk_data, size_t size1, size_t size, size_t size2)
/*@
requires
    !is_null(chunk_data);
    // no overflow
    size1 <= (u64)MAXu32();
    size <=  (u64)MAXu32();
    size2 <= (u64)MAXu32();
    let size_all = size1 + size + size2 + Cn_chunk_hdr_size();
    size_all <= (u64)MAXu32();
    take C_pre = Cn_char_array(chunk_data, size_all);

    let chunk_hdr = array_shift<byte>(chunk_data, size1);
    let chunk = array_shift<byte>(chunk_data, size1 + Cn_chunk_hdr_size());
    let remaining = array_shift<byte>(chunk_data, size1 + size + Cn_chunk_hdr_size());
ensures
    take C1 = Cn_char_array(chunk_data, size1);
    take chunk_hdr_only_u = W<struct chunk_hdr_only>(chunk_hdr);
    take C2 = Cn_char_array(chunk, size);
    take C3 = Cn_char_array(remaining, size2);
@*/
{
        /*
                +---------------------------+  ← chunk_data
                |          size1            |
                +---------------------------+  ← chunk_hdr
                |        chunk_hdr          |
                +---------------------------+  ← chunk
                |           size            |
                +---------------------------+  ← remaining
                |          size2            |
                +---------------------------+  ← end
        */

        /*@ unpack Cn_char_array(chunk_data, size_all); @*/

        size_t size_all = size1 + size + size2 + chunk_hdr_size();
        char *chunk_hdr = chunk_data + size1;
        char *chunk = (char *)chunk_hdr + chunk_hdr_size();
        char *remaining = chunk + size;
        LemmaSplitAndNewChunk(chunk_data, size1, size_all - size1);
        size_all -= size1;
        LemmaSplitAndNewChunk(chunk_hdr, chunk_hdr_size(), size_all - chunk_hdr_size());
        size_all -= chunk_hdr_size();
        LemmaSplitAndNewChunk(chunk, size, size_all - size);

        /*@ unpack Cn_char_array(...); @*/
        /*@ from_bytes W<struct chunk_hdr_only>(chunk_hdr); @*/
	/*@ unpack Cn_char_array(...); @*/
}


void LemmaCreateNewChunk(struct chunk_hdr *chunk, size_t size,
                         struct chunk_hdr *prev,
                         struct hyp_allocator *allocator)
/*@
requires
        !is_null(prev);
        take HA_pre = Cn_hyp_allocator_focusing_on(allocator, prev);
        let P_pre = HA_pre.lseg.chunk;


        let allocator_end = (u64)HA_pre.ha.start + (u64)HA_pre.ha.size;
        HA_pre.ha.start <= (u64)prev && (u64)prev < allocator_end;

        // order
        // (i) prev <= prev_alloc_end
        // (ii)      <= chunk
        // (iii)     <= chunk_alloc_end
        // (iv)      <= prev_old_mapped_size
        // (v)       <= prev old_va_size
        // (vi)      <= allocator_end
        let prev_alloc_end = (u64)prev + (u64)P_pre.alloc_size + Cn_chunk_hdr_size();
        let chunk_alloc_end = (u64)chunk + size + Cn_chunk_hdr_size();
        let prev_old_mapped_size = (u64)prev + (u64)P_pre.mapped_size;
        let prev_old_va_size = (u64)prev + (u64)P_pre.va_size;
        (u64)prev <= (u64)prev + Cn_chunk_hdr_size(); // (i)
        (u64)prev + Cn_chunk_hdr_size() <= prev_alloc_end; // (i')
        prev_alloc_end <= (u64)chunk; // (ii)
        (u64)chunk < (u64)chunk + Cn_chunk_hdr_size(); // (iii')
        (u64)chunk + Cn_chunk_hdr_size() <= chunk_alloc_end; // (iii'')
        chunk_alloc_end <= prev_old_mapped_size; // (iv)
        prev_old_mapped_size <= prev_old_va_size; // (v)
        prev_old_va_size <= allocator_end; // (vi)
ensures
        take HA_post = Cn_hyp_allocator_focusing_on_for_install(allocator, prev, chunk, Option_u64_some{value: (u64)size}, false);
        HA_post.ha == HA_pre.ha;
        HA_post.lseg.before == HA_pre.lseg.before;
        HA_post.lseg.after == HA_pre.lseg.after;
        HA_post.lseg.chunk.header_address == HA_pre.lseg.chunk.header_address;
        HA_post.lseg.chunk.mapped_size == HA_pre.lseg.chunk.mapped_size;
        HA_post.lseg.chunk.alloc_size == HA_pre.lseg.chunk.alloc_size;
        (u64)HA_post.lseg.chunk.va_size + (u64)HA_post.va_size == (u64)HA_pre.lseg.chunk.va_size;

         take chunk_hdr_only_u = W<struct chunk_hdr_only>(chunk);
        take X = Cn_char_array(array_shift<byte>(chunk, Cn_chunk_hdr_size() + (u64)size), (u64)HA_post.va_size - (u64)size - Cn_chunk_hdr_size());


        take V = Cn_char_array(array_shift<byte>(chunk, Cn_chunk_hdr_size()), (u64)size);
@*/
{
        /*@
                split_case(ptr_eq(
                        member_shift<struct chunk_hdr>(prev, node)->next,
                        member_shift<struct hyp_allocator>(allocator, chunks)));
        @*/
        // maybe? for chunk_unmapped_size
        /*@ unpack Cn_chunk_hdrs(member_shift<struct chunk_hdr>(prev, node)->next,
                member_shift<struct chunk_hdr>(prev, node), HA_pre.ha.last, Cn_hyp_allocator_core(HA_pre.ha));
        @*/
        unsigned long chunk_end = (unsigned long)prev + prev->mapped_size +
                                  chunk_unmapped_size(prev, allocator);
        size_t size_1 = (u64)chunk - (u64)prev - chunk_hdr_size() - prev->alloc_size;
        size_t size_2 = chunk_end - (u64)chunk - chunk_hdr_size() - size;
        LemmaCreateNewChunkAux((char*)chunk_data(prev) + prev->alloc_size, size_1, size, size_2);
	/*@ unpack MaybeChunkHdr(...); @*/
}
#endif

// chunk: the new chunk to install
// size: alloc size for chunk
// prev: the previous chunk for `chunk`
//   - this is never be allocator->chunks
// invariant:
//   - there is no chunk between prev and chunk
//   - chunk is not owned by the allocator
static int chunk_install(struct chunk_hdr *chunk, size_t size,
                         struct chunk_hdr *prev,
                         struct hyp_allocator *allocator)
/*@
    requires
        take Pre = ChunkInstallPre(chunk, size, prev, allocator);
    ensures
        take Post = ChunkInstallPost(chunk, size, prev, allocator, Pre.ha, Pre.lseg, return);
        // TODO: take alloc_size buffer
@*/

{
        size_t prev_mapped_size;

        /* First chunk, first allocation */
        if (!prev) {
	        /*@ unpack ChunkInstallPre(...); @*/
	        /*@ unpack FirstAllocation(...); @*/
#ifdef __CN_VERIFY
                LemmaCreateNewChunkAux((char *)allocator->start, 0, size, (u64)allocator->size - size - chunk_hdr_size());
#endif
                // Drop the garbage due to the lemma
                /*@ unpack Cn_char_array((pointer)allocator->start, 0u64); @*/
                INIT_LIST_HEAD(&chunk->node);
                // HK: non-rust ownership type part
                // See the comments in chunk_list_insert
                // HK: Currently we encounter the CN issue #148,
                // so we cannot go further with the spec.
                /*@ unpack Cn_chunk_hdrs(member_shift<struct hyp_allocator>(allocator, chunks)->next, member_shift<struct hyp_allocator>(allocator, chunks), Pre.ha.last, Cn_hyp_allocator_core(Pre.ha));
                @*/
                list_add(&chunk->node, &allocator->chunks);
                chunk->mapped_size = PAGE_ALIGN(chunk_size(size));
                chunk->alloc_size = size;

                chunk_hash_update(chunk);

#ifdef __CN_VERIFY
		/*@ unpack MaybeChunkHdr(...); @*/
		/*@ unpack CondListHead(...); @*/
#endif
                return 0;
        }
	/*@ unpack ChunkInstallPre(...); @*/

        if (chunk_unmapped_region(prev) < (unsigned long)chunk)
                return -EINVAL;

        if ((unsigned long)chunk_data(prev) + prev->alloc_size > (unsigned long)chunk)
                return -EINVAL;

#ifdef __CN_VERIFY
        LemmaCreateNewChunk(chunk, size, prev, allocator);
#endif
        prev_mapped_size = prev->mapped_size;
        prev->mapped_size = (unsigned long)chunk - (unsigned long)prev;


        chunk->mapped_size = prev_mapped_size - prev->mapped_size;
        chunk->alloc_size = size;

        /*@
                split_case(ptr_eq(
                        member_shift<struct chunk_hdr>(prev, node)->next,
                        member_shift<struct hyp_allocator>(allocator, chunks)));
        @*/
        /*@
        unpack Cn_chunk_hdrs(member_shift<struct chunk_hdr>(prev, node)->next,
                member_shift<struct chunk_hdr>(prev, node), Pre.ha.last, Cn_hyp_allocator_core(Pre.ha));
        @*/

        chunk_list_insert(chunk, prev, allocator);

        return 0;
}

static int chunk_merge(struct chunk_hdr *chunk, struct hyp_allocator *allocator)
/*@
requires
        take HA_pre = Cn_hyp_allocator_focusing_on(allocator, chunk);
        HA_pre.lseg.before != Chunk_nil {};
        let prev = match (HA_pre.lseg.before) {
            Chunk_nil {} => {
                // dummy
                {
                    header_address: 0u64,
                    va_size: 0u32,
                    alloc_size: 0u32,
                    mapped_size: 0u32
                }
            }
            Chunk_cons {hd:hdr, tl:tl} => {
                hdr
            }
        };
        let prev_tl = match (HA_pre.lseg.before) {
            Chunk_nil {} => {
                // dummy
                Chunk_nil {}
            }
            Chunk_cons {hd:hdr, tl:tl} => {
                tl
            }
        };
        let C = HA_pre.lseg.chunk;
ensures
        let cond1 = (C.alloc_size != 0u32 || prev.alloc_size != 0u32);
        cond1 implies return != 0i32;
        !cond1 implies return == 0i32;

        let cond2 = prev.header_address + (u64)prev.mapped_size != (u64)chunk;
        let merge_able = !cond1 && !cond2;

        take HA_post = Cn_hyp_allocator_focusing_on(allocator, (pointer)prev.header_address);
        HA_post.lseg.before == prev_tl;

        merge_able implies HA_post.lseg.chunk.mapped_size == prev.mapped_size + C.mapped_size;
@*/
{
        /*@ split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev,
                member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        /*@ unpack Cn_chunk_hdrs_rev(...); @*/
        /* The caller already validates prev */
        struct chunk_hdr *prev = __chunk_prev(chunk, allocator);

        if (WARN_ON(!prev))
                return -EINVAL;


        /* Can only merge free chunks */
        if (chunk_is_used(chunk) || chunk_is_used(prev))
                return -EBUSY;


        /* Can't merge non-contiguous mapped regions */
        if (chunk_unmapped_region(prev) != (unsigned long)chunk)
                return 0;


        /* mapped region inheritance */
        prev->mapped_size += chunk->mapped_size;

        chunk_list_del(chunk, allocator);

        return 0;
}
/*@
function (u64)Cn_chunk_needs_mapping(u64 mapped_size, u64 size)
{
        (Cn_chunk_size(size) <= mapped_size) ? 0u64 : PAGE_ALIGN(Cn_chunk_size(size) - mapped_size)
}
@*/

static size_t chunk_needs_mapping(struct chunk_hdr *chunk, size_t size)
/*@
        requires
                take C_pre = Own_chunk_hdr(chunk);
        ensures
                take C_post = Own_chunk_hdr(chunk);
                C_pre == C_post;
                return == Cn_chunk_needs_mapping((u64)C_post.mapped_size, size);
@*/
{
        // TODO: fix this. Due to the Cerberus elaboration bug, we cannot use
        // size_t here currently.
        // size_t mapping_missing, mapping_needs = chunk_size(size);
        size_t mapping_missing, mapping_needs = chunk_size(size);

        if (mapping_needs <= chunk->mapped_size)
                return 0;


        mapping_missing = PAGE_ALIGN(mapping_needs - chunk->mapped_size);

        return mapping_missing;
}

/*
 * When a chunk spans over several pages, split it at the start of the latest
 * page. This allows to punch holes in the mapping to reclaim pages.
 *
 *  +--------------+
 *  |______________|
 *  |______________|<- Next chunk
 *  |_ _ _ __ _ _ _|
 *  |              |<- New chunk installed, page aligned
 *  +--------------+
 *  +--------------+
 *  |              |
 *  |              |<- Allow to reclaim this page
 *  |              |
 *  |              |
 *  +--------------+
 *  +--------------+
 *  |              |
 *  |______________|
 *  |______________|<- Chunk to split at page alignment
 *  |              |
 *  +--------------+
 */
static int chunk_split_aligned(struct chunk_hdr *chunk,
                               struct hyp_allocator *allocator)
{
        struct chunk_hdr *next_chunk = chunk_get_next(chunk, allocator);
        unsigned long delta, mapped_end = chunk_unmapped_region(chunk);
        struct chunk_hdr *new_chunk;

        if (PAGE_ALIGNED(mapped_end))
                return 0;


        new_chunk = (struct chunk_hdr *)PAGE_ALIGN_DOWN(mapped_end);
        if ((unsigned long)new_chunk <= (unsigned long)chunk)
                return -EINVAL;


        delta = ((unsigned long)next_chunk - (unsigned long)new_chunk);

        /*
         * This shouldn't happen, chunks are installed to a minimum distance
         * from the page start
         */
        WARN_ON(delta < chunk_size(0UL));

        WARN_ON(chunk_install(new_chunk, 0, chunk, allocator));

        return 0;
}

// TODO(HK): fix this after the elaboration bug is fixed
//static int chunk_inc_map(struct chunk_hdr *chunk, size_t map_size,
// HK: It takes a lot of time to prove this spec (more than 8 minutes on my machine)
static int chunk_inc_map(struct chunk_hdr *chunk, size_t map_size,
                         struct hyp_allocator *allocator)
/*@
        requires
                !is_null(chunk);
                take HA_pre = Cn_hyp_allocator_focusing_on(allocator, chunk);
                let C_pre = HA_pre.lseg.chunk;
        ensures
                take HA_post = Cn_hyp_allocator_focusing_on(allocator, chunk);
                HA_post.ha == HA_pre.ha;
                HA_post.lseg.before == HA_pre.lseg.before;
                HA_post.lseg.after == HA_pre.lseg.after;

                let C_post = HA_post.lseg.chunk;
                C_post.alloc_size == C_pre.alloc_size;
                C_post.va_size == C_pre.va_size;
                C_post.header_address == C_pre.header_address;

                let cond = (u64)C_pre.va_size - (u64)C_pre.mapped_size < map_size;
                cond implies return == -EINVAL();

                (return == 0i32) implies
                C_post.mapped_size == (C_pre.mapped_size + (u32)map_size);

                (return != 0i32) implies
                C_post.mapped_size == C_pre.mapped_size;
@*/
{
        int ret;

        // HK: we need this because of `chunk_hash_validate` in get_next_chunk...
        /*@
        split_case(ptr_eq(
                    member_shift<struct chunk_hdr>(chunk, node)->next,
                    member_shift<struct hyp_allocator>(allocator, chunks)));
        unpack Cn_chunk_hdrs(member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct chunk_hdr>(chunk, node), HA_pre.ha.last, Cn_hyp_allocator_core(HA_pre.ha));
        @*/
        //if (chunk->node.next != &allocator->chunks) {
        //        /*@
        //        split_case(ptr_eq(
        //                (member_shift<struct chunk_hdr>(chunk, node)->next)->next,
        //                member_shift<struct hyp_allocator>(allocator, chunks)));
        //        unpack Cn_chunk_hdrs((member_shift<struct chunk_hdr>(chunk, node)->next)->next,
        //        (member_shift<struct chunk_hdr>(chunk, node)->next), HA_pre.ha.last, Cn_hyp_allocator_core(HA_pre.ha));
        //        @*/
        //}
        if (chunk_unmapped_size(chunk, allocator) < map_size) {
	        /*@ unpack MaybeChunkHdr(array_shift<char>(member_shift<struct chunk_hdr>(chunk, node)->next, -offsetof(chunk_hdr, node)), !ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next, member_shift<struct hyp_allocator>(allocator, chunks))); @*/
                return -EINVAL;
        }
	/*@ unpack MaybeChunkHdr(array_shift<char>(member_shift<struct chunk_hdr>(chunk, node)->next, -offsetof(chunk_hdr, node)), !ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next, member_shift<struct hyp_allocator>(allocator, chunks))); @*/

        ret = hyp_allocator_map(allocator, chunk_unmapped_region(chunk),
                                map_size);
        if (ret)
                return ret;


        chunk->mapped_size += map_size;
        /*@ split_case(ptr_eq(
                    member_shift<struct chunk_hdr>(chunk, node),
                    member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        /*@ split_case(ptr_eq(
                    member_shift<struct chunk_hdr>(chunk, node)->next,
                    member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        /*@ split_case(!is_null(member_shift<struct chunk_hdr>(chunk, node)));@*/
        /*@ split_case(!is_null(member_shift<struct chunk_hdr>(chunk, node)->next));@*/
        chunk_hash_update(chunk);
	/*@ unpack MaybeChunkHdr(chunk, !is_null(chunk)); @*/
        return 0;
}

static size_t chunk_dec_map(struct chunk_hdr *chunk,
                            struct hyp_allocator *allocator,
                            size_t reclaim_target)
{
        unsigned long start, end;
        size_t reclaimable;

        start = PAGE_ALIGN((unsigned long)chunk +
                           chunk_size(chunk->alloc_size));
        end = chunk_unmapped_region(chunk);

        if (start >= end)
                return 0;


        reclaimable = end - start;
        if (reclaimable < PAGE_SIZE)
                return 0;


        if (chunk_split_aligned(chunk, allocator))
                return 0;


        end = chunk_unmapped_region(chunk);
#ifdef NO_STATEMENT_EXPRS
        reclaimable = min_u64(end - start, reclaim_target);
#else  /* NO_STATEMENT_EXPRS */
        reclaimable = min(end - start, reclaim_target);
#endif /* NO_STATEMENT_EXPRS */
        start = end - reclaimable;

        hyp_allocator_unmap(allocator, start, reclaimable);

        chunk->mapped_size -= reclaimable;
        chunk_hash_update(chunk);

        return reclaimable;
}

/*@
function (u64) Cn_chunk_addr_fixup(u64 addr)
{

        // let min_chunk_size = Cn_chunk_size(0u64);
        // let page = PAGE_ALIGN_DOWN(addr);
        // let delta = addr - page;
        // let res = delta == 0u64 ? addr :
        //         (delta < min_chunk_size ? (page + min_chunk_size) : addr);
        (addr - PAGE_ALIGN_DOWN(addr)) == 0u64 ? addr :
                ((addr - PAGE_ALIGN_DOWN(addr)) < Cn_chunk_size(0u64) ? (PAGE_ALIGN_DOWN(addr) + Cn_chunk_size(0u64)) : addr)
}
@*/

static unsigned long chunk_addr_fixup(unsigned long addr)
/*@
    ensures return == Cn_chunk_addr_fixup(addr);
@*/
{
        unsigned long min_chunk_size = chunk_size(0UL);
        unsigned long page = PAGE_ALIGN_DOWN(addr);
        unsigned long delta = addr - page;

        if (!delta)
                return addr;


        /*
         * To maximize reclaim, a chunk must fit between the page start and this
         * addr.
         */
        if (delta < min_chunk_size)
                return page + min_chunk_size;



        return addr;
}

/*@
function (boolean) Cn_chunk_can_split(cn_lseg lseg, u64 addr)
{
        match (lseg.after) {
                // last chunk
                Chunk_nil {} => { false }
                Chunk_cons {hd:hdr, tl:tl} => {
                        ((addr + Cn_chunk_size(0u64)) < lseg.chunk.header_address + (u64)lseg.chunk.va_size)
                }
        }
}
@*/

static bool chunk_can_split(struct chunk_hdr *chunk, unsigned long addr,
                            struct hyp_allocator *allocator)

/*
   required_size
   |-------------|-------------|
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           va_size
   => |---------|    |-----------|
        |--------------^
*/
/*@
        requires
                !is_null(chunk);
                take HA_pre = Cn_hyp_allocator_focusing_on(allocator, chunk);
        ensures
                take HA_post = Cn_hyp_allocator_focusing_on(allocator, chunk);
                HA_post == HA_pre;
                return == (Cn_chunk_can_split(HA_pre.lseg, addr) ? 1u8 : 0u8);
@*/
{
        unsigned long chunk_end;

        /*
         * There is no point splitting the last chunk, subsequent allocations
         * would be able to use this space anyway.
         */
        /*@ split_case(ptr_eq(
                member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        /*@ unpack Cn_chunk_hdrs(member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct chunk_hdr>(chunk, node), HA_pre.ha.last, Cn_hyp_allocator_core(HA_pre.ha)); @*/
        if (list_is_last(&chunk->node, &allocator->chunks))
                return false;


        chunk_end = (unsigned long)chunk + chunk->mapped_size +
                    chunk_unmapped_size(chunk, allocator);
	/*@ unpack MaybeChunkHdr(array_shift<char>(member_shift<struct chunk_hdr>(chunk, node)->next, -offsetof(chunk_hdr, node)), !ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next, member_shift<struct hyp_allocator>(allocator, chunks))); @*/
        return addr + chunk_size(0UL) < chunk_end;
}
/*@
function (boolean) chunk_recycle_aux(datatype cn_chunk_hdrs pre, datatype cn_chunk_hdrs post, cn_chunk_hdr next_chunk )
{
        match (post) {
                Chunk_nil {} => { false }
                Chunk_cons { hd: chunk, tl: tl } => {
                        tl == pre && chunk == next_chunk
                }
        }
}
@*/

/*@
function (u64) Cn_expected_mapping(pointer chunk, u64 size)
{
        Cn_chunk_addr_fixup((u64)chunk + Cn_chunk_size(size)) - (u64)chunk
}
@*/

static int chunk_recycle(struct chunk_hdr *chunk, size_t size,
                         struct hyp_allocator *allocator)
/*@
    requires
        take HA_pre = Cn_hyp_allocator_focusing_on(allocator, chunk);
        let C_pre = HA_pre.lseg.chunk;
        size > 0u64 && size < (u64)HA_pre.ha.size;
        C_pre.alloc_size == 0u32;

        // suffix '_' is to avoid the name conflict due to Fulminate
        let new_chunk_addr_ = Cn_chunk_addr_fixup((u64)chunk + Cn_chunk_size(size));
        new_chunk_addr_ >= (u64)chunk;
        let chunk_va_size_post = new_chunk_addr_ - (u64)chunk;
        let new_chunk_va_size = (u32)((u64)C_pre.va_size - chunk_va_size_post);
    ensures
        take HA_post = Cn_hyp_allocator_focusing_on(allocator, chunk);

        HA_pre.ha.start == HA_post.ha.start;
        HA_pre.ha.size == HA_post.ha.size;
        ptr_eq(HA_pre.ha.head, HA_post.ha.head);

        let C_post = HA_post.lseg.chunk;
        let can_split = Cn_chunk_can_split(HA_pre.lseg, new_chunk_addr_);
        (return == 0i32 && can_split) implies
                C_post == {
                        header_address: C_pre.header_address,
                        mapped_size: (u32)chunk_va_size_post,
                        alloc_size: (u32)size,
                        va_size: (u32)chunk_va_size_post
                };

        let tmp_mapped_size = (u64)C_pre.mapped_size + Cn_chunk_needs_mapping((u64)C_pre.mapped_size, size);
        (return == 0i32 && !can_split) implies
                C_post == {
                        header_address: C_pre.header_address,
                        mapped_size: (u32)tmp_mapped_size,
                        alloc_size: (u32)size,
                        va_size: C_pre.va_size
                };
        take U = Conditional_Cn_char_array(array_shift<byte>(chunk, Cn_chunk_hdr_size()), size, return == 0i32);

@*/
{
	/*@ assert(!is_null(chunk)); @*/
        unsigned long new_chunk_addr = (unsigned long)chunk + chunk_size(size);
        size_t missing_map, expected_mapping = size;
        struct chunk_hdr *new_chunk = NULL;
        int ret;

        /*@
        split_case(ptr_eq(
                member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct hyp_allocator>(allocator, chunks)));
        @*/

        /*@ unpack Cn_chunk_hdrs(member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct chunk_hdr>(chunk, node), HA_pre.ha.last, Cn_hyp_allocator_core(HA_pre.ha)); @*/

        new_chunk_addr = chunk_addr_fixup(new_chunk_addr);
        if (chunk_can_split(chunk, new_chunk_addr, allocator)) {
                new_chunk = (struct chunk_hdr *)new_chunk_addr;
                // HK: when we can split the chunk,
                // the va addresses of the header of the new chunk have to be mapped.
                // HK: :exploding_head:
                //   new_chunk_addr == chunk + chunk_hdr_size() + size + Δ;
                //   chunk_data(chunk) == chunk + chunk_hdr_size();
                // so,
                //   expected_mapping == size + chunk_hdr_size() + Δ
                // where Δ < 32, right?
                expected_mapping = new_chunk_addr + chunk_hdr_size() -
                                        (unsigned long)chunk_data(chunk);
        }
        missing_map = chunk_needs_mapping(chunk, expected_mapping);
        if (missing_map) {
                ret = chunk_inc_map(chunk, missing_map, allocator);
                if (ret)
                        return ret;

        }

        /*@ unpack Cn_chunk_hdrs(...); @*/
#ifdef __CN_VERIFY
        LemmaSplitAndNewChunk(chunk_data(chunk), size, chunk->mapped_size +
                                                        chunk_unmapped_size(chunk, allocator)- size - chunk_hdr_size());
#endif
        chunk->alloc_size = size;

        chunk_hash_update(chunk);

        if (new_chunk) {
                // /*@
                // apply SplitAndNewChunk(original_cn_char_array, (u32)size_1, (u32)size_2, (u32)size_3);
                // @*/
                //(u64)chunk_va_size_post - (Cn_chunk_hdr_size() + size)
                // chunk must be non null
		/*@ assert(!is_null(chunk)); @*/
	        /*@ unpack MaybeChunkHdr(...); @*/
		/* CN DIFF */
		/* HK: capturing the return value is needed to unfold `ChunkInstallPost` */
		    int ret = chunk_install(new_chunk, 0, chunk, allocator);
                    WARN_ON(ret);
                /*@ split_case(is_null(chunk)); @*/
                /*@ split_case(ret == 0i32); @*/
		/*@ unpack ChunkInstallPost(...); @*/

                // destroy the garbage here
                /*@ unpack Cn_char_array(...); @*/
        }

	/*@ unpack MaybeChunkHdr(...); @*/
        return 0;
}

static size_t chunk_try_destroy(struct chunk_hdr *chunk,
                                struct hyp_allocator *allocator,
                                size_t reclaim_target)
{
        size_t unmapped;

        if (chunk_is_used(chunk))
                return 0;


        /* Don't kill the entire chunk if this is not necessary */
        if (chunk->mapped_size > reclaim_target)
                return 0;


        if (list_is_first(&chunk->node, &allocator->chunks)) {
                /* last standing chunk ? */
                if (!list_is_last(&chunk->node, &allocator->chunks))
                        return 0;


                list_del(&chunk->node);
                goto unmap;
        }

        /*
         * Resolve discontiguous unmapped zones that are the result
         * of a previous chunk_dec_map().
         *
         * To make sure we still keep track of that unmapped zone in our free
         * list, we need either to be the last chunk or to have prev unused. Two
         * contiguous chunks can be both free if they are separated by an
         * unmapped zone (see chunk_recycle()).
         */

        if (!PAGE_ALIGNED((unsigned long)chunk))
                return 0;


        if (list_is_last(&chunk->node, &allocator->chunks))
                goto destroy;


        if (chunk_is_used(chunk_get_prev(chunk, allocator)))
                return 0;


        if (chunk_split_aligned(chunk, allocator))
                return 0;

destroy:
        chunk_list_del(chunk, allocator);
unmap:
        unmapped = chunk->mapped_size;
        hyp_allocator_unmap(allocator, (unsigned long)chunk,
                            chunk->mapped_size);

        return unmapped;
}
/*@
// function (boolean) SetupFirstChunk_ex1(cn_chunk_hdrs after)
// {
//         match (after) {
//             Chunk_nil {} => { false }
//             Chunk_cons { hd: next_chunk, tl: tl } => {
//                     tl == Chunk_nil {}
//             }
//         }
//
// }
predicate (void) SetupFirstChunk(pointer allocator, cn_hyp_allocator ha_pre, size_t size, i32 ret)
{
    if (ret == 0i32) {
        let start = (pointer)ha_pre.start;
        take HA_post =Cn_hyp_allocator_focusing_on(allocator, start);
        let allocator_end = (u64)HA_post.ha.start + (u64)HA_post.ha.size;
        let first_chunk = {
                header_address: (u64)start,
                mapped_size: (u32)PAGE_ALIGN(Cn_chunk_size(size)),
                alloc_size: (u32) size,
                va_size: (u32) (allocator_end - (u64)start)
        };
        assert(HA_post.lseg.after == Chunk_nil {});
        assert(HA_post.lseg.chunk == first_chunk);
        assert(HA_post.lseg.before == Chunk_nil {} );
        let ha_post = {
                head: ha_pre.head,
                size: ha_pre.size,
                start: ha_pre.start,
                first: member_shift<struct chunk_hdr_only>(start, node),
                last: member_shift<struct chunk_hdr_only>(start, node)
        };
        assert(HA_post.ha == ha_post);

        // the chunk allocated to the client
        let chunk_data = array_shift<byte>(start, Cn_chunk_hdr_size());
        take Arr = Cn_char_array(chunk_data, size);

        return;
    } else {
        take a_out=Cn_hyp_allocator(allocator);
        assert(a_out.ha == ha_pre);
        return;
    }
}
@*/

static int setup_first_chunk(struct hyp_allocator *allocator, size_t size)
/*@
    requires take a_in=Cn_hyp_allocator(allocator);
    ptr_eq(a_in.ha.head, a_in.ha.first);
    size >= MIN_ALLOC();
    PAGE_ALIGN(Cn_chunk_size(size)) >= size; // no overflow
    ensures
    take X = SetupFirstChunk(allocator, a_in.ha, size, return);
    PAGE_ALIGN(Cn_chunk_size(size)) > (u64)a_in.ha.size implies return != 0i32;
@*/
{
        int ret;

        ret = hyp_allocator_map(allocator, allocator->start,
                                PAGE_ALIGN(chunk_size(size)));
        if (ret)
                return ret;


        /*@ split_case(a_in.hdrs==Chunk_nil{}); @*/
        /*@ split_case(is_null(NULL)); @*/
        /*CN*/int retv = chunk_install((struct chunk_hdr *)allocator->start, size, NULL, allocator);
	/*@ unpack ChunkInstallPost((pointer)a_in.ha.start, size, NULL, allocator, a_in.ha, {before: Chunk_nil {}, after: Chunk_nil {}, chunk: {header_address: 0u64, mapped_size: 0u32, alloc_size: 0u32, va_size: 0u32} }, retv); @*/
	/*CN*/return retv;
}
/*@
// This is for get_free_chunk
predicate [rec] (datatype cn_chunk_hdrs) Cn_chunk_hdrs_rev_alt(pointer p, pointer next, pointer first_chunk_node, cn_hyp_allocator_core ha, pointer head)
{
        if (ptr_eq(p,head)) {
                assert(ha.start <= ha.start + (u64)ha.size);
                assert(ptr_eq(next, first_chunk_node));
                return Chunk_nil {};
        } else {
                assert(!is_null(p));
                let header_address = array_shift<char>(p, -(offsetof(chunk_hdr_only, node)) ); // or some offsetof arithmetic
                take cn_hdr = Cn_chunk_hdr(header_address, ha);
                assert(ptr_eq(cn_hdr.Node.next, next));
                // HK: I think this assertion is not needed, if CN handles NULL "properly"
                // c.f. https://github.com/rems-project/cn/issues/135
                assert(!is_null(cn_hdr.Node.next));
                assert(!is_null(cn_hdr.Node.prev));
                take tl = Cn_chunk_hdrs_rev_alt(cn_hdr.Node.prev, p, first_chunk_node, ha, head);

                return Chunk_cons { hd: cn_hdr.Hdr, tl: tl };
        }
}

predicate ({cn_hyp_allocator ha, cn_chunk_hdr best_chunk, struct list_head node}) LemmaCnChunkHdrsRevToCnChunkHdrsInv(pointer allocator, pointer chunk, pointer best_chunk)
{
    if (ptr_eq(member_shift<struct chunk_hdr>(chunk, node), member_shift<struct chunk_hdr>(best_chunk, node))) {
        take ha = Cn_hyp_allocator_only(allocator);
        let ha_core = Cn_hyp_allocator_core(ha);
        take BestChunk = Cn_chunk_hdr(best_chunk, ha_core);
        assert(!is_null(BestChunk.Node.next));
        assert(!is_null(BestChunk.Node.prev));
        let best_chunk_node = member_shift<struct chunk_hdr>(best_chunk, node);
        take hdrs2_post = Cn_chunk_hdrs(BestChunk.Node.next, best_chunk_node, ha.last, ha_core);
        return {ha: ha, best_chunk: BestChunk.Hdr, node: BestChunk.Node};
    }
    else
    {
        take ha = Cn_hyp_allocator_only(allocator);
        let ha_core = Cn_hyp_allocator_core(ha);

        take BestChunk = Cn_chunk_hdr(best_chunk, ha_core);
        assert(!is_null(BestChunk.Node.next));
        assert(!is_null(BestChunk.Node.prev));
        let best_chunk_node = member_shift<struct chunk_hdr>(best_chunk, node);

        take cn_hdr = Cn_chunk_hdr(chunk, ha_core);
        assert(!is_null(cn_hdr.Node.next));
        assert(!is_null(cn_hdr.Node.prev));

        let chunk_node = member_shift<struct chunk_hdr>(chunk, node);
        take hdrs1 = Cn_chunk_hdrs_rev_alt(cn_hdr.Node.prev, chunk_node, BestChunk.Node.next, ha_core, best_chunk_node);
        take hdrs2 = Cn_chunk_hdrs(cn_hdr.Node.next, chunk_node, ha.last, ha_core);
        return {ha: ha, best_chunk: BestChunk.Hdr, node: BestChunk.Node};
    }
}
@*/

#ifdef __CN_VERIFY
void LemmaCnChunkHdrsRevToCnChunkHdrs(struct hyp_allocator *allocator, struct chunk_hdr *best_chunk)
/*@
        requires
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);

                take BestChunk = Cn_chunk_hdr(best_chunk, ha_core);
                !is_null(BestChunk.Node.next);
                !is_null(BestChunk.Node.prev);

                let best_chunk_node = member_shift<struct chunk_hdr>(best_chunk, node);

                take hdrs2 = Cn_chunk_hdrs_rev_alt(ha.last, ha_core.head, BestChunk.Node.next, ha_core, best_chunk_node);
        ensures
                take ha2 = Cn_hyp_allocator_only(allocator);
                ha == ha2;

                take BestChunk2 = Cn_chunk_hdr(best_chunk, ha_core);
                !is_null(BestChunk.Node.next);
                !is_null(BestChunk.Node.prev);

                BestChunk == BestChunk2;
                take hdrs2_post = Cn_chunk_hdrs(BestChunk.Node.next, best_chunk_node, ha.last, ha_core);

@*/
{
        /*@ split_case(ptr_eq(ha.last, best_chunk_node)); @*/
        /*@ unpack Cn_chunk_hdrs_rev_alt(...); @*/
        struct chunk_hdr *chunk;

        for (chunk = list_last_entry(&allocator->chunks, struct chunk_hdr, node);
             &chunk->node != &best_chunk->node;
             chunk = list_prev_entry(chunk, node))
        /*@ inv {allocator} unchanged;
                {best_chunk} unchanged;
                take Inv = LemmaCnChunkHdrsRevToCnChunkHdrsInv(allocator, chunk, best_chunk);
                ha == Inv.ha;
                BestChunk.Hdr == Inv.best_chunk;
                BestChunk.Node == Inv.node;
        @*/
        {
                ///*@ assert(ptr_eq(member_shift<struct chunk_hdr>(chunk, node), member_shift<struct chunk_hdr>(best_chunk, node))); @*/
                /*@
		unpack LemmaCnChunkHdrsRevToCnChunkHdrsInv(...);
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev,
                                member_shift<struct chunk_hdr>(best_chunk, node)
                        )
                );
                unpack Cn_chunk_hdrs_rev_alt(...);
                @*/
                /*@
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev->prev,
                                member_shift<struct chunk_hdr>(best_chunk, node)
                        )
                );
                @*/
                if (chunk->node.prev != &best_chunk->node)
                {
                        /*@
                        unpack Cn_chunk_hdrs_rev_alt(...);
                        @*/
                }
        }
	/*@ unpack LemmaCnChunkHdrsRevToCnChunkHdrsInv(...); @*/



}
/*@
predicate (cn_hyp_allocator) LemmaCnChunkHdrsRevToCnHypAllocatorInv(pointer allocator, pointer chunk)
{
        if (ptr_eq(member_shift<struct chunk_hdr>(chunk, node), member_shift<struct hyp_allocator>(allocator, chunks))) {
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);
                take hdrs2 = Cn_chunk_hdrs(ha.first, ha.head, ha.last, ha_core);
                return ha;
        }
        else
        {
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);
                take cn_hdr = Cn_chunk_hdr(chunk, ha_core);
                assert(!is_null(cn_hdr.Node.next));
                assert(!is_null(cn_hdr.Node.prev));

                let chunk_node = member_shift<struct chunk_hdr>(chunk, node);
                take hdrs1 = Cn_chunk_hdrs_rev(cn_hdr.Node.prev, chunk_node, ha.first, ha_core);
                take hdrs2 = Cn_chunk_hdrs(cn_hdr.Node.next, chunk_node, ha.last, ha_core);
                return ha;
        }
}

@*/
void LemmaCnChunkHdrsRevToCnHypAllocator(struct hyp_allocator *allocator)
/*@
    requires
        take ha = Cn_hyp_allocator_only(allocator);
        let ha_core = Cn_hyp_allocator_core(ha);
        take hdrs1 = Cn_chunk_hdrs_rev(ha.last, ha.head, ha.first, ha_core);
    ensures
        take ha2 = Cn_hyp_allocator_only(allocator);
        take hdrs2 = Cn_chunk_hdrs(ha.first, ha.head, ha.last, ha_core);
        ha == ha2;
@*/
{
        /*@ split_case(ptr_eq(ha.last, ha.head)); @*/
        /*@ unpack  Cn_chunk_hdrs_rev(...); @*/
        struct chunk_hdr *chunk;

        for (chunk = list_last_entry(&allocator->chunks, struct chunk_hdr, node);
             !list_entry_is_head(chunk, &allocator->chunks, node);
             chunk = list_prev_entry(chunk, node))
        /*@ inv {allocator} unchanged;
                take Inv = LemmaCnChunkHdrsRevToCnHypAllocatorInv(allocator, chunk);
                ha == Inv;
        @*/
        {
                /*@
		unpack LemmaCnChunkHdrsRevToCnHypAllocatorInv(...);
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );
                unpack Cn_chunk_hdrs_rev(...);
                @*/
                /*@
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev->prev,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );
                @*/
                if (!list_entry_is_head(list_prev_entry(chunk, node), &allocator->chunks, node))
                {
                        /*@
                        unpack Cn_chunk_hdrs_rev(...);
                        @*/
                }
        }
	/*@ unpack LemmaCnChunkHdrsRevToCnHypAllocatorInv(...); @*/
}

void LemmaConcatCnChunkHdrsRev(struct hyp_allocator *allocator, struct chunk_hdr *chunk, struct chunk_hdr *best_chunk)
/*@
        requires
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);

                take BestChunk = Cn_chunk_hdr(best_chunk, ha_core);
                !is_null(BestChunk.Node.next);
                !is_null(BestChunk.Node.prev);

                take Chunk = Cn_chunk_hdr(chunk, ha_core);
                !is_null(Chunk.Node.next);
                !is_null(Chunk.Node.prev);

                let best_chunk_node = member_shift<struct chunk_hdr>(best_chunk, node);
                let chunk_node = member_shift<struct chunk_hdr>(chunk, node);

                take hdrs1 = Cn_chunk_hdrs_rev(BestChunk.Node.prev, best_chunk_node, ha.first, ha_core);
                // a bit hack? set the last chunk to chunk_node
                take hdrs2 = Cn_chunk_hdrs_rev_alt(Chunk.Node.prev, chunk_node, BestChunk.Node.next, ha_core, best_chunk_node);
        ensures
                take ha2 = Cn_hyp_allocator_only(allocator);
                ha == ha2;

                take Chunk2 = Cn_chunk_hdr(chunk, ha_core);
                Chunk == Chunk2;

                take hdrs3 = Cn_chunk_hdrs_rev(Chunk.Node.prev, chunk_node, ha.first, ha_core);

@*/
{
        /*@
        split_case(ptr_eq(Chunk.Node.prev, best_chunk_node));
        unpack Cn_chunk_hdrs_rev_alt(Chunk.Node.prev, chunk_node, BestChunk.Node.next, ha_core, best_chunk_node);
        @*/
        if (chunk->node.prev == &best_chunk->node)
        {
                return;
        } else {
                chunk = list_prev_entry(chunk, node);
                LemmaConcatCnChunkHdrsRev(allocator, chunk, best_chunk);
                return;
        }
}
#endif

/*@
predicate (void) GetFreeChunk(pointer allocator, u64 size, pointer result, {cn_hyp_allocator ha, datatype cn_chunk_hdrs hdrs} HA_in )
{
        if (ptr_eq(result, NULL)) {
                take HA_out = Cn_hyp_allocator(allocator);
                assert(HA_in.ha == HA_out.ha);
                return;
        } else {
                take HA_out = Cn_hyp_allocator_focusing_on(allocator, result);
                let lseg = HA_out.lseg;

                assert(HA_in.ha.size == HA_out.ha.size);
                assert(HA_in.ha.start == HA_out.ha.start);
                assert(HA_in.ha.head == HA_out.ha.head);
                assert(is_free_chunk(lseg.chunk, size));
                return;
        }
}
@*/


/*@

predicate (cn_hyp_allocator) GetFreeChunkInv(pointer allocator, pointer chunk, pointer best_chunk, u64 best_available_size, u64 size)
{
        // phase1: best_chunk not found yet
        // phase2: at least one best_chunk found

        // Since CN cannot write nested ifs, the predicate definition looks a bit weird.
        // phase 1 end
        if (ptr_eq(member_shift<struct chunk_hdr>(chunk, node), member_shift<struct hyp_allocator>(allocator, chunks)) && is_null(best_chunk)) {
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);
                take hdrs1 = Cn_chunk_hdrs_rev(ha.last, ha.head, ha.first, ha_core);
                return ha;
        // phase 2 end
        } else { if (ptr_eq(member_shift<struct chunk_hdr>(chunk, node), member_shift<struct hyp_allocator>(allocator, chunks))) {
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);

                take BestChunk = Cn_chunk_hdr(best_chunk, ha_core);
                assert(!is_null(BestChunk.Node.next));
                assert(!is_null(BestChunk.Node.prev));
                let best_chunk_node = member_shift<struct chunk_hdr>(best_chunk, node);
                assert(BestChunk.Hdr.alloc_size == 0u32);
                assert(Cn_chunk_size(size)  <= (u64)BestChunk.Hdr.va_size);
                assert(best_available_size == (u64)BestChunk.Hdr.va_size);

                take hdrs1 = Cn_chunk_hdrs_rev(BestChunk.Node.prev, best_chunk_node, ha.first, ha_core);
                take hdrs2 = Cn_chunk_hdrs_rev_alt(ha.last, ha.head, BestChunk.Node.next, ha_core, best_chunk_node);
                return ha;
        }
        // phase 1
        else { if (is_null(best_chunk)) {
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);
                take Chunk = Cn_chunk_hdr(chunk, ha_core);
                assert(!is_null(Chunk.Node.next));
                assert(!is_null(Chunk.Node.prev));
                let chunk_node = member_shift<struct chunk_hdr>(chunk, node);

                take hdrs1 = Cn_chunk_hdrs_rev(Chunk.Node.prev, chunk_node, ha.first, ha_core);
                take hdrs3 = Cn_chunk_hdrs(Chunk.Node.next, chunk_node, ha.last, ha_core);
                return ha;
        // phase 2
        } else {
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);

                take BestChunk = Cn_chunk_hdr(best_chunk, ha_core);
                assert(!is_null(BestChunk.Node.next));
                assert(!is_null(BestChunk.Node.prev));
                assert(BestChunk.Hdr.alloc_size == 0u32);
                assert(Cn_chunk_size(size) <= (u64)BestChunk.Hdr.va_size);
                assert(best_available_size == (u64)BestChunk.Hdr.va_size);

                take Chunk = Cn_chunk_hdr(chunk, ha_core);
                assert(!is_null(Chunk.Node.next));
                assert(!is_null(Chunk.Node.prev));

                let best_chunk_node = member_shift<struct chunk_hdr>(best_chunk, node);
                let chunk_node = member_shift<struct chunk_hdr>(chunk, node);

                take hdrs1 = Cn_chunk_hdrs_rev(BestChunk.Node.prev, best_chunk_node, ha.first, ha_core);
                take hdrs2 = Cn_chunk_hdrs_rev_alt(Chunk.Node.prev, chunk_node, BestChunk.Node.next, ha_core, best_chunk_node);
                assert(hdrs2 == Chunk_nil{} implies (Chunk.Node.prev == best_chunk_node && BestChunk.Node.next == chunk_node));

                take hdrs3 = Cn_chunk_hdrs(Chunk.Node.next, chunk_node, ha.last, ha_core);
                return ha;
        }
        }
        }
}
@*/

static struct chunk_hdr *get_free_chunk(struct hyp_allocator *allocator, size_t size)
// should the spec of this characterise "best", or just ensure that this returns a legit chunk?  We guess the latter is sufficient for functional correctness and we'll do that
// should the spec of this pull out the ownership of that chunk, or just identify the chunk?  We guess the context will sometimes have to mess with neighbouring chunks, so we'll do the pulling out there, not here
// what variable name to use for the result of Cn_hyp_allocator?
// (should CN support enforced per-type naming conventions?)
/*@
requires
        take HA_in = Cn_hyp_allocator(allocator);
        let ha_full = HA_in.ha;
        let ha = {head: ha_full.head, start: ha_full.start, size: ha_full.size, first: ha_full.first};
        !ptr_eq(ha.first, ha.head);
        size <= Cn_chunk_size(size); // no overflow
ensures  take res = GetFreeChunk(allocator, size, return, HA_in);

// is_free_chunk(ret,size,HA_in.hdrs); // it returns a chunk in the list (or NIL?) st the alloc_size is zero and total size (not just mapped size, and including header size) is at least what you asked for
@*/

{
        /*CN*/ struct chunk_hdr * retv = NULL;
        /* CN DIFF */
        // version: e6f1cbbab1843a62714bf19329cbabf43adbd297
        struct chunk_hdr *chunk, *best_chunk = NULL;
        size_t best_available_size = SIZE_MAX;

        // HK: O(n) search for the best chunk
        // Several thoughts:
        // 1. Doesn't care about the mapped_size, which may involve a lot of
        // mappings and unmappings. No?
        // 2. the invariant should be a bit complicated
        //  | 1 | -> | 2 | ... -> |best_chunk| -> ... -> |cur| -> ... -> |last|
        // a possible strategy for ownerships when best_chunk is not null
        //   - ListSeg Fst      ; first part until best_chunk
        //   - Chunk_hdr Best   ; best_chunk
        //   - ListSeg Discarded; from next of best_chunk to cur
        //   - Chunk_hdr Cur    ; cur
        //   - List Remaining   ; from next of cur to last
        // where ListSeg is a reversed list

        // HK: Unfolding GetFreeChunkInv for the loop entry
	/*@ unpack FirstAllocation(...); @*/
        /*@ unpack Cn_chunk_hdrs(ha.first, ha_full.head, ha_full.last, Cn_hyp_allocator_core(ha_full)); @*/

        list_for_each_entry(chunk, &allocator->chunks, node)
        /*@ inv {allocator} unchanged;
                {size} unchanged;
                take I = GetFreeChunkInv(allocator, chunk, best_chunk, best_available_size, size);
                I == ha_full;
                !is_null(chunk);
        @*/
        {
                // needs to split the following:
                // https://github.com/rems-project/cn/issues/245
                /*@ split_case(is_null(best_chunk)); @*/
                /*@
		unpack GetFreeChunkInv(allocator, chunk, best_chunk, best_available_size, size);
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );
                unpack Cn_chunk_hdrs(
                        member_shift<struct chunk_hdr>(chunk, node)->next,
                        member_shift<struct chunk_hdr>(chunk, node), ha_full.last,
                        Cn_hyp_allocator_core(ha_full)
                ); @*/ /*@
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next->next,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );
                @*/
#ifdef __CN_VERIFY
                if (!list_entry_is_head(list_next_entry(chunk, node), &allocator->chunks, node))
                {
                        /*@
                        unpack Cn_chunk_hdrs(
                                member_shift<struct chunk_hdr>(chunk, node)->next->next,
                                member_shift<struct chunk_hdr>(chunk, node)->next, ha_full.last,
                                Cn_hyp_allocator_core(ha_full)
                        );
                        @*/
                }
#endif
                // if (best_chunk) {
                        // /*@
                        // split_case(ptr_eq(member_shift<struct chunk_hdr>(best_chunk, node)->next,
                        //         member_shift<struct hyp_allocator>(allocator, chunks)
                        // ));
                        // unpack Cn_chunk_hdrs(
                        //         member_shift<struct chunk_hdr>(best_chunk, node)->next,
                        //         member_shift<struct chunk_hdr>(best_chunk, node), ha_full.last,
                        //         Cn_hyp_allocator_core(ha_full)
                        // );
                        // @*/
                //}
                size_t available_size = chunk->mapped_size +
					chunk_unmapped_size(chunk, allocator);
		/*@ unpack MaybeChunkHdr(...); @*/
		if (chunk_is_used(chunk))
			continue;

		if (chunk_size(size) > available_size)
			continue;

		if (best_available_size <= available_size)
			continue;

#ifdef __CN_VERIFY
                if (best_chunk) {
                        LemmaConcatCnChunkHdrsRev(allocator, chunk, best_chunk);
                }
#endif
		best_chunk = chunk;
		best_available_size = available_size;
                // ghost state manipulation
                // (concat) hdrs1 <- hdrs1 + hdrs2
                // (empty)  hdrs2 <- Chunk_nil {}
        }
        /*@ split_case(is_null(best_chunk)); @*/
#ifdef __CN_VERIFY
        if (best_chunk) {
                /*@ unpack GetFreeChunkInv(...); @*/
                LemmaCnChunkHdrsRevToCnChunkHdrs(allocator, best_chunk);
        } else {
                /*@ unpack GetFreeChunkInv(...); @*/
                LemmaCnChunkHdrsRevToCnHypAllocator(allocator);
        }
#endif

        /*CN*/ retv = chunk_get(best_chunk);
	/*@ unpack MaybeChunkHdr(...); @*/
	/*CN*/ return retv;
}

#ifdef __CN_VERIFY
/*@
predicate (cn_hyp_allocator) LemmaLsegToChunkHdrsInv(pointer chunk, pointer allocator)
{
        if (ptr_eq(member_shift<struct chunk_hdr>(chunk, node), member_shift<struct hyp_allocator>(allocator, chunks))) {
                take C2 = Cn_hyp_allocator(allocator);
                return C2.ha;
        }
        else
        {
                take ha = Cn_hyp_allocator_only(allocator);
                let ha_core = Cn_hyp_allocator_core(ha);
                take cn_hdr = Cn_chunk_hdr(chunk, ha_core);
                assert(!is_null(cn_hdr.Node.next));
                assert(!is_null(cn_hdr.Node.prev));

                let chunk_node = member_shift<struct chunk_hdr>(chunk, node);
                take hdrs1 = Cn_chunk_hdrs_rev(cn_hdr.Node.prev, chunk_node, ha.first, ha_core);
                take hdrs2 = Cn_chunk_hdrs(cn_hdr.Node.next, chunk_node, ha.last, ha_core);
                return ha;
        }
}
@*/

void LemmaLsegToChunkHdrs(struct hyp_allocator *allocator, struct chunk_hdr *chunk)
/*@
        requires
                take C = Cn_hyp_allocator_focusing_on(allocator, chunk);
                let ha_full = C.ha;
                let ha = Cn_hyp_allocator_core(ha_full);
                let node = member_shift<struct chunk_hdr>(chunk, node);
        ensures
                take C2 = Cn_hyp_allocator(allocator);
                C.ha == C2.ha;
@*/
{
        /*@
        split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next, ha.head));
        unpack Cn_chunk_hdrs(member_shift<struct chunk_hdr>(chunk, node)->next, node, ha_full.last, Cn_hyp_allocator_core(ha_full));
        split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev, ha.head));
        unpack Cn_chunk_hdrs_rev(member_shift<struct chunk_hdr>(chunk, node)->prev, node, ha_full.first, Cn_hyp_allocator_core(ha_full));
        @*/

        while (!list_entry_is_head(chunk, &allocator->chunks, node))
        /*@ inv {allocator} unchanged;
                take Inv = LemmaLsegToChunkHdrsInv(chunk, allocator);
                Inv == ha_full;

        @*/
        {
                /*@
		unpack LemmaLsegToChunkHdrsInv(...);
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );
                unpack Cn_chunk_hdrs_rev(...);
                @*/
                chunk = list_prev_entry(chunk, node);
                /*@
                split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node), ha.head));

                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );

                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );@*/
                if (!list_entry_is_head(chunk, &allocator->chunks, node))
                {
                        /*@
                        unpack Cn_chunk_hdrs_rev(...);
                        @*/
                }
        }
        /*@
	unpack LemmaLsegToChunkHdrsInv(...);
        split_case(
                ptr_eq(member_shift<struct hyp_allocator>(allocator, chunks)->next,
                        member_shift<struct hyp_allocator>(allocator, chunks)
                )
        );
        @*/
}


/*@
predicate void LemmaGetLastChunkInv(pointer chunk, cn_hyp_allocator ha)
{
        if (ptr_eq(member_shift<struct chunk_hdr>(chunk, node),
                ha.head)) {
                let ha_core = Cn_hyp_allocator_core(ha);
                take hdrs = Cn_chunk_hdrs_rev(ha.last, ha.head, ha.first, ha_core);
                return;
        } else {
                let ha_core = Cn_hyp_allocator_core(ha);
                take cn_hdr = Cn_chunk_hdr(chunk, ha_core);
                assert(!is_null(cn_hdr.Node.next));
                assert(!is_null(cn_hdr.Node.prev));

                let chunk_node = member_shift<struct chunk_hdr>(chunk, node);
                take hdrs1 = Cn_chunk_hdrs_rev(cn_hdr.Node.prev, chunk_node, ha.first, ha_core);
                take hdrs2 = Cn_chunk_hdrs(cn_hdr.Node.next, chunk_node, ha.last, ha_core);
                return;
        }
}
@*/

void LemmaGetLastChunk(struct hyp_allocator *allocator)
/*@
        requires
                take C = Cn_hyp_allocator(allocator);
                !ptr_eq(C.ha.first, C.ha.head);
                let ha_full = C.ha;
                let ha = {head: ha_full.head, start: ha_full.start, size: ha_full.size, first: ha_full.first};
        ensures
                let last = array_shift<char>(C.ha.last, -offsetof(chunk_hdr, node));
                take C2 = Cn_hyp_allocator_focusing_on(allocator, last);
                C2.ha == C.ha;
@*/
{
        /*@ unpack Cn_chunk_hdrs(...); @*/
        struct chunk_hdr *chunk;
        /*@ unpack FirstAllocation(...); @*/

        list_for_each_entry(chunk, &allocator->chunks, node)
        /*@ inv {allocator} unchanged;
                take ha_full_inv = Cn_hyp_allocator_only(allocator);
                let ha_inv = {head: ha_full.head, start: ha_full.start, size: ha_full.size, first: ha_full.first};
                ha_full_inv == ha_full;
                take Inv = LemmaGetLastChunkInv(chunk, ha_full_inv);
        @*/
        {
                /*@
		unpack LemmaGetLastChunkInv(...);
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );
                unpack Cn_chunk_hdrs(...);
                @*/
                /*@
                split_case(
                        ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next->next,
                                member_shift<struct hyp_allocator>(allocator, chunks)
                        )
                );
                @*/
                if (!list_entry_is_head(list_next_entry(chunk, node), &allocator->chunks, node))
                {
                        /*@ unpack Cn_chunk_hdrs(...); @*/
                }
        }
        /*@
        split_case(
                ptr_eq(member_shift<struct hyp_allocator>(allocator, chunks)->prev,
                        member_shift<struct hyp_allocator>(allocator, chunks)
                )
        );
	unpack LemmaGetLastChunkInv(...);
        unpack Cn_chunk_hdrs_rev(...);
        split_case(
                ptr_eq(member_shift<struct hyp_allocator>(allocator, chunks)->next,
                        member_shift<struct hyp_allocator>(allocator, chunks)
                )
        );
        unpack Cn_chunk_hdrs(...);
        @*/
}
#endif

// HK: To avoid "mismatched types" error
void *hyp_alloc(size_t size)
/*@
        requires
                take HA_pre = Cn_hyp_allocator(&hyp_allocator);

                // The following check is done in memcache functions,
                // which we ignore in this verification.
                // So, we explicitly state the following.
                // More precicely, only the first allocation requires
                // `PAGE_ALIGN(Cn_chunk_size(actual_size))`. For the other allocations,
                // we can allocate Cn_chunk_size(actual_size).
                // However, for simplicity, we require this for all allocations.
                // size <= PAGE_ALIGN(Cn_chunk_size(actual_size)); // no overflow
                // PAGE_ALIGN(Cn_chunk_size(actual_size)) <= (u64)HA_pre.ha.size;
                let actual_size = cn_ALIGN(size == 0u64 ? MIN_ALLOC() : size, MIN_ALLOC());
        ensures
                take HA_post = Cn_hyp_allocator(&hyp_allocator);

                take U = MaybeCn_char_array(return, actual_size);
                // HA_post.ha.size == HA_pre.ha.size;
                // HA_post.ha.start == HA_pre.ha.start;
                // HA_post.ha.head == HA_pre.ha.head;
@*/
{
        struct hyp_allocator *allocator = &hyp_allocator;
        struct chunk_hdr *chunk, *last_chunk;
        unsigned long chunk_addr;
        size_t missing_map;
        int ret = 0;
        /* CN */ int cn_flag = 1;
        /* constrained by chunk_hdr *_size types */
        if (size > U32_MAX)
        {
                ret = -E2BIG;
                goto end_unlocked;
        }

#ifdef __CN_VERIFY
        /* CN */ int no_free_chunk = 0;
#endif

        // size = ALIGN(size ?: MIN_ALLOC, MIN_ALLOC);
        // the above gcc syntax is not supported by CN
        /*CN*/ size = ALIGN(size ? size : MIN_ALLOC, MIN_ALLOC);

        hyp_spin_lock(&allocator->lock);
        //PS: ownership from lock invariant
        //PS: hyp_spin_lock returns Cn_hyp_allocator(&allocator)
        /* CN DIFF */
        // this variable is used to split the case later in this function.
        cn_flag = list_empty(&hyp_allocator.chunks);
        /*@ split_case(
                ptr_eq(member_shift<struct hyp_allocator>(allocator, chunks)->next,
                        member_shift<struct hyp_allocator>(allocator, chunks)
                )); @*/
        /*@
        unpack Cn_chunk_hdrs(
                member_shift<struct hyp_allocator>(allocator, chunks)->next,
                member_shift<struct hyp_allocator>(allocator, chunks), HA_pre.ha.last,
                Cn_hyp_allocator_core(HA_pre.ha)
        );
        @*/
        if (cn_flag) {
	        /*@ unpack FirstAllocation(...); @*/
                ret = setup_first_chunk(allocator, size);
		/*@ split_case(ret == 0i32); @*/
                if (ret)
                        goto end;

		/*@ unpack SetupFirstChunk(...); @*/
                chunk = (struct chunk_hdr *)allocator->start;
        	/*@ split_case(is_null(chunk)); @*/
                goto end;
        }
	/*@ unpack FirstAllocation(...); @*/

        chunk = get_free_chunk(allocator, size);
        if (chunk) {
	        /*@ unpack GetFreeChunk(...); @*/
                ret = chunk_recycle(chunk, size, allocator);
                goto end;
        }
        // HK: when there is no free chunk, we divide the last chunk
#ifdef __CN_VERIFY
        no_free_chunk = 1;
	/*@ unpack GetFreeChunk(...); @*/
        LemmaGetLastChunk(allocator);
#endif


        last_chunk = chunk_get(list_last_entry(&allocator->chunks, struct chunk_hdr, node));
	/*@ unpack MaybeChunkHdr(...); @*/

        /*@ split_case(
                ptr_eq(member_shift<struct chunk_hdr>(last_chunk, node)->next,
                        member_shift<struct hyp_allocator>(allocator, chunks)
                )); @*/
        /*@
        unpack Cn_chunk_hdrs(
                member_shift<struct chunk_hdr>(last_chunk, node)->next,
                member_shift<struct chunk_hdr>(last_chunk, node), HA_pre.ha.last,
                Cn_hyp_allocator_core(HA_pre.ha)
        );
        @*/
        chunk_addr = (unsigned long)last_chunk + chunk_size(last_chunk->alloc_size);
        chunk_addr = chunk_addr_fixup(chunk_addr);
        chunk = (struct chunk_hdr *)chunk_addr;

        missing_map = chunk_needs_mapping(last_chunk,
                                          chunk_addr + chunk_size(size) -
                                                (unsigned long)chunk_data(last_chunk));
        if (missing_map) {
                ret = chunk_inc_map(last_chunk, missing_map, allocator);
                if (ret){
#ifdef __CN_VERIFY
                        LemmaLsegToChunkHdrs(allocator, last_chunk);
#endif
                        goto end;
                }
        }

        //LemmaSplitAndNewChunk(chunk_data(last_chunk) + last_chunk->alloc_size, , allocator->start + allocator->size - last_chunk->alloc_size - (unsigned long)chunk_data(last_chunk));
        /* CN DIFF */
        /*CN*/ int res_chunk_install = chunk_install(chunk, size, last_chunk, allocator);
        /*CN*/ WARN_ON(res_chunk_install);
        /*@ split_case(is_null(chunk)); @*/
        /*@ split_case(res_chunk_install == 0i32); @*/
	/*@ unpack ChunkInstallPost(...); @*/
#ifdef __CN_VERIFY
        LemmaLsegToChunkHdrs(allocator, last_chunk);
#endif
end:
        hyp_spin_unlock(&allocator->lock);
end_unlocked:

        *(this_cpu_ptr(&hyp_allocator_errno)) = ret;

        /* CN DIFF for proof */
#ifdef __CN_VERIFY
        if ((!ret || !cn_flag) && !no_free_chunk) {
                LemmaLsegToChunkHdrs(allocator, chunk);
        }
#endif

        /* Enforce zeroing allocated memory */
        if (!ret)
        {
	        /*@ unpack Conditional_Cn_char_array(...); @*/
                /* CN DIFF */
                // How do I write the spec to memset?
                memset(chunk_data(chunk), 0, size);
                // memset(chunk_data(chunk), 0, size);
        }
	/*@ unpack SetupFirstChunk(...); @*/
	/*@ unpack Conditional_Cn_char_array(...); @*/
        return ret ? NULL : chunk_data(chunk);
}

#ifndef STANDALONE
static size_t hyp_alloc_size(void *addr)
{
        struct hyp_allocator *allocator = &hyp_allocator;
        char *chunk_data = (char *)addr;
        struct chunk_hdr *chunk;
        size_t size;

        hyp_spin_lock(&allocator->lock);
        chunk = chunk_get(container_of(chunk_data, struct chunk_hdr, data));
        size = chunk->alloc_size;
        hyp_spin_unlock(&allocator->lock);

        return size;
}

void *hyp_alloc_account(size_t size, struct kvm *host_kvm)
{
        void *addr = hyp_alloc(size);

        if (addr)
                atomic64_add(hyp_alloc_size(addr),
                             &host_kvm->stat.protected_hyp_mem);
        return addr;
}
#endif /* STANDALONE */

void hyp_free(void *addr)
/*@
        requires
                !is_null(addr);
                let header_address = array_shift<byte>(addr, - Cn_chunk_hdr_size());
                take HA_pre = Cn_hyp_allocator_focusing_on(&hyp_allocator,header_address);
                let C = HA_pre.lseg.chunk;
                take U = Cn_char_array(addr, (u64)C.alloc_size);
        ensures
                take HA_post = Cn_hyp_allocator(&hyp_allocator);
@*/
{
        struct chunk_hdr *chunk, *prev_chunk, *next_chunk;
        struct hyp_allocator *allocator = &hyp_allocator;
        char *chunk_data = (char *)addr;

        hyp_spin_lock(&allocator->lock);

        chunk = chunk_get(container_of(chunk_data, struct chunk_hdr, data));
        /*@ unpack MaybeChunkHdr(...); @*/
        /*@
        split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev,
                member_shift<struct hyp_allocator>(allocator, chunks)));
        unpack Cn_chunk_hdrs_rev(...);
        @*/
        prev_chunk = chunk_get_prev(chunk, allocator);
        /*@
        split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct hyp_allocator>(allocator, chunks)));
        unpack Cn_chunk_hdrs(...); @*/
        next_chunk = chunk_get_next(chunk, allocator);

        // HK: free is easy :) except for merging
#ifdef __CN_VERIFY
        LemmaMergeArrays(chunk_data, chunk->alloc_size, chunk->mapped_size + chunk_unmapped_size(chunk, allocator) - chunk_hdr_size() - chunk->alloc_size);
#endif
        chunk->alloc_size = 0;
        // TODO: merge buffer
        chunk_hash_update(chunk);

        /*@ unpack MaybeChunkHdr(...); @*/
        if (next_chunk && !chunk_is_used(next_chunk)) {
                WARN_ON(chunk_merge(next_chunk, allocator));
                /*@ split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev,
                        member_shift<struct hyp_allocator>(allocator, chunks)));
                 unpack Cn_chunk_hdrs_rev(...);
                @*/
        }

        /*@ unpack MaybeChunkHdr(...); @*/
        if (prev_chunk && !chunk_is_used(prev_chunk)) {
                WARN_ON(chunk_merge(chunk, allocator));

                // HK: not sure why it's needed
                /*@ unpack MaybeChunkHdr(...); @*/
#ifdef __CN_VERIFY
                LemmaLsegToChunkHdrs(allocator, prev_chunk);
#endif
        }
        /* CN DIFF */ else {
                // HK: not sure why it's needed
                /*@ unpack MaybeChunkHdr(...); @*/
#ifdef __CN_VERIFY
                LemmaLsegToChunkHdrs(allocator, chunk);
#endif
        }

        hyp_spin_unlock(&allocator->lock);
}

#ifndef STANDALONE
void hyp_free_account(void *addr, struct kvm *host_kvm)
{
        size_t size = hyp_alloc_size(addr);

        hyp_free(addr);

        atomic64_sub(size, &host_kvm->stat.protected_hyp_mem);
}
#endif /* STANDALONE */

/*@
function (boolean) Cn_chunk_destroyable(cn_lseg lseg)
{
        lseg.chunk.alloc_size == 0u32
        && cn_IS_ALIGNED(lseg.chunk.header_address)
        && (match (lseg.before)
        {
                Chunk_nil {} => { lseg.after == Chunk_nil {} }
                Chunk_cons{ hd: hdr, tl:tl } => {
                        hdr.alloc_size == 0u32
                }
        })
}
@*/
/*
 * While chunk_try_destroy() is actually destroying what can be, this function
 * only help with estimating how much pages can be reclaimed. However the same
 * comments apply here.
 */
static bool chunk_destroyable(struct chunk_hdr *chunk,
                              struct hyp_allocator *allocator)
/*@
requires
        take HA = Cn_hyp_allocator_focusing_on(allocator, chunk);
        let C = HA.lseg.chunk;
ensures
        take HA_post = Cn_hyp_allocator_focusing_on(allocator, chunk);
        HA == HA_post;
        (Cn_chunk_destroyable(HA.lseg) ? 1u8 : 0u8) == return;
@*/
{
        if (chunk_is_used(chunk))
                return false;


        if (!PAGE_ALIGNED(chunk))
                return false;


        /*@
        split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->next,
                member_shift<struct hyp_allocator>(allocator, chunks)));
        unpack Cn_chunk_hdrs(...);
        split_case(ptr_eq(member_shift<struct chunk_hdr>(chunk, node)->prev,
                member_shift<struct hyp_allocator>(allocator, chunks)));
        unpack Cn_chunk_hdrs_rev(...);
        @*/

        if (list_is_first(&chunk->node, &allocator->chunks)) {
                if (list_is_last(&chunk->node, &allocator->chunks))
                        return true;


                return false;
        }

        /* CN DIFF */
        /*CN*/struct chunk_hdr *tmp = chunk_get_prev(chunk, allocator);
        /*@ unpack MaybeChunkHdr(...); @*/
        /*CN*/return !chunk_is_used(tmp);
}

static size_t chunk_reclaimable(struct chunk_hdr *chunk,
                                struct hyp_allocator *allocator)
/*@
requires
        take HA = Cn_hyp_allocator_focusing_on(allocator, chunk);
ensures
        take HA_post = Cn_hyp_allocator_focusing_on(allocator, chunk);
        let C = HA.lseg.chunk;
        HA == HA_post;
        let start = (Cn_chunk_destroyable(HA_post.lseg) ?
                (u64)chunk : PAGE_ALIGN((u64)chunk + Cn_chunk_size((u64)C.alloc_size)));
        let end = PAGE_ALIGN_DOWN(C.header_address + (u64)C.mapped_size);
        (start <= end ? end - start : 0u64) == return;
@*/
{
        unsigned long start, end = chunk_unmapped_region(chunk);

        /*
         * This should not happen, chunks are installed at a minimum distance
         * from the page start
         */
        WARN_ON(!PAGE_ALIGNED(end) &&
                (end - PAGE_ALIGN_DOWN(end) < chunk_size(0UL)));

        if (chunk_destroyable(chunk, allocator))
                start = (unsigned long)chunk;
        else
                start = PAGE_ALIGN((unsigned long)chunk + chunk_size(chunk->alloc_size));


        end = PAGE_ALIGN_DOWN(end);
        if (start > end)
                return 0;


        return end - start;
}

// HK: counts the number of unused but mapped pages.
// This includes the pages that are in the memcache.
int hyp_alloc_reclaimable(void)
{
        struct hyp_allocator *allocator = &hyp_allocator;
        struct chunk_hdr *chunk;
        int reclaimable = 0;
        int cpu;

        hyp_spin_lock(&allocator->lock);

        /*
         * This is slightly pessimistic: a real reclaim might be able to "fix"
         * discontiguous unmapped region by deleting chunks from the top to the
         * bottom.
         */
        list_for_each_entry(chunk, &allocator->chunks, node)
                reclaimable += chunk_reclaimable(chunk, allocator) >> PAGE_SHIFT;

        for (cpu = 0; cpu < hyp_nr_cpus; cpu++) {
                struct kvm_hyp_memcache *mc = per_cpu_ptr(&hyp_allocator_mc, cpu);

                reclaimable += mc->nr_pages;
        }

        hyp_spin_unlock(&allocator->lock);

        return reclaimable;
}

// Hk: another interesting target
void hyp_alloc_reclaim(struct kvm_hyp_memcache *mc, int target)
{
        struct hyp_allocator *allocator = &hyp_allocator;
        struct kvm_hyp_memcache *alloc_mc;
        struct chunk_hdr *chunk, *tmp;
        int cpu;

        if (target <= 0)
                return;


        hyp_spin_lock(&allocator->lock);

        /* Start emptying potential unused memcache */
        for (cpu = 0; cpu < hyp_nr_cpus; cpu++) {
                alloc_mc = per_cpu_ptr(&hyp_allocator_mc, cpu);

                while (alloc_mc->nr_pages) {
                        unsigned long order;
                        void *page = pop_hyp_memcache(alloc_mc, hyp_phys_to_virt, &order);

                        WARN_ON(order);
                        push_hyp_memcache(mc, page, hyp_virt_to_phys, 0);
                        WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(page), 1));

                        target--;
                        if (target <= 0)
                                goto done;

                }
        }

        list_for_each_entry_safe_reverse(chunk, tmp, &allocator->chunks, node) {
                size_t r;

                chunk_hash_validate(chunk);
                r = chunk_try_destroy(chunk, allocator, target << PAGE_SHIFT);
                if (!r)
                        r = chunk_dec_map(chunk, allocator, target << PAGE_SHIFT);


                target -= r >> PAGE_SHIFT;
                if (target <= 0)
                        break;

        }

        alloc_mc = this_cpu_ptr(&hyp_allocator_mc);
        while (alloc_mc->nr_pages) {
                unsigned long order;
                void *page = pop_hyp_memcache(alloc_mc, hyp_phys_to_virt, &order);

                WARN_ON(order);
                memset(page, 0, PAGE_SIZE);
                kvm_flush_dcache_to_poc(page, PAGE_SIZE);
                push_hyp_memcache(mc, page, hyp_virt_to_phys, 0);
                WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(page), 1));
        }
done:
        hyp_spin_unlock(&allocator->lock);
}

int hyp_alloc_refill(struct kvm_hyp_memcache *host_mc)
{
        struct kvm_hyp_memcache *alloc_mc = this_cpu_ptr(&hyp_allocator_mc);

        return refill_memcache(alloc_mc, host_mc->nr_pages + alloc_mc->nr_pages,
                               host_mc);
}

/*@

predicate (void) MaybeHypAlloc(pointer p, boolean cond)
{
    if (cond) {
        take H = Cn_hyp_allocator(p);
        return;
    } else {
        take HA1 = W<struct hyp_allocator>(&hyp_allocator);
        return;
    }
}

@*/

/* CN DIFF */
// avoid type mismatch
int hyp_alloc_init(size_t size)
#ifdef __CN_VERIFY
/*@
        accesses __io_map_base;
        accesses __hyp_vmemmap;
    requires
      // global variables
      __io_map_base > 0u64; __io_map_base + PAGE_ALIGN(size) > __io_map_base;
      (u64)&hyp_allocator > 0u64;
      take HA1 = W<struct hyp_allocator>(&hyp_allocator);
    ensures take HA2 = MaybeHypAlloc(&hyp_allocator, return == 0i32);
@*/
#endif
{
        struct hyp_allocator *allocator = &hyp_allocator;
        int ret;

        size = PAGE_ALIGN(size);

        /* constrained by chunk_hdr *_size types */
        if (size > U32_MAX)
                return -EINVAL;



        ret = pkvm_alloc_private_va_range(size, &allocator->start);
        if (ret) {
#ifdef __CN_VERIFY
                /*@ unpack Conditional_Cn_char_array(...); @*/
#endif
                return ret;
        }

        allocator->size = size;
        INIT_LIST_HEAD(&allocator->chunks);
        hyp_spin_lock_init(&allocator->lock);

#ifdef __CN_VERIFY
        /*@ unpack Conditional_Cn_char_array(...); @*/
#endif
        return 0;
}

int hyp_alloc_errno(void)
{
        int *errno = this_cpu_ptr(&hyp_allocator_errno);

        return *errno;
}

u8 hyp_alloc_missing_donations(void)
{
        u8 *missing = (this_cpu_ptr(&hyp_allocator_missing_donations));
        u8 __missing = *missing;

        *missing = 0;

        return __missing;
}

#ifndef STANDALONE
struct hyp_mgt_allocator_ops hyp_alloc_ops = {
        .refill = hyp_alloc_refill,
        .reclaim = hyp_alloc_reclaim,
        .reclaimable = hyp_alloc_reclaimable,
};
#else
void dump_chunks(void)
{
#ifndef __cerb__
        int printf(const char *, ...);
        struct hyp_allocator *allocator = &hyp_allocator;
        struct chunk_hdr *chunk;
        u64 i = 0;
        printf("\x1b[33mBEGIN\n");
        list_for_each_entry(chunk, &allocator->chunks, node) {
                printf("  [%"PRIu64"] %p -- &data: %p { .alloc_size: %u, .mapped_size: %u }\n",
                        i++, chunk, chunk_data(chunk), chunk->alloc_size,
                        chunk->mapped_size);
        }
        printf("END\x1b[0m\n");
#endif /* __cerb__ */
}
#endif
char* __kvm_my_alloc_is = __FILE__;
