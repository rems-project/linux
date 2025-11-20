/**
chunk:
| hdr | alloc'd | mapped-but-not-alloc'd | ..maybe unmapped VA part before the start of the next chunk (or the start+size) |

      ^^^^^^^^^^ alloc_size
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  mapped_size
**/


/* TP: perhaps there's an invariant that the last chunk is the only one that can be _partially_ used */

/*PS: `chunk_is_used` suggests that chunks can be unused, iff size=0.  But probably only transiently?  No, probably not - see the chunk_try_destroy comment.*/

/*PS: what are the hashes used for?  AIUI, to fail fast if the chunk header got stomped on by bad user code.  They cover the next/prev pointers so have to be updated whenever the list structure changes.  So not stable, so presumably not exposed to clients. Could be removed if the clients were persistently verified to be memory safe */

/*PS: in addition to our first sketch, the spec should constrain what is actually mapped - by making the underlying __hyp_allocator_map and pkvm_remove_mappings in shim.c have specs that record that as finite maps (and fail if something tries to map illegally).  And we need to spec the memcache operations. */

/*
[Note: Approach to Verifying `hyp_alloc` (HK) 16 May 2025]

In short, I'm taking both a top-down and bottom-up approach to verification.

Bottom-Up Approach:
   At first, I've proven most of the list-related functions in `list.h`, as well as leaf functions like `__chunk_next` by using raw pointer specifications.
   This approach works well for leaf functions. However, when verifying higher-level functions like `chunk_install` and ultimately `hyp_alloc`, it becomes clear that we need inductive predicates—without them, writing accurate specifications becomes difficult. (of course :))

Issues with `lookup`:
   The use of the predicate `lookup` is somewhat ugly and introduces a need for extra lemmas. These should be unnecessary if we define an appropriate inductive predicate.

Introducing List Segments:
   To address this, I introduced the concept of a **list segment** to model the allocator's chunk list—an idea commonly used in separation logic.
   I defined a predicate, `cn_hyp_allocator_focusing_on(allocator, chunk)`, which uses a list segment predicate (`cn_lseg`).
   This predicate captures ownerships of both the allocator's management region and the list segment up to a given chunk.

Top-Down Specification Effort:
   I'm now writing the specification for `hyp_alloc` in a **top-down** manner, starting from `hyp_alloc`, then moving to `chunk_install`, `chunk_list_insert`, and so on.
   However, I'm currently distracted by some CN-related bugs, so I'm currently working on fixing those.
   As a result, the specification in its current state is incomplete and should not be fully trusted.

The boundary Between Top-Down and Bottom-Up:
   The boundary between the top-down and bottom-up part should be the place where lemmas are needed.
   For this,  I think it's worth reconsidering the work by Hermes & Krebbers (ITP 2024).
   Previously, I thought their approach wouldn't apply to this program. However, that might have been because I wasn't yet familiar enough with CN and separation logic at the time.
   (see the comment in `chunk_list_insert` for more details)
*/

#if 0
#include <inttypes.h>

typedef uint8_t         u8;
typedef uint32_t        u32;
typedef uint64_t        u64;

typedef u64             phys_addr_t;


// This is defined in include/linux/types.h
struct list_head {
        struct list_head *next, *prev;
};

// TODO: spinlock
typedef u64             hyp_spinlock_t;

static struct hyp_allocator {
        struct list_head        chunks;
        unsigned long           start;
        u32                     size;
        hyp_spinlock_t          lock;
} hyp_allocator;

struct chunk_hdr {
        u32                     alloc_size;
        u32                     mapped_size;
        struct list_head        node;
        u32                     hash;
        char                    data /* __aligned(8) */;
};
#endif

/*@
function (i32) EINVAL() {
       22i32
}
function (u64) cn_ALIGN(u64 x, u64 a) {
       (x + (a - 1u64)) & ~(a - 1u64)
}

function (u64) PAGE_SIZE() {
        shift_left(1u64, 12u64)
}

function (boolean) cn_IS_ALIGNED(u64 addr) {
        (addr & (PAGE_SIZE() - 1u64)) == 0u64
}

function (u64) PAGE_ALIGN_DOWN(u64 addr) {
        let page_mask = shift_left(1u64, 12u64) - 1u64;
        (addr & ~page_mask)
}
function (u64) PAGE_ALIGN(u64 addr) {
        let page_mask = shift_left(1u64, 12u64) - 1u64;
        (addr + page_mask) & ~page_mask
}
@*/

/*@
type_synonym va = u64

type_synonym cn_chunk_hdr = {
  va header_address, // the VA of the start of the chunk_hdr
  u32 alloc_size, // exactly as in the C
  u32 mapped_size,  // exactly as in the C
  u32 va_size      // implicit in the C: the total va space size of this chunk (TODO: update the other defns to match)
  // no node, no hash, no data, no ownership here
}

type_synonym cn_hyp_allocator = {
        pointer head,    // used for checking the last chunk
        pointer first,   // used for list walking
        pointer last,    // last chunk
        va start,
        u32 size
}

type_synonym cn_hyp_allocator_core = {
        pointer head,    // used for checking the last chunk
        pointer first,
        va start,
        u32 size
}

function (cn_hyp_allocator_core) Cn_hyp_allocator_core(cn_hyp_allocator ha)
{
        {
                head: ha.head,
                first: ha.first,
                start: ha.start,
                size: ha.size
        }
}

datatype cn_chunk_hdrs {
  Chunk_nil {},
  Chunk_cons { cn_chunk_hdr hd, datatype cn_chunk_hdrs tl }
}

datatype option_u64 {
        Option_u64_none {},
        Option_u64_some { u64 value }
}


predicate [nounfold] void Cn_char_array(pointer p, u64 size)
{
        take U = each(u64 i; i < size){
                W<byte>(array_shift<byte>(p, i))
        };
        return;
}
predicate void Cn_char_array_with_offset(pointer p, u64 size, u64 offset)
{
        take U = each(u64 i; offset <= i && i < offset + size){
                W<byte>(array_shift<byte>(p, i))
        };
        return;
}

predicate void Conditional_Cn_char_array(pointer p, u64 size, boolean cond)
{
        if (cond) {
                take U = Cn_char_array(p, size);
                return;
        }
        else {
                return;
        }
}

predicate void MaybeCn_char_array(pointer p, u64 size)
{
        if (ptr_eq(p, NULL)) {
                return;
        } else {
                take U = Cn_char_array(p, size);
                return;
        }
}


@*/

/*PS: if we're abstracting the chunks to a CN custom list as above, then we'll abstract a `struct chunk_hdr *chunk` to a natural-number index into that list and define an `nth`?  Or add the actual address to the abstraction and search for that to access?  Think we need that address in any case, though that doesn't decide this. */

/*@


function (pointer) my_container_of_chunk_hdr (pointer p)
{
     (pointer)((u64)p - (u64)offsetof(chunk_hdr, node))
}
function (boolean) is_last_chunk(pointer node_address, struct hyp_allocator ha)
{
        ptr_eq(node_address, ha.chunks.prev)
}
predicate (cn_hyp_allocator) Cn_hyp_allocator_only(pointer p)
{
        assert((u64)p > 0u64);
        assert((u64)p + sizeof<struct hyp_allocator> > (u64)p);
        take ha = RW<struct hyp_allocator>(p);
        let cn_hyp = {
                head:  member_shift<struct hyp_allocator>(p, chunks),
                first: ha.chunks.next,
                last:  ha.chunks.prev,
                start: ha.start,
                size:  ha.size
        };
        assert(!is_null(cn_hyp.head));
        assert(!is_null(cn_hyp.first));
        assert(!is_null(cn_hyp.last));
        assert(ha.start < (u64)cn_hyp.start + (u64)cn_hyp.size);
        assert(ha.start > 0u64);
        return cn_hyp;
}
@*/

/*@
// Own_chunk just owns the chunk header and the mapped part of the chunk
predicate (cn_chunk_hdr_raw) Own_chunk_hdr(pointer chunk)
{
        assert(!is_null(chunk));
        take alloc_size = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, alloc_size));
        take mapped_size = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, mapped_size));
        take node = RW<struct list_head>(member_shift<struct chunk_hdr>(chunk, node));
        assert((u64)node.next != 0u64);
        assert((u64)node.prev != 0u64);
        assert(!is_null(node.next));
        assert(!is_null(node.prev));
        take hash = RW<unsigned>(member_shift<struct chunk_hdr>(chunk, hash));
        take explicit_padding = W<unsigned>(member_shift<struct chunk_hdr>(chunk, explicit_padding));
        let cn_hdr = {
                alloc_size: alloc_size,
                mapped_size: mapped_size,
                node: node,
                hash: hash
        };
        return cn_hdr;
}

// check_node: we assume that alloc_size and node are set.
predicate ({cn_chunk_hdr Hdr, struct list_head Node}) Cn_chunk_hdr_inner(pointer header_address, cn_hyp_allocator_core ha, option_u64 va_size_opt, boolean check_node, option_u64 alloc_size_opt, boolean valid_mapped_size)
{

        assert(!is_null(header_address));
        take hdr = Own_chunk_hdr(header_address);

        let end = ha.start + (u64)ha.size;
        // The following does not hold, because the node.next can be ha.head.
        // assert(check_node implies (u64)hdr.node.next <= end);

        let va_size = match (va_size_opt) {
                Option_u64_none {} => {
                        (Cn_list_is_last(hdr.node, ha.head) ? end : (u64)my_container_of_chunk_hdr(hdr.node.next) ) - (u64)header_address
                }
                Option_u64_some {value: v} => { v }
        };
        let cn_hdr = {
                header_address : (u64) header_address,
                alloc_size : hdr.alloc_size,
                mapped_size : hdr.mapped_size,
                va_size: (u32)va_size
        };

        let valid_chunk = Option_u64_none {} == alloc_size_opt;
        assert((valid_chunk && valid_mapped_size) implies (u64)hdr.alloc_size + Cn_chunk_hdr_size() <= (u64)hdr.mapped_size);
        // LemmaCreateNewChunk
        assert(valid_mapped_size implies cn_hdr.mapped_size <= cn_hdr.va_size);
        assert(valid_chunk implies cn_hdr.va_size <= ha.size);

        // own chunk data
        let alloc_size = match alloc_size_opt {
                Option_u64_none {} => {
                        (u64)cn_hdr.alloc_size
                }
                Option_u64_some {value: v} => {
                        v
                }
        };
        let start = array_shift<byte>(header_address, Cn_chunk_hdr_size() + alloc_size );
        let size_owned_by_ha = (u64)cn_hdr.va_size -  Cn_chunk_hdr_size() - alloc_size;
        take A = Cn_char_array(start, size_owned_by_ha);

        // check non-overlappingness
        assert(cn_hdr.header_address >= ha.start);
        let chunk_end = cn_hdr.header_address + (u64) cn_hdr.mapped_size;
        assert(valid_mapped_size implies chunk_end <= end);
        // HK: needed to ensure no-integer overflow?
        assert(valid_mapped_size implies chunk_end >= cn_hdr.header_address);


        // HK: the chunk lists must be sorted in address order.
        // (otherwise, the chunk_unmapped_size function may return incorrect sizes)
        // unless this is not the last chunk
        assert(
                check_node implies
                (((u64)member_shift<struct chunk_hdr>(header_address, node) < (u64)hdr.node.next
                    && ha.start <= (u64)hdr.node.next
                    && (u64) hdr.node.next < end)
                || (u64)hdr.node.next == (u64)ha.head)
        );
        assert(
                check_node implies
                (
                ((u64)hdr.node.prev < (u64)member_shift<struct chunk_hdr>(header_address, node)
                    && ha.start <= (u64)hdr.node.prev
                    && (u64) hdr.node.prev < end)
                || (u64)hdr.node.prev == (u64)ha.head)
        );

        return {Hdr: cn_hdr, Node: hdr.node};

}

// Cn_chunk_hdr validates the locations of the chunk header and its next are
// in the hyp_allocator's address space
// HK: the predicate name should be Cn_chunk not Cn_chunk_hdr, as it also owns
// the chunk data if necessary.
predicate ({cn_chunk_hdr Hdr, struct list_head Node}) Cn_chunk_hdr(pointer header_address, cn_hyp_allocator_core ha)
{
        take cn_hdr = Cn_chunk_hdr_inner(header_address, ha, Option_u64_none {}, true, Option_u64_none {}, true);
        return cn_hdr;
}

datatype cn_chunk_option {
        Chunk_none {},
        Chunk_some { cn_chunk_hdr hdr, struct list_head node }
}

predicate (datatype cn_chunk_option) Maybe_Cn_chunk_hdr(pointer header_address, cn_hyp_allocator_core ha, boolean condition)
{
        if (condition)
        {
                take cn_hdr = Cn_chunk_hdr(header_address, ha);
                return Chunk_some { hdr: cn_hdr.Hdr, node: cn_hdr.Node };
        }
        else
        {
                return Chunk_none {};
        }
}

// HK: prev is unused? what is for?
// -> HK: important for sanity check of linked list (e.g. node->next->prev == node)
predicate [rec] (datatype cn_chunk_hdrs) Cn_chunk_hdrs(pointer p, pointer prev,  pointer last_node, cn_hyp_allocator_core ha)
{
        if (ptr_eq(p,ha.head)) {
                assert(ha.start <= ha.start + (u64)ha.size);
                assert(ptr_eq(prev, last_node));
                // I think this is incorrect, because now that we use this predicate
                // for list segments, `last` no longer necesarily refers to
                // the last element of the hyp_allocator.
                // assert(ha.last == prev);
                return Chunk_nil {};
        } else {
                assert(!is_null(p));

                let header_address = array_shift<byte>(p, -(offsetof(chunk_hdr_only, node)) ); // or some offsetof arithmetic
                take cn_hdr = Cn_chunk_hdr(header_address, ha);
                assert(ptr_eq(cn_hdr.Node.prev, prev));
                // HK: I think this assertion is not needed, if CN handles NULL "properly"
                // c.f. https://github.com/rems-project/cn/issues/135
                assert(!is_null(cn_hdr.Node.next));
                assert(!is_null(cn_hdr.Node.prev));
                take tl = Cn_chunk_hdrs(cn_hdr.Node.next, p, last_node, ha);

                // do we want to use resources to track the va-address-space "ownership" of any unmapped part of va address space between this chunk and the next (or the end)? unclear. pretend not for now
                return Chunk_cons { hd: cn_hdr.Hdr, tl: tl };
        }
}

predicate [rec] (datatype cn_chunk_hdrs) Cn_chunk_hdrs_rev(pointer p, pointer next, pointer first_chunk_node, cn_hyp_allocator_core ha)
{
        if (ptr_eq(p,ha.head)) {
                assert(ha.start <= ha.start + (u64)ha.size);
                assert(ptr_eq(next, first_chunk_node));
                return Chunk_nil {};
        } else {
                assert(!is_null(p));
                let header_address = array_shift<byte>(p, -(offsetof(chunk_hdr_only, node)) ); // or some offsetof arithmetic
                take cn_hdr = Cn_chunk_hdr(header_address, ha);
                assert(ptr_eq(cn_hdr.Node.next, next));
                // HK: I think this assertion is not needed, if CN handles NULL "properly"
                // c.f. https://github.com/rems-project/cn/issues/135
                assert(!is_null(cn_hdr.Node.next));
                assert(!is_null(cn_hdr.Node.prev));
                take tl = Cn_chunk_hdrs_rev(cn_hdr.Node.prev, p, first_chunk_node, ha);

                return Chunk_cons { hd: cn_hdr.Hdr, tl: tl };
        }
}

// this kind of predicate makes CN buggy, so we avoid this
// see: https://github.com/rems-project/cn/issues/115
// predicate (datatype cn_chunk_hdrs) Cn_chunk_hdrs_rev(pointer p, pointer prev, cn_hyp_allocator ha,  pointer last, datatype cn_chunk_hdrs accum)
// {
//         if (ptr_eq(p,last)) {
//                 return accum;
//         } else {
//                 let header_address = array_shift<char>(p, -(offsetof(chunk_hdr, node)));
//                 take cn_hdr = Cn_chunk_hdr(header_address, ha);
//                 assert(ptr_eq(cn_hdr.Node.prev, prev));
//                 let c = Chunk_cons { hd: cn_hdr.Hdr, tl: accum };
//                 take res = Cn_chunk_hdrs_rev(cn_hdr.Node.next, p, ha, last, c);
//                 return res;
//         }
// }

type_synonym cn_lseg = {
        cn_chunk_hdrs before,
        cn_chunk_hdr chunk,
        cn_chunk_hdrs after
}

predicate ({cn_hyp_allocator ha, cn_lseg lseg}) Cn_hyp_allocator_focusing_on( pointer p, pointer chunk) { // p points to a struct hyp_allocator
  take ha_full = Cn_hyp_allocator_only(p);
  let ha = {head: ha_full.head, start: ha_full.start, size: ha_full.size, first: ha_full.first};
  let end = ha.start + (u64)ha.size;
  assert(ha.start < end);  // no overflow

  // own this chunk
  take cn_hdr = Cn_chunk_hdr(chunk, ha);
  assert(!is_null(cn_hdr.Node.next));
  assert(!is_null(cn_hdr.Node.prev));

  // chunk must be a valid chunk in the allocator
  let chunk_node = member_shift<struct chunk_hdr_only>(chunk, node);
  take hdrs1 = Cn_chunk_hdrs_rev(cn_hdr.Node.prev, chunk_node, ha_full.first, ha);
  take hdrs2 = Cn_chunk_hdrs(cn_hdr.Node.next, chunk_node, ha_full.last, ha);
  let lseg = {before: hdrs1, chunk: cn_hdr.Hdr, after: hdrs2};
  return( {ha:ha_full, lseg: lseg} );
  // morally on initialisation this owns all the va space that isn't in the chunks - but we're not currently representing "va ownership" with ownership.  So there is no extra ownership on initialisation - that's all in the memcache
}



// chunk_install is a special case for the fundamental invariant for the chunk lists
// as it temporarily breaks the invariant.
predicate ({cn_chunk_hdr Hdr, struct list_head Node, u64 va_size}) Cn_chunk_hdr_for_install(pointer header_address, pointer chunk, cn_hyp_allocator_core ha,  option_u64 alloc_size_opt, boolean valid_mapped_size)
{
        let end = ha.start + (u64)ha.size;
        let va_size_1 = (u64)chunk - (u64)header_address;
        take P = Cn_chunk_hdr_inner(header_address, ha, Option_u64_some{value:va_size_1} , true, Option_u64_none{}, valid_mapped_size);

        let next_chunk = (Cn_list_is_last(P.Node, ha.head) ? end : (u64)my_container_of_chunk_hdr(P.Node.next) );
        assert((u64)chunk < next_chunk);
        let va_size_2 =  next_chunk - (u64)chunk;

        //take C = Cn_chunk_hdr_inner(chunk, ha, Option_u64_some{value: va_size_2}, false, alloc_size_opt, valid_mapped_size);
        return {Hdr: P.Hdr, Node: P.Node, va_size: va_size_2};

}


predicate ({cn_hyp_allocator ha, cn_lseg lseg, u64 va_size}) Cn_hyp_allocator_focusing_on_for_install( pointer p, pointer prev, pointer chunk,  option_u64 alloc_size_opt, boolean valid_mapped_size) {
  take ha_full = Cn_hyp_allocator_only(p);
  let ha = {head: ha_full.head, start: ha_full.start, size: ha_full.size, first: ha_full.first};
  let end = ha.start + (u64)ha.size;
  assert(ha.start < end);  // no overflow

  // own this chunk
  take cn_hdr = Cn_chunk_hdr_for_install(prev, chunk, ha, alloc_size_opt, valid_mapped_size);
  assert(!is_null(cn_hdr.Node.next));
  assert(!is_null(cn_hdr.Node.prev));

  // chunk must be a valid chunk in the allocator
  let chunk_node = member_shift<struct chunk_hdr_only>(prev, node);
  take hdrs1 = Cn_chunk_hdrs_rev(cn_hdr.Node.prev, chunk_node, ha_full.first, ha);
  take hdrs2 = Cn_chunk_hdrs(cn_hdr.Node.next, chunk_node, ha_full.last, ha);
  let lseg = {before: hdrs1, chunk: cn_hdr.Hdr, after: hdrs2};
  return ( {ha:ha_full, lseg:lseg, va_size: cn_hdr.va_size} );

}


// **This function is specialized for chunk lists obtained by Cn_hyp_allocator_focusing_on**
// That is, it assumes
// - before: in the reverse order
// - after: in the forward order
function [rec] (datatype cn_chunk_hdrs) ConcatChunkList(datatype cn_chunk_hdrs before, cn_chunk_hdrs after)
{
        match (before) {
        Chunk_nil {} => {
                after
        }
        Chunk_cons {hd:hdr, tl:tl} => {
                Chunk_cons{hd: hdr, tl: ConcatChunkList(tl, after)}
        }
        }
}

lemma ListSeg (pointer allocator, pointer result)
        requires
            take HA1 = Cn_hyp_allocator_focusing_on(allocator, result);
            let lseg = HA1.lseg;
        ensures
            take HA2 = Cn_hyp_allocator(allocator);
            HA2 == {ha: HA1.ha, hdrs: ConcatChunkList(lseg.before, Chunk_cons {hd: lseg.chunk, tl: lseg.after})};

lemma ListSegAfterNull (pointer allocator, pointer result)
        requires
            take HA1 = Cn_hyp_allocator_focusing_on(allocator, result);
            let lseg = HA1.lseg;
        ensures
            take HA2 = Cn_hyp_allocator(allocator);
            HA2 == {ha: HA1.ha, hdrs: ConcatChunkList(lseg.before, Chunk_cons {hd: lseg.chunk, tl: lseg.after})};

// HK:This is actually wrong in terms of pa-based ownership.
// Even though you have the va-ownership of the va region [start, start+size), you do not have the right to access the memory, as they are not mapped physically for now.
// I will fix this later when I start to consider memcache things.
predicate (void) FirstAllocation(pointer start, u32 size, boolean cond)
{
        if (cond) {
                take X = Cn_char_array(start, (u64)size);
                return;
        } else {
                return;
        }
}

predicate ({cn_hyp_allocator ha, datatype cn_chunk_hdrs hdrs}) Cn_hyp_allocator( pointer p ) { // p points to a struct hyp_allocator
  take ha_full = Cn_hyp_allocator_only(p);
  let ha = {head: ha_full.head, first: ha_full.first, start: ha_full.start, size: ha_full.size};
  let end = ha.start + (u64)ha.size;
  assert(ha.start < end);  // no overflow
  take hdrs = Cn_chunk_hdrs(ha.first, ha.head, ha_full.last, ha);
  take C = FirstAllocation((pointer)ha.start, ha.size, ptr_eq(ha.first, ha.head));
  return( {ha:ha_full, hdrs:hdrs} );
}



function (boolean) is_free_chunk(cn_chunk_hdr hdr, u64 size)
{
           hdr.alloc_size == 0u32 // i.e., unused
        && (u64) hdr.va_size // the code's available_size
        >= Cn_chunk_size(size) // TODO: where chunk_size is a CN copy of their macro
        // we ignore the hash check of the chunk_get macro - even though to
        // prove safety of the actual code we would need to check the hash
        // checks succeed.
}

// function (bool) is_free_chunk(pointer p,u32 size, datatype cn_chunk_hdrs hdrs)
// {
//      // it returns a chunk in the list (or NIL?) st the alloc_size is zero
//      // and total size (not just mapped size, and including header size) is
//      // at least what you asked for.

//      _is_free_chunk(lookup(p, hdrs),size)
// }

@*/
