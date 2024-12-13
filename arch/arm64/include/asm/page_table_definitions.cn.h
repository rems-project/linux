// --- page table definitions --------------------------------------------------

// We assume a setup where pages, and hence individual page tables,
// are 4096 bytes in size (2^12). On a 64-bit platform (with pointers
// of 2^3 bytes size) that means an individual page table can fit
// 2^9=512 entries. An overall page table has maximum depth of four
// levels (levels 0 -- 3). For any given 64-bit pointer, to be
// address-translated, only a portion of up to 48 bits are the actual
// address (the *input address*). In the most basic setup, these 48
// bits are divided into four times 9 bits, which are taken as indices
// into page table levels 0 through 3, with the remaining 12 bits used
// as an offset into the page of physical memory obtained from the
// page table lookup (if the address is mapped).
// 
// Different configurations from this basic setup are possible: input
// addresses can be made smaller by setting an appropriate hardware
// register, and the page table depth can be reduced by setting the
// initial translation level to be greater than 0.
//
// For small input address sizes (relative to the number of
// translation levels), the default table encoding would lead to
// wasted space and pointer indirection, due to mostly-empty top level
// page tables (i.e. 12 bits, plus 9 bits times the number of
// translation levels, could encode significantly larger addresses
// than the chosen input address size). 
// 
// When the input address size is sufficiently small for that, it is
// then possible to optimise and use *concatenated page tables*:
// instead of a regular level-n page-table setup, using the
// concatenated-page-table scheme, one gets a level-(n-1) page table
// where the top level becomes *an array of page tables* that
// effectively represents the two upper levels of the page table
// within a single page: the part of the input address dedicated for
// the initial level of the address translation is used to index the
// page-table array, the resulting page-table is indexed using the
// next 9-bit index. When the input address size permits, the
// concatenated scheme is selected by chosing an initial translation
// level that is one greater than what one would have chosen
// otherwise.
//
// Note: Armv8.2 introduced an architecture extension that allows for
// input addresses of larger sizes, up to 52 bits, and initial address
// translation levels of -1, which our specification does not handle
// yet.



/*@
@*/



/*for tree carver*/ void include_page_table_definitions(void) {}
