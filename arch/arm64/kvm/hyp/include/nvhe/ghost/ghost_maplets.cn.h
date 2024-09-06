/*@
type_synonym page = u64

type_synonym range = { 
	u64 start, 
	u64 nr_pages 
}

datatype maplet_page_state {
	MAPLET_PAGE_STATE_PRIVATE_OWNED {},
	MAPLET_PAGE_STATE_SHARED_OWNED {},
	MAPLET_PAGE_STATE_SHARED_BORROWED {},
	// MAPLET_PAGE_STATE_UNKNOWN for encodings that don't correspond to any of the above states.
	MAPLET_PAGE_STATE_UNKNOWN {}
}

datatype maplet_memtype_attr {
	MAPLET_MEMTYPE_DEVICE {},
	MAPLET_MEMTYPE_NORMAL_CACHEABLE {},
	// MAPLET_MEMTYPE_UNKNOWN for encodings that do not correspond to any of the above
	MAPLET_MEMTYPE_UNKNOWN {}
}

type_synonym maplet_permissions = u8 // TODO: should be u4

// TODO: the following should all be u4's
function (maplet_permissions) maplet_perm_r () {
	1u8
}

function (maplet_permissions) maplet_perm_w () {
	2u8
}

function (maplet_permissions) maplet_perm_x () {
	4u8
}

function (maplet_permissions) maplet_perm_unknown () {
	8u8
}


type_synonym maplet_attributes = {
	maplet_permissions prot,
	maplet_page_state provenance,
	maplet_memtype_attr memtype
}

datatype maplet_owner_annotation {
	MAPLET_OWNER_ANNOT_OWNED_HOST {},
	MAPLET_OWNER_ANNOT_OWNED_GUEST {},
	MAPLET_OWNER_ANNOT_OWNED_HYP {},
	// MAPLET_OWNER_ANNOT_UNKNOWN for encodings that don't match one of the known encodings of the above.
	MAPLET_OWNER_ANNOT_UNKNOWN {}
}

type_synonym maplet_target_annot = {
	maplet_owner_annotation owner,
	// the raw descriptor
	// not semantically meaningful, used in printing and diffs.
	u64 raw_arch_annot
}

type_synonym memblock_flags = u8 // TODO: should be u4

// TODO: the following should all be u4's
function (memblock_flags) memblock_none () {
	0x0u8
}

function (memblock_flags) memblock_hotplug () {
	0x1u8
}

function (memblock_flags) memblock_mirror () {
	0x2u8
}

function (memblock_flags) memblock_nomap () {
	0x4u8
}

function (memblock_flags) memblock_driver_managed () {
	0x8u8
}

datatype maplet_target {
	Map { range oa_range, maplet_attributes attrs },
        Annot { maplet_owner_annotation owner, u64 raw_arch_annot },
        Memblock { memblock_flags flags }
}

type_synonym mapping = map<page, maplet_target>
@*/
