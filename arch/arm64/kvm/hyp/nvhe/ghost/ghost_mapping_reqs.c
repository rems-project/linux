
/* the mapping requests made by pkvm to construct its own mapping (in setup.c, mm.c) */


/* historical comment... */
// experiment with C executable version of the main EL2 page-table
// spec established by pKVM initialisation, using C versions of the
// EL2 address translation definition, in a style that could easily be
// used by the pKVM devs.

// We might be able to check that something like this "semantics" of
// address translation is equivalent to the Armv8-A ASL definition
// (under a raft of system-state assumptions appropriate to pKVM)
// simply by using isla on the compiled binary and asking an SMT
// solver - after unfolding everything, there wouldn't be that many
// cases.

// And we might be able to prove in RefinedC / CN that the actual
// page-table setup, done by pKVM in setup.c recreate_hyp_mappings
// using hyp_create_mappings using kvm_pgtable_hyp_map, establishes
// this.

// How we design the refinement-type assertion language(s) to make it
// easy to express this kind of thing in a way that can easily be
// shown to correspond to this executable C version is an interesting
// question...

// Note that as written this checks a sample minimal fact about pKVM's
// own putative mapping at hyp_pgtable, not whatever is installed in
// TTBR0_EL2, so it's suitable for use _before_ the idmap tango, not
// necessarily after.
//
// Note that it reads pagetable contents just using the current
// mapping, whatever that is - one needs assumptions about that to
// make this assertion check meaningful.


#include <asm/kvm_pgtable.h>

//#include <asm/kvm_asm.h>
// extern void __kvm_timer_set_cntvoff(u64 cntvoff);

//#include <nvhe/memory.h>
#include <asm/kvm_pkvm.h>
#include <nvhe/mm.h>
#include <linux/bits.h>
#include <linux/list.h>




#include <nvhe/early_alloc.h>


#include <asm/kvm_mmu.h>
#include <hyp/ghost/ghost_extra_debug-pl011.h>
#include <nvhe/ghost/ghost_pgtable.h>
#include <nvhe/ghost/ghost_mapping_reqs.h>
//#include <nvhe/spinlock.h>

//#include <asm/kvm_s2mpu.h>

// very hackish copies of linux sort libraries to get them linked in to nvhe.  there must be a much better way to do this...
#include <nvhe/ghost/ghost_sort_hack.h>
#include <nvhe/ghost/ghost_list_sort_hack.h>


#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

// linking to definitions in setup.c
extern void *stacks_base;
extern void *vmemmap_base;
extern void *hyp_pgt_base;
extern void *host_s2_pgt_base;

extern void* early_remainder;

// JK: add the following lines to memorize size
extern unsigned long stacks_size;
extern unsigned long vmemmap_size;
extern unsigned long hyp_pgt_size;
extern unsigned long host_s2_pgt_size;


//DEFINE_HYP_SPINLOCK(ghost_lock);
//bool ghost_initialised = false;


/**********************************************
 * EL2 mapping requests
**********************************************/



// this abstracts to itself, i.e. to the canonical interpretation for data structures (especially simple as this contains no pointers)
struct mapping_req {
	enum mapping_req_kind kind;           // the kind of this mapping_req
	u64 cpu;                          // cpu ID in 0..NR_CPUS-1 for HYP_PERCPU or HYP_STACKS mapping_reqs; DUMMY_CPU (0) otherwise
	u64 virt;                         // pKVM EL2 after-the-switch start virtual address, page-aligned
	phys_addr_t phys;                 // start physical address, page-aligned
	u64 size;                         // size, as the number of 4k pages
	enum kvm_pgtable_prot prot;       // protection
	char *doc;                        // documentation string, ignore in maths
};

// invariants:
// - after construction, sorted by kind^H^H virtual^H^H physical address
// - non-overlapping virtual address ranges
// - at most one per mapping_req_kind except HYP_PERCPU, for which at most one for each cpu up to NR_CPUS
// - count <= MAX_MAPPING_REQS
// abstracts to:
// - a finite set of [[struct mapping_req]] also satisfying the above
struct mapping_reqs {
	struct mapping_req m[MAX_MAPPING_REQS];
	u64 count;
};


// most of our checker code treats datastructures pseudo-functionally,
// but we have to allocate them somehow, and we can't put them on the
// stack as pKVM has only one page of stack per-CPU.  We also want to
// hide this from the setup.c call sites, where mapping_reqs data has to
// flow from record_hyp_mapping_reqs to later check_hyp_mapping_reqs.  So we
// just make global variables, but we use them explicitly only in the
// top-level functions of this file; below that we pass pointers to
// them around.
static struct mapping_reqs mapping_reqs;


/* sort mapping_reqs by virtual^H^H physical address*/

/* we do this after construction with the linux heapsort, as it's
   handy, but it might be tidier to maintain sortedness during
   construction */

static int mapping_req_compare_virt(const void *lhs, const void *rhs)
{
	if (((const struct mapping_req *)lhs)->virt < ((const struct mapping_req *)rhs)->virt) return -1;
	if (((const struct mapping_req *)lhs)->virt > ((const struct mapping_req *)rhs)->virt) return 1;
	return 0;
}

static int mapping_req_compare_phys(const void *lhs, const void *rhs)
{
	if (((const struct mapping_req *)lhs)->phys < ((const struct mapping_req *)rhs)->phys) return -1;
	if (((const struct mapping_req *)lhs)->phys > ((const struct mapping_req *)rhs)->phys) return 1;
	return 0;
}


void sort_mapping_reqs_virt(struct mapping_reqs *mapping_reqs)
{
	sort(&mapping_reqs->m, mapping_reqs->count, sizeof(struct mapping_req), mapping_req_compare_virt, NULL);
}

void sort_mapping_reqs_phys(struct mapping_reqs *mapping_reqs)
{
	sort(&mapping_reqs->m, mapping_reqs->count, sizeof(struct mapping_req), mapping_req_compare_phys, NULL);
}

/* print mapping_reqs */
void hyp_put_prot(enum kvm_pgtable_prot prot)
{
	if (prot & KVM_PGTABLE_PROT_DEVICE) hyp_putc('D'); else hyp_putc('-');
	if (prot & KVM_PGTABLE_PROT_R) hyp_putc('R'); else hyp_putc('-');
	if (prot & KVM_PGTABLE_PROT_W) hyp_putc('W'); else hyp_putc('-');
	if (prot & KVM_PGTABLE_PROT_X) hyp_putc('X'); else hyp_putc('-');
	hyp_putsp(" ");
}

void hyp_put_mapping_req_kind(enum mapping_req_kind kind)
{
	switch (kind) {
	case HYP_TEXT:                  hyp_putsp("HYP_TEXT          "); break;
	case HYP_DATA:                  hyp_putsp("HYP_DATA          "); break;
	case HYP_RODATA:                hyp_putsp("HYP_RODATA        "); break;
	case HYP_BSS:                   hyp_putsp("HYP_BSS           "); break;
	case HYP_VGIC:                  hyp_putsp("HYP_VGIC          "); break;
	case HYP_IDMAP:                 hyp_putsp("HYP_IDMAP         "); break;
	case HYP_STACKS:                hyp_putsp("HYP_STACKS  "); break;
	case HYP_VMEMMAP:               hyp_putsp("HYP_VMEMMAP       "); break;
	case HYP_S1_PGTABLE:            hyp_putsp("HYP_S1_PGTABLE    "); break;
	case HYP_S2_PGTABLE:            hyp_putsp("HYP_S2_PGTABLE    "); break;
	case HYP_VMEMMAP_MAP:           hyp_putsp("HYP_VMEMMAP_MAP   "); break;
	case HYP_UART:                  hyp_putsp("HYP_UART          "); break;
	case HYP_WORKSPACE:             hyp_putsp("HYP_WORKSPACE     "); break;
	case HYP_PVMFW:                 hyp_putsp("HYP_PVMFW         "); break;
	case HYP_BP_HARDEN_HYP_VECS:    hyp_putsp("HYP_BP_HARDEN_HYP_VECS"); break;
	case HYP_PERCPU:                hyp_putsp("HYP_PERCPU  "); break;
	case HYP_MODULE:                hyp_putsp("HYP_MODULE  "); break;
	case HYP_HCALL:                 hyp_putsp("HYP_HCALL   "); break;
	case HYP_DEVICE:                hyp_putsp("HYP_DEVICE  "); break;
	case HYP_HOST_RODATA:           hyp_putsp("HYP_HOST_RODATA "); break;
	case HYP_HOST_BSS:              hyp_putsp("HYP_HOST_BSS    "); break;
	default:                        hyp_putsp("unknown mapping_req kind"); break;
	}
	hyp_putsp(" ");
}

void hyp_put_mapping_req(struct mapping_req *map)
{
	if (map->kind == HYP_NULL)
		hyp_putsp("HYP_MAPPING_REQ_NULL");
	else {
		hyp_putsxn("virt",map->virt,64);
		hyp_putsxn("virt'",(map->virt + PAGE_SIZE*map->size),64);
		hyp_putsxn("phys",map->phys,64);
		hyp_putsxn("phys'",map->phys + PAGE_SIZE*map->size,64);
		hyp_putsxn("size(p)",(u32)map->size,32);
		hyp_put_prot(map->prot);
		hyp_put_mapping_req_kind(map->kind);
		if ((map->kind == HYP_PERCPU) || (map->kind == HYP_STACKS)) hyp_putsxn("cpu",(u8)map->cpu,8);
		hyp_putsp(map->doc);
	}
}

void hyp_put_mapping_reqs(struct mapping_reqs *mapping_reqs)
{
	u64 i;
	for (i=0; i<mapping_reqs->count; i++) {
		if (i>=1 && mapping_reqs->m[i].phys == mapping_reqs->m[i-1].phys+mapping_reqs->m[i-1].size*PAGE_SIZE)
			hyp_putc('-');
		else
			hyp_putc(' ');
		hyp_put_mapping_req(&mapping_reqs->m[i]);
		hyp_putc('\n');
	}
}

void ghost_hyp_put_mapping_reqs(void)
{
	hyp_puts("pkvm requested hyp mapping_reqs\n");
	//        sort_mapping_reqs_phys(&mapping_reqs);
	hyp_put_mapping_reqs(&mapping_reqs);
}





/* **************************************************************************
 * record the intended pKVM mapping_reqs
 */

void ghost_record_mapping_req_virt(void *from, void *to, enum kvm_pgtable_prot prot, enum mapping_req_kind kind, u64 cpu)
{
	// TODO: understand the address space conversions in the 2021-12 code
	u64 virt_from = (u64)from;
	u64 virt_to = (u64)to;
	u64 virt_from_aligned, virt_to_aligned;
	u64 size;
	phys_addr_t phys;
	struct mapping_reqs *mp = &mapping_reqs;
	if (mp->count >= MAX_MAPPING_REQS)
		check_assert_fail("extend_mapping_reqs_virt full");

	virt_from_aligned = (u64)virt_from & PAGE_MASK;
	virt_to_aligned = PAGE_ALIGN((u64)virt_to);
	size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;
	phys = hyp_virt_to_phys((void*)virt_from_aligned);

	mp->m[mp->count].doc = NULL;
	mp->m[mp->count].kind = kind;
	mp->m[mp->count].cpu = cpu;
	mp->m[mp->count].virt = virt_from_aligned;
	mp->m[mp->count].phys = phys;
	mp->m[mp->count].size = size;
	mp->m[mp->count].prot = prot;
	mp->count++;

	sort_mapping_reqs_virt(&mapping_reqs);
}


void ghost_record_mapping_req(unsigned long start, unsigned long size,
			unsigned long phys, enum kvm_pgtable_prot prot, enum mapping_req_kind kind)
{
	struct mapping_reqs *mp = &mapping_reqs;
	mp->m[mp->count].doc = NULL;
	mp->m[mp->count].kind = kind;
	mp->m[mp->count].cpu = DUMMY_CPU;
	mp->m[mp->count].virt = start;
	mp->m[mp->count].phys = phys;
	mp->m[mp->count].size = size >> PAGE_SHIFT;
	mp->m[mp->count].prot = prot;
	mp->count++;
	sort_mapping_reqs_virt(&mapping_reqs);
}


// record a mapping_req for a range of hypervisor virtual addresses
void extend_mapping_reqs_virt(struct mapping_reqs *mapping_reqs, enum mapping_req_kind kind, u64 cpu, char *doc, void *virt_from, void *virt_to, enum kvm_pgtable_prot prot)
{
	u64 virt_from_aligned, virt_to_aligned;
	u64 size;
	phys_addr_t phys;
	if (mapping_reqs->count >= MAX_MAPPING_REQS)
		check_assert_fail("extend_mapping_reqs_virt full");

	virt_from_aligned = (u64)virt_from & PAGE_MASK;
	virt_to_aligned = PAGE_ALIGN((u64)virt_to);
	size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;
	phys = hyp_virt_to_phys((void*)virt_from_aligned);

	mapping_reqs->m[mapping_reqs->count].doc = doc;
	mapping_reqs->m[mapping_reqs->count].kind = kind;
	mapping_reqs->m[mapping_reqs->count].cpu = cpu;
	mapping_reqs->m[mapping_reqs->count].virt = virt_from_aligned;
	mapping_reqs->m[mapping_reqs->count].phys = phys;
	mapping_reqs->m[mapping_reqs->count].size = size;
	mapping_reqs->m[mapping_reqs->count].prot = prot;
	mapping_reqs->count++;

	sort_mapping_reqs_virt(mapping_reqs);
}

// record the mapping_req for the idmap, adapting hyp_create_idmap from arch/arm64/kvm/hyp/nvhe/mm.c
void extend_mapping_reqs_image_idmap(struct mapping_reqs *mapping_reqs, enum mapping_req_kind kind, u64 cpu, char *doc, void *virt_from, void *virt_to, enum kvm_pgtable_prot prot)
{
	u64 virt_from_aligned, virt_to_aligned;
	u64 size;
	phys_addr_t phys;
	if (mapping_reqs->count >= MAX_MAPPING_REQS)
		check_assert_fail("extend_mapping_reqs_image_idmap full");

	virt_from_aligned = (u64)virt_from & PAGE_MASK;
	virt_to_aligned = PAGE_ALIGN((u64)virt_to);
	size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;
	phys = hyp_virt_to_phys((void*)virt_from_aligned);

	mapping_reqs->m[mapping_reqs->count].doc = doc;
	mapping_reqs->m[mapping_reqs->count].kind = kind;
	mapping_reqs->m[mapping_reqs->count].cpu = cpu;
	mapping_reqs->m[mapping_reqs->count].virt = phys;  // NB
	mapping_reqs->m[mapping_reqs->count].phys = phys;
	mapping_reqs->m[mapping_reqs->count].size = size;
	mapping_reqs->m[mapping_reqs->count].prot = prot;
	mapping_reqs->count++;

	sort_mapping_reqs_virt(mapping_reqs);
}


// record a mapping_req for a range of hypervisor virtual addresses to a specific physical address, for the vmemmap
void extend_mapping_reqs_vmemmap(struct mapping_reqs *mapping_reqs, enum mapping_req_kind kind, u64 cpu, char *doc, void *virt_from, void *virt_to, phys_addr_t phys, enum kvm_pgtable_prot prot)
{
	u64 virt_from_aligned, virt_to_aligned;
	u64 size;
	if (mapping_reqs->count >= MAX_MAPPING_REQS)
		check_assert_fail("extend_mapping_reqs_vmemmap full");

	virt_from_aligned = (u64)virt_from & PAGE_MASK;
	virt_to_aligned = PAGE_ALIGN((u64)virt_to);
	size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;

	mapping_reqs->m[mapping_reqs->count].doc = doc;
	mapping_reqs->m[mapping_reqs->count].kind = kind;
	mapping_reqs->m[mapping_reqs->count].cpu = cpu;
	mapping_reqs->m[mapping_reqs->count].virt = virt_from_aligned;
	mapping_reqs->m[mapping_reqs->count].phys = phys;
	mapping_reqs->m[mapping_reqs->count].size = size;
	mapping_reqs->m[mapping_reqs->count].prot = prot;
	mapping_reqs->count++;

	sort_mapping_reqs_virt(mapping_reqs);
}

// * record a mapping_req for the uart  TODO
// */
//void extend_mapping_reqs_uart(void);
//{
//  phys_addr_t phys = CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR;
//  enum kvm_pgtable_prot prot = PAGE_HYP_DEVICE;
//  u64 size = 1;
//  void *virt = __io_map_base;
//
//  u64 virt_from_aligned, virt_to_aligned;
//  u64 size;
//  virt_from_aligned = (u64)virt_from & PAGE_MASK;
//  virt_to_aligned = PAGE_ALIGN((u64)virt_to);
//  size = (virt_to_aligned - virt_from_aligned) >> PAGE_SHIFT;
//
//  mapping_reqs[kind].doc = doc;
//  mapping_reqs[kind].kind = kind;
//  mapping_reqs[kind].cpu = cpu;
//  mapping_reqs[kind].virt = virt_from_aligned;
//  mapping_reqs[kind].phys = phys;
//  mapping_reqs[kind].size = size;
//  mapping_reqs[kind].prot = prot;
//}





/* old comment - now irrelevant? */
// call with hyp_pgtable.pgd to check putative mappings as described
// in hyp_pgtable, before the switch.  After the switch, we can do the
// same but using the then-current TTBR0_EL2 value instead of the
// hyp_pgtable.pgd


// truly horrible hackery - we need this function from the middle of pgtable.c for the instrumentation checking (though not for the spec), but we can't pull it out from there.

// and we have another arch_prot_of_prot in ghost_spec.c.  Have to rationalise later.

#define KVM_PTE_TYPE			BIT(1)
#define KVM_PTE_TYPE_BLOCK		0
#define KVM_PTE_TYPE_PAGE		1
#define KVM_PTE_TYPE_TABLE		1

#define KVM_PTE_LEAF_ATTR_LO		GENMASK(11, 2)

#define KVM_PTE_LEAF_ATTR_LO_S1_ATTRIDX	GENMASK(4, 2)
#define KVM_PTE_LEAF_ATTR_LO_S1_AP	GENMASK(7, 6)
#define KVM_PTE_LEAF_ATTR_LO_S1_AP_RO	3
#define KVM_PTE_LEAF_ATTR_LO_S1_AP_RW	1
#define KVM_PTE_LEAF_ATTR_LO_S1_SH	GENMASK(9, 8)
#define KVM_PTE_LEAF_ATTR_LO_S1_SH_IS	3
#define KVM_PTE_LEAF_ATTR_LO_S1_AF	BIT(10)

#define KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR	GENMASK(5, 2)
#define KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R	BIT(6)
#define KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W	BIT(7)
#define KVM_PTE_LEAF_ATTR_LO_S2_SH	GENMASK(9, 8)
#define KVM_PTE_LEAF_ATTR_LO_S2_SH_IS	3
#define KVM_PTE_LEAF_ATTR_LO_S2_AF	BIT(10)

#define KVM_PTE_LEAF_ATTR_HI		GENMASK(63, 51)

#define KVM_PTE_LEAF_ATTR_HI_SW		GENMASK(58, 55)

#define KVM_PTE_LEAF_ATTR_HI_S1_XN	BIT(54)

#define KVM_PTE_LEAF_ATTR_HI_S2_XN	BIT(54)

#define KVM_PTE_LEAF_ATTR_S2_PERMS	(KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R | \
					 KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W | \
					 KVM_PTE_LEAF_ATTR_HI_S2_XN)

#define KVM_INVALID_PTE_OWNER_MASK	GENMASK(9, 2)
#define KVM_MAX_OWNER_ID		FIELD_MAX(KVM_INVALID_PTE_OWNER_MASK)


static int hyp_set_prot_attr(enum kvm_pgtable_prot prot, kvm_pte_t *ptep)
{
	bool device = prot & KVM_PGTABLE_PROT_DEVICE;
	u32 mtype = device ? MT_DEVICE_nGnRE : MT_NORMAL;
	kvm_pte_t attr = FIELD_PREP(KVM_PTE_LEAF_ATTR_LO_S1_ATTRIDX, mtype);
	//u32 sh = KVM_PTE_LEAF_ATTR_LO_S1_SH_IS;
	u32 ap = (prot & KVM_PGTABLE_PROT_W) ? KVM_PTE_LEAF_ATTR_LO_S1_AP_RW :
					       KVM_PTE_LEAF_ATTR_LO_S1_AP_RO;

	if (!(prot & KVM_PGTABLE_PROT_R))
		return -EINVAL;

	if (prot & KVM_PGTABLE_PROT_X) {
		if (prot & KVM_PGTABLE_PROT_W)
			return -EINVAL;

		if (device)
			return -EINVAL;
	} else {
		attr |= KVM_PTE_LEAF_ATTR_HI_S1_XN;
	}

	attr |= FIELD_PREP(KVM_PTE_LEAF_ATTR_LO_S1_AP, ap);
	//attr |= FIELD_PREP(KVM_PTE_LEAF_ATTR_LO_S1_SH, sh);
	//      attr |= KVM_PTE_LEAF_ATTR_LO_S1_AF;
	attr |= prot & KVM_PTE_LEAF_ATTR_HI_SW;
	*ptep = attr;

	return 0;
}

struct maplet_attributes attrs_from_req(struct mapping_req *r)
{
	struct maplet_attributes attrs;
	attrs.memtype = 0;
	attrs.provenance = 0;
	attrs.prot = 0;

	if (r->prot & KVM_PGTABLE_PROT_R)
		attrs.prot |= MAPLET_PERM_R;
	if (r->prot & KVM_PGTABLE_PROT_W)
		attrs.prot |= MAPLET_PERM_W;
	if (r->prot & KVM_PGTABLE_PROT_X)
		attrs.prot |= MAPLET_PERM_X;

	if (r->prot & KVM_PGTABLE_PROT_DEVICE)
		attrs.memtype = MAPLET_MEMTYPE_DEVICE;
	else
		attrs.memtype = MAPLET_MEMTYPE_NORMAL_CACHEABLE;


	if (r->prot & KVM_PGTABLE_PROT_SW0)
		attrs.provenance = MAPLET_PAGE_STATE_SHARED_OWNED;
	else if (r->prot & KVM_PGTABLE_PROT_SW1)
		attrs.provenance = MAPLET_PAGE_STATE_SHARED_BORROWED;
	else if (!(r->prot & (KVM_PGTABLE_PROT_SW0 | KVM_PGTABLE_PROT_SW1)))
		attrs.provenance = MAPLET_PAGE_STATE_PRIVATE_OWNED;
	else
		attrs.provenance = MAPLET_PAGE_STATE_UNKNOWN;

	return attrs;
}

mapping interpret_mapping_reqs(void)
{
	mapping map = mapping_empty_();
	u64 i;
	struct mapping_req *mr;
	for (i=0; i<mapping_reqs.count; i++) {
		mr = &mapping_reqs.m[i];
		if (mr->kind != HYP_PVMFW) {
			extend_mapping_coalesce(
				&map, GHOST_STAGE1, mr->virt, mr->size,
				maplet_target_mapped_attrs(mr->phys, mr->size, attrs_from_req(mr)));
		}
	}
	return map;
}

void ghost_check_hyp_mapping_reqs(struct kvm_pgtable *pg, bool noisy)
{
	ghost_lock_maplets();
	hyp_puts("ghost_check_hyp_mappings (ignoring HYP_PVMFW)");
	hyp_putc('\n');
	//bool res;
	if (pg==0) {
		hyp_puts("ghost_check_hyp_mappings given pg==0");
		hyp_putc('\n');
		goto out;
	}

	mapping mapping_pkvm = ghost_record_pgtable(pg, NULL, "check_hyp_mapping_reqs pgd", 2);
	mapping mapping_reqs = interpret_mapping_reqs();
	mapping_equal(mapping_reqs, mapping_pkvm, "check_hyp_mapping_reqs", "mapping_reqs", "mapping_pkvm",2);
	free_mapping(mapping_pkvm);
	free_mapping(mapping_reqs);
out:
	ghost_unlock_maplets();
	return; // res;
}



