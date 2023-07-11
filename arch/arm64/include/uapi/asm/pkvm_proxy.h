/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_PKVM_PROXY_H
#define __ASM_PKVM_PROXY_H

#include <linux/types.h>
#include <linux/ptrace.h>

#define HPROX_HVC_TYPE 'h'
#define HPROX_STRUCTS_TYPE 's'
#define HPROX_ALLOC_TYPE 'a'
#define HPROX_MEMCACHE_TYPE 'm'


// Perform the HVC numbered hvcnum, with this number of arguments.
// The ioctl parameter is an array containing the arguments
#define HVC_PROXY_IOCTL(hvcnum, numarg) \
	_IOC(_IOC_WRITE, HPROX_HVC_TYPE, hvcnum, 8 * numarg)


// All those ioctl return a size or an offset as return value.
#define HPROX_STRUCT_KVM_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 0)
// The argument must be a `enum struct_kvm_fields`
#define HPROX_STRUCT_KVM_GET_OFFSET _IO(HPROX_STRUCTS_TYPE, 1)
#define HPROX_HYP_VM_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 2)
#define HPROX_PGD_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 3)
#define HPROX_STRUCT_KVM_VCPU_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 4)
// The argument must be a: `enum struct_kvm_vcpu_fields`
#define HPROX_STRUCT_KVM_VCPU_GET_OFFSET _IO(HPROX_STRUCTS_TYPE, 5)
#define HPROX_HYP_VCPU_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 6)

enum struct_kvm_fields {
	HPROX_NR_MEM_SLOT_PAGES, /* unsigned long */
	HPROX_VCPU_ARRAY, /* xarray */
	HPROX_MAX_VCPUS, /* int */
	HPROX_CREATED_VCPUS, /* int */
	HPROX_ARCH_PKVM_ENABLED, /* bool */
	HPROX_ARCH_PKVM_TEARDOWN_MC, /* struct hprox_memcache */
};

enum struct_kvm_vcpu_fields {
	HPROX_VCPU_ID, /* int */
	HPROX_VCPU_IDX, /* int */
	HPROX_VCPU_CFLAGS, /* 8 bits bitfield */
	HPROX_VCPU_IFLAGS, /* 8 bits bitfield */
	HPROX_VCPU_FEATURES, /* KVM_VCPU_MAX_FEATURES bits bitfield */
	HPROX_VCPU_HCR_EL2, /* u64 */
	HPROX_VCPU_FAULT, /* struct hprox_vcpu_fault_info */
	HPROX_VCPU_REGS, /* struct user_pt_regs */
	HPROX_VCPU_FP_REGS, /* struct user_fpsimd_state */
	HPROX_VCPU_MEMCACHE, /* struct hprox_memcache */
	// TODO add SVE state, for now SVE-less guests only
};

struct hprox_vcpu_fault_info {
	__u64 esr_el2; /* Hyp Syndrom Register */
	__u64 far_el2; /* Hyp Fault Address Register */
	__u64 hpfar_el2; /* Hyp IPA Fault Address Register */
	__u64 disr_el1; /* Deferred [SError] Status Register */
};

// User accessible memcache struct. This need to match up kvm_hyp_memcache
struct hprox_memcache {
        __u64 head; // kernel address, might not be accessible, if not
			    // donated from a hprox_alloc region.
	unsigned long nr_pages;
};
// The HPROX_ALLOC ioctl can either allocate through `vmalloc` or
// `alloc_pages_exact`
enum hprox_alloc_type { HPROX_VMALLOC, HPROX_PAGES_EXACT };

// The ioctl parameter is the size of the allocation.
// This return a mmapable file descriptor of the kernel allocation
#define HPROX_ALLOC(alloc) _IO(HPROX_ALLOC_TYPE, alloc)
#define HPROX_ALLOC_PAGES HPROX_ALLOC(HPROX_PAGES_EXACT)

// Those are ioctl on the mmapable fd from the HPROX_ALLOC ioct
#define HPROX_ALLOC_KADDR _IOR('A',0, __u64)
#define HPROX_ALLOC_PHYS _IOR('A', 1, __u64)
#define HPROX_ALLOC_RELEASE _IO('A', 2)
#define HPROX_ALLOC_FREE _IO('A', 3)

// Memcache ioctls, free is encoded as topup 0
#define HPROX_MEMCACHE_FREE \
	_IOWR(HPROX_MEMCACHE_TYPE, 0, struct hprox_memcache)
#define HPROX_MEMCACHE_TOPUP(n) \
	_IOWR(HPROX_MEMCACHE_TYPE, (n), struct hprox_memcache)

#endif /* __ASM_PKVM_PROXY_H */
