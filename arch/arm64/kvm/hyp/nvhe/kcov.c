// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Sebastian Ene <sebastianene@google.com>
 * Author: Thibaut Perami <thibautp@google.com>
 */

#include <linux/kvm_host.h>
#include <linux/mm.h>

#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

#include <asm/kvm_emulate.h>

#include <nvhe/mem_protect.h>
#include <nvhe/memory.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/trap_handler.h>

u64 __ro_after_init hyp_kimage_voffset;
u64 __ro_after_init hyp_kimage_vaddr;

static DEFINE_HYP_SPINLOCK(kcov_buffer_lock);

static inline u32 get_active_pid(void){
	/* The EL1 scheduler is responsible for putting the user thread PID in
	 * this register */
	return read_sysreg(contextidr_el1);
}

struct kcov_buffer {
	/* Size of the buffer (number of 8-bytes words *)
	 * It should be a multiple of PTRS_PER_PTE */
	unsigned int size;
	/* How much of size is currently mapped, should be <= size. */
	unsigned int mapped;
	/* The location of the buffer. If NULL, this slot is free in the
	 * kcov_buffers array */
	u64 *area;
	/* If the buffer is inactive this contains 0.
         *
	 * If the buffer is active, this contains the user-thread PID. In that
	 * case area must not be null, and mapped must equal size
	 */
	u32 current_pid;
};

/* The list of mapped kcov buffers. The area address being NULL, means
 * unallocated buffer. Any modification on an active buffer (current_id set)
 * must be done by code called by the same user thread, that way it cannot
 * interfere/race with tracing by other CPUs
 */
static struct kcov_buffer kcov_buffers[CONFIG_NVHE_KCOV_NUM_BUFFERS];

/* Per-CPU pointers into the kcov_buffers array.
 * NULL means the current thread is not actively tracing
 */
static DEFINE_PER_CPU(struct kcov_buffer *, kcov_active_buffer);

void pkvm_kcov_enter_from_host(void)
{
	u64 cpu_offset = read_sysreg(tpidr_el2);

	u32 pid = get_active_pid();
	if(!pid)
		return;

	/* This linear walk is inefficient on every host hypercall
	 * TODO: Perf improvements */
	for (int i = 0; i < CONFIG_NVHE_KCOV_NUM_BUFFERS; i++) {
		if (kcov_buffers[i].current_pid == pid) {
			if (WARN_ON(kcov_buffers[i].area == NULL))
				continue;
			*SHIFT_PERCPU_PTR(&kcov_active_buffer, cpu_offset) =
				&kcov_buffers[i];
			return;
		}
	}
}

void pkvm_kcov_exit_to_host(void)
{
	u64 cpu_offset = read_sysreg(tpidr_el2);
	*SHIFT_PERCPU_PTR(&kcov_active_buffer, cpu_offset) = NULL;
}

/*
 * Convert a hypervisor active IP to static kernel image pointer that can index
 * the kernel image file
 */
static inline u64 canonicalize_ip(u64 ip)
{
	ip = __hyp_pa(ip);
	ip += hyp_kimage_voffset;

#ifdef CONFIG_RANDOMIZE_BASE
	ip -= (hyp_kimage_vaddr - KIMAGE_VADDR);
#endif
	return ip;
}

/*
 * Entry point from hypervisor instrumented code.
 * This is called once per basic-block/edge.
 * The EL1 kernel equivalent function is in kernel/kcov.c
 */
void __sanitizer_cov_trace_pc(void)
{
	u64 cpu_offset = read_sysreg(tpidr_el2);
	u64 pos;
	struct kcov_buffer *buf =
		*SHIFT_PERCPU_PTR(&kcov_active_buffer, cpu_offset);

	if (!buf)
		return;
	if (WARN_ON(!(buf->area))) {
		return;
	}

	/* There is no concurrent access possible, because only one physical CPU
	 * can have the current thread active at a time and the hypervisor code
	 * is not interruptible */

	pos = buf->area[0] + 1;
	if (unlikely(pos >= buf->size))
		return;
	buf->area[0] = pos;
	buf->area[pos] = canonicalize_ip(_RET_IP_);
}

static int find_free_buffer_slot(void)
{
	for (int i = 0; i < CONFIG_NVHE_KCOV_NUM_BUFFERS; i++) {
		if (kcov_buffers[i].area == NULL) {
			BUG_ON(kcov_buffers[i].current_pid != 0);
			return i;
		}
	}
	return -ENOBUFS;
}

u64 __pkvm_kcov_init_buffer(uint size)
{
	unsigned long vaddr;
	int index;
	int ret;

	if (!IS_ALIGNED(size, PTRS_PER_PTE))
		return -EINVAL;

	if (!size)
		return -EINVAL;

	hyp_spin_lock(&kcov_buffer_lock);
	ret = find_free_buffer_slot();
	if (ret < 0)
		goto unlock;
	index = ret;

	ret = pkvm_alloc_private_va_range(size * sizeof(u64), &vaddr);
	if (ret)
		goto unlock;

	kcov_buffers[index].area = (u64 *)vaddr;
	kcov_buffers[index].size = size;
	kcov_buffers[index].mapped = 0;
	ret = index;
unlock:
	hyp_spin_unlock(&kcov_buffer_lock);
	return ret;
}

u64 __pkvm_kcov_buffer_add_page(u64 index, u64 pfn)
{
	int ret = -EINVAL;
	void *page_lm = hyp_pfn_to_virt(pfn);
	u64* vaddr;

	if (index >= CONFIG_NVHE_KCOV_NUM_BUFFERS)
		return -EINVAL;

	hyp_spin_lock(&kcov_buffer_lock);
	if (!kcov_buffers[index].area)
		goto unlock;

	if (kcov_buffers[index].mapped >= kcov_buffers[index].size)
		goto unlock;

	BUG_ON(kcov_buffers[index].current_pid);

	ret = __pkvm_host_share_hyp(pfn);
	if(ret)
		goto unlock;

	ret = hyp_pin_shared_mem(page_lm, page_lm + PAGE_SIZE);
	if (ret)
		goto unshare;

	vaddr = kcov_buffers[index].area + kcov_buffers[index].mapped;

	hyp_spin_lock(&pkvm_pgd_lock);
	ret = kvm_pgtable_hyp_map(&pkvm_pgtable, (u64)vaddr, PAGE_SIZE, hyp_pfn_to_phys(pfn), PAGE_HYP);
	hyp_spin_unlock(&pkvm_pgd_lock);
	if (ret)
		goto unpin;

	// Success!
	kcov_buffers[index].mapped += PTRS_PER_PTE;
	goto unlock;

unpin:
	hyp_unpin_shared_mem(page_lm, page_lm + PAGE_SIZE);

unshare:
	WARN_ON(__pkvm_host_unshare_hyp(pfn));

unlock:
	hyp_spin_unlock(&kcov_buffer_lock);
	return ret;
}

int __pkvm_kcov_teardown_buffer(u64 index)
{
	u64 *vaddr;
	kvm_pte_t pte;
	u32 level;
	u64 pfn;
	void *page_lm;

	if (index >= CONFIG_NVHE_KCOV_NUM_BUFFERS)
		return -EINVAL;

	hyp_spin_lock(&kcov_buffer_lock);

	if (kcov_buffers[index].current_pid) {
		hyp_spin_unlock(&kcov_buffer_lock);
		return -EBUSY;
	}

	if (kcov_buffers[index].mapped == 0) {
		kcov_buffers[index].area = NULL;
		hyp_spin_unlock(&kcov_buffer_lock);
		return 0;
	}

	kcov_buffers[index].mapped -= PTRS_PER_PTE;

	vaddr = kcov_buffers[index].area + kcov_buffers[index].mapped;

	hyp_spin_lock(&pkvm_pgd_lock);
	BUG_ON(kvm_pgtable_get_leaf(&pkvm_pgtable, (u64)vaddr, &pte, &level));
	BUG_ON(level != KVM_PGTABLE_MAX_LEVELS - 1);
	BUG_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, (u64)vaddr, PAGE_SIZE) != PAGE_SIZE);
	hyp_spin_unlock(&pkvm_pgd_lock);

	pfn = kvm_pte_to_pfn(pte);
	page_lm = hyp_pfn_to_virt(pfn);
	hyp_unpin_shared_mem(page_lm, page_lm + PAGE_SIZE);
	WARN_ON(__pkvm_host_unshare_hyp(pfn));

	hyp_spin_unlock(&kcov_buffer_lock);

	return -EAGAIN;
}

int __pkvm_kcov_enable(u64 index)
{
	u32 pid = get_active_pid();
	int ret;

	/* The kernel should not call kcov_enable for the idle process */
	if (WARN_ON(!pid))
		return -EINVAL;

	hyp_spin_lock(&kcov_buffer_lock);
	if (kcov_buffers[index].current_pid) {
		ret = -EBUSY;
		goto unlock_kcov;
	}
	if (kcov_buffers[index].area == NULL) {
		ret = -EINVAL;
		goto unlock_kcov;
	}
	if (kcov_buffers[index].mapped != kcov_buffers[index].size) {
		ret = -ENOMEM;
		goto unlock_kcov;
	}

	kcov_buffers[index].current_pid = pid;
	ret = 0;

unlock_kcov:
	hyp_spin_unlock(&kcov_buffer_lock);
	return ret;
}

int __pkvm_kcov_disable(void)
{
	u64 cpu_offset = read_sysreg(tpidr_el2);
	struct kcov_buffer *buf =
		*SHIFT_PERCPU_PTR(&kcov_active_buffer, cpu_offset);

	if (!buf)
		return -EINVAL;

	BUG_ON(buf->current_pid != get_active_pid());

	*SHIFT_PERCPU_PTR(&kcov_active_buffer, cpu_offset) = NULL;
	hyp_spin_lock(&kcov_buffer_lock);
	buf->current_pid = 0;
	hyp_spin_unlock(&kcov_buffer_lock);
	return 0;
}
