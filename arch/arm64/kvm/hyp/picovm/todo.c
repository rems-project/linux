// Adding here globals and functions that we don't yet properly support but
// that are needed for linking a whole kernel

// for struct kvm_host_data and struct kvm_cpu_context
#include <linux/kvm_host.h>

// from arch/arm64/kvm/hyp/nvhe/ghost/ghost_recording.c
// originally from arch/arm64/kvm/va_layout.c
u64 tag_val;
u8 tag_lsb;

// from arch/arm64/kvm/hyp/nvhe/early_alloc.c
s64 __ro_after_init hyp_physvirt_offset;

// from arch/arm64/kvm/hyp/nvhe/setup.c
unsigned long arm64_kvm_hyp_debug_uart_addr;

// from arch/arm64/kvm/hyp/nvhe/pkvm.c
unsigned long __icache_flags;
unsigned int kvm_arm_vmid_bits;


// from arch/arm64/kvm/hyp/nvhe/hyp-main.c
DEFINE_PER_CPU(struct kvm_nvhe_init_params, kvm_init_params);

// from arch/arm64/kvm/hyp/nvhe/mem_protect.c
void handle_host_mem_abort(struct kvm_cpu_context *host_ctxt)
{
	// TODO
}


// from arch/arm64/kvm/hyp/nvhe/switch.c
DEFINE_PER_CPU(struct kvm_host_data, kvm_host_data);
DEFINE_PER_CPU(struct kvm_cpu_context, kvm_hyp_ctxt);
DEFINE_PER_CPU(unsigned long, kvm_hyp_vector);

asmlinkage void __noreturn hyp_panic(void)
{
	// TODO
}
asmlinkage void __noreturn hyp_panic_bad_stack(void)
{
	hyp_panic();
}
asmlinkage void kvm_unexpected_el2_exception(void)
{
	// TODO
}
