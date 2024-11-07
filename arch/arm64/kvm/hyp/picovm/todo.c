// Adding here globals and functions that we don't yet properly support but
// that are needed for linking a whole kernel

// for struct kvm_host_data and struct kvm_cpu_context
#include <picovm/picovm_host.h>

// NOTE: from arch/arm64/kvm/hyp/nvhe/ghost/ghost_recording.c
// originally NOTE: from arch/arm64/kvm/va_layout.c
u64 tag_val;
u8 tag_lsb;

// NOTE: from arch/arm64/kvm/hyp/nvhe/setup.c
unsigned long arm64_kvm_hyp_debug_uart_addr;

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
