// Adding here globals and functions that we don't yet properly support but
// that are needed for linking a whole kernel

// for struct picovm_host_data and struct picovm_cpu_context
#include <picovm/host.h>

// NOTE: from arch/arm64/kvm/hyp/nvhe/ghost/ghost_recording.c
// originally NOTE: from arch/arm64/kvm/va_layout.c
u64 tag_val;
u8 tag_lsb;

// NOTE: from arch/arm64/kvm/hyp/nvhe/setup.c
unsigned long arm64_kvm_hyp_debug_uart_addr;

DEFINE_PER_CPU(struct picovm_host_data, picovm_host_data);
DEFINE_PER_CPU(struct picovm_cpu_context, picovm_hyp_ctxt);
DEFINE_PER_CPU(unsigned long, picovm_hyp_vector);


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
