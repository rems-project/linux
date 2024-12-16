// Adding here globals and functions that we don't yet properly support but
// that are needed for linking a whole kernel

// #include <picovm/linux/types.h>
// #include <picovm/per-cpu.h>
// #include <picovm/kvm_host.h>



// DEFINE_PER_CPU(struct kvm_host_data, kvm_host_data);
// DEFINE_PER_CPU(struct kvm_cpu_context, picovm_hyp_ctxt);
// DEFINE_PER_CPU(unsigned long, picovm_hyp_vector);


// asmlinkage void __noreturn hyp_panic(void)
// {
// 	// TODO
// }

// asmlinkage void __noreturn hyp_panic_bad_stack(void)
// {
// 	hyp_panic();
// }
// asmlinkage void kvm_unexpected_el2_exception(void)
// {
// 	// TODO
// }
