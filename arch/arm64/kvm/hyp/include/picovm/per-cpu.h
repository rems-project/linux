#ifndef __PICOVM_PER_CPU_H
#define __PICOVM_PER_CPU_H

// TODO: license

#define raw_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	arch_raw_cpu_ptr(ptr);						\
})


#define raw_smp_processor_id() (*raw_cpu_ptr(&cpu_number))


// From include/linux/percpu-defs.h
#ifndef PER_CPU_ATTRIBUTES
#define PER_CPU_ATTRIBUTES
#endif

#include <picovm/linux/compiler.h>

#ifndef PER_CPU_BASE_SECTION
#ifdef CONFIG_SMP
#define PER_CPU_BASE_SECTION ".data..percpu"
#else
#define PER_CPU_BASE_SECTION ".data"
#endif
#endif

#define __PCPU_ATTRS(sec)						\
	__percpu __attribute__((section(PER_CPU_BASE_SECTION sec)))	\
	PER_CPU_ATTRIBUTES

#define DECLARE_PER_CPU_SECTION(type, name, sec)			\
	extern __PCPU_ATTRS(sec) typeof(type) name

#define DEFINE_PER_CPU_SECTION(type, name, sec)				\
	__PCPU_ATTRS(sec) typeof(type) name

#define DECLARE_PER_CPU_READ_MOSTLY(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..read_mostly")


#define DECLARE_PER_CPU(type, name)					\
	DECLARE_PER_CPU_SECTION(type, name, "")

#define DEFINE_PER_CPU(type, name)					\
	DEFINE_PER_CPU_SECTION(type, name, "")

#define SHIFT_PERCPU_PTR(__p, __offset)					\
	RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset))




// #ifdef __KVM_NVHE_HYPERVISOR__
extern unsigned long __hyp_per_cpu_offset(unsigned int cpu);
#define __per_cpu_offset
#define per_cpu_offset(cpu)	__hyp_per_cpu_offset((cpu))
// #endif

// From include/asm-generic/percpu.h
#ifndef __my_cpu_offset
#define __my_cpu_offset per_cpu_offset(raw_smp_processor_id())
#endif


#ifndef arch_raw_cpu_ptr
#define arch_raw_cpu_ptr(ptr) SHIFT_PERCPU_PTR(ptr, __my_cpu_offset)
#endif

#define __verify_pcpu_ptr(ptr)						\
do {									\
	const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;	\
	(void)__vpp_verify;						\
} while (0)

#define per_cpu_ptr(ptr, cpu)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)));			\
})

#if 0

#define raw_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	arch_raw_cpu_ptr(ptr);						\
})

// From arch/arm64/asm/smp.h
DECLARE_PER_CPU_READ_MOSTLY(int, cpu_number);
#define raw_smp_processor_id() (*raw_cpu_ptr(&cpu_number))


#define this_cpu_ptr(ptr) raw_cpu_ptr(ptr)

// #endif



// From arch/arm64/asm/smp.h
DECLARE_PER_CPU_READ_MOSTLY(int, cpu_number);
#define raw_smp_processor_id() (*raw_cpu_ptr(&cpu_number))

#ifndef __my_cpu_offset
#define __my_cpu_offset per_cpu_offset(raw_smp_processor_id())
#endif


#ifndef arch_raw_cpu_ptr
#define arch_raw_cpu_ptr(ptr) SHIFT_PERCPU_PTR(ptr, __my_cpu_offset)
#endif


extern unsigned long __hyp_per_cpu_offset(unsigned int cpu);
#define __per_cpu_offset
#define per_cpu_offset(cpu)	__hyp_per_cpu_offset((cpu))


#define __verify_pcpu_ptr(ptr)						\
do {									\
	const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;	\
	(void)__vpp_verify;						\
} while (0)


#ifdef CONFIG_SMP

/*
 * Add an offset to a pointer but keep the pointer as-is.  Use RELOC_HIDE()
 * to prevent the compiler from making incorrect assumptions about the
 * pointer value.  The weird cast keeps both GCC and sparse happy.
 */
#define SHIFT_PERCPU_PTR(__p, __offset)					\
	RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset))

#define per_cpu_ptr(ptr, cpu)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)));			\
})

#define raw_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	arch_raw_cpu_ptr(ptr);						\
})

#ifdef CONFIG_DEBUG_PREEMPT
#define this_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR(ptr, my_cpu_offset);				\
})
#else
#define this_cpu_ptr(ptr) raw_cpu_ptr(ptr)
#endif

#else	/* CONFIG_SMP */

#define VERIFY_PERCPU_PTR(__p)						\
({									\
	__verify_pcpu_ptr(__p);						\
	(typeof(*(__p)) __kernel __force *)(__p);			\
})

#define per_cpu_ptr(ptr, cpu)	({ (void)(cpu); VERIFY_PERCPU_PTR(ptr); })
#define raw_cpu_ptr(ptr)	per_cpu_ptr(ptr, 0)
#define this_cpu_ptr(ptr)	raw_cpu_ptr(ptr)

#endif	/* CONFIG_SMP */


/*

({
    do {
        const void *__vpp_verify =
            (typeof((&kvm_host_data) + 0))((void *)0);
        (void)__vpp_verify;
    } while (0);
    ({
        unsigned long __ptr;
        __ptr = (unsigned long)((
            typeof(*(&kvm_host_data)) *)(&kvm_host_data));
        (typeof((
            typeof(*(&kvm_host_data))
                *)(&kvm_host_data)))(__ptr +
                             ((__hyp_my_cpu_offset())));
    });
})

*/
#endif


DECLARE_PER_CPU_READ_MOSTLY(int, cpu_number);


// #define __LINUX_COMPILER_H
// #include <asm-generic/percpu.h>
// #define raw_smp_processor_id() (*raw_cpu_ptr(&cpu_number))
// #include <asm-generic/percpu.h>




// #define	this_cpu_ptr		raw_cpu_ptr

// #define this_cpu_ptr(X)	0 // TODO
#define this_cpu_ptr(X)							\
	({								\
	do {								\
		const void *__vpp_verify =				\
		(typeof((X) + 0))((void *)0);				\
		(void)__vpp_verify;					\
	} while (0);							\
	({								\
		unsigned long __ptr;					\
		__ptr = (unsigned long)((				\
		typeof(*(X)) *)(X));					\
		(typeof((						\
		typeof(*(X))						\
			*)(X)))(__ptr +					\
				((read_sysreg(tpidr_el2))));		\
	});								\
	})

#endif /* __PICOVM_PER_CPU_H */
