#ifndef RTS_DEPS
#define RTS_DEPS

// Any RTS dependencies on system headers should be done through this file.
// __CN_INSTRUMENT indicates that we are using the header
// *after* the pre-processor, so we need to use the manual definition.
// This flag is not set when compiling the implementation of the RTS
// and then we use normal system headers.

#ifdef __CN_INSTRUMENT
  #include "cerb_types.h"

  // We define this just for the declarations in this file.
  // We also ensure that this is the first #include in the instrumented files.
  // See also the end of `rts.h` where these are undefined.

  #define size_t    __cerbty_size_t
  #define uint8_t   __cerbty_uint8_t
  #define uint16_t  __cerbty_uint16_t
  #define uint32_t  __cerbty_uint32_t
  #define uint64_t  __cerbty_uint64_t
  #define uintptr_t __cerbty_uintptr_t
  #define int8_t    __cerbty_int8_t
  #define int16_t   __cerbty_int16_t
  #define int32_t   __cerbty_int32_t
  #define int64_t   __cerbty_int64_t
  #define intptr_t  __cerbty_intptr_t
  #define alignof   _Alignof

#else
  #include <linux/limits.h>
  #include <linux/string.h>
  #include <asm/kvm_pkvm.h>

  #include <nvhe/cn/cn_alloc.h>

  #define alignof(t) __alignof__(t)
  #define max_align_t __uint128_t
  #define FILE void

  #define assert(x) BUG_ON(!(x))
  #define exit(x) BUG()
  #define fprintf(a, fmt, ...) {}
  #define printf(fmt, ...) {}

#endif

#endif
