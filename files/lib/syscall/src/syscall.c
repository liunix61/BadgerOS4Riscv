
// SPDX-License-Identifier: MIT

#include "syscall.h"

// These syscalls *do* actually take parameters, but GCC doesn't realise this.
#pragma GCC diagnostic ignored "-Wunused-parameter"

#ifdef __riscv
#define SYSCALL_DEF(num, enum, name, returns, ...)                                                                     \
    returns name(__VA_ARGS__) __attribute__((naked));                                                                  \
    returns name(__VA_ARGS__) {                                                                                        \
        asm("li a7, " #num "; ecall; ret");                                                                            \
    }
#elif defined(__x86_64__)
#define SYSCALL_DEF(num, enum, name, returns, ...)                                                                     \
    returns name(__VA_ARGS__) __attribute__((naked));                                                                  \
    returns name(__VA_ARGS__) {                                                                                        \
        asm("mov rax, " #num "; mov r10, rcx; syscall; ret");                                                          \
    }
#endif

#include "syscall_defs.inc"
