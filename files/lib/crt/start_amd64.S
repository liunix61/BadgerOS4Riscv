
# SPDX-License-Identifier: MIT

#include "syscall.h"

    .global main
    .intel_syntax



    .global _start
    .text
    .p2align 1
_start:
    lea  %rsp, stack_top[%rip]
    xor  %ebp, %ebp
    
    # Set signal handler return trampoline.
    xor  %edi, %edi
    lea  %rsi, sigret_trampoline[%rip]
    call syscall_proc_sighandler
    
    # TODO: argc and argv.
    
    # Call main function.
    call main
    
    # Run exit syscall if main returns.
    mov  %rdi, %rax
    jmp  syscall_proc_exit



sigret_trampoline:
    jmp  syscall_proc_sigret



    # Main stack.
    .section ".bss"
stack_bottom:
    .zero 1024
stack_top:
