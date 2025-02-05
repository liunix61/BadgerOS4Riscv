
# SPDX-License-Identifier: MIT

#include "cpu/isr_ctx.h"
    .intel_syntax



    .text
    .align 2
    .global amd64_syscall_entry
    # The entrypoint of AMD64 system calls; sets up some registers and transfers control to C.
    # Syscall has saved RFLAGS to R11 and saves the next instruction's address to RCX.
    # Because RCX is not available for the SYSV ABI, R10 is used instead.
amd64_syscall_entry:
    # Use swapgs to get access to the ISR context.
    swapgs
    
    # Save RIP, RSP and RFLAGS.
    mov [%gs:isr_ctx_t_regs+cpu_regs_t_rip], %rcx
    mov [%gs:isr_ctx_t_regs+cpu_regs_t_rsp], %rsp
    mov [%gs:isr_ctx_t_regs+cpu_regs_t_rflags], %r11
    
    # Move R10 back into RCX so we can directly call the syscall impl.
    mov %rcx, %r10
    
    # Swap context to the kernel one and re-enable interrupts.
    call amd64_syscall_raise
    # sti
