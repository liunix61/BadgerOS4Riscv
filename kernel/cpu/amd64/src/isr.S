
# SPDX-License-Identifier: MIT

#include "cpu/isr.h"
#include "cpu/regs.h"
#include "cpu/msr.h"
#include "port/hardware.h"
    // .cfi_sections .debug_frame
    .intel_syntax





    # Macro for IRQs with error codes.
    .macro irq_ec index
    .type __amd64_irq_\index, %function
__amd64_irq_\index:
    push \index
    jmp  __amd64_irq
    .size __amd64_irq_\index, .-__amd64_irq_\index
    .endm



    # Macro for IRQs without error codes.
    .macro irq_noec index
    .type __amd64_irq_\index, %function
__amd64_irq_\index:
    push 0
    push \index
    jmp  __amd64_irq
    .size __amd64_irq_\index, .-__amd64_irq_\index
    .endm



    # Macro for saving a single GPR.
    .macro save_reg name
    mov [%gs:isr_ctx_t_regs+cpu_regs_t_\name], %\name
    .endm



    # Macro for restoring a single GPR.
    .macro restore_reg name
    mov %\name, [%gs:isr_ctx_t_regs+cpu_regs_t_\name]
    .endm



    # Macro for saving general-purpose registers.
    .macro save_gprs
    save_reg rax
    save_reg rbx
    save_reg rcx
    save_reg rdx
    save_reg rsi
    save_reg rdi
    save_reg rbp
    save_reg r8
    save_reg r9
    save_reg r10
    save_reg r11
    save_reg r12
    save_reg r13
    save_reg r14
    save_reg r15
    .endm



    # Macro for restoring general-purpose registers.
    .macro restore_gprs
    restore_reg rax
    restore_reg rbx
    restore_reg rcx
    restore_reg rdx
    restore_reg rsi
    restore_reg rdi
    restore_reg rbp
    restore_reg r8
    restore_reg r9
    restore_reg r10
    restore_reg r11
    restore_reg r12
    restore_reg r13
    restore_reg r14
    restore_reg r15
    .endm





    # Explicit context switch.
    # Interrupts must be disabled on entry and will be re-enabled on exit.
    # If the context switch target is not set, this is a NOP.
    .text
    .global isr_context_switch
    .type isr_context_switch, %function
isr_context_switch:
    mov  %rax, [%gs:isr_ctx_t_ctxswitch]
    cmp  %rax, 0
    jnz  1f
    
    # No switch target, re-enable interrupts and return.
    sti
    ret
1:
    # Save registers.
    # We know the caller to be kernel code,
    # so there is no need to save the segment registers.
    save_gprs
    
    # Save special regs.
    mov  %rdi, [%rsp]
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_rip], %rdi
    mov  %rdi, %cs
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_cs], %rdi
    pushf
    pop  %rdi
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_rflags], %rdi
    add  %rdi, %rsp, 8
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_rsp], %rdi
    mov  %rdi, %ss
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_ss], %rdi
    
    # Write GSBASE to switch contexts.
    jz   1f
    shr  %rdx, %rax, 32
    mov  %ecx, MSR_GSBASE
    wrmsr
    
    # Write KGSBASE, which is either the ISR context or the thread pointer.
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_gsbase]
    shr  %rdx, %rax, 32
    mov  %ecx, MSR_KGSBASE
    wrmsr
    
    # Transfer special regs from ISR context to interrupt frame.
    sub  %rsp, 40
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_rip]
    mov  [%rsp+amd64_irqframe_t_rip], %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_cs]
    mov  [%rsp+amd64_irqframe_t_cs], %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_rflags]
    mov  [%rsp+amd64_irqframe_t_rflags], %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_rsp]
    mov  [%rsp+amd64_irqframe_t_rsp], %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_ss]
    mov  [%rsp+amd64_irqframe_t_ss], %rax
    
    restore_gprs
    swapgs
    iretq
    





    # Trap and interrupt call handler.
    .text
    .type __trap_asm, %function
__amd64_irq:
    swapgs
    
    # Save segment registers and set them to 0.
    push %rax
    push %rbx
    xor  %rbx, %rbx
    
    mov  %ax, %gs
    mov  %gs, %rbx
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_gs], %ax
    mov  %ds, %rbx
    mov  %ax, %ds
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_ds], %ax
    mov  %es, %rbx
    mov  %ax, %es
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_es], %ax
    mov  %fs, %rbx
    mov  %ax, %fs
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_fs], %ax
    
    pop  %rbx
    pop  %rax
    
    # Save general-purpose registers.
    save_gprs
    
    # Transfer special regs from interrupt frame to ISR context.
    mov  %rax, [%rsp+16+amd64_irqframe_t_rip]
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_rip], %rax
    mov  %rax, [%rsp+16+amd64_irqframe_t_cs]
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_cs], %rax
    mov  %rax, [%rsp+16+amd64_irqframe_t_rflags]
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_rflags], %rax
    mov  %rax, [%rsp+16+amd64_irqframe_t_rsp]
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_rsp], %rax
    mov  %rax, [%rsp+16+amd64_irqframe_t_ss]
    mov  [%gs:isr_ctx_t_regs+cpu_regs_t_ss], %rax
    
    # Call C handler.
    mov  %rdi, [%rsp+0]
    mov  %rsi, [%rsp+8]
    call amd64_trap_handler
    
    # Check for context switch.
    mov  %rax, [%gs:isr_ctx_t_ctxswitch]
    cmp  %rax, 0
    
    # Write GSBASE to switch contexts.
    jz   1f
    shr  %rdx, %rax, 32
    mov  %ecx, MSR_GSBASE
    wrmsr
    
    # Write KGSBASE, which is either the ISR context or the thread pointer.
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_gsbase]
    shr  %rdx, %rax, 32
    mov  %ecx, MSR_KGSBASE
    wrmsr
1:
    # Transfer special regs from ISR context to interrupt frame.
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_rip]
    mov  [%rsp+16+amd64_irqframe_t_rip], %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_cs]
    mov  [%rsp+16+amd64_irqframe_t_cs], %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_rflags]
    mov  [%rsp+16+amd64_irqframe_t_rflags], %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_rsp]
    mov  [%rsp+16+amd64_irqframe_t_rsp], %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_ss]
    mov  [%rsp+16+amd64_irqframe_t_ss], %rax
    
    # Restore general-purpose registers.
    restore_gprs
    
    # Restore segment registers.
    push %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_ds]
    mov  %ds, %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_es]
    mov  %es, %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_fs]
    mov  %fs, %rax
    mov  %rax, [%gs:isr_ctx_t_regs+cpu_regs_t_gs]
    mov  %gs, %rax
    pop  %rax
    
    # Return from interrupt.
    add %rsp, 16
    swapgs
    iretq





    # IRQ stubs.
    .text
    irq_noec 0
    irq_noec 1
    irq_noec 2
    irq_noec 3
    irq_noec 4
    irq_noec 5
    irq_noec 6
    irq_noec 7
    irq_ec 8
    irq_noec 9
    irq_ec 10
    irq_ec 11
    irq_ec 12
    irq_ec 13
    irq_ec 14
    irq_noec 15
    irq_noec 16
    irq_ec 17
    irq_noec 18
    irq_noec 19
    irq_noec 20
    irq_ec 21
    irq_noec 22
    irq_noec 23
    irq_noec 24
    irq_noec 25
    irq_noec 26
    irq_noec 27
    irq_noec 28
    irq_ec 29
    irq_ec 30
    irq_noec 31
    
    # Stubs for platform-specific IRQs.
    .rept 256
    .if \+ >= 32
    irq_noec \+
    .endif
    .endr





    # Pointers to IRQ stubs.
    .global idt_stubs
    .data
idt_stubs:
    .rept 256
    .8byte __amd64_irq_\+
    .endr

    .global idt_stubs_len
idt_stubs_len:
    .8byte 256
