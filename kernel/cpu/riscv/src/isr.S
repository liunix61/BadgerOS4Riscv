
# SPDX-License-Identifier: MIT

#include "cpu/isr.h"
#include "cpu/regs.h"
#include "port/hardware.h"
    .global __global_pointer$
    .global memprotect_swap_from_isr
    .cfi_sections .debug_frame



#if __riscv_xlen == 64
#define ST_REG sd
#define LD_REG ld
#else
#define ST_REG sw
#define LD_REG lw
#endif

#define GET_REG_OFF(regname)  isr_ctx_t_regs+cpu_regs_t_##regname
#define SAVE_CFI_REG(regname) ST_REG regname, GET_REG_OFF(regname)(t0); .cfi_rel_offset %regname, GET_REG_OFF(regname)
#define REST_CFI_REG(regname) LD_REG regname, GET_REG_OFF(regname)(t0); .cfi_restore %regname



    # Entry code for an ISR or trap handler; save T0-T3 and swap out SP/GP/TP.
    # Assumes valid `isr_ctx_t *` in CSR scratch.
    .macro isr_entry
#pragma region
    .cfi_return_column 64
    .cfi_signal_frame
    .cfi_register 64, CSR_EPC
    
    # Save tempregs t0-t3.
    csrrw   t0, CSR_SCRATCH, t0
    .cfi_def_cfa t0, 0
    SAVE_CFI_REG(t1)
    csrrw   t1, CSR_SCRATCH, t0
    .cfi_def_cfa CSR_SCRATCH, 0
    ST_REG  t1, isr_ctx_t_regs+cpu_regs_t_t0(t0)
    .cfi_rel_offset t1, isr_ctx_t_regs+cpu_regs_t_t0
    
    SAVE_CFI_REG(t2)
    SAVE_CFI_REG(t3)
    
    # Save special regs.
    SAVE_CFI_REG(ra)
    SAVE_CFI_REG(sp)
    SAVE_CFI_REG(gp)
    SAVE_CFI_REG(tp)
    
    # Clear context to switch field.
    ST_REG  x0, isr_ctx_t_ctxswitch(t0)
    
    # Save PC.
    csrr    t1, CSR_EPC
    ST_REG  t1, isr_ctx_t_regs+cpu_regs_t_pc(t0)
    .cfi_rel_offset 64, isr_ctx_t_regs+cpu_regs_t_pc
    
#if !RISCV_M_MODE_KERNEL
    # Save SUM and MXR.
    LD_REG  t3, isr_ctx_t_flags(t0)
    li      t2, (1 << RISCV_STATUS_SUM_BIT) | (1 << RISCV_STATUS_MXR_BIT)
    or      t3, t3, t2
    csrrc   t1, sstatus, t2
    xor     t3, t3, t2
    and     t1, t1, t2
    or      t3, t3, t1
    ST_REG  t3, isr_ctx_t_flags(t0)
#endif
    
    # Set up special regs.
    li      tp, 0
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop
    LD_REG  t1, isr_ctx_t_flags(t0)
    andi    t1, t1, ISR_CTX_FLAG_KERNEL
    # For kernel threads, just use the thread's stack.
    bnez    t1, 1f
    # For user threads, use the memory allocated for the kernel stack.
    # This is safe even for syscalls because the ISR finishes before the stack is used.
    LD_REG  sp, isr_ctx_t_user_isr_stack(t0)
1:
#pragma endregion
    .endm



    # Exit code for an ISR or trap handler; restores tempregs and SP/GP/TP.
    # Assumes valid `isr_ctx_t *` in t0.
    .macro isr_exit
#pragma region
    # Restore PC.
    LD_REG  t1, isr_ctx_t_regs+cpu_regs_t_pc(t0)
    csrw    CSR_EPC, t1
    .cfi_restore CSR_EPC
    
#if !RISCV_M_MODE_KERNEL
    # Restore SUM and MXR.
    LD_REG  t1, isr_ctx_t_flags(t0)
    li      t2, (1 << RISCV_STATUS_SUM_BIT) | (1 << RISCV_STATUS_MXR_BIT)
    and     t1, t1, t2
    csrs    sstatus, t1
#endif
    
    # Restore special regs.
    LD_REG  ra, isr_ctx_t_regs+cpu_regs_t_ra(t0)
    .cfi_restore ra
    LD_REG  sp, isr_ctx_t_regs+cpu_regs_t_sp(t0)
    .cfi_restore sp
    LD_REG  gp, isr_ctx_t_regs+cpu_regs_t_gp(t0)
    .cfi_restore gp
    LD_REG  tp, isr_ctx_t_regs+cpu_regs_t_tp(t0)
    .cfi_restore tp
    
    # Restore tempregs t0-t3.
    LD_REG  t1, isr_ctx_t_regs+cpu_regs_t_t0(t0)
    csrw    CSR_SCRATCH, t1
    LD_REG  t3, isr_ctx_t_regs+cpu_regs_t_t3(t0)
    .cfi_restore t3
    LD_REG  t2, isr_ctx_t_regs+cpu_regs_t_t2(t0)
    .cfi_restore t2
    LD_REG  t1, isr_ctx_t_regs+cpu_regs_t_t1(t0)
    .cfi_restore t1
    csrrw   t0, CSR_SCRATCH, t0
    .cfi_restore t0
#pragma endregion
    .endm



    # Save all regs not saved by `isr_entry`.
    # Assumes valid `isr_ctx_t *` in t0.
    .macro save_all_regs
#pragma region
    SAVE_CFI_REG(s0)
    SAVE_CFI_REG(s1)
    SAVE_CFI_REG(a0)
    SAVE_CFI_REG(a1)
    SAVE_CFI_REG(a2)
    SAVE_CFI_REG(a3)
    SAVE_CFI_REG(a4)
    SAVE_CFI_REG(a5)
    SAVE_CFI_REG(a6)
    SAVE_CFI_REG(a7)
    SAVE_CFI_REG(s2)
    SAVE_CFI_REG(s3)
    SAVE_CFI_REG(s4)
    SAVE_CFI_REG(s5)
    SAVE_CFI_REG(s6)
    SAVE_CFI_REG(s7)
    SAVE_CFI_REG(s8)
    SAVE_CFI_REG(s9)
    SAVE_CFI_REG(s10)
    SAVE_CFI_REG(s11)
    SAVE_CFI_REG(t4)
    SAVE_CFI_REG(t5)
    SAVE_CFI_REG(t6)
#pragma endregion
    .endm



    # Restore all regs not restored by `isr_exit`.
    # Assumes valid `isr_ctx_t *` in t0.
    .macro restore_all_regs
#pragma region
    REST_CFI_REG(s0)
    REST_CFI_REG(s1)
    REST_CFI_REG(a0)
    REST_CFI_REG(a1)
    REST_CFI_REG(a2)
    REST_CFI_REG(a3)
    REST_CFI_REG(a4)
    REST_CFI_REG(a5)
    REST_CFI_REG(a6)
    REST_CFI_REG(a7)
    REST_CFI_REG(s2)
    REST_CFI_REG(s3)
    REST_CFI_REG(s4)
    REST_CFI_REG(s5)
    REST_CFI_REG(s6)
    REST_CFI_REG(s7)
    REST_CFI_REG(s8)
    REST_CFI_REG(s9)
    REST_CFI_REG(s10)
    REST_CFI_REG(s11)
    REST_CFI_REG(t4)
    REST_CFI_REG(t5)
    REST_CFI_REG(t6)
#pragma endregion
    .endm





    # Explicit context switch.
    # Interrupts must be disabled on entry and will be re-enabled on exit.
    # If the context switch target is not set, this is a NOP.
    .text
    .global isr_context_switch
    .type isr_context_switch, %function
    .align 2
    .cfi_startproc
isr_context_switch:
    # Check for context switch required.
    csrr    t0, CSR_SCRATCH
    LD_REG  t1, isr_ctx_t_ctxswitch(t0)
    bnez    t1, .isr_context_switch_do_switch
    
    # Re-enable interrupts.
    li      t1, 1 << CSR_STATUS_IE_BIT
    csrs    CSR_STATUS, t1
    ret
    
.isr_context_switch_do_switch:
    # Re-enable interrupts on exit.
    li      t1, 1 << CSR_STATUS_PIE_BIT
    csrs    CSR_STATUS, t1
    
    # Do the context switching things.
    # Save SP/GP/TP and PC.
    ST_REG  ra, isr_ctx_t_regs+cpu_regs_t_pc(t0)
    ST_REG  ra, isr_ctx_t_regs+cpu_regs_t_ra(t0)
    ST_REG  sp, isr_ctx_t_regs+cpu_regs_t_sp(t0)
    ST_REG  gp, isr_ctx_t_regs+cpu_regs_t_gp(t0)
    ST_REG  tp, isr_ctx_t_regs+cpu_regs_t_tp(t0)
    save_all_regs
    
    # Save SUM and MXR.
#if !RISCV_M_MODE_KERNEL
    LD_REG  t3, isr_ctx_t_flags(t0)
    li      t2, (1 << RISCV_STATUS_SUM_BIT) | (1 << RISCV_STATUS_MXR_BIT)
    or      t3, t3, t2
    csrrc   t1, sstatus, t2
    xor     t3, t3, t2
    and     t1, t1, t2
    or      t3, t3, t1
    ST_REG  t3, isr_ctx_t_flags(t0)
#endif
    
    # Switch context and set new privilege.
    LD_REG  t0, isr_ctx_t_ctxswitch(t0)
    csrw    CSR_SCRATCH, t0
    
    # Swap memory protection.
    jal     memprotect_swap_from_isr
    csrr    t0, CSR_SCRATCH
    LD_REG  t1, isr_ctx_t_flags(t0)
    andi    t1, t1, ISR_CTX_FLAG_KERNEL
    li      t2, CSR_STATUS_PP_MASK << CSR_STATUS_PP_BASE_BIT
    bnez    t1, .isr_context_switch_do_k
    
    # To user mode.
    csrc    CSR_STATUS, t2
    j       .isr_context_switch_ret
    
.isr_context_switch_do_k:
    # To kernel mode.
    csrs    CSR_STATUS, t2
    
.isr_context_switch_ret:
    # Return to new context.
    restore_all_regs
    isr_exit
#pragma endregion
    RISCV_TRAP_RET
    .cfi_endproc





    # Trap and interrupt handler.
    .text
    .type __trap_asm, %function
    .align 2
    .cfi_startproc
__trap_asm:
    isr_entry
    save_all_regs
    
    # Construct fake stack frame for kernel backtrace.
    csrr    ra, CSR_EPC
    addi    sp, sp, -16
#if __riscv_xlen == 64
    sd      ra, 8(sp)
    sd      s0, 0(sp)
#else
    sw      ra, 12(sp)
    sw      s0, 8(sp)
#endif
    addi    s0, sp, 16
    ST_REG  s0, isr_ctx_t_frameptr(t0)
    mv      s1, t0
    .cfi_def_cfa s1, 0
    
    # Most of the trap handler is implemented in C.
    jal     riscv_trap_handler
    csrr    t0, CSR_SCRATCH
    .cfi_def_cfa CSR_SCRATCH, 0
    
    # Discard fake stack frame.
    addi    sp, sp, 16
    
    # Check for outstanding context switch.
    # If nonnull, context will be switched.
    LD_REG  t1, isr_ctx_t_ctxswitch(t0)
    beq     t1, x0, 2f
    # Swap out the context pointer.
    csrr    t0, CSR_SCRATCH
    LD_REG  t0, isr_ctx_t_ctxswitch(t0)
    csrw    CSR_SCRATCH, t0
    # Swap memory protection.
    jal     memprotect_swap_from_isr
    csrr    t0, CSR_SCRATCH
    # Set privilege level.
    LD_REG  t2, isr_ctx_t_flags(t0)
    andi    t2, t2, ISR_CTX_FLAG_KERNEL
    li      t3, CSR_STATUS_PP_MASK << CSR_STATUS_PP_BASE_BIT
    bnez    t2, 1f
    # Zero; user thread; clear xPP.
    csrc    CSR_STATUS, t3
    j       2f
1:
    # Nonzero; kernel thread; set xPP.
    csrs    CSR_STATUS, t3
    
2:
    restore_all_regs
    isr_exit
#pragma endregion
    RISCV_TRAP_RET
    .cfi_endproc
    .size __trap_asm, .-__trap_asm





    # Interrupt vector table for the CPU.
    # This must be aligned to a 256-byte boundary, so it is in a special section.
    .section ".interrupt_vector_table", "ax", @progbits
    .global riscv_interrupt_vector_table
riscv_interrupt_vector_table:
    .option push
    .option norvc
    # Trap handler.
    j __trap_asm
    # Interrupt handlers.
    .rept RISCV_VT_INT_COUNT
    j __trap_asm
    .endr
    # Padding.
#if RISCV_VT_PADDING
    .skip RISCV_VT_PADDING*4
#endif
    .option pop
#pragma endregion
