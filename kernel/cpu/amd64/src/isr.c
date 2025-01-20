
// SPDX-License-Identifier: MIT

#include "cpu/isr.h"

#include "backtrace.h"
#include "cpu/isr_ctx.h"
#include "interrupt.h"
#include "log.h"
#include "panic.h"
#include "port/hardware.h"
#include "process/internal.h"
#include "process/sighandler.h"
#include "process/types.h"
#include "rawprint.h"
#include "scheduler/cpu.h"
#include "scheduler/types.h"
#if MEMMAP_VMEM
#include "cpu/mmu.h"
#include "memprotect.h"
#endif



// Trap names.
static char const *const trapnames[] = {
    "Division error",
    "Debug trap",
    "Non-maskable interrupt",
    "Breakpoint",
    "Overflow",
    "Bound range exceeded",
    "Invalid opcode",
    "Device not available",
    "Double fault",
    NULL, // Coprocessor segment overrun.
    "Invalid TSS",
    "Segment not present",
    "Stack-segment fault",
    "General protection fault",
    "Page fault",
    NULL, // Reserved.
    NULL, // x87 FP exception.
    NULL, // Alignment check.
    "Machine check",
    "SIMD floating-point exception",
    NULL, // Virtualization exception.
    "Control protection exception",
    NULL, // Reserved.
    NULL, // Reserved.
    NULL, // Reserved.
    NULL, // Reserved.
    NULL, // Reserved.
    NULL, // Reserved.
    NULL, // Hypervisor injection exception.
    "VMM communication exception",
    "Security exception",
};
enum { TRAPNAMES_LEN = sizeof(trapnames) / sizeof(trapnames[0]) };

// Kill a process from a trap / ISR.
static void kill_proc_on_trap() {
    proc_exit_self(-1);
    irq_disable();
    sched_lower_from_isr();
    isr_context_switch();
    __builtin_unreachable();
}

// Called from ASM on non-system call trap.
void amd64_trap_handler(size_t trapno, size_t error_code) {
    isr_ctx_t *kctx = isr_ctx_get();

    if (trapno < TRAPNAMES_LEN && trapnames[trapno]) {
        rawprint(trapnames[trapno]);
    } else {
        rawprint("Exception 0x");
        rawprinthex(trapno, 2);
    }
    rawprint(" at PC 0x");
    rawprinthex(kctx->regs.rip, 16);
    rawputc('\n');

    // TODO: Memory addresses.

    bool is_k = kctx->regs.rflags;
    rawprint("Running in ");
    rawprint(is_k ? "kernel mode" : "user mode");
    if (is_k != !!(kctx->flags & ISR_CTX_FLAG_KERNEL)) {
        rawprint(" (despite is_kernel_thread=");
        rawputc((kctx->flags & ISR_CTX_FLAG_KERNEL) ? '1' : '0');
        rawputc(')');
    }
    rawputc('\n');

    backtrace_from_ptr(kctx->frameptr);

    isr_ctx_dump(kctx);

    // if (is_k || error_code == 8) {
    // When the kernel traps it's a bad time.
    panic_poweroff();
    // } else {
    //     // When the user traps just stop the process.
    //     sched_raise_from_isr(kctx->thread, false, kill_proc_on_trap);
    // }
    // isr_ctx_swap(kctx);
}

// Return a value from the syscall handler.
void syscall_return(long long value) {
    sched_thread_t *thread = isr_ctx_get()->thread;
    isr_ctx_t      *usr    = &thread->user_isr_ctx;

    usr->regs.rax = value;
    usr->regs.rip = usr->regs.rcx;

    if (proc_signals_pending_raw(thread->process)) {
        proc_signal_handler();
    }
    irq_disable();
    sched_lower_from_isr();
    isr_context_switch();
    __builtin_unreachable();
}
