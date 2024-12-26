
// SPDX-License-Identifier: MIT

#include "cpu/riscv.h"
#include "interrupt.h"
#include "log.h"
#include "panic.h"

#ifdef CPU_RISCV_ENABLE_SBI_TIME
// Called by the interrupt handler when the CPU-local timer fires.
void riscv_sbi_timer_interrupt();
#endif

// Interrupt handler for the INTC to forward external interrupts to.
void (*intc_ext_irq_handler)();

void riscv_interrupt_handler() {
    long cause;
    asm("csrr %0, " CSR_CAUSE_STR : "=r"(cause));

    long int_no = cause & RISCV_VT_ICAUSE_MASK;

    if (int_no == RISCV_INT_SUPERVISOR_EXT) {
        intc_ext_irq_handler();
#ifdef CPU_RISCV_ENABLE_SBI_TIME
    } else if (int_no == RISCV_INT_SUPERVISOR_TIMER) {
        asm("csrc sie, %0" ::"r"(1 << RISCV_INT_SUPERVISOR_TIMER));
        riscv_sbi_timer_interrupt();
#endif
    } else {
        logkf_from_isr(LOG_FATAL, "Unhandled interrupt 0x%{long;x}", cause);
        panic_abort();
    }
}
