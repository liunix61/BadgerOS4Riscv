
// SPDX-License-Identifier: MIT

#include "interrupt.h"

#include "cpu/isr.h"
#include "cpulocal.h"



// Initialise interrupt drivers for this CPU.
void irq_init(isr_ctx_t *tmp_ctx) {
    // Install interrupt handler.
    asm volatile("csrw sstatus, 0");
    asm volatile("csrw stvec, %0" ::"r"(riscv_interrupt_vector_table));
    asm volatile("csrw sscratch, %0" ::"r"(tmp_ctx));

    // Disable all internal interrupts.
    asm volatile("csrw sie, 0");
}
