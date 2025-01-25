
// SPDX-License-Identifier: MIT

#include "interrupt.h"

#include "cpu/isr.h"
#include "cpulocal.h"



// BSP CPU-local data.
static cpulocal_t bsp_cpulocal = {0};

// Temporary interrupt context before scheduler.
static isr_ctx_t tmp_ctx = {
    .flags    = ISR_CTX_FLAG_KERNEL,
    .cpulocal = &bsp_cpulocal,
};

// Initialise interrupt drivers for this CPU.
void irq_init() {
    // Install interrupt handler.
    asm volatile("csrw sstatus, 0");
    asm volatile("csrw stvec, %0" ::"r"(riscv_interrupt_vector_table));
    asm volatile("csrw sscratch, %0" ::"r"(&tmp_ctx));

    // Disable all internal interrupts.
    asm volatile("csrw sie, 0");
}
