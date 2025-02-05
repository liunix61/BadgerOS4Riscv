
// SPDX-License-Identifier: MIT

#include "isr_ctx.h"
#include "scheduler/types.h"



// Helper function that swaps from user to kernel ISR context on syscall.
void amd64_syscall_raise() {
    isr_ctx_t *cur  = isr_ctx_get();
    isr_ctx_t *next = &cur->thread->kernel_isr_ctx;
}
