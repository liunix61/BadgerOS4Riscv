
// SPDX-License-Identifier: MIT

#include "backtrace.h"

#include "attributes.h"
#include "isr_ctx.h"
#include "rawprint.h"

#include <stddef.h>

#ifndef BACKTRACE_DEPTH
#define BACKTRACE_DEPTH 32
#endif



// Given stack frame pointer, perform backtrace.
void backtrace_from_ptr(void *frame_pointer) {
    rawprint("**** BEGIN BACKRTACE ****\n");
    // Prev RBP offset: 0 words
    // Prev RIP offset: 1 word
    atomic_thread_fence(memory_order_acquire);
    size_t *fp = frame_pointer;
    for (int i = 0; i < BACKTRACE_DEPTH; i++) {
        size_t ra;
        if ((size_t)fp < 0x1000 || isr_noexc_copy_size(&ra, fp + 1)) {
            break;
        }
        rawprint("0x");
        rawprinthex(ra, sizeof(size_t) * 2);
        rawputc('\n');
        if ((size_t)fp < 0x1000 || isr_noexc_copy_size((size_t *)&fp, fp)) {
            break;
        }
    }
    rawprint("**** END BACKRTACE ****\n");
}

// Perform backtrace as called.
void backtrace() NAKED;
void backtrace() {
    // clang-format off
    asm volatile(
        "mov %rdi, %rbp;"
        "jmp backtrace_from_ptr;"
    );
    // clang-format on
}
