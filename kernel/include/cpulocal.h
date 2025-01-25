
// SPDX-License-Identifier: MIT

#pragma once

#include "cpu/arch_cpulocal.h"
#include "scheduler/scheduler.h"
#include "time_private.h"

#include <stddef.h>



// CPU-local data.
typedef struct {
    // Current CPU ID.
    size_t            cpuid;
    // Current SMP CPU inder.
    int               cpu;
    // ISR stack top.
    size_t            isr_stack_top;
    // ISR stack bottom.
    size_t            isr_stack_bottom;
    // CPU-local scheduler data.
    sched_cpulocal_t *sched;
    // CPU-local timer data.
    time_cpulocal_t   time;
    // Arch-specific CPU-local data.
    arch_cpulocal_t   arch;
} cpulocal_t;

// Per-CPU CPU-local data.
extern cpulocal_t *cpulocal;
