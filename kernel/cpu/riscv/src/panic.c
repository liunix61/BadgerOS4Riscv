
// SPDX-License-Identifier: MIT

#include "panic.h"

#include "cpu/regs.h"

void cpu_panic_poweroff() {
    asm volatile("csrci " CSR_STATUS_STR ", %0" ::"ri"(1 << CSR_STATUS_IE_BIT));
    while (1) asm volatile("wfi");
}
