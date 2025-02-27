
// SPDX-License-Identifier: MIT

#include "panic.h"

void cpu_panic_poweroff() {
    asm volatile("cli");
    while (1) asm volatile("hlt");
}
