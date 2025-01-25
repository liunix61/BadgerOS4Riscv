
// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>



// Division Error
#define X86_EXC_DE 0x0
// Debug
#define X86_EXC_DB 0x1
// Breakpoint
#define X86_EXC_BP 0x3
// Overflow
#define X86_EXC_OF 0x4
// Bound Range Exceeded
#define X86_EXC_BR 0x5
// Invalid Opcode
#define X86_EXC_UD 0x6
// Device Not Available
#define X86_EXC_NM 0x7
// Double Fault
#define X86_EXC_DF 0x8
// Invalid TSS
#define X86_EXC_TS 0xA
// Segment Not Present
#define X86_EXC_NP 0xB
// Stack-Segment Fault
#define X86_EXC_SS 0xC
// General Protection Fault
#define X86_EXC_GP 0xD
// Page Fault
#define X86_EXC_PF 0xE
// x87 Floating-Point Exception
#define X86_EXC_MF 0x10
// Alignment Check
#define X86_EXC_AC 0x11
// Machine Check
#define X86_EXC_MC 0x12
// SIMD Floating-Point Exception
#define X86_EXC_XM 0x13
// Virtualization Exception
#define X86_EXC_VE 0x14
// Control Protection Exception
#define X86_EXC_CP 0x15
// Hypervisor Injection Exception
#define X86_EXC_HV 0x1C
// VMM Communication Exception
#define X86_EXC_VC 0x1D
// Security Exception
#define X86_EXC_SX 0x1E

// AMD64 IDT entry.
typedef __uint128_t x86_idtent_t;

// IDT entry flag: Present.
#define IDT_FLAG_P         ((__uint128_t)1 << 47)
// IDT entry flag: Privilege levels that are allowed to call this interrupt.
#define IDT_FLAG_DPL_BASE  45
// IDT entry flag: Privilege levels that are allowed to call this interrupt.
#define IDT_FLAG_DPL_MASK  ((__uint128_t)3 << IDT_FLAG_DPL_MASK)
// IDT entry flag: Gate type.
#define IDT_FLAG_GATE_MASK ((__uint128_t)15 << 40)
// Gate type: Interrupt gate.
#define IDT_FLAG_GATE_INT  ((__uint128_t)14 << 40)
// Gate type: Trap gate.
#define IDT_FLAG_GATE_TRAP ((__uint128_t)15 << 40)
// IDT entry field: Interrupt stack table.
#define IDT_FLAG_IST_BASE  32
// IDT entry field: Interrupt stack table.
#define IDT_FLAG_IST_MASK  ((__uint128_t)15 << IDT_FLAG_IST_BASE)

// Format an IDT entry.
#define FORMAT_IDTENT(offset, segment, priv, is_int, ist)                                                              \
    (IDT_FLAG_P | ((priv) << IDT_FLAG_DPL_BASE) | ((segment) << 16) | ((offset) & 0xffff) |                            \
     (((__uint128_t)(offset) & 0xffffffffffff0000) << 32) | (is_int ? IDT_FLAG_GATE_INT : IDT_FLAG_GATE_TRAP))



// Enable interrupts if a condition is met.
static inline void irq_enable_if(bool enable) {
    // TODO.
    (void)enable;
}

// Disable interrupts if a condition is met.
static inline void irq_disable_if(bool disable) {
    // TODO.
    (void)disable;
}

// Enable interrupts.
static inline void irq_enable() {
    // TODO.
}

// Disable interrupts.
// Returns whether interrupts were enabled.
static inline bool irq_disable() {
    // TODO.
    return 0;
}

// Query whether interrupts are enabled in this CPU.
static inline bool irq_is_enabled() {
    // TODO.
    return 0;
}
