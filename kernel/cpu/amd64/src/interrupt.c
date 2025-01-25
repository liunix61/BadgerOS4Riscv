
// SPDX-License-Identifier: MIT

#include "interrupt.h"

#include "cpu/isr.h"
#include "cpu/msr.h"
#include "cpu/priv_level.h"
#include "cpu/segmentation.h"
#include "cpulocal.h"



// BSP global descriptor table.
static uint64_t bsp_gdt[] = {
    0,
    // Entry 1 is for kernel code.
    GDT_FLAG_L | GDT_ACCESS_E | GDT_ACCESS_S | GDT_ACCESS_RW | GDT_ACCESS_P,
    // Entry 2 is for kernel data.
    GDT_ACCESS_S | GDT_ACCESS_RW | GDT_ACCESS_P,
    // Entry 3 is for user code.
    GDT_FLAG_L | GDT_ACCESS_E | GDT_ACCESS_S | GDT_ACCESS_RW | GDT_ACCESS_P | (PRIV_USER << GDT_ACCESS_DPL_BASE),
    // Entry 4 is for user data.
    GDT_ACCESS_S | GDT_ACCESS_RW | GDT_ACCESS_P | (PRIV_USER << GDT_ACCESS_DPL_BASE),
    // Entry 5 is empty.
    0,
    // Entry 6 is the TSS.
    GDT_ACCESS_A | GDT_ACCESS_E | GDT_ACCESS_P,
    // Entry 7 is the 32 MSB of TSS address.
    0,
};

// Interrupt descriptor table.
static x86_idtent_t idt[256] = {};

// Set up the GDT in BadgerOS-owned memory.
void x86_setup_gdt() {
    struct PACKED {
        uint16_t size;
        void    *addr;
    } gdtr = {
        sizeof(bsp_gdt) - 1,
        bsp_gdt,
    };
    asm volatile("lgdt [%0]" ::"m"(gdtr));
}

// Set up the IDT in BadgerOS-owned memory.
void x86_setup_idt() {
    struct PACKED {
        uint16_t size;
        void    *addr;
    } idtr = {
        256 * sizeof(x86_idtent_t) - 1,
        idt,
    };
    asm volatile("lidt [%0]" ::"m"(idtr));
}

// Reload the segment registers.
void x86_reload_segments() NAKED;
void x86_reload_segments() {
    // Load the global descriptor table and update segment registers.
    // clang-format off
    asm volatile(
        "pushq %0;"
        "lea rax, [1f];"
        "push rax;"
        "retfq;"
        "1:;"
        "mov ax, %1;"
        "mov ss, ax;"
        "xor rax, rax;"
        "mov ds, ax;"
        "mov es, ax;"
        "mov fs, ax;"
        "mov gs, ax;"
        "ret;"
        ::
        "i"(FORMAT_SEGMENT(SEGNO_KCODE, 0, PRIV_KERNEL)),
        "i"(FORMAT_SEGMENT(SEGNO_KDATA, 0, PRIV_KERNEL))
        :
        "rax", "memory"
    );
    // clang-format on
}



// BSP TSS.
static uint8_t bsp_tss[TSS_SIZE];

// BSP CPU-local data.
static cpulocal_t bsp_cpulocal = {
    .arch.tss = &bsp_tss,
};

// Temporary interrupt context before scheduler.
static isr_ctx_t tmp_ctx = {
    .flags       = ISR_CTX_FLAG_KERNEL,
    .regs.cs     = FORMAT_SEGMENT(SEGNO_KCODE, 0, PRIV_KERNEL),
    .regs.ss     = FORMAT_SEGMENT(SEGNO_KDATA, 0, PRIV_KERNEL),
    .regs.rflags = RFLAGS_AC,
    .cpulocal    = &bsp_cpulocal,
};

// Array of IDT handler stubs.
extern size_t const idt_stubs[];
// Number of IDT handler stubs.
extern size_t const idt_stubs_len;

// Initialise interrupt drivers for this CPU.
void irq_init() {
    // TODO: Fill in addresses for TSS entry.
    // Set up GDT for booting CPU.
    x86_setup_gdt();
    x86_reload_segments();

    // Fill in the TSS address, which isn't possible at compile time.
    size_t tss_addr  = (size_t)&bsp_tss;
    bsp_gdt[6]      |= GDT_BASE(tss_addr);
    bsp_gdt[7]      |= tss_addr >> 32;

    // Load the TSS.
    asm volatile("ltr %0" ::"r"((uint16_t)FORMAT_SEGMENT(6, 0, PRIV_KERNEL)));

    // Set up IDT handlers.
    for (size_t i = 0; i < idt_stubs_len; i++) {
        idt[i] = FORMAT_IDTENT((size_t)idt_stubs[i], FORMAT_SEGMENT(SEGNO_KCODE, 0, PRIV_KERNEL), PRIV_KERNEL, 0, 0);
    }
    // Load the IDT.
    x86_setup_idt();

    // Set GSBASE to the address of the ISR context.
    msr_write(MSR_GSBASE, (uint64_t)&tmp_ctx);
    msr_write(MSR_KGSBASE, (uint64_t)&tmp_ctx);
}



// Enable the IRQ.
void irq_ch_enable(int irq) {
}

// Disable the IRQ.
void irq_ch_disable(int irq) {
}

// Query whether the IRQ is enabled.
bool irq_ch_is_enabled(int irq) {
    return false;
}
