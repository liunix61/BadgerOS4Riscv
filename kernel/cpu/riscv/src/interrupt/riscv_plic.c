
// SPDX-License-Identifier: MIT

#include "cpu/interrupt/riscv_plic.h"

#include "assertions.h"
#include "cpu/interrupt/riscv_intc.h"
#include "driver.h"
#include "interrupt.h"
#include "malloc.h"
#include "memprotect.h"
#include "smp.h"

#define REG_READ(addr)       (*(uint32_t const volatile *)(addr))
#define REG_WRITE(addr, val) (*(uint32_t volatile *)(addr) = (val))
#define REG_SET_BIT(addr, bitno)                                                                                       \
    ({                                                                                                                 \
        size_t   atmp = (addr);                                                                                        \
        uint32_t mask = 1ul << (bitno);                                                                                \
        REG_WRITE(atmp, REG_READ(atmp) | mask);                                                                        \
    })
#define REG_CLEAR_BIT(addr, bitno)                                                                                     \
    ({                                                                                                                 \
        size_t   atmp = (addr);                                                                                        \
        uint32_t mask = 1ul << (bitno);                                                                                \
        REG_WRITE(atmp, REG_READ(atmp) & ~mask);                                                                       \
    })



// PLIC context descriptor.
typedef struct {
    // HART ID of target CPU.
    size_t  hartid;
    // Target CPU interrupt number.
    uint8_t irq;
} plic_ctx_t;

// PLIC base address.
static size_t      plic_base;
// Number of PLIC contexts.
static uint16_t    plic_ctx_count;
// PLIC contexts.
static plic_ctx_t *plic_ctx;
// PLIC context to use per SMP CPU.
static uint16_t   *plic_smp_ctx;

// Generic interrupt handler that runs all callbacks on an IRQ.
void generic_interrupt_handler(int irq);


// Enable an interrupt for a specific CPU.
void irq_ch_enable_affine(int irq, int cpu_index) {
    assert_dev_drop(irq > 0);
    uint16_t ctx = plic_smp_ctx[cpu_index];
    REG_SET_BIT(PLIC_ENABLE_OFF(ctx) + irq / 32 * 4 + plic_base, irq % 32);
}

// Disable an interrupt for a specific CPU.
void irq_ch_disable_affine(int irq, int cpu_index) {
    assert_dev_drop(irq > 0);
    uint16_t ctx = plic_smp_ctx[cpu_index];
    REG_CLEAR_BIT(PLIC_ENABLE_OFF(ctx) + irq / 32 * 4 + plic_base, irq % 32);
}

// Enable the IRQ.
void irq_ch_enable(int irq) {
    for (int i = 0; i < smp_count; i++) {
        irq_ch_enable_affine(irq, i);
    }
}

// Disable the IRQ.
void irq_ch_disable(int irq) {
    for (int i = 0; i < smp_count; i++) {
        irq_ch_disable_affine(irq, i);
    }
}

// Query whether the IRQ is enabled.
bool irq_ch_is_enabled(int irq) {
    return false;
}



// PLIC interrupt handler.
void plic_interrupt_handler() {
    uint16_t local_ctx = plic_smp_ctx[smp_cur_cpu()];
    uint32_t irq       = REG_READ(PLIC_CLAIM_OFF(local_ctx) + plic_base);
    if (irq) {
        generic_interrupt_handler(irq);
    }
}



// Init PLIC driver from DTB.
static void plic_dtb_init(dtb_handle_t *dtb, dtb_node_t *node, uint32_t addr_cells, uint32_t size_cells) {
    (void)addr_cells;
    (void)size_cells;
    // Read PLIC properties.
    size_t paddr = dtb_read_cells(dtb, node, "reg", 0, addr_cells);
    size_t size  = dtb_read_cells(dtb, node, "reg", addr_cells, size_cells);
    assert_always(dtb_read_uint(dtb, node, "#address-cells") == 0);
    assert_always(dtb_read_uint(dtb, node, "#interrupt-cells") == 1);

    // Read interrupt mappings.
    dtb_prop_t *int_ext = dtb_get_prop(dtb, node, "interrupts-extended");
    plic_ctx_count      = int_ext->content_len / 8;
    plic_ctx            = malloc(plic_ctx_count * sizeof(plic_ctx_t));
    plic_smp_ctx        = malloc(sizeof(uint16_t) * smp_count);

    // Read interrupt context mappings.
    for (uint16_t i = 0; i < plic_ctx_count; i++) {
        uint32_t    phandle = dtb_prop_read_cell(dtb, int_ext, i * 2);
        dtb_node_t *ictl    = dtb_phandle_node(dtb, phandle);
        if (!ictl) {
            logkf(LOG_ERROR, "Unable to find interrupt controller %{u32;d}", phandle);
            continue;
        }
        plic_ctx[i].irq  = dtb_prop_read_cell(dtb, int_ext, i * 2 + 1);
        dtb_node_t *cpu  = ictl->parent;
        dtb_node_t *cpus = cpu->parent;
        if (!cpu) {
            logkf(LOG_ERROR, "Unable to find CPU for interrupt controller %{u32;d}", phandle);
        } else {
            uint32_t cpu_acell = dtb_read_uint(dtb, cpus, "#address-cells");
            size_t   cpu_id    = dtb_read_cells(dtb, cpu, "reg", 0, cpu_acell);
            plic_ctx[i].hartid = cpu_id;
        }
    }

    // Create PLIC to SMP CPU mappings.
    for (uint16_t i = 0; i < plic_ctx_count; i++) {
        if (plic_ctx[i].irq == RISCV_INT_SUPERVISOR_EXT) {
            plic_smp_ctx[smp_get_cpu(plic_ctx[i].hartid)] = i;
            // logkf(LOG_DEBUG, "CPU%{d} PLIC ctx is %{d}", smp_get_cpu(plic_ctx[i].hartid), i);
        }
    }

    // Map the PLIC into memory.
    plic_base = memprotect_alloc_vaddr(size);
    memprotect_k(plic_base, paddr, size, MEMPROTECT_FLAG_RW | MEMPROTECT_FLAG_IO);

    // Set INTC external interrupt handler.
    intc_ext_irq_handler = plic_interrupt_handler;
}

// Define PLIC driver.
DRIVER_DECL(riscv_plic_driver) = {
    .type             = DRIVER_TYPE_DTB,
    .dtb_supports_len = 2,
    .dtb_supports     = (char const *[]){"sifive,plic-1.0.0", "riscv,plic0"},
    .dtb_init         = plic_dtb_init,
};
