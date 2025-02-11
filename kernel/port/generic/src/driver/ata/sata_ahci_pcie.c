
// SPDX-License-Identifier: MIT

#include "driver.h"
#include "driver/ata/ahci.h"
#include "interrupt.h"
#include "log.h"
#include "malloc.h"
#include "page_alloc.h"
#include "scheduler/scheduler.h"



// SATA AHCI vtable.
static ata_vtable_t const sata_vtable = {};

// SATA AHCI interrupt handler.
static void sata_ahci_isr(int irq_no, void *cookie) {
    (void)irq_no;
    sata_handle_t *handle = cookie;

    uint32_t irq                               = handle->regs->generic_host_ctrl.irq_status;
    handle->regs->generic_host_ctrl.irq_status = irq;
    while (irq) {
        int index  = __builtin_ctz(irq);
        irq       ^= 1 << index;
    }
}

// Initialize SATA AHCI driver with PCI.
static void driver_sata_ahci_pci_init(pci_addr_t addr) {
    timestamp_us_t lim;

    sata_handle_t *handle = malloc(sizeof(sata_handle_t));
    if (!handle) {
        logk(LOG_ERROR, "Out of memory while initializing SATA AHCI");
        goto error;
    }

    // Map the BAR for this AHCI controller.
    void           *cfgm = pcie_ecam_vaddr(addr);
    pcie_hdr_dev_t *hdr  = cfgm;
    logkf(LOG_INFO, "Detected SATA AHCI at %{u8;x}:%{u8;x}.%{u8;d}", addr.bus, addr.dev, addr.func);
    pci_bar_handle_t bar = pci_bar_map(&hdr->bar[5]);
    if (!bar.pointer) {
        logkf(LOG_WARN, "Unable to map BAR space for SATA AHCI");
        goto error;
    }

    // Set up the AHCI controller for usage by BadgerOS.
    ahci_bar_t     *regs = bar.pointer;
    ahci_bar_ghc_t *ghc  = &regs->generic_host_ctrl;

    if (ghc->cap2.supports_bios_handoff) {
        // Perform BIOS/OS handoff.
        lim                = time_us() + 2000000;
        ghc->bohc.os_owned = true;
        while (ghc->bohc.bios_owned || ghc->bohc.bios_busy) {
            if (time_us() > lim) {
                logk(LOG_ERROR, "Failed to take HBA ownership");
                goto error;
            }
            thread_sleep(10000);
        }
    }

    // Reset the HBA.
    ghc->ghc.hba_reset = 1;
    lim                = time_us() + 1000000;
    while (ghc->ghc.hba_reset) {
        if (time_us() > lim) {
            logk(LOG_ERROR, "Failed to reset HBA");
            goto error;
        }
        thread_sleep(10000);
    }

    // Switch to ACHI mode if it wasn't already enabled.
    ghc->ghc.ahci_en = true;

    // Create SATA port handles.
    handle->base.vtable   = &sata_vtable;
    handle->addr          = addr;
    handle->bar           = bar;
    handle->regs          = regs;
    handle->ports_enabled = 0;
    handle->n_ports       = regs->generic_host_ctrl.cap.n_ports + 1;

    // Allocate FIS(256) and command memory(1K) for ports.
    handle->fis_paddr = phys_page_alloc((handle->n_ports + 15) / 16, false);
    handle->cmd_paddr = phys_page_alloc((handle->n_ports + 3) / 4, false);

    for (int i = 0; i < handle->n_ports; i++) {
        regs->ports[i].cmdlist_addr = handle->cmd_paddr + 1024 * i;
        regs->ports[i].fis_addr     = handle->fis_paddr + 256 * i;
    }

    // Detect drives.
    for (int i = 0; i < handle->n_ports; i++) {
        if (regs->ports[i].sstatus.detect) {
            logkf(LOG_INFO, "Found drive in slot %{d}", i);
            handle->ports_enabled |= 1ul << i;
        }
    }

    // Enable interrupts.
    int cpu_irq = pci_trace_irq_pin(addr, hdr->irq_pin);
    isr_install(cpu_irq, sata_ahci_isr, handle);
    irq_ch_enable(cpu_irq);
    ghc->irq_status = -1;
    ghc->ghc.irq_en = true;

    return;
error:
    free(handle);
    logkf(LOG_ERROR, "Failed to initialize SATA AHCI at %{u8;x}:%{u8;x}.%{u8;d}", addr.bus, addr.dev, addr.func);
}

DRIVER_DECL(driver_sata_ahci_pcie) = {
    .type                = DRIVER_TYPE_PCI,
    .pci_class.baseclass = PCI_BCLASS_STORAGE,
    .pci_class.subclass  = PCI_SUBCLASS_STORAGE_SATA,
    .pci_class.progif    = PCI_PROGIF_STORAGE_SATA_AHCI,
    .pci_init            = driver_sata_ahci_pci_init,
};
