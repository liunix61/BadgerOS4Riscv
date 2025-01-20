
// SPDX-License-Identifier: MIT

#include "driver/pcie.h"

#include "arrays.h"
#include "assertions.h"
#include "driver.h"
#include "log.h"
#include "memprotect.h"



// PCIe controller data.
static pcie_controller_t ctl;
// Whether the PCIe controller is present.
static bool              ctl_present;



// Apply VMM mappings to make the PCIe controller accessible.
bool pcie_memprotect(pcie_controller_t *ctl) {
    size_t   bus_count   = ctl->bus_end - ctl->bus_start + 1;
    size_t   config_size = bus_count * PCIE_ECAM_SIZE_PER_BUS;
    uint32_t flags       = MEMPROTECT_FLAG_RW | MEMPROTECT_FLAG_IO;
    return memprotect_k(ctl->config_vaddr, ctl->config_paddr, config_size, flags);
}

// Initialise the PCIe controller.
// Init successful or not, takes ownership of the memory in `ctl`.
static bool pcie_controller_init() {
    // Allocate ranges of virtual memory to map the controller into.
    size_t bus_count   = ctl.bus_end - ctl.bus_start + 1;
    size_t config_size = bus_count * PCIE_ECAM_SIZE_PER_BUS;
    ctl.config_vaddr   = memprotect_alloc_vaddr(config_size);
    if (!ctl.config_vaddr) {
        free(ctl.ranges);
        return -1;
    }

    // Apply VMM mappings to make the device accessible.
    if (!pcie_memprotect(&ctl)) {
        memprotect_free_vaddr(ctl.config_vaddr);
        free(ctl.ranges);
        return -1;
    }
    ctl_present = true;

    return true;
}


// Find a matching driver.
static bool find_pci_driver(pci_class_t classcode, pci_addr_t addr) {
    for (driver_t const *driver = start_drivers; driver != stop_drivers; driver++) {
        if (driver->type != DRIVER_TYPE_PCI) {
            continue;
        }
        if (driver->pci_class.baseclass == classcode.baseclass && driver->pci_class.subclass == classcode.subclass &&
            driver->pci_class.progif == classcode.progif) {
            driver->pci_init(addr);
            return true;
        }
    }
    return false;
}

// Enumerate function via ECAM.
static void pcie_ecam_func_detect(uint8_t bus, uint8_t dev, uint8_t func) {
    pcie_hdr_com_t *hdr = (void *)(ctl.config_vaddr + (bus * 256 + dev * 8 + func) * 4096);
    logkf(
        LOG_DEBUG,
        "PCIe device %{u8;x}:%{u8;x}.%{u8;d} detected, type %{u8;x}, class %{u8;x}:%{u8;x}:%{u8;x}",
        bus,
        dev,
        func,
        hdr->hdr_type,
        hdr->classcode.baseclass,
        hdr->classcode.subclass,
        hdr->classcode.progif
    );
    find_pci_driver(hdr->classcode, (pci_addr_t){bus, dev, func});
}

// Enumerate device via ECAM.
static void pcie_ecam_dev_detect(uint8_t bus, uint8_t dev) {
    pcie_hdr_com_t *hdr = (void *)(ctl.config_vaddr + (bus * 256 + dev * 8) * 4096);
    if (hdr->vendor_id == 0xffff) {
        return;
    }
    pcie_ecam_func_detect(bus, dev, 0);
    bool multifunc = hdr->hdr_type & 0x80;
    if (multifunc) {
        for (uint8_t func = 1; func < 8; func++) {
            hdr = (void *)(ctl.config_vaddr + (bus * 256 + dev * 8 + func) * 4096);
            if (hdr->vendor_id == 0xffff) {
                continue;
            }
            pcie_ecam_func_detect(bus, dev, func);
        }
    }
}

// Enumerate devices via ECAM.
void pcie_ecam_detect() {
    if (!ctl_present) {
        return;
    }
    logk(LOG_INFO, "Enumerating PCIe devices");
    for (unsigned bus = ctl.bus_start; bus <= ctl.bus_end; bus++) {
        for (uint8_t dev = 0; dev < 32; dev++) {
            pcie_ecam_dev_detect(bus, dev);
        }
    }
}

// Get the ECAM virtual address for a device.
void *pcie_ecam_vaddr(pci_addr_t addr) {
    if (addr.bus < ctl.bus_start || addr.bus > ctl.bus_end) {
        return NULL;
    }
    return (void *)(ctl.config_vaddr + ((addr.bus - ctl.bus_start) * 256 + addr.dev * 8 + addr.func) * 4096);
}


// Get info from a BAR register.
pci_bar_info_t pci_bar_info(VOLATILE pci_bar_t *bar) {
    if (*bar & BAR_FLAG_IO) {
        // I/O BARs.
        pci_bar_t orig = *bar;
        *bar           = -1;
        pci_bar_t len  = 1 + ~(*bar & BAR_IO_ADDR_MASK);
        *bar           = orig;
        return (pci_bar_info_t){
            .is_io    = true,
            .is_64bit = false,
            .prefetch = false,
            .paddr    = orig & BAR_IO_ADDR_MASK,
            .len      = len,
        };

    } else if (*bar & BAR_FLAG_64BIT) {
        // 64-bit memory BARs.
        pci_bar64_t *bar64 = (pci_bar64_t *)bar;
        pci_bar64_t  orig  = *bar64;
        *bar64             = -1;
        pci_bar64_t len    = 1 + ~(*bar64 & BAR_MEM64_ADDR_MASK);
        *bar64             = orig;
        return (pci_bar_info_t){
            .is_io    = false,
            .is_64bit = true,
            .prefetch = *bar & BAR_FLAG_PREFETCH,
            .paddr    = orig & BAR_MEM64_ADDR_MASK,
            .len      = len,
        };

    } else {
        // 32-bit memory BARs.
        pci_bar64_t orig = *bar;
        *bar             = -1;
        pci_bar64_t len  = 1 + ~(*bar & BAR_MEM32_ADDR_MASK);
        *bar             = orig;
        return (pci_bar_info_t){
            .is_io    = false,
            .is_64bit = false,
            .prefetch = *bar & BAR_FLAG_PREFETCH,
            .paddr    = orig & BAR_MEM32_ADDR_MASK,
            .len      = len,
        };
    }
}

// Map a BAR into CPU virtual memory.
pci_bar_handle_t pci_bar_map(VOLATILE pci_bar_t *bar) {
    // Get info from this BAR register.
    pci_bar_info_t info = pci_bar_info(bar);

    // Find a matching PCI BAR range.
    pci_paddr_t ppa;
    uint64_t    pci_paddr;
    size_t      i;
    for (i = 0; i < ctl.ranges_len; i++) {
        ppa       = ctl.ranges[i].pci_paddr;
        pci_paddr = ((uint64_t)ppa.addr_hi << 32) | ppa.addr_lo;
        if ((ppa.attr.type == PCI_ASPACE_IO) == info.is_io && pci_paddr <= info.paddr &&
            pci_paddr + ctl.ranges[i].length >= info.paddr + info.len) {
            break;
        }
    }
    if (i >= ctl.ranges_len) {
        // No matches found.
        return (pci_bar_handle_t){0};
    }

    // Determine CPU physical address.
    size_t cpu_paddr = ctl.ranges[i].cpu_paddr + info.paddr - pci_paddr;

    // Determine appropriate flags.
    int flags = MEMPROTECT_FLAG_RW | MEMPROTECT_FLAG_NC;
    if (!ppa.attr.prefetch) {
        flags |= MEMPROTECT_FLAG_IO;
    }

    // Create MMU mapping.
    size_t vaddr = memprotect_alloc_vaddr(info.len);
    if (!vaddr || !memprotect_k(vaddr, cpu_paddr, info.len, flags)) {
        return (pci_bar_handle_t){0};
    }

    return (pci_bar_handle_t){
        .bar     = info,
        .pointer = (void *)vaddr,
    };
}

// Trace a PCI interrupt pin [1,4] to a CPU interrupt.
// Returns -1 if the interrupt does not exist.
int pci_trace_irq_pin(pci_addr_t addr, int pci_irq) {
    pci_paddr_t paddr = {
        .attr.bus  = addr.bus,
        .attr.dev  = addr.dev,
        .attr.func = addr.func,
    };
    paddr.attr.val &= ctl.irqmap_mask.attr.val;
    for (size_t i = 0; i < ctl.irqmap_len; i++) {
        if (paddr.attr.val == ctl.irqmap[i].pci_paddr.attr.val && pci_irq == ctl.irqmap[i].pci_irq) {
            return ctl.irqmap[i].cpu_irq;
        }
    }
    return -1;
}



#ifdef PORT_ENABLE_DTB
// Extract ranges from DTB.
static bool pci_dtb_ranges(dtb_handle_t *handle, dtb_node_t *node) {
    dtb_prop_t *ranges = dtb_get_prop(handle, node, "ranges");
    if (!ranges) {
        logk(LOG_ERROR, "Missing ranges for PCI");
        return false;
    }

    // PCIe cell counts must match these numbers.
    if (dtb_read_uint(handle, node, "#size-cells") != 2) {
        logk(LOG_ERROR, "Incorrect #size-cells for PCI");
        return false;
    }
    if (dtb_read_uint(handle, node, "#address-cells") != 3) {
        logk(LOG_ERROR, "Incorrect #address-cells for PCI");
        return false;
    }

    // If ranges is empty, it is identity-mapped.
    if (ranges->content_len == 0) {
        ctl.ranges_len = 1;
        ctl.ranges     = malloc(sizeof(pci_bar_range_t));
        if (!ctl.ranges) {
            return false;
        }
        ctl.ranges[0] = (pci_bar_range_t){
            .cpu_paddr = 0,
            .pci_paddr = {0},
            .length    = SIZE_MAX,
        };
        return true;
    }

    // A PCI range mapping is always 7 cells total.
    ctl.ranges_len = ranges->content_len / (4 * 7);
    ctl.ranges     = malloc(ctl.ranges_len * sizeof(pci_bar_range_t));
    if (!ctl.ranges) {
        logk(LOG_ERROR, "Out of memory while initializing PCI");
        return false;
    }
    for (size_t i = 0; i < ctl.ranges_len; i++) {
        ctl.ranges[i] = (pci_bar_range_t){
            .cpu_paddr          = dtb_prop_read_cells(handle, ranges, i * 7 + 3, 2),
            .pci_paddr.attr.val = dtb_prop_read_cells(handle, ranges, i * 7 + 0, 1),
            .pci_paddr.addr_hi  = dtb_prop_read_cells(handle, ranges, i * 7 + 1, 1),
            .pci_paddr.addr_lo  = dtb_prop_read_cells(handle, ranges, i * 7 + 2, 1),
            .length             = dtb_prop_read_cells(handle, ranges, i * 7 + 6, 1),
        };
    }
    return true;
}

// Extract interrupt mappings from DTB.
static bool pci_dtb_irqmap(dtb_handle_t *handle, dtb_node_t *node) {
    // PCI #interrupt-cells must be 1.
    if (dtb_read_uint(handle, node, "#interrupt-cells") != 1) {
        logk(LOG_ERROR, "Incorrect #interrupt-cells for PCI");
        return false;
    }

    dtb_prop_t *interrupt_mask = dtb_get_prop(handle, node, "interrupt-map-mask");
    if (!interrupt_mask) {
        logk(LOG_WARN, "Missing interrupt-map-mask for PCI");
        return false;

    } else if (interrupt_mask->content_len != 16) {
        logk(LOG_ERROR, "Incorrect interrupt-map-mask for PCI");
        return false;

    } else {
        ctl.irqmap_mask.attr.val = dtb_prop_read_cell(handle, interrupt_mask, 0);
        ctl.irqmap_mask.addr_hi  = dtb_prop_read_cell(handle, interrupt_mask, 1);
        ctl.irqmap_mask.addr_lo  = dtb_prop_read_cell(handle, interrupt_mask, 2);
    }

    // TODO: DTB supports far more complex interrupt trees than BadgerOS does.
    // BadgerOS only supports interrupts directly into the CPU's interrupt controller.
    dtb_prop_t *interrupt_map = dtb_get_prop(handle, node, "interrupt-map");
    if (!interrupt_map) {
        logk(LOG_ERROR, "Missing interrupt-map for PCI");
    }

    ctl.irqmap_len = interrupt_map->content_len / 4 / 6;
    ctl.irqmap     = malloc(sizeof(pci_irqmap_t) * ctl.irqmap_len);
    if (!ctl.irqmap) {
        logk(LOG_ERROR, "Out of memory while initializing PCI");
        return false;
    }
    for (size_t i = 0; i < ctl.irqmap_len; i++) {
        ctl.irqmap[i].pci_paddr.attr.val = dtb_prop_read_cell(handle, interrupt_map, i * 6 + 0);
        ctl.irqmap[i].pci_paddr.addr_hi  = dtb_prop_read_cell(handle, interrupt_map, i * 6 + 1);
        ctl.irqmap[i].pci_paddr.addr_lo  = dtb_prop_read_cell(handle, interrupt_map, i * 6 + 2);
        ctl.irqmap[i].pci_irq            = dtb_prop_read_cell(handle, interrupt_map, i * 6 + 3);
        // phandle = dtb_prop_read_cell(handle, interrupt_map, i * 6 + 4);
        ctl.irqmap[i].cpu_irq            = dtb_prop_read_cell(handle, interrupt_map, i * 6 + 5);
    }

    return true;
}

// DTB init for normal PCIe.
static void pcie_driver_dtbinit(dtb_handle_t *handle, dtb_node_t *node, uint32_t addr_cells, uint32_t size_cells) {
    (void)size_cells;
    if (ctl_present) {
        logk(LOG_WARN, "Multiple PCIe controllers detected; only the first is used.");
        return;
    }
    ctl.type = PCIE_CTYPE_GENERIC_ECAM;

    // Read configuration space physical address.
    ctl.config_paddr = dtb_read_cells(handle, node, "reg", 0, addr_cells);

    // Read bus range.
    dtb_prop_t *bus_range = dtb_get_prop(handle, node, "bus-range");
    if (bus_range->content_len != 8) {
        logk(LOG_ERROR, "Incorrect bus-range for PCI");
        goto malformed_dtb;
    }
    ctl.bus_start = dtb_prop_read_cell(handle, bus_range, 0);
    ctl.bus_end   = dtb_prop_read_cell(handle, bus_range, 1);

    // Read PCIe interrupt mappings.
    if (!pci_dtb_irqmap(handle, node)) {
        goto malformed_dtb;
    }

    // Read PCIe range mappings.
    if (!pci_dtb_ranges(handle, node)) {
        goto malformed_dtb;
    }

    pcie_controller_init();
    return;

malformed_dtb:
    logk(LOG_WARN, "Initialization failed; ignoring this PCIe controller!");
}

#ifdef __riscv
// DTB init for FU740 PCIe.
static void
    pcie_fu740_driver_dtbinit(dtb_handle_t *handle, dtb_node_t *node, uint32_t addr_cells, uint32_t size_cells) {
    if (ctl_present) {
        logk(LOG_WARN, "Multiple PCIe controllers detected; only the first is used.");
        return;
    }
    ctl.type = PCIE_CTYPE_SIFIVE_FU740;
    if (!pci_dtb_ranges(handle, node)) {
        logk(LOG_WARN, "Malformed DTB; ignoring this PCIe controller!");
        return;
    }
    // TODO: Find FU740 PCIe configuration space.
    pcie_controller_init();
}
#endif
#endif



#ifdef PORT_ENABLE_DTB
// Driver for normal no-nonsense PCIe.
DRIVER_DECL(pcie_driver_dtb) = {
    .type             = DRIVER_TYPE_DTB,
    .dtb_supports_len = 1,
    .dtb_supports     = (char const *[]){"pci-host-ecam-generic"},
    .dtb_init         = pcie_driver_dtbinit,
};

#ifdef __riscv
// Driver for the factually stupid incoherent SiFive FU740 proprietary nonsense PCIe.
DRIVER_DECL(pcie_fu740_driver_dtb) = {
    .type             = DRIVER_TYPE_DTB,
    .dtb_supports_len = 1,
    .dtb_supports     = (char const *[]){"sifive,fu740-pcie"},
    .dtb_init         = pcie_fu740_driver_dtbinit,
};
#endif
#endif
