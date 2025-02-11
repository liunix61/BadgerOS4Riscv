
// SPDX-License-Identifier: MIT

#pragma once

#include "attributes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>



// AHCI port interrupt numbers.
typedef union {
    struct {
        // Device to host register FIS interrupt.
        uint32_t d2h_reg_fis   : 1;
        // PIO setup FIS interrupt.
        uint32_t pio_setup_fis : 1;
        // DMA setup FIS interrupt.
        uint32_t dma_setup_fis : 1;
        // Set device bits interrupt.
        uint32_t set_dev_bits  : 1;
        // Unknown FIS interrupt.
        uint32_t unknown_fis   : 1;
        // Descriptor processed.
        uint32_t desc_proc     : 1;
        // Port connect status change.
        uint32_t port_status   : 1;
        // Device mechanical presence status.
        uint32_t presence      : 1;
        // Reserved.
        uint32_t               : 14;
        // PhyRdy signal changed.
        uint32_t phy_rdy       : 1;
        // Incorrect port multiplier status.
        uint32_t port_mul_err  : 1;
        // Overflow status.
        uint32_t overflow      : 1;
    };
    uint32_t val;
} ahci_bar_port_irq_t;

// Command and status register.
typedef union {
    struct {
        // Start command list.
        uint32_t cmd_start               : 1;
        // Spin up device.
        uint32_t spinup                  : 1;
        // Power on device.
        uint32_t poweron                 : 1;
        // Command list override.
        uint32_t clo                     : 1;
        // FIS receive enable.
        uint32_t fis_en                  : 1;
        // Reserved
        uint32_t                         : 3;
        // Current command slot being issued.
        uint32_t cur_slot                : 5;
        // Presence switch state.
        uint32_t present_switch          : 1;
        // FIS receive DMA engine is running.
        uint32_t fis_running             : 1;
        // Command list running.
        uint32_t cmd_running             : 1;
        // Cold presence state.
        uint32_t present_cold            : 1;
        // Port multiplier attached.
        uint32_t port_mul_det            : 1;
        // Hot plug capable port.
        uint32_t supports_hotplug        : 1;
        // Port has mechanical presence switch.
        uint32_t supports_present_switch : 1;
        // Supports cold presence detection.
        uint32_t supports_present_cold   : 1;
        // Is an external port.
        uint32_t is_external             : 1;
        // FIS-based switching capable.
        uint32_t supports_fis_switching  : 1;
        // Enable automatic partial to slumber.
        uint32_t auto_slumber_en         : 1;
        // Is an ATAPI device.
        uint32_t dev_is_atapi            : 1;
        // Enable drive LED even for ATAPI devices.
        uint32_t drive_led_atapi         : 1;
    };
    uint32_t val;
} ahci_bar_port_cmd_t;

// Task file data.
typedef union {
    struct {
        // Status.
        uint32_t status : 8;
        // Error.
        uint32_t err    : 8;
        // Reserved.
        uint32_t        : 16;
    };
    uint32_t val;
} ahci_bar_port_tfd_t;

// SATA status register.
typedef union {
    struct {
        // Device detection.
        uint32_t detect : 4;
        // Current interface speed..
        uint32_t speed  : 4;
        // Interface power management.
        uint32_t power  : 4;
    };
    uint32_t val;
} ahci_bar_port_sstatus_t;

// SATA control register.
typedef union {
    struct {
        // Devide detection initiation.
        uint32_t det       : 4;
        // Maximum speed.
        uint32_t max_speed : 4;
        // Allowed power management transitions.
        uint32_t power     : 4;
    };
    uint32_t val;
} ahci_bar_port_sctrl_t;

// SATA error register.
typedef union {
    struct {
        // Error code.
        uint32_t err  : 16;
        // Diagnostics code.
        uint32_t diag : 16;
    };
    uint32_t val;
} ahci_bar_port_err_t;

// SATA port multiplier notification management register.
typedef union {
    // TODO.
    uint32_t val;
} ahci_bar_port_notif_t;

// SATA port multiplier FIS-based switching control register.
typedef union {
    // TODO.
    uint32_t val;
} ahci_bar_port_swctrl_t;

// SATA device sleep management.
typedef union {
    // TODO.
    uint32_t val;
} ahci_bar_port_sleep_t;

// HBA BAR registers: AHCI port.
typedef struct {
    // Command list base address.
    VOLATILE uint64_t                cmdlist_addr;
    // FIS base address.
    VOLATILE uint64_t                fis_addr;
    // Interrupt status.
    VOLATILE ahci_bar_port_irq_t     irq_status;
    // Interrupt enable.
    VOLATILE ahci_bar_port_irq_t     irq_enable;
    // Command and status register.
    VOLATILE ahci_bar_port_cmd_t     cmd;
    // Task file data.
    VOLATILE ahci_bar_port_tfd_t     tfd;
    // Port signature.
    VOLATILE uint32_t                signature;
    // SATA status register.
    VOLATILE ahci_bar_port_sstatus_t sstatus;
    // SATA control register.
    VOLATILE ahci_bar_port_sctrl_t   sctrl;
    // SATA error register.
    VOLATILE ahci_bar_port_err_t     err;
    // SATA active mask.
    VOLATILE uint32_t                active;
    // Command issue.
    VOLATILE uint32_t                cmd_issue;
    // Port multiplier notification management.
    VOLATILE ahci_bar_port_notif_t   notif;
    // Port multiplier switching control.
    VOLATILE ahci_bar_port_swctrl_t  swctrl;
    // Device sleep control.
    VOLATILE ahci_bar_port_sleep_t   sleep_ctrl;
} ahci_bar_port_t;
