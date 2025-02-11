
// SPDX-License-Identifier: MIT

#pragma once

#include "attributes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>



// AHCI generic host control: Host Capabilities.
typedef union {
    struct {
        // Number of ports minus one.
        uint32_t n_ports                : 5;
        // Supports external SATA.
        uint32_t supports_esata         : 1;
        // Enclosure management supported.
        uint32_t supports_enclosure     : 1;
        // Command completion coalescing supported.
        uint32_t supports_cc_coalescing : 1;
        // Number of command slots minus one.
        uint32_t n_cmd_slots            : 1;
        // Partial state capable.
        uint32_t supports_pstate        : 1;
        // Slumber state capable.
        uint32_t supports_slumber       : 1;
        // Supports multiple DRQ blocks per PIO command.
        uint32_t pio_multi_drq          : 1;
        // Supports FIS-based switching.
        uint32_t supports_fis_switch    : 1;
        // Supports port multiplier.
        uint32_t supports_port_mul      : 1;
        // Supports AHCI only mode.
        uint32_t supports_ahci_only     : 1;
        // Reserved
        uint32_t                        : 1;
        // Interface speed support.
        uint32_t max_if_speed           : 4;
        // Supports command list override.
        uint32_t supports_clo           : 1;
        // Supports activity LED.
        uint32_t supports_led           : 1;
        // Supports aggressive link power management.
        uint32_t supports_alp           : 1;
        // Supports staggered spin-up.
        uint32_t supports_ss            : 1;
        // Supports mechanical presence switch.
        uint32_t supports_det_sw        : 1;
    };
    uint32_t val;
} ahci_ghc_cap_t;

// AHCI generic host control: Global Host Control.
typedef union {
    struct {
        // HBA reset.
        uint32_t hba_reset       : 1;
        // Interrupt enable.
        uint32_t irq_en          : 1;
        // HBA reverted to single MSI mode.
        uint32_t single_msi_mode : 1;
        // Reserved.
        uint32_t                 : 28;
        // Legacy AHCI enable.
        uint32_t ahci_en         : 1;
    };
    uint32_t val;
} ahci_ghc_ghc_t;

// AHCI generic host control: Interrupt Status.
typedef uint32_t ahci_ghc_is_t;

// AHCI generic host control: Ports Implemented.
typedef uint32_t ahci_ghc_pi_t;

// AHCI generic host control: Version.
typedef union {
    struct {
        // Major version.
        uint8_t maj[2];
        // Minor version.
        uint8_t min[2];
    };
    uint32_t val;
} ahci_ghc_vs_t;

// AHCI generic host control: Command Completion Coalescing Control.
typedef union {
    struct {
        // Enable coalescing of command completion interrupts.
        uint32_t enable        : 1;
        // Reserved.
        uint32_t               : 2;
        // Interrupt to use for this feature.
        uint32_t irq           : 5;
        // Number of command completions before an interrupt.
        uint32_t n_completions : 1;
        // Timeout in 1 millisecond interval.
        uint32_t timeout_ms    : 1;
    };
    uint32_t val;
} ahci_ghc_ccc_ctl_t;

// AHCI generic host control: Command Completion Coalsecing Ports.
typedef uint32_t ahci_ghc_ccc_ports_t;

// AHCI generic host control: Enclosure Management Location.
typedef union {
    // TODO.
    uint32_t val;
} ahci_ghc_em_loc_t;

// AHCI generic host control: Enclosure Management Control.
typedef union {
    // TODO.
    uint32_t val;
} ahci_ghc_em_ctl_t;

// AHCI generic host control: Host Capabilities Extended.
typedef union {
    struct {
        // Supports BIOS/OS handoff.
        uint32_t supports_bios_handoff   : 1;
        // Supports NVMHCI.
        uint32_t supports_nvmhci         : 1;
        // Supports automatic partial to slumber transitions.
        uint32_t supports_auto_slumber   : 1;
        // Supports device sleep.
        uint32_t supports_dev_sleep      : 1;
        // Supports aggressive device sleep management.
        uint32_t supports_adm            : 1;
        // Only allows device sleep from slumber.
        uint32_t sleep_from_slumber_only : 1;
    };
    uint32_t val;
} ahci_ghc_cap2_t;

// AHCI generic host control: BIOS/OS Handoff Control and Status.
typedef union {
    struct {
        // BIOS owned.
        uint32_t bios_owned : 1;
        // OS owned.
        uint32_t os_owned   : 1;
        // SMI on ownership change.
        uint32_t ooc_smi    : 1;
        // OS ownerchip change.
        uint32_t ooc        : 1;
        // BIOS busy.
        uint32_t bios_busy  : 1;
    };
    uint32_t val;
} ahci_ghc_bohc_t;

// HBA BAR registers: generic host control - not meant to be constructed.
typedef struct {
    // Host Capabilities.
    VOLATILE ahci_ghc_cap_t       cap;
    // Global Host Control.
    VOLATILE ahci_ghc_ghc_t       ghc;
    // Interrupt Status.
    VOLATILE ahci_ghc_is_t        irq_status;
    // Ports Implemented.
    VOLATILE ahci_ghc_pi_t        ports_impl;
    // Version.
    VOLATILE ahci_ghc_vs_t        version;
    // Command Completion Coalescing Control.
    VOLATILE ahci_ghc_ccc_ctl_t   ccc_ctl;
    // Command Completion Coalsecing Ports.
    VOLATILE ahci_ghc_ccc_ports_t ccc_ports;
    // Enclosure Management Location.
    VOLATILE ahci_ghc_em_loc_t    em_loc;
    // Enclosure Management Control.
    VOLATILE ahci_ghc_em_ctl_t    em_ctl;
    // Host Capabilities Extended.
    VOLATILE ahci_ghc_cap2_t      cap2;
    // BIOS/OS Handoff Control and Status.
    VOLATILE ahci_ghc_bohc_t      bohc;
} ahci_bar_ghc_t;
_Static_assert(sizeof(ahci_bar_ghc_t) == 0x2c, "Size of ahci_bar_t must be 0x2c");
