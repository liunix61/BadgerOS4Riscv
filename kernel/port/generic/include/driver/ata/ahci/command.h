
// SPDX-License-Identifier: MIT

#pragma once

#include "attributes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>



// Command header flags.
typedef union {
    struct {
        // Command FIS length in DWORDS.
        uint16_t cmd_fis_len : 5;
        // PIO setup FIS shall indicate ATAPI command.
        uint16_t is_atapi    : 1;
        // Write to storage medium.
        uint16_t is_write    : 1;
        // PRDs are prefetchable.
        uint16_t prefetch    : 1;
        // Command is part of a reset sequence.
        uint16_t is_reset    : 1;
        // TODO: Something about BIST and tests.
        uint16_t is_bist     : 1;
        // Clear the busy flag on R_OK.
        uint16_t clr_bsy_ok  : 1;
        // Reserved.
        uint16_t             : 1;
        // Port multiplier port.
        uint16_t pmul_port   : 4;
    };
    uint16_t val;
} achi_cmdflag_t;

// Command header entry.
typedef struct {
    // Command header flags.
    VOLATILE achi_cmdflag_t flags;
    // Physical Region Descriptor Table Length.
    VOLATILE uint16_t       prd_table_len;
    // PRD byte count; transferred byte count.
    VOLATILE uint32_t       prd_transfer_len;
    // Command table base address.
    VOLATILE uint64_t       cmdtab_paddr;
    // Reserved.
    uint32_t : 32;
    uint32_t : 32;
    uint32_t : 32;
    uint32_t : 32;
} ahci_cmdhdr_t;
