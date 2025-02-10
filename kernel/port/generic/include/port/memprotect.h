
// SPDX-License-Identifier: MIT

#pragma once

#include "list.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct mpu_ctx_t {
    // Linked list node.
    dlist_node_t node;
    // Page table root physical page number.
    size_t       root_ppn;
} mpu_ctx_t;

// HHDM length in pages.
extern size_t memprotect_hhdm_pages;
// Kernel virtual page number.
extern size_t memprotect_kernel_vpn;
// Kernel physical page number.
extern size_t memprotect_kernel_ppn;
// Kernel length in pages.
extern size_t memprotect_kernel_pages;
