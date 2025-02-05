
// SPDX-License-Identifier: MIT

#pragma once

#include "port/dtb.h"

// Initialise timer using the DTB.
void time_init_dtb(dtb_handle_t *dtb);
// Early timer init before ACPI (but not DTB).
void time_init_before_acpi();
// Initialise timer using ACPI.
void time_init_acpi();
