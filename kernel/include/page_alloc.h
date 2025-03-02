
// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>



// Allocate pages of physical memory.
// Uses physical page numbers (paddr / MEMMAP_PAGE_SIZE).
size_t phys_page_alloc(size_t page_count, bool for_user);
// Returns how large a physical allocation actually is.
// Uses physical page numbers (paddr / MEMMAP_PAGE_SIZE).
size_t phys_page_size(size_t ppn);
// Free pages of physical memory.
// Uses physical page numbers (paddr / MEMMAP_PAGE_SIZE).
void   phys_page_free(size_t ppn);
// Split a physical page allocation into two in the allocator.
// Uses physical page numbers (paddr / MEMMAP_PAGE_SIZE).
void   phys_page_split(size_t ppn);
