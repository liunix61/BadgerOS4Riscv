
// SPDX-License-Identifier: MIT

#include "usercopy.h"

#include "assertions.h"
#include "badge_strings.h"
#include "cpu/mmu.h"
#include "interrupt.h"
#include "isr_ctx.h"
#include "memprotect.h"
#include "process/internal.h"

// TODO: Convert to page fault intercepting memcpy.
// TODO: Migrate into generic process API.



// Determine string length in memory a user owns.
// Returns -1 if the user doesn't have access to any byte in the string.
ptrdiff_t strlen_from_user_raw(process_t *process, size_t user_vaddr, ptrdiff_t max_len) {
    if (!max_len) {
        return 0;
    }
    ptrdiff_t len = 0;

    // Check first page permissions.
    if (!(proc_map_contains_raw(process, user_vaddr, 1) & MEMPROTECT_FLAG_R)) {
        return -1;
    }

    // String length loop.
    mpu_ctx_t *old_mpu = isr_ctx_get()->mpu_ctx;
    memprotect_swap(&process->memmap.mpu_ctx);
    mmu_enable_sum();
    while (len < max_len && *(char const *)user_vaddr) {
        len++;
        user_vaddr++;
        if (user_vaddr % MEMMAP_PAGE_SIZE == 0) {
            // Check further page permissions.
            mmu_disable_sum();
            if (!(proc_map_contains_raw(process, user_vaddr, 1) & MEMPROTECT_FLAG_R)) {
                memprotect_swap(old_mpu);
                return -1;
            }
            mmu_enable_sum();
        }
    }
    mmu_disable_sum();

    memprotect_swap(old_mpu);
    return len;
}

// Copy bytes from user to kernel.
// Returns whether the user has access to all of these bytes.
// If the user doesn't have access, no copy is performed.
bool copy_from_user_raw(process_t *process, void *kernel_vaddr, size_t user_vaddr, size_t len) {
    if (!proc_map_contains_raw(process, user_vaddr, len)) {
        return false;
    }
    mpu_ctx_t *old_mpu = isr_ctx_get()->mpu_ctx;
    memprotect_swap(&process->memmap.mpu_ctx);
    mmu_enable_sum();
    mem_copy(kernel_vaddr, (void *)user_vaddr, len);
    mmu_disable_sum();
    memprotect_swap(old_mpu);
    return true;
}

// Copy from kernel to user.
// Returns whether the user has access to all of these bytes.
// If the user doesn't have access, no copy is performed.
bool copy_to_user_raw(process_t *process, size_t user_vaddr, void *kernel_vaddr0, size_t len) {
    if (!proc_map_contains_raw(process, user_vaddr, len)) {
        return false;
    }
    mpu_ctx_t *old_mpu = isr_ctx_get()->mpu_ctx;
    memprotect_swap(&process->memmap.mpu_ctx);
    mmu_enable_sum();
    mem_copy((void *)user_vaddr, kernel_vaddr0, len);
    mmu_disable_sum();
    memprotect_swap(old_mpu);
    return true;
}
