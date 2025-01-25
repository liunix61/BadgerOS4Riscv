
// SPDX-License-Identifier: MIT

#include "cpu/mmu.h"

#include "assertions.h"
#include "cpu/x86_cpuid.h"
#include "cpu/x86_cr.h"
#include "interrupt.h"
#include "isr_ctx.h"

_Static_assert(MEMMAP_PAGE_SIZE == MMU_PAGE_SIZE, "MEMMAP_PAGE_SIZE must equal MMU_PAGE_SIZE");



// Virtual address offset used for HHDM.
size_t mmu_hhdm_vaddr;
// Virtual address offset of the higher half.
size_t mmu_high_vaddr;
// Size of a "half".
size_t mmu_half_size;
// How large to make the HHDM, rounded up to pages.
size_t mmu_hhdm_size;
// Number of page table levels.
int    mmu_levels;
// SMAP is supported.
bool   smap_support;
// Process ID bits are supported.
bool   pcid_support;



// Load a word from physical memory.
static inline size_t pmem_load(size_t paddr) {
    assert_dev_drop(paddr < mmu_hhdm_size);
    return *(size_t volatile *)(paddr + mmu_hhdm_vaddr);
}

// Store a word to physical memory.
static inline void pmem_store(size_t paddr, size_t data) {
    assert_dev_drop(paddr < mmu_hhdm_size);
    *(size_t volatile *)(paddr + mmu_hhdm_vaddr) = data;
}



// MMU-specific init code.
void mmu_early_init() {
    // Enable NXE feature.
    msr_efer_t efer;
    efer.val = msr_read(MSR_EFER);
    efer.nxe = 1;
    msr_write(MSR_EFER, efer.val);

    // Check for SMAP support.
    smap_support = cpuid(0x07).ebx & (1 << 20);
    pcid_support = cpuid(0x17).ecx & (1 << 17);

    // Enable PCIDE and SMAP if supported.
    x86_cr4_t cr4;
    asm volatile("mov %0, cr4" : "=r"(cr4));
    cr4.pcide = pcid_support;
    cr4.smap  = smap_support;
    asm volatile("mov cr4, %0" ::"r"(cr4));

    // TODO: Detect number of paging levels supported by the CPU.
    mmu_levels     = 4;
    mmu_half_size  = 1llu << (12 + 9 * mmu_levels);
    mmu_high_vaddr = -mmu_half_size;

    if (smap_support) {
        // The kernel shall, by default, not access user memory.
        asm volatile("stac");
    }
}

// MMU-specific init code.
void mmu_init() {
}



// Read a PTE from the page table.
mmu_pte_t mmu_read_pte(size_t pte_paddr) {
    return (mmu_pte_t){.val = pmem_load(pte_paddr)};
}

// Write a PTE to the page table.
void mmu_write_pte(size_t pte_paddr, mmu_pte_t pte) {
    pmem_store(pte_paddr, pte.val);
}



// Swap in memory protections for the given context.
void memprotect_swap_from_isr() {
    memprotect_swap(isr_ctx_get()->mpu_ctx);
}

// Swap in memory protections for a given context.
void memprotect_swap(mpu_ctx_t *mpu) {
    mpu     = mpu ?: &mpu_global_ctx;
    bool ie = irq_disable();
    // TODO.
    irq_enable_if(ie);
}
