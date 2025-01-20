
#include "interrupt.h"

#include "assertions.h"
#include "malloc.h"
#include "panic.h"
#include "spinlock.h"

// This file implements ISRs by having a linked list per IRQ.
// It is possible to omit IRQs without ISRs,
// but doing so would involve a search of some kind during an interrupt,
// which would take more time than doing this.

// Installed ISR.
struct isr_entry {
    // Linked list node.
    dlist_node_t node;
    // IRQ to which this ISR belongs; used for removing ISRs.
    int          irq;
    // ISR function.
    isr_t        isr;
    // ISR cookie.
    void        *cookie;
};

// Spinlock that prevents concurrent IRQ servicing and list modification.
static spinlock_t isr_spinlock = SPINLOCK_T_INIT_SHARED;
// Array of ISR linked lists by IRQ number.
static int        isr_list_len;
// Array of ISR linked lists by IRQ number.
static dlist_t   *isr_list;



// Add an ISR to a certain IRQ.
isr_handle_t isr_install(int irq, isr_t isr_func, void *cookie) {
    assert_dev_drop(irq >= 0);
    isr_entry_t *entry = malloc(sizeof(isr_entry_t));
    entry->isr         = isr_func;
    entry->cookie      = cookie;

    bool ie = irq_disable();
    spinlock_take(&isr_spinlock);

    if (irq >= isr_list_len) {
        void *mem = realloc(isr_list, sizeof(dlist_t) * (irq + 1));
        if (!mem) {
            spinlock_release(&isr_spinlock);
            irq_enable_if(ie);
            free(entry);
            return NULL;
        }

        isr_list = mem;
        for (int i = isr_list_len; i <= irq; i++) {
            isr_list[i] = DLIST_EMPTY;
        }
        isr_list_len = irq + 1;
    }

    dlist_append(&isr_list[irq], &entry->node);

    spinlock_release(&isr_spinlock);
    irq_enable_if(ie);

    return entry;
}

// Remove an ISR.
void isr_remove(isr_handle_t handle) {
    bool ie = irq_disable();
    spinlock_take(&isr_spinlock);

    dlist_remove(&isr_list[handle->irq], &handle->node);

    spinlock_release(&isr_spinlock);
    irq_enable_if(ie);
}



// Generic interrupt handler that runs all callbacks on an IRQ.
void generic_interrupt_handler(int irq) {
    spinlock_take_shared(&isr_spinlock);

    // Assert that at least one ISR services this IRQ.
    if (irq < 0 || irq >= isr_list_len || !isr_list[irq].len) {
        logkf_from_isr(LOG_FATAL, "Unhandled IRQ #%{d}", irq);
        panic_abort();
    }

    // Run all ISRs attached to this IRQ.
    dlist_node_t *node = isr_list[irq].head;
    while (node) {
        isr_entry_t *handle = (void *)node;
        handle->isr(irq, handle->cookie);
        node = node->next;
    }

    spinlock_release_shared(&isr_spinlock);
}
