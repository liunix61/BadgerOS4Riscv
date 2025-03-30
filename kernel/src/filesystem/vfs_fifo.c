
// SPDX-License-Identifier: MIT

#include "filesystem/vfs_fifo.h"

#include "assertions.h"
#include "interrupt.h"
#include "malloc.h"

// FIFO object blocking ticket list entry.
typedef struct {
    // Doubly-linked list node.
    dlist_node_t node;
    // Thread to unblock.
    tid_t        thread;
    // Thread's blocking ticket.
    uint64_t     ticket;
} vfs_fifo_ticket_t;



// Create a FIFO object.
vfs_fifo_obj_t *vfs_fifo_create() {
    vfs_fifo_obj_t *fobj = calloc(1, sizeof(vfs_fifo_obj_t));

    if (fobj) {
        fobj->buffer_lock        = SPINLOCK_T_INIT_SHARED;
        fobj->read_blocked_lock  = SPINLOCK_T_INIT;
        fobj->write_blocked_lock = SPINLOCK_T_INIT;
    }

    return fobj;
}

// Destroy a FIFO object.
void vfs_fifo_destroy(vfs_fifo_obj_t *fobj) {
    assert_dev_drop(atomic_load(&fobj->read_count) == 0);
    assert_dev_drop(atomic_load(&fobj->write_count) == 0);

    if (fobj->buffer) {
        fifo_destroy(fobj->buffer);
    }
    free(fobj);
}



// Checks the possible conditions for unblocking for a FIFO on open.
// Takes `buffer_lock` exclusively if unblocked.
// Interrupts muse be disabled and will remain so.
static bool vfs_fifo_open_unblock_check(vfs_fifo_obj_t *fifo, bool as_read) {
    assert_dev_drop(!irq_is_enabled());
    spinlock_take(&fifo->buffer_lock);

    if (as_read ? atomic_load(&fifo->write_count) : atomic_load(&fifo->read_count)) {
        // The other end is open or being opened; unblock.
        return true;
    }

    // Other end is closed; block.
    spinlock_release(&fifo->buffer_lock);
    return false;
}

// Checks the possible conditions for unblocking for a FIFO on read/write.
// Takes `buffer_lock` shared if unblocked.
// Interrupts muse be disabled and will remain so.
static bool vfs_fifo_rw_unblock_check(vfs_fifo_obj_t *fifo, bool as_read) {
    assert_dev_drop(!irq_is_enabled());
    spinlock_take_shared(&fifo->buffer_lock);

    if (fifo->buffer && as_read ? fifo_max_recv(fifo->buffer) : fifo_max_send(fifo->buffer)) {
        // Other end is fully open and data/space is available; unblock.
        return true;
    }

    // Other end is not fully open or no data/space is available; block.
    spinlock_release_shared(&fifo->buffer_lock);
    return false;
}

// Block on a FIFO and take `buffer_lock` afterwards.
// If `as_open` is true, `buffer_lock` is taken exclusive, not shared.
static void vfs_fifo_block(vfs_fifo_obj_t *fifo, bool as_read, bool as_open) {
    dlist_t    *list = as_read ? &fifo->read_blocked : &fifo->write_blocked;
    spinlock_t *lock = as_read ? &fifo->read_blocked_lock : &fifo->write_blocked_lock;

    irq_disable();

    // Insert new blocking ticket into the list.
    vfs_fifo_ticket_t ent;
    ent.thread = sched_current_tid();
    ent.ticket = thread_block();
    spinlock_take(lock);
    dlist_append(list, &ent.node);
    spinlock_release(lock);

    // Double-check blocking condition.
    if (as_open ? vfs_fifo_open_unblock_check(fifo, as_read) : vfs_fifo_rw_unblock_check(fifo, as_read)) {
        // Race condition: The condition to block is no longer satisfied.
        thread_unblock(sched_current_tid(), ent.ticket);
    } else {
        // The condition to block is satisfied after the ticket as added to waiting list;
        // It is now time to yield and therefor block until notified.
        thread_yield();
    }
}

// Resume all readers or writers (but not both) on a FIFO.
// Interrupts muse be disabled and will remain so.
static void vfs_fifo_notify(vfs_fifo_obj_t *fifo, bool notify_readers) {
    assert_dev_drop(!irq_is_enabled());
    dlist_t    *list = notify_readers ? &fifo->read_blocked : &fifo->write_blocked;
    spinlock_t *lock = notify_readers ? &fifo->read_blocked_lock : &fifo->write_blocked_lock;

    spinlock_take(lock);
    vfs_fifo_ticket_t *ent = (void *)list->head;
    while (ent) {
        thread_unblock(ent->thread, ent->ticket);
        ent = (void *)ent->node.next;
    }
    spinlock_release(lock);
}

// Handle a file open for a FIFO.
void vfs_fifo_open(badge_err_t *ec, vfs_fifo_obj_t *fifo, bool nonblock, bool read, bool write) {
    // Open would never block if opened as O_RDWR.
    nonblock |= read && write;

    if (read) {
        atomic_fetch_add(&fifo->read_count, 1);
    }
    if (write) {
        atomic_fetch_add(&fifo->write_count, 1);
    }

    if (!nonblock) {
        vfs_fifo_block(fifo, read, true);
    } else {
        irq_disable();
        spinlock_take(&fifo->buffer_lock);
    }

    // Create the buffer if both read and write are present but it does not yet exist.
    if (atomic_load(&fifo->read_count) && atomic_load(&fifo->write_count) && !fifo->buffer) {
        fifo->buffer = fifo_create(1, 4096);
    }

    spinlock_release(&fifo->buffer_lock);

    // Wake writers waiting on the FIFO.
    vfs_fifo_notify(fifo, false);

    irq_enable();
    badge_err_set_ok(ec);
}

// Handle a file close for a FIFO.
void vfs_fifo_close(vfs_fifo_obj_t *fifo, bool had_read, bool had_write) {
    if (had_read) {
        atomic_fetch_sub(&fifo->read_count, 1);
    }
    if (had_write) {
        atomic_fetch_sub(&fifo->write_count, 1);
    }
}

// Handle a file read for a FIFO.
// WARNING: May sporadically return 0 in a blocking multi-read scenario.
fileoff_t vfs_fifo_read(badge_err_t *ec, vfs_fifo_obj_t *fifo, bool nonblock, uint8_t *readbuf, fileoff_t readlen) {
    if (!nonblock) {
        vfs_fifo_block(fifo, true, false);
    } else {
        irq_disable();
        spinlock_take_shared(&fifo->buffer_lock);
    }

    fileoff_t count = 0;
    if (fifo->buffer) {
        count = fifo_recv_n(fifo->buffer, readbuf, readlen);
        if (!count && nonblock) {
            badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_WOULDBLOCK);
        } else {
            badge_err_set_ok(ec);
        }
    } else {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_WOULDBLOCK);
    }

    spinlock_release_shared(&fifo->buffer_lock);

    // Wake blocking writers.
    vfs_fifo_notify(fifo, false);

    irq_enable();
    return count;
}

// Handle a file write for a FIFO.
// Raises ECAUSE_PIPE_CLOSED if `enforce_open` is true and the read end is closed.
fileoff_t vfs_fifo_write(
    badge_err_t *ec, vfs_fifo_obj_t *fifo, bool nonblock, bool enforce_open, uint8_t const *writebuf, fileoff_t writelen
) {
    if (enforce_open && !atomic_load(&fifo->read_count)) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_PIPE_CLOSED);
        return 0;
    }

    if (!nonblock) {
        vfs_fifo_block(fifo, true, false);
    } else {
        irq_disable();
        spinlock_take_shared(&fifo->buffer_lock);
    }

    fileoff_t count = 0;
    if (fifo->buffer) {
        count = fifo_send_n(fifo->buffer, writebuf, writelen);
        if (!count && nonblock) {
            badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_WOULDBLOCK);
        } else {
            badge_err_set_ok(ec);
        }
    } else {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_WOULDBLOCK);
    }

    spinlock_release_shared(&fifo->buffer_lock);

    // Wake blocking readers.
    vfs_fifo_notify(fifo, true);

    irq_enable();
    return count;
}