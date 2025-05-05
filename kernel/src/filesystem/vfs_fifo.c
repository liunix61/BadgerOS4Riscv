
// SPDX-License-Identifier: MIT

#include "filesystem/vfs_fifo.h"

#include "assertions.h"
#include "cpu/interrupt.h"
#include "interrupt.h"
#include "malloc.h"
#include "scheduler/waitlist.h"
#include "spinlock.h"
#include "time.h"

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
        fobj->buffer_lock   = SPINLOCK_T_INIT_SHARED;
        fobj->read_blocked  = (waitlist_t)WAITLIST_T_INIT;
        fobj->write_blocked = (waitlist_t)WAITLIST_T_INIT;
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

// Checks the possible conditions for unblocking for a FIFO.
// If `as_open` is true, `buffer_lock` is taken exclusive, not shared.
// Interrupts muse be disabled and will remain so.
static bool vfs_fifo_unblock_check(void *cookie) {
    struct {
        vfs_fifo_obj_t *fifo;
        bool            as_read;
        bool            as_open;
        bool            did_take_lock;
    } *data = cookie;
    if (data->as_open) {
        data->did_take_lock = vfs_fifo_open_unblock_check(data->fifo, data->as_read);
    } else {
        data->did_take_lock = vfs_fifo_rw_unblock_check(data->fifo, data->as_read);
    }
    return !data->did_take_lock;
}

// Block on a FIFO and take `buffer_lock` afterwards.
// If `as_open` is true, `buffer_lock` is taken exclusive, not shared.
// Interrupts muse be disabled and will remain so.
static void vfs_fifo_block(vfs_fifo_obj_t *fifo, bool as_read, bool as_open) {
    assert_dev_drop(!irq_is_enabled());
    waitlist_t *list = as_read ? &fifo->read_blocked : &fifo->write_blocked;
    struct {
        vfs_fifo_obj_t *fifo;
        bool            as_read;
        bool            as_open;
        bool            did_take_lock;
    } data = {
        fifo,
        as_read,
        as_open,
        false,
    };
    waitlist_block(list, TIMESTAMP_US_MAX, vfs_fifo_unblock_check, &data);
    if (!data.did_take_lock) {
        if (as_open) {
            spinlock_take(&fifo->buffer_lock);
        } else {
            spinlock_take_shared(&fifo->buffer_lock);
        }
    }
}

// Resume all readers or writers (but not both) on a FIFO.
// Interrupts muse be disabled and will remain so.
static void vfs_fifo_notify(vfs_fifo_obj_t *fifo, bool notify_readers) {
    assert_dev_drop(!irq_is_enabled());
    waitlist_t *list = notify_readers ? &fifo->read_blocked : &fifo->write_blocked;
    waitlist_notify(list);
}

// Handle a file open for a FIFO.
void vfs_fifo_open(badge_err_t *ec, vfs_fifo_obj_t *fifo, bool nonblock, bool read, bool write) {
    assert_dev_keep(irq_disable());

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
    assert_dev_keep(irq_disable());
    if (!nonblock) {
        vfs_fifo_block(fifo, true, false);
    } else {
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
    assert_dev_keep(irq_disable());
    if (enforce_open && !atomic_load(&fifo->read_count)) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_PIPE_CLOSED);
        return 0;
    }

    if (!nonblock) {
        vfs_fifo_block(fifo, false, false);
    } else {
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