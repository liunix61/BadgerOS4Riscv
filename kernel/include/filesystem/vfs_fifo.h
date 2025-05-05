
// SPDX-License-Identifier: MIT

#pragma once

#include "fifo.h"
#include "filesystem/vfs_internal.h"
#include "scheduler/waitlist.h"
#include "spinlock.h"

// VFS information used to manage FIFOs.
typedef struct vfs_fifo_obj vfs_fifo_obj_t;

// VFS information used to manage FIFOs.
struct vfs_fifo_obj {
    // FIFO data storage.
    fifo_t    *buffer;
    // Spinlock that guards the data storage.
    spinlock_t buffer_lock;
    // Number of readers.
    atomic_int read_count;
    // Number of writers.
    atomic_int write_count;
    // Threads blocked on read.
    waitlist_t read_blocked;
    // Threads blocked on write.
    waitlist_t write_blocked;
};

// Create a FIFO object.
vfs_fifo_obj_t *vfs_fifo_create();
// Destroy a FIFO object.
void            vfs_fifo_destroy(vfs_fifo_obj_t *fobj);

// Handle a file open for a FIFO.
void      vfs_fifo_open(badge_err_t *ec, vfs_fifo_obj_t *fobj, bool nonblock, bool read, bool write);
// Handle a file close for a FIFO.
void      vfs_fifo_close(vfs_fifo_obj_t *fobj, bool had_read, bool had_write);
// Handle a file read for a FIFO.
// WARNING: May sporadically return 0 in a blocking multi-read scenario.
// Raises ECAUSE_PIPE_CLOSED if `enforce_open` is true and the write end is closed.
fileoff_t vfs_fifo_read(badge_err_t *ec, vfs_fifo_obj_t *fobj, bool nonblock, uint8_t *readbuf, fileoff_t readlen);
// Handle a file write for a FIFO.
// Raises ECAUSE_PIPE_CLOSED if `enforce_open` is true and the read end is closed.
fileoff_t vfs_fifo_write(
    badge_err_t *ec, vfs_fifo_obj_t *fobj, bool nonblock, bool enforce_open, uint8_t const *writebuf, fileoff_t writelen
);
