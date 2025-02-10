
// SPDX-License-Identifier: MIT

#pragma once

#include "list.h"
#include "time.h"

#include <stdatomic.h>
#include <stdbool.h>

// A mutex.
typedef struct {
    // Mutex allows sharing.
    bool        is_shared;
    // Spinlock guarding the waiting list.
    atomic_flag wait_spinlock;
    // Share count and/or is locked.
    atomic_int  shares;
    // List of threads waiting for this mutex.
    dlist_t     waiting_list;
} mutex_t;

#include "badge_err.h"
#include "scheduler/scheduler.h"

// Mutex waiting list entry.
typedef struct {
    // Linked list node.
    dlist_node_t node;
    // Thread ID.
    tid_t        tid;
    // Thread blocking ticket.
    uint64_t     ticket;
} mutex_waiting_entry_t;

#define MUTEX_FAST_LOOPS    256
#define MUTEX_T_INIT        ((mutex_t){0, ATOMIC_FLAG_INIT, 0, {0}})
#define MUTEX_T_INIT_SHARED ((mutex_t){1, ATOMIC_FLAG_INIT, 0, {0}})



// Recommended way to create a mutex at run-time.
void mutex_init(badge_err_t *ec, mutex_t *mutex, bool shared);
// Clean up the mutex.
void mutex_destroy(badge_err_t *ec, mutex_t *mutex);

// Try to acquire `mutex` within `max_wait_us` microseconds.
// If `max_wait_us` is too long or negative, do not use the timeout.
// Returns true if the mutex was successully acquired.
bool mutex_acquire(badge_err_t *ec, mutex_t *mutex, timestamp_us_t max_wait_us);
// Release `mutex`, if it was initially acquired by this thread.
// Returns true if the mutex was successfully released.
bool mutex_release(badge_err_t *ec, mutex_t *mutex);

// Try to acquire a share in `mutex` within `max_wait_us` microseconds.
// If `max_wait_us` is too long or negative, do not use the timeout.
// Returns true if the share was successfully acquired.
bool mutex_acquire_shared(badge_err_t *ec, mutex_t *mutex, timestamp_us_t max_wait_us);
// Release `mutex`, if it was initially acquired by this thread.
// Returns true if the mutex was successfully released.
bool mutex_release_shared(badge_err_t *ec, mutex_t *mutex);
