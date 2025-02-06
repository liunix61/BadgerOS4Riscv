
// SPDX-License-Identifier: MIT

#pragma once

#include "list.h"
#include "scheduler/scheduler.h"
#include "time.h"

#include <stdatomic.h>
#include <stdbool.h>

// Semaphore waiting list entry.
typedef struct {
    // Linked list node.
    dlist_node_t node;
    // Thread ID.
    tid_t        tid;
    // Thread blocking ticket.
    uint64_t     ticket;
} sem_waiting_entry_t;

// Semaphore.
typedef struct {
    // Number of times posted.
    atomic_int  available;
    // Spinlock guarding the waiting list.
    atomic_flag wait_spinlock;
    // Threads waiting for the semaphore to be posted.
    dlist_t     waiting_list;
} sem_t;

#define SEM_FAST_LOOPS 256
#define SEM_T_INIT     ((sem_t){0, ATOMIC_FLAG_INIT, DLIST_EMPTY})

// Initialize a new semaphore.
void sem_init(sem_t *sem);
// Clean up a semaphore.
void sem_destroy(sem_t *sem);

// Reset the semaphore count.
void sem_reset(sem_t *sem);
// Post the semaphore once.
void sem_post(sem_t *sem);
// Await the semaphore.
bool sem_await(sem_t *sem, timestamp_us_t timeout);
