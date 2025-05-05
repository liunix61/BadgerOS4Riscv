
// SPDX-License-Identifier: MIT

#include "semaphore.h"

#include "assertions.h"
#include "scheduler/waitlist.h"



// Initialize a new semaphore.
void sem_init(sem_t *sem) {
    *sem = (sem_t)SEM_T_INIT;
    atomic_thread_fence(memory_order_release);
}

// Clean up a semaphore.
void sem_destroy(sem_t *sem) {
    assert_dev_drop(!sem->waiting_list.list.len);
}

// Reset the semaphore count.
void sem_reset(sem_t *sem) {
    atomic_store_explicit(&sem->available, 0, memory_order_relaxed);
}

// Post the semaphore once.
void sem_post(sem_t *sem) {
    assert_dev_keep(atomic_fetch_add(&sem->available, 1) < __INT_MAX__);
    waitlist_notify(&sem->waiting_list);
}

static bool sem_block_double_check(void *cookie) {
    sem_t *sem = cookie;
    return atomic_load_explicit(&sem->available, memory_order_relaxed) == 0;
}

// Block on a semaphore.
static void sem_block(sem_t *sem, timestamp_us_t timeout) {
    waitlist_block(&sem->waiting_list, timeout, sem_block_double_check, sem);
}

// Await the semaphore.
bool sem_await(sem_t *sem, timestamp_us_t timeout) {
    // Compute timeout.
    timestamp_us_t now = time_us();
    if (timeout < 0 || timeout - TIMESTAMP_US_MAX + now >= 0) {
        timeout = TIMESTAMP_US_MAX;
    } else {
        timeout += now;
    }

    int cur = atomic_load_explicit(&sem->available, memory_order_relaxed);

    // Fast path.
    for (int i = SEM_FAST_LOOPS; i >= 0; i--) {
        assert_dev_drop(cur >= 0);
        if (!cur) {
            cur = atomic_load_explicit(&sem->available, memory_order_relaxed);
        } else if (atomic_compare_exchange_weak_explicit(
                       &sem->available,
                       &cur,
                       cur - 1,
                       memory_order_acquire,
                       memory_order_relaxed
                   )) {
            return true;
        }
    }

    // Slow path.
    while (time_us() < timeout) {
        assert_dev_drop(cur >= 0);
        if (!cur) {
            sem_block(sem, timeout);
            cur = atomic_load_explicit(&sem->available, memory_order_relaxed);

        } else if (atomic_compare_exchange_weak_explicit(
                       &sem->available,
                       &cur,
                       cur - 1,
                       memory_order_acquire,
                       memory_order_relaxed
                   )) {
            return true;
        }
    }

    return false;
}
