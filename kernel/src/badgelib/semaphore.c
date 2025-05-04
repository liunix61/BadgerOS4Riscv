
// SPDX-License-Identifier: MIT

#include "semaphore.h"

#include "assertions.h"
#include "interrupt.h"
#include "scheduler/isr.h"
#include "scheduler/types.h"



// Initialize a new semaphore.
void sem_init(sem_t *sem) {
    *sem = SEM_T_INIT;
    atomic_thread_fence(memory_order_release);
}

// Clean up a semaphore.
void sem_destroy(sem_t *sem) {
    assert_dev_drop(!atomic_flag_test_and_set(&sem->wait_spinlock));
    assert_dev_drop(!sem->waiting_list.len);
}

// Reset the semaphore count.
void sem_reset(sem_t *sem) {
    atomic_store_explicit(&sem->available, 0, memory_order_relaxed);
}

// Post the semaphore once.
void sem_post(sem_t *sem) {
    assert_dev_keep(atomic_fetch_add(&sem->available, 1) < __INT_MAX__);
    irq_disable();
    while (atomic_flag_test_and_set_explicit(&sem->wait_spinlock, memory_order_acquire));
    sem_waiting_entry_t *first = (void *)dlist_pop_front(&sem->waiting_list);
    if (first) {
        thread_unblock(first->tid, first->ticket);
    }
    atomic_flag_clear_explicit(&sem->wait_spinlock, memory_order_release);
    irq_enable();
}

// Wake from teh timeout.
static void sem_unblock_from_timer(void *cookie0) {
    sem_waiting_entry_t *cookie = cookie0;
    thread_unblock(cookie->tid, cookie->ticket);
}

// Block on a semaphore.
static void sem_block(sem_t *sem, timestamp_us_t timeout) {
    irq_disable();

    sem_waiting_entry_t ent = {
        .node   = DLIST_NODE_EMPTY,
        .tid    = sched_current_tid(),
        .ticket = thread_block(),
    };
    timertask_t task = {
        .callback  = sem_unblock_from_timer,
        .cookie    = &ent,
        .timestamp = timeout,
    };

    while (atomic_flag_test_and_set_explicit(&sem->wait_spinlock, memory_order_acquire));
    dlist_append(&sem->waiting_list, &ent.node);
    atomic_flag_clear_explicit(&sem->wait_spinlock, memory_order_release);

    if (timeout < TIMESTAMP_US_MAX) {
        time_add_async_task(&task);
    }

    if (atomic_load_explicit(&sem->available, memory_order_relaxed)) {
        thread_unblock(ent.tid, ent.ticket);
        while (atomic_flag_test_and_set_explicit(&sem->wait_spinlock, memory_order_acquire));
        if (ent.node.next) {
            dlist_remove(&sem->waiting_list, &ent.node);
        }
        atomic_flag_clear_explicit(&sem->wait_spinlock, memory_order_release);
    } else {
        thread_yield();
    }

    if (timeout < TIMESTAMP_US_MAX) {
        time_cancel_async_task(task.taskno);
    }
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
