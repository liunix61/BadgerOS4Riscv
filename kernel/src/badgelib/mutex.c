
// SPDX-License-Identifier: MIT

#include "mutex.h"

#include "assertions.h"
#include "cpu/isr.h"
#include "interrupt.h"
#include "log.h"
#include "scheduler/isr.h"
#include "scheduler/scheduler.h"
#include "scheduler/types.h"
#include "smp.h"
#include "time.h"

// Magic value for exclusive locking.
#define EXCLUSIVE_MAGIC ((int)__INT_MAX__ / 4)



// Recommended way to create a mutex at run-time.
void mutex_init(badge_err_t *ec, mutex_t *mutex, bool shared) {
    *mutex = ((mutex_t){shared, ATOMIC_FLAG_INIT, 0, {0}});
    atomic_thread_fence(memory_order_release);
    badge_err_set_ok(ec);
}

// Clean up the mutex.
void mutex_destroy(badge_err_t *ec, mutex_t *mutex) {
    // The mutex must always be completely unlocked to guarantee no threads are waiting on it.
    assert_always(mutex->shares == 0);
    assert_dev_drop(!atomic_flag_test_and_set(&mutex->wait_spinlock));
    badge_err_set_ok(ec);
}



// Mutex resume by timer.
static void mutex_unblock_from_timer(void *cookie0) {
    mutex_waiting_entry_t *cookie = cookie0;
    thread_unblock(cookie->tid, cookie->ticket);
}

// Mutex blocking implementation.
// If the mutex's value changes from `double_check_value`,
// the block is instantly cancelled to prevent race conditions locking up the thread.
static void mutex_block(mutex_t *mutex, timestamp_us_t timeout, int double_check_value) {
    irq_disable();

    mutex_waiting_entry_t ent = {
        .node   = DLIST_NODE_EMPTY,
        .tid    = sched_current_tid(),
        .ticket = thread_block(),
    };
    timertask_t task = {
        .callback  = mutex_unblock_from_timer,
        .cookie    = &ent,
        .timestamp = timeout,
    };

    while (atomic_flag_test_and_set_explicit(&mutex->wait_spinlock, memory_order_acquire));
    dlist_append(&mutex->waiting_list, &ent.node);
    atomic_flag_clear_explicit(&mutex->wait_spinlock, memory_order_release);

    if (timeout < TIMESTAMP_US_MAX) {
        time_add_async_task(&task);
    }

    if (atomic_load(&mutex->shares) != double_check_value) {
        // If the value changed, unblock early to prevent race conditions.
        thread_unblock(ent.tid, ent.ticket);
        while (atomic_flag_test_and_set_explicit(&mutex->wait_spinlock, memory_order_acquire));
        dlist_remove(&mutex->waiting_list, &ent.node);
        atomic_flag_clear_explicit(&mutex->wait_spinlock, memory_order_release);
    } else {
        thread_yield();
    }

    if (timeout < TIMESTAMP_US_MAX) {
        time_cancel_async_task(task.taskno);
    }
}

// Notify the first waiting thread of the mutex being released.
static void mutex_notify(mutex_t *mutex) {
    bool ie = irq_disable();
    while (atomic_flag_test_and_set_explicit(&mutex->wait_spinlock, memory_order_acquire));

    mutex_waiting_entry_t *ent;
    do {
        ent = (void *)dlist_pop_front(&mutex->waiting_list);
    } while (ent && !thread_unblock(ent->tid, ent->ticket));

    atomic_flag_clear_explicit(&mutex->wait_spinlock, memory_order_release);
    irq_enable_if(ie);
}

// Atomically await the expected value and swap in the new value.
static inline bool
    await_swap_atomic_int(mutex_t *mutex, timestamp_us_t timeout, int expected, int new_value, memory_order order) {
    int loops = MUTEX_FAST_LOOPS;
    do {
        int old_value = expected;
        if (atomic_compare_exchange_weak_explicit(&mutex->shares, &old_value, new_value, order, memory_order_relaxed)) {
            return true;
        } else if (loops) {
            loops--;
        } else {
            mutex_block(mutex, timeout, old_value);
        }
    } while (time_us() < timeout);
    return false;
}

// Atomically check the value does not exceed a threshold and add 1.
static inline bool thresh_add_atomic_int(mutex_t *mutex, timestamp_us_t timeout, int threshold, memory_order order) {
    int old_value = atomic_load(&mutex->shares);
    int loops     = MUTEX_FAST_LOOPS;
    do {
        int new_value = old_value + 1;
        if (!(old_value >= threshold || new_value >= threshold) &&
            atomic_compare_exchange_weak_explicit(&mutex->shares, &old_value, new_value, order, memory_order_relaxed)) {
            return true;
        } else if (loops) {
            loops--;
        } else {
            mutex_block(mutex, timeout, old_value);
        }
    } while (time_us() < timeout);
    return false;
}

// Atomically check the value doesn't equal either illegal values and subtract 1.
static inline bool unequal_sub_atomic_int(mutex_t *mutex, int unequal0, int unequal1, memory_order order) {
    int old_value = atomic_load(&mutex->shares);
    while (1) {
        int new_value = old_value - 1;
        if (!(old_value == unequal0 || old_value == unequal1) &&
            atomic_compare_exchange_weak_explicit(&mutex->shares, &old_value, new_value, order, memory_order_relaxed)) {
            return true;
        } else {
            thread_yield();
        }
    }
}



// Try to acquire `mutex` within `timeout` microseconds.
// Returns true if the mutex was successully acquired.
bool mutex_acquire(badge_err_t *ec, mutex_t *mutex, timestamp_us_t timeout) {
    // Compute timeout.
    timestamp_us_t now = time_us();
    if (timeout < 0 || timeout - TIMESTAMP_US_MAX + now >= 0) {
        timeout = TIMESTAMP_US_MAX;
    } else {
        timeout += now;
    }
    // Await the shared portion to reach 0 and then lock.
    if (await_swap_atomic_int(mutex, timeout, 0, EXCLUSIVE_MAGIC, memory_order_acquire)) {
        // If that succeeds, the mutex was acquired.
        badge_err_set_ok(ec);
        return true;
    } else {
        // Acquire failed.
        badge_err_set(ec, ELOC_UNKNOWN, ECAUSE_TIMEOUT);
        return false;
    }
}

// Release `mutex`, if it was initially acquired by this thread.
// Returns true if the mutex was successfully released.
bool mutex_release(badge_err_t *ec, mutex_t *mutex) {
    assert_dev_drop(atomic_load(&mutex->shares) >= EXCLUSIVE_MAGIC);
    if (await_swap_atomic_int(mutex, TIMESTAMP_US_MAX, EXCLUSIVE_MAGIC, 0, memory_order_release)) {
        // Successful release.
        mutex_notify(mutex);
        badge_err_set_ok(ec);
        return true;
    } else {
        // Mutex was not taken exclusively.
        badge_err_set(ec, ELOC_UNKNOWN, ECAUSE_ILLEGAL);
        return false;
    }
}

// Try to acquire a share in `mutex` within `timeout` microseconds.
// Returns true if the share was successfully acquired.
bool mutex_acquire_shared(badge_err_t *ec, mutex_t *mutex, timestamp_us_t timeout) {
    if (!mutex->is_shared) {
        badge_err_set(ec, ELOC_UNKNOWN, ECAUSE_ILLEGAL);
        return false;
    }
    // Compute timeout.
    timestamp_us_t now = time_us();
    if (timeout < 0 || timeout - TIMESTAMP_US_MAX + now >= 0) {
        timeout = TIMESTAMP_US_MAX;
    } else {
        timeout += now;
    }
    // Take a share.
    if (thresh_add_atomic_int(mutex, timeout, EXCLUSIVE_MAGIC, memory_order_acquire)) {
        // If that succeeds, the mutex was successfully acquired.
        badge_err_set_ok(ec);
        return true;
    } else {
        // If that fails, abort trying to lock.
        badge_err_set(ec, ELOC_UNKNOWN, ECAUSE_TIMEOUT);
        return false;
    }
}

// Release `mutex`, if it was initially acquired by this thread.
// Returns true if the mutex was successfully released.
bool mutex_release_shared(badge_err_t *ec, mutex_t *mutex) {
    assert_dev_drop(atomic_load(&mutex->shares) < EXCLUSIVE_MAGIC);
    if (!unequal_sub_atomic_int(mutex, 0, EXCLUSIVE_MAGIC, memory_order_release)) {
        // Prevent the counter from underflowing.
        badge_err_set(ec, ELOC_UNKNOWN, ECAUSE_ILLEGAL);
        return false;
    } else {
        // Successful release.
        mutex_notify(mutex);
        badge_err_set_ok(ec);
        return true;
    }
}
