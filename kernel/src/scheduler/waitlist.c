
// SPDX-License-Identifier: MIT

#include "scheduler/waitlist.h"

#include "assertions.h"
#include "cpu/interrupt.h"
#include "list.h"
#include "scheduler/isr.h"
#include "scheduler/scheduler.h"
#include "spinlock.h"
#include "time.h"



// Resume a blocked thread by means of a timer.
static void timer_resume(void *arg) {
    waitlist_ent_t *ent = arg;
    thread_unblock(ent->thread, ent->ticket);
}

// Block on a waiting list.
// Runs `double_check(cookie)` and unblocks if false to prevent race conditions.
void waitlist_block(waitlist_t *list, timestamp_us_t timeout, bool (*double_check)(void *), void *cookie) {
    bool ie = irq_disable();

    waitlist_ent_t ent = {
        .node    = DLIST_NODE_EMPTY,
        .in_list = true,
        .thread  = sched_current_tid(),
        .ticket  = thread_block(),
    };
    timertask_t task = {
        .callback  = timer_resume,
        .cookie    = &ent,
        .timestamp = timeout,
    };

    spinlock_take(&list->lock);
    dlist_append(&list->list, &ent.node);
    spinlock_release(&list->lock);

    if (timeout < TIMESTAMP_US_MAX) {
        time_add_async_task(&task);
    }

    if (!double_check(cookie)) {
        thread_unblock(ent.thread, ent.ticket);
        irq_enable();
    } else {
        thread_yield();
    }

    if (timeout < TIMESTAMP_US_MAX) {
        time_cancel_async_task(task.taskno);
    }

    assert_dev_keep(irq_disable());
    spinlock_take(&list->lock);
    if (ent.in_list) {
        dlist_remove(&list->list, &ent.node);
    } else {
        assert_dev_drop(!dlist_contains(&list->list, &ent.node));
    }
    spinlock_release(&list->lock);
    irq_enable_if(ie);
}

// Try to resume a thread blocked on the waiting list.
void waitlist_notify(waitlist_t *list) {
    bool ie = irq_disable();
    spinlock_take(&list->lock);

    while (1) {
        waitlist_ent_t *ent = (waitlist_ent_t *)dlist_pop_front(&list->list);
        if (!ent)
            break;
        ent->in_list = false;
        if (thread_unblock(ent->thread, ent->ticket))
            break;
    }

    spinlock_release(&list->lock);
    irq_enable_if(ie);
}
