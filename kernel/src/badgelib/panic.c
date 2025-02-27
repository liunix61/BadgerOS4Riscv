
// SPDX-License-Identifier: MIT

#include "panic.h"

#include "backtrace.h"
#include "interrupt.h"
#include "isr_ctx.h"
#include "log.h"
#include "rawprint.h"

#include <stdatomic.h>

void abort() {
    panic_abort();
}

void cpu_panic_poweroff();

static void kekw() {
    // clang-format off
    char const *const msg =
    "======+++++++***************####**++++++========" "\n"
    "=--:::----:-==++*****+++++==++++*+====---=======" "\n"
    "-::........::-==++++++===--:::.:::::::-=========" "\n"
    ":::----=---:::-====++===--:::...::-=============" "\n"
    "--==+++++=+++=::--==+++=----==+++++***+++=======" "\n"
    ":.      :----======+#*++===-===---:.:::::--=====" "\n"
    "=----===+++++======+**++++=====--::-===---------" "\n"
    "==----:-==========++++++++++++====++++**++====++" "\n"
    "========+++========+++++++++++++++=======+++=+++" "\n"
    "=====++++++========++++====+++***++++++**#*+++++" "\n"
    "=====++++++=======++====-=====+*##******##*+++++" "\n"
    "===+++++=======+++**+==-=========*#######*++++++" "\n"
    "=========-===---========+++=--=*+==+****++++++++" "\n"
    "---====--==:...:----::.  .::::=========+++======" "\n"
    "-------:--:..........:::::::::::::-=--==========" "\n"
    "--------:. .. ....:-:. .::...:::..::----========" "\n"
    "-------:...........--....::...::...::::---======" "\n"
    "------:. .........-===:.:::...:::......:---=====" "\n"
    "-----=-. .... ..     ..........:::::::.  :--====" "\n"
    "------=-::-...+##=                    ::-:-=====" "\n"
    "::::--====-=+:     :::......:--=----:.-----====-" "\n"
    ".::----==--=+=--=+++**********++==---===--===---" "\n"
    ".:-:-=--===-==--=+****++++++++++=--=*===-====---" "\n"
    "..:-:==-======---=++++++++====---===+========---" "\n"
    "..:---==-=====---==========+#*=--==+++=======--=" "\n"
    "...--:=+===---============++++=====++=======---=" "\n";
    // clang-format on
    // c9 8d 74
    rawprint("\033[38;2;201;141;116m\n\n");
    rawprint(msg);
    rawprint("\033[0m\n\n");
}

static atomic_int panic_flag;

// Try to atomically claim the panic flag.
// Only ever call this if a subsequent call to `panic_abort_unchecked` or `panic_poweroff_unchecked` is imminent.
void claim_panic() {
    if (atomic_fetch_add_explicit(&panic_flag, 1, memory_order_release)) {
        // Didn't win the flag.
        cpu_panic_poweroff();
    }
}

// Like `panic_abort`, but does not check the panic flag.
void panic_abort_unchecked() {
    logkf_from_isr(LOG_FATAL, "`panic_abort()` called!");
    backtrace();
    kernel_cur_regs_dump();
    panic_poweroff_unchecked();
}

// Like `panic_poweroff`, but does not check the panic flag.
void panic_poweroff_unchecked() {
    rawprint("**** KERNEL PANIC ****\n");
    int also = atomic_load_explicit(&panic_flag, memory_order_relaxed) - 1;
    if (also) {
        rawprintdec(also, 0);
        rawprint(" other CPU");
        if (also != 1) {
            rawputc('s');
        }
        rawprint(" also panicked\n");
    }
    kekw();
    cpu_panic_poweroff();
}

// Call this function when and only when the kernel has encountered a fatal error.
// Prints register dump for current kernel context and jumps to `panic_poweroff`.
void panic_abort() {
    claim_panic();
    panic_abort_unchecked();
}

// Call this function when and only when the kernel has encountered a fatal error.
// Immediately power off or reset the system.
void panic_poweroff() {
    claim_panic();
    panic_poweroff_unchecked();
}

// Check for a panic and immediately halt if it has happened.
void check_for_panic() {
    if (atomic_load_explicit(&panic_flag, memory_order_relaxed)) {
        // If the flag is set, some other core must have panicked.
        cpu_panic_poweroff();
    }
}
