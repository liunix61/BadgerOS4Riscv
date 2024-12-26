
// SPDX-License-Identifier: MIT

#include "panic.h"

#include "backtrace.h"
#include "interrupt.h"
#include "isr_ctx.h"
#include "log.h"
#include "rawprint.h"

void abort() {
    panic_abort();
}

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

// Call this function when and only when the kernel has encountered a fatal error.
// Prints register dump for current kernel context and jumps to `panic_poweroff`.
void panic_abort() {
    irq_disable();
    logkf_from_isr(LOG_FATAL, "`panic_abort()` called!");
    backtrace();
    kernel_cur_regs_dump();
    panic_poweroff();
}

// Call this function when and only when the kernel has encountered a fatal error.
// Immediately power off or reset the system.
void panic_poweroff() {
    rawprint("**** KERNEL PANIC ****\nhalted\n");
    kekw();
    asm volatile("csrci " CSR_STATUS_STR ", %0" ::"ri"(1 << CSR_STATUS_IE_BIT));
    while (1) asm volatile("wfi");
}
