
// SPDX-License-Identifier: MIT

#include "signal.h"
#include "syscall.h"



size_t strlen(char const *cstr) {
    char const *pre = cstr;
    while (*cstr) cstr++;
    return cstr - pre;
}

void print(char const *cstr) {
    syscall_temp_write(cstr, strlen(cstr));
}

void putd(uint64_t value, int decimals) {
    char tmp[20];

    int i;
    for (i = 0; i < 20; i++) {
        tmp[19 - i]  = '0' + value % 10;
        value       /= 10;
        if (!value) {
            break;
        }
    }

    if (decimals < i) {
        decimals = i;
    } else if (decimals > 20) {
        decimals = 20;
    }

    syscall_temp_write(tmp + 20 - decimals, decimals);
}

char const hextab[] = "0123456789ABCDEF";

int main() {
    syscall_proc_sighandler(SIGHUP, SIG_IGN);

    print("Hi, Ther.\n");

    // int ec = syscall_fs_mkfifo(-1, "/myfifo", 7);
    // print("mkfifo returned ");
    // putd(ec, 1);
    // print("\n");

    // int fd = syscall_fs_open(-1, "/myfifo", 7, OFLAGS_READWRITE | OFLAGS_NONBLOCK);
    // print("open returned ");
    // putd(fd, 1);
    // print("\n");

    long pipes[2];
    int  ec = syscall_fs_pipe(pipes, 0);
    print("pipe returned ");
    putd(ec, 1);
    print("\n");

    ec = syscall_fs_write(pipes[1], "mydata", 6);
    print("write returned ");
    putd(ec, 1);
    print("\n");

    char mybuf[6];
    int  count = syscall_fs_read(pipes[0], mybuf, 6);
    print("read returned ");
    putd(count, 1);
    print("\n");

    print("Read data:\n");
    syscall_temp_write(mybuf, count);
    print("\n");

    syscall_sys_shutdown(false);

    return 0;
}
