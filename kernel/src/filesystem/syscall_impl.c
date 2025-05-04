
// SPDX-License-Identifier: MIT

#include "filesystem/syscall_impl.h"

#include "filesystem.h"
#include "port/hardware_allocation.h"
#include "process/internal.h"
#include "syscall_util.h"
#include "usercopy.h"
#if MEMMAP_VMEM
#include "cpu/mmu.h"
#endif

// Open a file, optionally relative to a directory.
// Returns <= -1 on error, file descriptor number of success.
file_t syscall_fs_open(file_t dirfd, char const *path, size_t path_len, int oflags) {
    sysutil_memassert(path, path_len, MEMPROTECT_FLAG_R);

    if (path_len > FILESYSTEM_PATH_MAX) {
        return -ECAUSE_TOOLONG;
    } else if (oflags & KOFLAGS_MASK) {
        return -ECAUSE_PARAM;
    }
    process_t *const proc = proc_current();

#if MEMMAP_VMEM
    // Safely copy the path from user memory to the kernel stack.
    char k_path[FILESYSTEM_PATH_MAX + 1];
    copy_from_user_raw(proc_current(), k_path, (size_t)path, path_len);
#else
    // No MMU so it's not necessary to copy this path.
    char const *k_path = path;
#endif

    // Actually open the file.
    file_t fd   = fs_open(NULL, dirfd, k_path, path_len, oflags);
    file_t u_fd = -1;

    if (fd >= 0) {
        badge_err_t ec;
        // If successful, try to add this file descriptor to the process.
        u_fd = proc_add_fd_raw(&ec, proc, fd);
        if (!badge_err_is_ok(&ec)) {
            fs_close(NULL, fd);
            u_fd = -ec.cause;
        }
    }

    return u_fd;
}

// Flush and close a file.
int syscall_fs_close(file_t u_fd) {
    process_t *const proc = proc_current();
    badge_err_t      ec;
    file_t           fd = proc_find_fd_raw(NULL, proc_current(), u_fd);
    proc_remove_fd_raw(&ec, proc, u_fd);
    if (!badge_err_is_ok(&ec)) {
        return -ec.cause;
    } else {
        fs_close(NULL, fd);
        return 0;
    }
}

// Read bytes from a file.
// Returns -1 on EOF, <= -2 on error, read count on success.
long syscall_fs_read(file_t u_fd, void *read_buf, long read_len) {
    sysutil_memassert(read_buf, read_len, MEMPROTECT_FLAG_W);

    badge_err_t ec;
    file_t      fd = proc_find_fd_raw(&ec, proc_current(), u_fd);
    if (fd != -1) {
#if MEMMAP_VMEM
        mmu_enable_sum();
#endif
        fileoff_t read = fs_read(&ec, fd, read_buf, read_len);
#if MEMMAP_VMEM
        mmu_disable_sum();
#endif
        if (read <= 0) {
            return -ec.cause;
        }
        return read;
    }
    return -ec.cause;
}

// Write bytes to a file.
// Returns <= -1 on error, write count on success.
long syscall_fs_write(file_t u_fd, void const *write_buf, long write_len) {
    sysutil_memassert(write_buf, write_len, MEMPROTECT_FLAG_R);

    badge_err_t ec;
    file_t      fd = proc_find_fd_raw(&ec, proc_current(), u_fd);
    if (fd != -1) {
#if MEMMAP_VMEM
        mmu_enable_sum();
#endif
        fileoff_t written = fs_write(&ec, fd, write_buf, write_len);
#if MEMMAP_VMEM
        mmu_disable_sum();
#endif
        if (written <= 0) {
            return -ec.cause;
        }
        return written;
    }
    return -ec.cause;
}

// Read directory entries from a directory handle.
// See `dirent_t` for the format.
// Returns <= -1 on error, read count on success.
long syscall_fs_getdents(file_t u_fd, void *read_buf, long read_len) {
    sysutil_memassert(read_buf, read_len, MEMPROTECT_FLAG_W);
    file_t fd = proc_find_fd_raw(NULL, proc_current(), u_fd);
    fs_seek(NULL, fd, 0, SEEK_ABS);
    return fs_read(NULL, fd, read_buf, read_len);
}

// Get file status given file handler or path, optionally following the final symlink.
// If `path` is specified, it is interpreted as relative to the working directory.
// If both `path` and `fd` are specified, `path` is relative to the directory that `fd` describes.
// If only `fd` is specified, the inode referenced by `fd` is stat'ed.
// If `follow_link` is false, the last symlink in the path is not followed.
int syscall_fs_stat(file_t fd, char const *path, size_t path_len, bool follow_link, stat_t *stat_out) {
    sysutil_memassert(path, path_len, MEMPROTECT_FLAG_R);
    sysutil_memassert(stat_out, sizeof(stat_t), MEMPROTECT_FLAG_W);
    if (path_len > FILESYSTEM_PATH_MAX) {
        return -ECAUSE_TOOLONG;
    }

    badge_err_t ec;

#if MEMMAP_VMEM
    // Safely copy the path from user memory to the kernel stack.
    char k_path[FILESYSTEM_PATH_MAX + 1];
    copy_from_user_raw(proc_current(), k_path, (size_t)path, path_len);

    stat_t stat_tmp;
    fs_stat(&ec, fd, k_path, path_len, follow_link, &stat_tmp);
    copy_to_user_raw(proc_current(), (size_t)stat_out, &stat_tmp, sizeof(stat_t));
#else
    fs_stat(&ec, fd, path, path_len, follow_link, stat_out);
#endif

    return -ec.cause;
}

// Create a new directory.
// If `at` is -1, `path` is relative to the working directory.
// Returns <= -1 on error, file 0 on success.
int syscall_fs_mkdir(file_t at, char const *path, size_t path_len) {
    sysutil_memassert(path, path_len, MEMPROTECT_FLAG_R);
    if (path_len > FILESYSTEM_PATH_MAX) {
        return -ECAUSE_TOOLONG;
    }

    badge_err_t ec;

#if MEMMAP_VMEM
    // Safely copy the path from user memory to the kernel stack.
    char k_path[FILESYSTEM_PATH_MAX + 1];
    copy_from_user_raw(proc_current(), k_path, (size_t)path, path_len);

    fs_mkdir(&ec, at, k_path, path_len);
#else
    fs_mkdir(&ec, fd, path, path_len);
#endif

    return -ec.cause;
}

// Delete a directory if it is empty.
// If `at` is -1, `path` is relative to the working directory.
// Returns <= -1 on error, file 0 on success.
int syscall_fs_rmdir(file_t at, char const *path, size_t path_len) {
    sysutil_memassert(path, path_len, MEMPROTECT_FLAG_R);
    if (path_len > FILESYSTEM_PATH_MAX) {
        return -ECAUSE_TOOLONG;
    }

    badge_err_t ec;

#if MEMMAP_VMEM
    // Safely copy the path from user memory to the kernel stack.
    char k_path[FILESYSTEM_PATH_MAX + 1];
    copy_from_user_raw(proc_current(), k_path, (size_t)path, path_len);

    fs_rmdir(&ec, at, k_path, path_len);
#else
    fs_rmdir(&ec, fd, path, path_len);
#endif

    return -ec.cause;
}

// Create a new link to an existing inode.
// If `*_at` is -1, the respective `*_path` is relative to the working directory.
// Returns <= -1 on error, file 0 on success.
int syscall_fs_link(
    file_t old_at, char const *old_path, size_t old_path_len, file_t new_at, char const *new_path, size_t new_path_len
) {
    sysutil_memassert(old_path, old_path_len, MEMPROTECT_FLAG_R);
    sysutil_memassert(new_path, new_path_len, MEMPROTECT_FLAG_R);
    if (old_path_len > FILESYSTEM_PATH_MAX || new_path_len > FILESYSTEM_PATH_MAX) {
        return -ECAUSE_TOOLONG;
    }

    badge_err_t ec;

#if MEMMAP_VMEM
    char k_old_path[FILESYSTEM_PATH_MAX + 1];
    copy_from_user_raw(proc_current(), k_old_path, (size_t)old_path, old_path_len);

    char k_new_path[FILESYSTEM_PATH_MAX + 1];
    copy_from_user_raw(proc_current(), k_new_path, (size_t)new_path, new_path_len);

    fs_link(&ec, old_at, k_old_path, old_path_len, new_at, k_new_path, new_path_len);
#else
    fs_link(&ec, old_at, old_path, old_path_len, new_at, new_path, new_path_len);
#endif

    return -ec.cause;
}

// Remove a link to an inode. If it is the last link, the file is deleted.
// If `at` is -1, `path` is relative to the working directory.
// Returns <= -1 on error, file 0 on success.
int syscall_fs_unlink(file_t at, char const *path, size_t path_len) {
    sysutil_memassert(path, path_len, MEMPROTECT_FLAG_R);
    if (path_len > FILESYSTEM_PATH_MAX) {
        return -ECAUSE_TOOLONG;
    }

    badge_err_t ec;

#if MEMMAP_VMEM
    // Safely copy the path from user memory to the kernel stack.
    char k_path[FILESYSTEM_PATH_MAX + 1];
    copy_from_user_raw(proc_current(), k_path, (size_t)path, path_len);

    fs_unlink(&ec, at, k_path, path_len);
#else
    fs_unlink(&ec, fd, path, path_len);
#endif

    return -ec.cause;
}

// Create a new FIFO / named pipe.
// If `at` is -1, `path` is relative to the working directory.
// Returns <= -1 on error, file 0 on success.
int syscall_fs_mkfifo(file_t at, char const *path, size_t path_len) {
    sysutil_memassert(path, path_len, MEMPROTECT_FLAG_R);
    if (path_len > FILESYSTEM_PATH_MAX) {
        return -ECAUSE_TOOLONG;
    }

    badge_err_t ec;

#if MEMMAP_VMEM
    // Safely copy the path from user memory to the kernel stack.
    char k_path[FILESYSTEM_PATH_MAX + 1];
    copy_from_user_raw(proc_current(), k_path, (size_t)path, path_len);

    fs_mkfifo(&ec, at, k_path, path_len);
#else
    fs_mkfifo(&ec, fd, path, path_len);
#endif

    return -ec.cause;
}

// Create a new pipe.
// `fds[0]` will be written with the pointer to the read end, `fds[1]` the write end.
// Returns <= -1 on error, file 0 on success.
int syscall_fs_pipe(long fds[2], int flags) {
    sysutil_memassert(fds, 2 * sizeof(long), MEMPROTECT_FLAG_R);

    if (flags & KOFLAGS_MASK) {
        return -ECAUSE_PARAM;
    }

    // Create the pipe.
    badge_err_t ec;
    fs_pipe_t   pipes = fs_pipe(&ec, flags);

    // Add the FDs to the process.
    long u_reader = proc_add_fd_raw(NULL, proc_current(), pipes.reader);
    if (u_reader < 0) {
        fs_close(NULL, pipes.reader);
        fs_close(NULL, pipes.writer);
        return -ECAUSE_NOMEM;
    }

    long u_writer = proc_add_fd_raw(NULL, proc_current(), pipes.writer);
    if (u_writer < 0) {
        proc_remove_fd_raw(NULL, proc_current(), u_reader);
        fs_close(NULL, pipes.reader);
        fs_close(NULL, pipes.writer);
        return -ECAUSE_NOMEM;
    }

    // Everything succeeded, copy the FDs to the user memory.
    mmu_enable_sum();
    fds[0] = u_reader;
    fds[1] = u_writer;
    mmu_disable_sum();

    return -ec.cause;
}
