
// SPDX-License-Identifier: MIT

#pragma once

#include "filesystem/fs_ramfs_types.h"
#include "filesystem/vfs_internal.h"

// Inode number of the root directory of a RAM filesystem.
#define VFS_RAMFS_INODE_ROOT  1
// First regular inode of a RAM filesystem.
#define VFS_RAMFS_INODE_FIRST 2

// Try to mount a ramfs filesystem.
bool fs_ramfs_mount(badge_err_t *ec, vfs_t *vfs);
// Unmount a ramfs filesystem.
void fs_ramfs_umount(vfs_t *vfs);

// Insert a new file into the given directory.
// If `dir` is NULL, the root directory is used.
// If the file already exists, does nothing.
void fs_ramfs_create_file(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, char const *name, size_t name_len);
// Insert a new directory into the given directory.
// If `dir` is NULL, the root directory is used.
// If the file already exists, does nothing.
void fs_ramfs_create_dir(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, char const *name, size_t name_len);
// Unlink a file from the given directory.
// If the file is currently open, the file object for it is provided in `file`.
void fs_ramfs_unlink(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, char const *name, size_t name_len, vfs_file_obj_t *file
);
// Create a new hard link from one path to another relative to their respective dirs.
// Fails if `old_path` names a directory.
void fs_ramfs_link(
    badge_err_t    *ec,
    vfs_t          *vfs,
    vfs_file_obj_t *old_obj,
    vfs_file_obj_t *new_dir,
    char const     *new_name,
    size_t          new_name_len
);
// Create a new symbolic link from one path to another, the latter relative to a dir handle.
void fs_ramfs_symlink(
    badge_err_t    *ec,
    vfs_t          *vfs,
    char const     *target_path,
    size_t          target_path_len,
    vfs_file_obj_t *link_dir,
    char const     *link_name,
    size_t          link_name_len
);
// Create a new named FIFO at a path relative to a dir handle.
void fs_ramfs_mkfifo(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, char const *name, size_t name_len);

// Read all entries from a directory.
dirent_list_t fs_ramfs_dir_read(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir);

// Read the directory entry with the matching name.
// Returns true if the entry was found.
bool fs_ramfs_dir_find_ent(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, dirent_t *ent, char const *name, size_t name_len
);

// Stat a file object.
void fs_ramfs_stat(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file, stat_t *stat);

// Open a file handle for the root directory.
void fs_ramfs_root_open(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file);
// Open a file for reading and/or writing.
void fs_ramfs_file_open(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, vfs_file_obj_t *file, char const *name, size_t name_len
);
// Close a file opened by `fs_ramfs_file_open`.
// Only raises an error if `file` is an invalid file descriptor.
void fs_ramfs_file_close(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file);
// Read bytes from a file.
void fs_ramfs_file_read(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file, fileoff_t offset, uint8_t *readbuf, fileoff_t readlen
);
// Write bytes from a file.
void fs_ramfs_file_write(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file, fileoff_t offset, uint8_t const *writebuf, fileoff_t writelen
);
// Change the length of a file opened by `fs_ramfs_file_open`.
void fs_ramfs_file_resize(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file, fileoff_t new_size);

// Commit all pending writes to disk.
// The filesystem, if it does caching, must always sync everything to disk at once.
void fs_ramfs_flush(badge_err_t *ec, vfs_t *vfs);
