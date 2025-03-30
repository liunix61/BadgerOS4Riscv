
// SPDX-License-Identifier: MIT

#pragma once

#include "filesystem/vfs_internal.h"



/* ==== FAT-specific functions ==== */

// Is this FAT entry free?
#define FS_FAT_IS_FAT_FREE(entry) ((entry) == 0)
// Is this FAT entry not defective and allocated?
#define FS_FAT_IS_FAT_ALLOC(entry)                                                                                     \
    ({                                                                                                                 \
        uint32_t tmp = (entry);                                                                                        \
        tmp >= 2 && tmp <= 0x0ffffff6;                                                                                 \
    })
// Is this FAT entry the end of file?
#define FS_FAT_IS_FAT_EOF(entry) (((entry) & 0x0ffffff8) == 0x0ffffff8)
// EOF value for FAT entries.
#define FS_FAT_FAT_EOF           0x0ffffff8



/* ==== VFS interface ==== */

// Try to mount a FAT filesystem.
bool fs_fat_mount(badge_err_t *ec, vfs_t *vfs);
// Unmount a FAT filesystem.
void fs_fat_umount(vfs_t *vfs);
// Identify whether a block device contains a FAT filesystem.
// Returns false on error.
bool fs_fat_detect(badge_err_t *ec, blkdev_t *dev);

// Insert a new file into the given directory.
// If the file already exists, does nothing.
void fs_fat_create_file(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, char const *name, size_t name_len);
// Insert a new directory into the given directory.
// If the file already exists, does nothing.
void fs_fat_create_dir(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, char const *name, size_t name_len);
// Unlink a file from the given directory.
// If the file is currently open, the file object for it is provided in `file`.
void fs_fat_unlink(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, char const *name, size_t name_len, vfs_file_obj_t *file
);
// FAT doesn't support this; raises ECAUSE_UNSUPPORTED.
void fs_fat_link(
    badge_err_t    *ec,
    vfs_t          *vfs,
    vfs_file_obj_t *old_obj,
    vfs_file_obj_t *new_dir,
    char const     *new_name,
    size_t          new_name_len
);
// FAT doesn't support this; raises ECAUSE_UNSUPPORTED.
void fs_fat_symlink(
    badge_err_t    *ec,
    vfs_t          *vfs,
    char const     *target_path,
    size_t          target_path_len,
    vfs_file_obj_t *link_dir,
    char const     *link_name,
    size_t          link_name_len
);
// FAT doesn't support this; raises ECAUSE_UNSUPPORTED.
void fs_fat_mkfifo(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, char const *name, size_t name_len);

// Read all entries from a directory.
dirent_list_t fs_fat_dir_read(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir);

// Read the directory entry with the matching name.
// Returns true if the entry was found.
bool fs_fat_dir_find_ent(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, dirent_t *ent, char const *name, size_t name_len
);

// Stat a file object.
void fs_fat_stat(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file, stat_t *stat);

// Open a file handle for the root directory.
void fs_fat_root_open(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file);
// Open a file for reading and/or writing.
void fs_fat_file_open(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *dir, vfs_file_obj_t *file, char const *name, size_t name_len
);
// Close a file opened by `fs_fat_file_open`.
// Only raises an error if `file` is an invalid file descriptor.
void fs_fat_file_close(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file);
// Read bytes from a file.
void fs_fat_file_read(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file, fileoff_t offset, uint8_t *readbuf, fileoff_t readlen
);
// Write bytes from a file.
void fs_fat_file_write(
    badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file, fileoff_t offset, uint8_t const *writebuf, fileoff_t writelen
);
// Change the length of a file opened by `fs_fat_file_open`.
void fs_fat_file_resize(badge_err_t *ec, vfs_t *vfs, vfs_file_obj_t *file, fileoff_t new_size);

// Commit all pending writes to disk.
// The filesystem, if it does caching, must always sync everything to disk at once.
void fs_fat_flush(badge_err_t *ec, vfs_t *vfs);
