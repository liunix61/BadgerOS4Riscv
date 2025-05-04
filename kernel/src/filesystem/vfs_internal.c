
// SPDX-License-Identifier: MIT

#include "filesystem/vfs_internal.h"

#include "arrays.h"
#include "assertions.h"
#include "filesystem/vfs_fifo.h"
#include "malloc.h"



// File objects array mutex.
static mutex_t          objs_mtx = MUTEX_T_INIT_SHARED;
// Array of existing file objects.
static size_t           objs_len, objs_cap;
// Array of existing file objects.
static vfs_file_obj_t **objs;



// Open the root directory of the filesystem.
static vfs_file_obj_t *create_root_fobj(badge_err_t *ec, vfs_t *vfs) {
    badge_err_t ec0 = {0};
    ec              = ec ?: &ec0;

    // Allocate memory for the file handle.
    vfs_file_obj_t *obj = calloc(1, sizeof(vfs_file_obj_t));
    if (!obj) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOMEM);
        return NULL;
    }
    obj->cookie = calloc(1, vfs->driver->file_cookie_size);
    if (!obj->cookie) {
        free(obj);
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOMEM);
        return NULL;
    }

    // Fill out common fields.
    mutex_init(NULL, &obj->mutex, true);
    obj->vfs      = vfs;
    obj->refcount = 1;

    // Call FS-specific open root.
    vfs->vtable.root_open(ec, vfs, obj);
    if (!badge_err_is_ok(ec)) {
        free(obj->cookie);
        free(obj);
        return NULL;
    }

    return obj;
}

// Sort by VFS, then by inode.
static int vfs_file_obj_cmp(void const *a_ptr, void const *b_ptr) {
    vfs_file_obj_t const *a = *(void **)a_ptr;
    vfs_file_obj_t const *b = *(void **)b_ptr;

    if ((size_t)a->vfs < (size_t)b->vfs) {
        return -1;
    } else if ((size_t)a->vfs > (size_t)b->vfs) {
        return 1;
    } else if (a->inode < b->inode) {
        return -1;
    } else if (a->inode > b->inode) {
        return 1;
    } else {
        return 0;
    }
}

// Open existing file object.
static vfs_file_obj_t *open_existing(vfs_t *vfs, inode_t inode) {
    vfs_file_obj_t  dummy     = {.vfs = vfs, .inode = inode};
    vfs_file_obj_t *dummy_ptr = &dummy;

    array_binsearch_t res  = array_binsearch(objs, sizeof(void *), objs_len, &dummy_ptr, vfs_file_obj_cmp);
    vfs_file_obj_t   *fobj = NULL;
    if (res.found) {
        fobj = vfs_file_dup(objs[res.index]);
    }

    return fobj;
}



// Open the root directory of the filesystem.
vfs_file_obj_t *vfs_root_open(badge_err_t *ec, vfs_t *vfs) {
    mutex_acquire(NULL, &objs_mtx, TIMESTAMP_US_MAX);

    // Try to get existing file object.
    vfs_file_obj_t *fobj = open_existing(vfs, vfs->inode_root);
    if (fobj) {
        mutex_release(NULL, &objs_mtx);
        badge_err_set_ok(ec);
        return fobj;
    }

    // Create new file object.
    fobj = create_root_fobj(ec, vfs);
    if (!fobj) {
        mutex_release(NULL, &objs_mtx);
        return NULL;
    }

    // Insert into file objects list.
    if (!array_lencap_sorted_insert(&objs, sizeof(void *), &objs_len, &objs_cap, &fobj, vfs_file_obj_cmp)) {
        vfs->vtable.file_close(NULL, vfs, fobj);
        free(fobj->cookie);
        free(fobj);
        fobj = NULL;
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOMEM);
    } else {
        badge_err_set_ok(ec);
    }

    mutex_release(NULL, &objs_mtx);

    return fobj;
}


// Create a new empty file.
vfs_file_obj_t *vfs_mkfile(badge_err_t *ec, vfs_file_obj_t *dir, char const *name, size_t name_len) {
    if (dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return NULL;
    }
    badge_err_t ec0 = {0};
    ec              = ec ?: &ec0;
    dir->vfs->vtable.create_file(ec, dir->vfs, dir, name, name_len);
    if (!badge_err_is_ok(ec)) {
        return NULL;
    }
    return vfs_file_open(ec, dir, name, name_len);
}

// Insert a new directory into the given directory.
void vfs_mkdir(badge_err_t *ec, vfs_file_obj_t *dir, char const *name, size_t name_len) {
    if (dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return;
    }
    dir->vfs->vtable.create_dir(ec, dir->vfs, dir, name, name_len);
}

// Unlink a file from the given directory.
// If this is the last reference to an inode, the inode is deleted.
void vfs_unlink(badge_err_t *ec, vfs_file_obj_t *dir, char const *name, size_t name_len) {
    if (dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return;
    }

    // Find the dirent.
    dirent_t ent;
    if (!dir->vfs->vtable.dir_find_ent(ec, dir->vfs, dir, &ent, name, name_len)) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOTFOUND);
        return;
    }
    if (ent.is_dir) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_DIR);
        return;
    }

    dir->vfs->vtable.unlink(ec, dir->vfs, dir, name, name_len, open_existing(dir->vfs, ent.inode));
}

// Create a new hard link from one path to another relative to their respective dirs.
// Fails if `old_path` names a directory.
void vfs_link(
    badge_err_t *ec, vfs_file_obj_t *old_obj, vfs_file_obj_t *new_dir, char const *new_name, size_t new_name_len
) {
    // No need to check for pipes at `old_obj` because BadgerOS doesn't allow linking nameless files.
    if (new_dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return;
    }

    if (old_obj->type == FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_DIR);
        return;
    } else if (old_obj->vfs != new_dir->vfs) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_CROSSDEV);
        return;
    }

    old_obj->vfs->vtable.link(ec, old_obj->vfs, old_obj, new_dir, new_name, new_name_len);
}

// Create a new symbolic link from one path to another, the latter relative to a dir handle.
void vfs_symlink(
    badge_err_t    *ec,
    char const     *target_path,
    size_t          target_path_len,
    vfs_file_obj_t *link_dir,
    char const     *link_name,
    size_t          link_name_len
) {
    if (link_dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return;
    }
    link_dir->vfs->vtable.symlink(ec, link_dir->vfs, target_path, target_path_len, link_dir, link_name, link_name_len);
}

// Create a new named FIFO at a path relative to a dir handle.
void vfs_mkfifo(badge_err_t *ec, vfs_file_obj_t *dir, char const *name, size_t name_len) {
    if (dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return;
    }
    dir->vfs->vtable.mkfifo(ec, dir->vfs, dir, name, name_len);
}

// Remove a directory if it is empty.
void vfs_rmdir(badge_err_t *ec, vfs_file_obj_t *dir, char const *name, size_t name_len) {
    if (dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return;
    }

    // Find the dirent.
    dirent_t ent;
    if (!dir->vfs->vtable.dir_find_ent(ec, dir->vfs, dir, &ent, name, name_len)) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOTFOUND);
        return;
    }
    if (!ent.is_dir) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return;
    }

    // Assert that no filesystem is mounted here.
    vfs_file_obj_t *existing = open_existing(dir->vfs, ent.inode);
    if (dir->is_vfs_root) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_INUSE);
        vfs_file_drop_ref(NULL, existing);
        return;
    }

    dir->vfs->vtable.rmdir(ec, dir->vfs, dir, name, name_len, existing);
}


// Read all entries from a directory.
dirent_list_t vfs_dir_read(badge_err_t *ec, vfs_file_obj_t *dir) {
    if (dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return (dirent_list_t){0};
    }
    return dir->vfs->vtable.dir_read(ec, dir->vfs, dir);
}

// Read the directory entry with the matching name.
// Returns true if the entry was found.
bool vfs_dir_find_ent(badge_err_t *ec, vfs_file_obj_t *dir, dirent_t *ent, char const *name, size_t name_len) {
    if (dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return false;
    }
    return dir->vfs->vtable.dir_find_ent(ec, dir->vfs, dir, ent, name, name_len);
}


// Stat a file object.
void vfs_stat(badge_err_t *ec, vfs_file_obj_t *file, stat_t *stat_out) {
    if (!file->vfs) {
        // Special case: Stat on an unnamed pipe.
        mem_set(stat_out, 0, sizeof(stat_t));
        return;
    }
    file->vfs->vtable.stat(ec, file->vfs, file, stat_out);
}


// Create a new pipe with one read and one write end.
vfs_pipe_t vfs_pipe(badge_err_t *ec, int flags) {
    vfs_file_obj_t *fobj = calloc(1, sizeof(vfs_file_obj_t));
    if (!fobj) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOMEM);
        return (vfs_pipe_t){0};
    }
    fobj->refcount = 2;
    fobj->type     = FILETYPE_FIFO;
    fobj->fifo     = vfs_fifo_create();
    if (!fobj->fifo) {
        free(fobj);
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOMEM);
        return (vfs_pipe_t){0};
    }
    vfs_fifo_open(NULL, fobj->fifo, true, true, true);
    badge_err_set_ok(ec);

    return (vfs_pipe_t){fobj, fobj};
}

// Open a file or directory for reading and/or writing given parent directory handle.
vfs_file_obj_t *vfs_file_open(badge_err_t *ec, vfs_file_obj_t *dir, char const *name, size_t name_len) {
    if (dir->type != FILETYPE_DIR) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_IS_FILE);
        return NULL;
    }
    badge_err_t ec0 = {0};
    ec              = ec ?: &ec0;

    // Current dir entry needs no lookup.
    if (name_len == 1 && name[0] == '.') {
        badge_err_set_ok(ec);
        return vfs_file_dup(dir);
    }

    // If an FS is mounted here, redirect to its root directory, unless the filename is `..`.
    if (dir->mounted_fs && !(name_len == 2 && name[0] == '.' && name[1] == '.')) {
        dir = dir->mounted_fs->root_dir_obj;
    }

    // Find the dirent.
    dirent_t ent;
    if (!dir->vfs->vtable.dir_find_ent(ec, dir->vfs, dir, &ent, name, name_len)) {
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOTFOUND);
        return NULL;
    }

    // Redirect root directory references to the mountpoint.
    if (ent.inode == dir->vfs->inode_root) {
        return vfs_file_dup(dir->vfs->root_parent_obj);
    }

    mutex_acquire(NULL, &objs_mtx, TIMESTAMP_US_MAX);

    // Try to get existing file object.
    vfs_file_obj_t *fobj = open_existing(dir->vfs, ent.inode);
    if (fobj) {
        mutex_release(NULL, &objs_mtx);
        badge_err_set_ok(ec);
        return fobj;
    }

    // Allocate new file object.
    fobj = calloc(1, sizeof(vfs_file_obj_t));
    if (!fobj) {
        goto err0;
    }
    fobj->cookie   = calloc(1, dir->vfs->driver->file_cookie_size);
    fobj->vfs      = dir->vfs;
    fobj->refcount = 1;
    if (!fobj->cookie) {
        goto err1;
    }
    mutex_init(NULL, &fobj->mutex, true);

    // Open new file object.
    dir->vfs->vtable.file_open(ec, dir->vfs, dir, fobj, name, name_len);
    if (!badge_err_is_ok(ec)) {
        goto err2;
    }

    if (fobj->type == FILETYPE_FIFO) {
        // FIFO object created here, open will be called by the file desc code.
        fobj->fifo = vfs_fifo_create();
    }

    // Insert into file objects list.
    if (!array_lencap_sorted_insert(&objs, sizeof(void *), &objs_len, &objs_cap, &fobj, vfs_file_obj_cmp)) {
        dir->vfs->vtable.file_close(NULL, dir->vfs, fobj);
        free(fobj->cookie);
        free(fobj);
        fobj = NULL;
        badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOMEM);
    } else {
        badge_err_set_ok(ec);
    }

    mutex_release(NULL, &objs_mtx);

    return fobj;

err2:
    free(fobj->cookie);
err1:
    free(fobj);
err0:
    mutex_release(NULL, &objs_mtx);
    badge_err_set(ec, ELOC_FILESYSTEM, ECAUSE_NOMEM);
    return NULL;
}

// Duplicate a file or directory handle.
vfs_file_obj_t *vfs_file_dup(vfs_file_obj_t *orig) {
    atomic_fetch_add(&orig->refcount, 1);
    return orig;
}

// Close a file opened by `vfs_file_open`.
// Only raises an error if `file` is an invalid file descriptor.
void vfs_file_drop_ref(badge_err_t *ec, vfs_file_obj_t *file) {
    if (atomic_fetch_sub(&file->refcount, 1) == 1) {
        // Remove from file objects list.
        array_binsearch_t res = array_binsearch(objs, sizeof(void *), objs_len, &file, vfs_file_obj_cmp);
        if (res.found) {
            array_lencap_remove(&objs, sizeof(void *), &objs_len, &objs_cap, NULL, res.index);
        } else {
            assert_dev_drop(file->vfs == NULL);
        }

        if (file->type == FILETYPE_FIFO) {
            // Closing a FIFO or pipe.
            vfs_fifo_destroy(file->fifo);
        }
        if (!file->vfs) {
            // Special case: An unnamed pipe does not have a filesystem; skip closing there.
            badge_err_set_ok(ec);
            return;
        }
        file->vfs->vtable.file_close(ec, file->vfs, file);
        free(file->cookie);
    } else {
        badge_err_set_ok(ec);
    }
}

// Read bytes from a file.
// The entire read succeeds or the entire read fails, never partial read.
void vfs_file_read(badge_err_t *ec, vfs_file_obj_t *file, fileoff_t offset, uint8_t *readbuf, fileoff_t readlen) {
    file->vfs->vtable.file_read(ec, file->vfs, file, offset, readbuf, readlen);
}

// Write bytes to a file.
// If the file is not large enough, it fails.
// The entire write succeeds or the entire write fails, never partial write.
void vfs_file_write(
    badge_err_t *ec, vfs_file_obj_t *file, fileoff_t offset, uint8_t const *writebuf, fileoff_t writelen
) {
    file->vfs->vtable.file_write(ec, file->vfs, file, offset, writebuf, writelen);
}

// Change the length of a file opened by `vfs_file_open`.
void vfs_file_resize(badge_err_t *ec, vfs_file_obj_t *file, fileoff_t new_size) {
    file->vfs->vtable.file_resize(ec, file->vfs, file, new_size);
}


// Commit all pending writes on a file to disk.
// The filesystem, if it does caching, must always sync everything to disk at once.
void vfs_file_flush(badge_err_t *ec, vfs_file_obj_t *file) {
    file->vfs->vtable.file_flush(ec, file->vfs, file);
}

// Commit all pending writes to disk.
// The filesystem, if it does caching, must always sync everything to disk at once.
void vfs_flush(badge_err_t *ec, vfs_t *vfs) {
    vfs->vtable.flush(ec, vfs);
}
