
// SPDX-License-Identifier: MIT

#pragma once

#include "badge_err.h"
#include "time.h"

#include <stddef.h>

// Maximum age in microseconds of a write cache entry.
#define BLKDEV_WRITE_CACHE_TIMEOUT 1000000
// Minimum age in microseconds of a read cache entry.
#define BLKDEV_READ_CACHE_TIMEOUT  1000000
// Default depth of block device cache.
#define BLKDEV_DEFAULT_CACHE_DEPTH 64

// Size type used for block devices.
typedef uint64_t blksize_t;
// Offset type used for block devices.
typedef int64_t  blkoff_t;

// Block device handle.
typedef struct blkdev blkdev_t;

// Prepare a block device for reading and/or writing.
// All other `blkdev_*` functions assume the block device was opened using this function.
// For some block devices, this may allocate caches.
void      blkdev_open(badge_err_t *ec, blkdev_t *dev);
// Flush write caches and close block device.
void      blkdev_close(badge_err_t *ec, blkdev_t *dev);
// Get a block device's size in blocks.
blksize_t blkdev_get_size(blkdev_t *dev);
// Get a block device's block size.
blksize_t blkdev_get_block_size(blkdev_t *dev);
// Is this block device read-only?
bool      blkdev_is_readonly(blkdev_t *dev);

// Query the erased status of a block.
// On devices which cannot erase blocks, this will always return true.
// Returns true on error.
bool blkdev_is_erased(badge_err_t *ec, blkdev_t *dev, blksize_t block);
// Explicitly erase a block, if possible.
// On devices which cannot erase blocks, this will do nothing.
void blkdev_erase(badge_err_t *ec, blkdev_t *dev, blksize_t block);
// Erase if necessary and write a block.
// This operation may be cached and therefor delayed.
void blkdev_write(badge_err_t *ec, blkdev_t *dev, blksize_t block, uint8_t const *writebuf);
// Read bytes with absolute address.
// This operation may be cached.
void blkdev_read_bytes(badge_err_t *ec, blkdev_t *dev, blksize_t abspos, uint8_t *readbuf, size_t readbuf_len);
// Erase if necessary and write a bytes.
// This is very likely to cause a read-modify-write operation.
void blkdev_write_bytes(badge_err_t *ec, blkdev_t *dev, blksize_t abspos, uint8_t const *writebuf, size_t writebuf_len);
// Read a block.
// This operation may be cached.
void blkdev_read(badge_err_t *ec, blkdev_t *dev, blksize_t block, uint8_t *readbuf);
// Partially write a block.
// This is very likely to cause a read-modify-write operation.
void blkdev_write_partial(
    badge_err_t   *ec,
    blkdev_t      *dev,
    blksize_t      block,
    size_t         subblock_offset,
    uint8_t const *writebuf,
    size_t         writebuf_len
);
// Partially read a block.
// This may use read caching if the device doesn't support partial read.
void blkdev_read_partial(
    badge_err_t *ec, blkdev_t *dev, blksize_t block, size_t subblock_offset, uint8_t *readbuf, size_t readbuf_len
);

// Flush the write cache to the block device.
void blkdev_flush(badge_err_t *ec, blkdev_t *dev);
// Call this function occasionally per block device to do housekeeping.
// Manages flushing of caches and erasure.
void blkdev_housekeeping(badge_err_t *ec, blkdev_t *dev);
// Allocate a cache for a block device.
void blkdev_create_cache(badge_err_t *ec, blkdev_t *dev, size_t cache_depth, bool cache_reads);
// Remove a cache from a block device.
void blkdev_delete_cache(badge_err_t *ec, blkdev_t *dev);

// Show a summary of the cache entries.
void blkdev_dump_cache(blkdev_t *dev);
