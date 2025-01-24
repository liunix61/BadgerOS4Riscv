
// SPDX-License-Identifier: MIT

#pragma once

#include "assertions.h"
#include "attributes.h"

/*
    FAT filesystems are divided into 4 main regions:
        Boot sector
        Reserved
        FAT(s)
        Data

    The boot sector for FAT12 or FAT16 is:
        fat_bpb_t
        fat16_header_t
        (unused until index 510)
        0x55
        0xAA

    The boot sector for FAT32 is:
        fat_bpb_t
        fat32_header_t
        fat16_header_t
        (unused until index 510)
        0x55
        0xAA

    FAT12 and FAT16 have a fixed, preallocated root directory outside of the data clusers,
    while FAT32 has a dynamic root directory size that lives in the data clusters.
*/



/* ==== On-disk structures ==== */

#define FAT_ATTR_READ_ONLY 0x01
#define FAT_ATTR_HIDDEN    0x02
#define FAT_ATTR_SYSTEM    0x04
#define FAT_ATTR_VOLUME_ID 0x08
#define FAT_ATTR_DIRECTORY 0x10
#define FAT_ATTR_ARCHIVE   0x20
#define FAT_ATTR_LONG_NAME (FAT_ATTR_READ_ONLY | FAT_ATTR_HIDDEN | FAT_ATTR_SYSTEM | FAT_ATTR_VOLUME_ID)

#define FAT_ATTR2_LC_NAME 0x08
#define FAT_ATTR2_LC_EXT  0x10

// FAT BIOS parameter block.
typedef struct PACKED LITTLE_ENDIAN {
    // Used for the x86 jump to bootloader.
    uint8_t  jumpboot[3];
    // OEM name, recommended is "MSWIN4.1".
    char     oem_name[8];
    // Bytes per physical sector, one of 512, 1024, 2048, 4096.
    uint16_t bytes_per_sector;
    // Sectors per cluster (allocation unit), power of 2 greater greater than 0.
    // Note: Clusters larger than 32K are poorly supported by others.
    uint8_t  sectors_per_cluster;
    // Reserved sector count starting at first physical sector.
    // Note: On FAT12 and FAT16, this value should be 1.
    uint16_t reserved_sector_count;
    // Number of copies of the FAT, should be 2.
    uint8_t  fat_count;
    // Number file of entries in the root directory.
    // Note: On FAT32, this is value must be 0.
    uint16_t root_entry_count;
    // 16-bit total sector count.
    // If the sector count is more than 65535, `sector_count_32` is used.
    uint16_t sector_count_16;
    // Media type, 0xF0 or 0xF8 - 0xFF.
    // Note: The first byte of every FAT must equal this value.
    uint8_t  media_type;
    // 16-bit sectors per FAT count.
    uint16_t sectors_per_fat_16;
    // Sectors per track for floppy disks.
    uint16_t sectors_per_track;
    // Number of heads for floppy disks.
    uint16_t head_count;
    // Number of "hidden" sectors (usually reserved by the bootloader).
    uint32_t hidden_sector_count;
    // 32-bit total sector count.
    uint32_t sector_count_32;
} fat_bpb_t;
static_assert(sizeof(fat_bpb_t) == 36);

// FAT12/FAT16 filesystem header.
typedef struct PACKED LITTLE_ENDIAN {
    // Drive number for floppy disks.
    uint8_t  drive_number;
    // Reserved; set to 0.
    uint8_t  _reserved1;
    // Extended boot signature; set to 0x29.
    uint8_t  boot_signature;
    // Volume ID.
    uint32_t volume_id;
    // Volume label, upper-case ASCII padded with 0x20.
    char     volume_label[11];
    // User-facing filesystem type string, upper-case ASCII padded with 0x20.
    char     filesystem_string[8];
} fat16_header_t;
static_assert(sizeof(fat16_header_t) == 26);

// FAT32 filesystem header.
// Inserted before the FAT12/FAT16 filesystem header.
typedef struct PACKED LITTLE_ENDIAN {
    // 32-bit sectors per FAT.
    uint32_t sectors_per_fat_32;
    // Extra filesystem flags; see `FAT32_EXTFLAG_*`.
    uint16_t extra_flags;
    // Filesystem version; set to 0.
    uint16_t fs_version;
    // First cluster of the root directory, usually 2.
    uint32_t first_root_cluster;
    // Sector number of the active filesystem info structure.
    uint16_t fs_info_sector;
    // Sector number of the backup bootsector, should be 6.
    uint16_t backup_bootsector;
    // Reserved, set to 0.
    uint8_t  _reserved[12];
} fat32_header_t;
static_assert(sizeof(fat32_header_t) == 28);

// FAT date format.
typedef union PACKED LITTLE_ENDIAN {
    struct {
        // Day (1-31).
        uint16_t day   : 5;
        // Month (1-12).
        uint16_t month : 4;
        // Years since 1980.
        uint16_t year  : 7;
    };
    uint16_t val;
} fat_date_t;

// FAT directory entry.
typedef struct PACKED LITTLE_ENDIAN {
    // Short filename in 8.3 format.
    char       name[11];
    // File attributes.
    uint8_t    attr;
    // Additional attributes.
    uint8_t    attr2;
    // Creation time in 0.1s increments.
    uint8_t    ctime_tenth;
    // Creation time in 2s increments.
    uint16_t   ctime_2s;
    // Creation date.
    fat_date_t ctime;
    // Last accessed date.
    fat_date_t atime;
    // High 16 bits of first cluster.
    uint16_t   first_cluster_hi;
    // Modification time in 2s increments.
    uint16_t   mtime_2s;
    // Modification date.
    fat_date_t mtime;
    // Low 16 bits of first cluster.
    uint16_t   first_cluster_lo;
    // File size in bytes.
    uint32_t   size;
} fat_dirent_t;
static_assert(sizeof(fat_dirent_t) == 32);



/* ==== In-memory structures ==== */

// Which type of FAT is mounted right now.
typedef enum {
    FAT12,
    FAT16,
    FAT32,
} fs_fat_type_t;

// FAT filesystem opened file / directory handle.
// This handle is shared between multiple holders of the same file.
typedef struct {
    // Data clusters in which the file's content is stored.
    uint32_t       *clusters;
    // Number of allocated clusters.
    size_t          clusters_len, clusters_cap;
    // Parent directory.
    vfs_file_obj_t *parent;
    // Position of dirent in parent dir.
    uint32_t        dirent_no;
} fs_fat_file_t;

// Mounted FAT filesystem.
typedef struct {
    /* ==== Static filesystem information ====*/
    // Which type of FAT is mounted right now.
    fs_fat_type_t type;
    // Sector size in bytes.
    uint32_t      bytes_per_sector;
    // Cluster size in sectors.
    uint32_t      sectors_per_cluster;
    // First data sector.
    uint32_t      data_sector;
    // First sector of the first FAT.
    uint32_t      fat_sector;
    // Total sectors per FAT.
    uint32_t      sectors_per_fat;
    // Number of clusters excluding reserved values.
    uint32_t      cluster_count;
    // Root directory sector for FAT12 or FAT16.
    uint32_t      legacy_root_sector;
    // Root directory entry count for FAT12 or FAT16.
    uint16_t      legacy_root_size;
    // Root directory start cluster for FAT32.
    uint32_t      fat32_root_cluster;
    // Index of the currently active FAT.
    uint8_t       active_fat;
    // FAT entry mutex required for FAT12 specifically.
    mutex_t       fat12_mutex;

    /* ==== Dynamic information ==== */
    // Bitmap of free clusters in the FAT.
    size_t              *free_bitmap;
    // Number of free clusters.
    atomic_uint_fast32_t free_clusters;
} fs_fat_t;
