/*
 * Chonky - A FAT32 file system library.
 * Author: timre13
 */

#ifndef CHONKY_FAT32_H
#define CHONKY_FAT32_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

//------------------------------------------------------------------------------

/*
 * Note: return value is not used, it's only there to match `printf()`s signature.
 */
typedef int (*chonkyOutFun_t)(const char*, ...);

/*
 * You can overwrite these functions to redirect or silence output.
 */
extern chonkyOutFun_t chout; // Normal output
extern chonkyOutFun_t cherr; // Errors
extern chonkyOutFun_t chdbg; // Verbose debug messages

//------------------------------------------------------------------------------

#define PACKED __attribute__((packed))

typedef unsigned int uint;
typedef unsigned long int ulong;

typedef enum bool
{
    false,
    true,
} bool;

void printHex(unsigned char* buffer, int n);

//------------------------------------------------------------------------------

typedef struct BPB BPB;
typedef struct EBPB EBPB;
typedef struct FSInfo FSInfo;
typedef struct DirIteratorEntry DirIteratorEntry;

typedef struct Fat32Context
{
    FILE*       file;
    BPB*        bpb;
    EBPB*       ebpb;
    FSInfo*     fsinfo;
    ulong       fatSizeBytes;
    uint8_t*    fat;
    // The first sector where dir entries can be stored
    uint32_t    firstDataSector;
    uint64_t    rootDirAddr;
} Fat32Context;

Fat32Context* fat32ContextNew(const char* devFilePath);
void fat32ContextFree(Fat32Context** contextP);
uint32_t fat32GetFirstSectorOfCluster(const Fat32Context* cont, uint32_t cluster);
void fat32PrintInfo(Fat32Context* cont);
void fat32ListDir(Fat32Context* cont, uint64_t addr);
DirIteratorEntry* fat32FindInDir(Fat32Context* cont, uint64_t addr, const char* toFind);
DirIteratorEntry* fat32OpenFile(Fat32Context* cont, const char* path);

//------------------------------------------------------------------------------

#define BPB_OEM_LEN 8

/* BIOS Parameter Block */
typedef struct BPB
{
    uint8_t     _reserved0[3];
    uint8_t     oemIdentifier[BPB_OEM_LEN];
    uint16_t    sectorSize;
    uint8_t     sectorsPerClusters;
    uint16_t    reservedSectorCount;
    uint8_t     fatCount;
    uint16_t    dirEntryCount; // TODO: 0 in FAT32?
    uint16_t    _sectorCount;
    uint8_t     mediaType; // TODO: Interpret media type value
    uint16_t    _sectorsPerFat; // FAT12/FAT16 only, don't use
    uint16_t    sectorsPerTrack;
    uint16_t    headCount;
    uint32_t    hiddenSectCount;
    uint32_t    _largeSectCount;
} PACKED BPB;

uint32_t BPBGetSectorCount(const BPB* input);

//------------------------------------------------------------------------------

#define EBPB_LABEL_LEN 11
#define EBPB_SYS_ID_LEN 8

/* Extended BIOS Parameter Block */
typedef struct EBPB
{
    uint32_t    sectorsPerFat;
    uint16_t    flags;
    uint16_t    fatVersion;
    uint32_t    rootDirClusterNum;
    uint16_t    fsInfoSectorNum;
    uint16_t    backupSectorNum;
    uint8_t     _reserved0[12];
    uint8_t     driveNum;
    uint8_t     ntFlags;
    uint8_t     signature; // Must be 0x28 or 0x29
    uint32_t    serialNum;
    uint8_t     label[EBPB_LABEL_LEN];
    uint8_t     systemId[EBPB_SYS_ID_LEN];
    /* Boot code */
    /* MBR signature (0xAA55) */
} PACKED EBPB;

//------------------------------------------------------------------------------

#define FSINFO_LEAD_SIG     0x41615252
#define FSINFO_SIG          0x61417272
#define FSINFO_TRAIL_SIG    0xaa550000
#define FSINFO_NOT_KNOWN_FREE_CLUST_CNT  0xffffffff
#define FSINFO_NOT_KNOWN_NEXT_FREE_CLUST 0xffffffff
typedef struct FSInfo
{
    uint32_t    leadSig;
    uint8_t     _reserved0[480];
    uint32_t    signature;
    uint32_t    freeCount;
    uint32_t    nextFree;
    uint8_t     _reserved1[12];
    uint32_t    trailSig;
} PACKED FSInfo;

//------------------------------------------------------------------------------

/*
 * 4 most significant bits: reserved.
 * 28 least significant bits: cluster index.
 */
typedef uint32_t ClusterPtr;

uint32_t clusterPtrGetIndex(ClusterPtr ptr);
bool clusterPtrIsBadCluster(ClusterPtr ptr);
bool clusterPtrIsLastCluster(ClusterPtr ptr);
bool clusterPtrIsNull(ClusterPtr ptr);
uint32_t fatGetNextClusterPtr(const Fat32Context* cont, ClusterPtr current);

//------------------------------------------------------------------------------

#define DIRENTRY_FILENAME_LEN 11
#define DIRENTRY_ATTR_READONLY  (1 << 0)
#define DIRENTRY_ATTR_HIDDEN    (1 << 1)
#define DIRENTRY_ATTR_SYSTEM    (1 << 2)
#define DIRENTRY_ATTR_VOLUME_ID (1 << 3)
#define DIRENTRY_ATTR_DIRECTORY (1 << 4)
#define DIRENTRY_ATTR_ARCHIVE   (1 << 5)
#define DIRENTRY_ATTR_LONG_NAME       \
            ( DIRENTRY_ATTR_READONLY  \
            | DIRENTRY_ATTR_HIDDEN    \
            | DIRENTRY_ATTR_SYSTEM    \
            | DIRENTRY_ATTR_VOLUME_ID )
#define DIRENTRY_MASK_LONG_NAME       \
            ( DIRENTRY_ATTR_READONLY  \
            | DIRENTRY_ATTR_HIDDEN    \
            | DIRENTRY_ATTR_SYSTEM    \
            | DIRENTRY_ATTR_VOLUME_ID \
            | DIRENTRY_ATTR_DIRECTORY \
            | DIRENTRY_ATTR_ARCHIVE   )
typedef struct DirEntry
{
    uint8_t     fileName[DIRENTRY_FILENAME_LEN];
    uint8_t     attributes;
    uint8_t     ntReserved;
    uint8_t     creationTimeTenthSec;
    uint16_t    _creationTime;
    uint16_t    _creationDate;
    uint16_t    _accessDate;
    uint16_t    _entryFirstClusterNum1;
    uint16_t    _modTime;
    uint16_t    _modDate;
    uint16_t    _entryFirstClusterNum2;
    uint32_t    fileSize;
} PACKED DirEntry;

bool dirEntryIsVolumeLabel(const DirEntry* entry);
bool dirEntryIsLFE(uint8_t attrs);
bool dirEntryIsDir(const DirEntry* entry);
bool dirEntryIsFile(const DirEntry* entry);
bool dirEntryIsEmpty(const DirEntry* entry);
ClusterPtr dirEntryGetClusterPtr(const DirEntry* entry);
uint32_t dirEntryGetFirstClusterNumber(const DirEntry* input);
uint64_t dirEntryGetDataAddress(const Fat32Context* cont, const DirEntry* entry);
char* dirEntryAttrsToStr(uint8_t attrs);
int dirEntryReadFileData(Fat32Context* cont, const DirEntry* entry, uint8_t* buffer, size_t bufferSize);

//------------------------------------------------------------------------------

typedef struct DirEntryTime
{
    uint hour;
    uint min;
    uint sec;
} PACKED DirEntryTime;

DirEntryTime toDirEntryTime(uint16_t input);
char* dirEntryTimeToStr(const DirEntryTime* input);

//------------------------------------------------------------------------------

typedef struct DirEntryDate
{
    uint year;
    uint month;
    uint day;
} PACKED DirEntryDate;

DirEntryDate toDirEntryDate(uint16_t input);
char* dirEntryDateToStr(const DirEntryDate* input);

//------------------------------------------------------------------------------

#define LFE_ENTRY_NAME_LEN 13
#define LFE_FULL_NAME_LEN LFE_ENTRY_NAME_LEN*16
typedef struct LfeEntry
{
    uint8_t nameStrIndex;
    uint16_t _name0[5];
    uint8_t _attr; // 0x0F - LFE attribute
    uint8_t _type; // Long entry type, should be 0 for file names
    uint8_t checksum;
    uint16_t _name1[6];
    uint16_t _alwaysZero;
    uint16_t _name2[2];
} PACKED LfeEntry;

uint16_t* lfeEntryGetNameUCS2(const LfeEntry* entry);
char* lfeEntryGetNameASCII(const LfeEntry* entry);

//------------------------------------------------------------------------------

typedef struct DirIteratorEntry
{
    DirEntry* entry;
    char* longFilename;
    // Address of the entry itself, not where it points to
    uint64_t address;
} DirIteratorEntry;

void dirIteratorEntryFree(DirIteratorEntry** entryP);
char* dirIteratorEntryGetFileName(DirIteratorEntry* entry);

typedef struct DirIterator
{
    uint64_t _address;
    uint64_t _initAddr;
    char* _longFilename;
    uint8_t _lfeChecksums[16];
} DirIterator;

DirIterator* dirIteratorNew(uint64_t addr);
DirIteratorEntry* dirIteratorNext(Fat32Context* cont, DirIterator* it);
void dirIteratorSetAddress(DirIterator* it, uint64_t addr);
void dirIteratorRewind(DirIterator* it);
void dirIteratorFree(DirIterator** itP);

//------------------------------------------------------------------------------

#endif // CHONKY_FAT32_H
