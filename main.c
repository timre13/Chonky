/*
 * Chonky - A FAT32 file system library.
 * Author: timre13
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

//------------------------------------------------------------------------------

#define PACKED __attribute__((packed))

long limit(long val, long _limit)
{
    return val > _limit ? _limit : val;
}

typedef enum
{
    false,
    true,
} bool;

typedef unsigned int uint;

void printHex(unsigned char* buffer, int n)
{
    for (int i=0; i < n; ++i)
    {
        printf("%02x ", buffer[i]);
        if (i % 32 == 31)
        {
            printf("\n");
        }
    }
}

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
    uint16_t    dirEntryCount;
    uint16_t    _sectorCount;
    uint8_t     mediaType;
    uint16_t    _sectorsPerFat; // FAT12/FAT16 only, don't use
    uint16_t    sectorsPerTrack;
    uint16_t    headCount;
    uint32_t    hiddenSectCount;
    uint32_t    _largeSectCount;
} PACKED BPB;

uint32_t getSectorCount(const BPB* input)
{
    // If _sectorCount is 0, threre are more than 65535 sectors, so the number is stored in _largeSectCount
    return input->_sectorCount == 0 ? input->_largeSectCount : input->_sectorCount;
}

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
    uint8_t     signature;
    uint32_t    serialNum;
    uint8_t     label[EBPB_LABEL_LEN];
    uint8_t     systemId[EBPB_SYS_ID_LEN];
    /* Boot code */
    /* MBR signature (0xAA55) */
} PACKED EBPB;

//------------------------------------------------------------------------------

typedef struct ClusterEntry
{
    uint8_t     reserved: 4;
    uint32_t    address: 28;
} PACKED ClusterEntry;

bool isBadCluster(const ClusterEntry* entry)
{
    return entry->address == 0x0FFFFFF7;
}

bool isLastCluster(const ClusterEntry* entry)
{
    return entry->address >= 0x0FFFFFF8;
}

//------------------------------------------------------------------------------

#define DIRENTRY_FILENAME_LEN 11
#define DIRENTRY_ATTR_FLAG_READONLY     0x01
#define DIRENTRY_ATTR_FLAG_HIDDEN       0x02
#define DIRENTRY_ATTR_FLAG_SYSTEM       0x04
#define DIRENTRY_ATTR_FLAG_VOLUME_ID    0x08
#define DIRENTRY_ATTR_FLAG_DIRECTORY    0x10
#define DIRENTRY_ATTR_FLAG_ARCHIVE      0x20
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

bool isLongFileNameEntry(uint8_t attrs)
{
    return attrs ==
        ( DIRENTRY_ATTR_FLAG_READONLY
        | DIRENTRY_ATTR_FLAG_HIDDEN
        | DIRENTRY_ATTR_FLAG_SYSTEM
        | DIRENTRY_ATTR_FLAG_VOLUME_ID);
}

uint32_t getFirstClusterNumber(const DirEntry* input)
{
    return ((uint32_t)input->_entryFirstClusterNum1 << 16) | (uint32_t)input->_entryFirstClusterNum2;
}

char* dirEntryAttrsToStr(uint8_t attrs)
{
    char* str = malloc(6);

    if (isLongFileNameEntry(attrs))
    {
        strncpy(str, "LFE", 6);
        return str;
    }

    strncpy(str, "------", 6);
    if (attrs & DIRENTRY_ATTR_FLAG_READONLY)    str[0] = 'R';
    if (attrs & DIRENTRY_ATTR_FLAG_HIDDEN)      str[1] = 'H';
    if (attrs & DIRENTRY_ATTR_FLAG_SYSTEM)      str[2] = 'S';
    if (attrs & DIRENTRY_ATTR_FLAG_VOLUME_ID)   str[3] = 'V';
    if (attrs & DIRENTRY_ATTR_FLAG_DIRECTORY)   str[4] = 'D';
    if (attrs & DIRENTRY_ATTR_FLAG_ARCHIVE)     str[5] = 'A';
    return str;
}

//------------------------------------------------------------------------------

typedef struct DirEntryTime
{
    unsigned int hour;
    unsigned int min;
    unsigned int sec;
} PACKED DirEntryTime;

DirEntryTime toDirEntryTime(uint16_t input)
{
    DirEntryTime time = {
        .hour = ((uint)input & (uint)0x1111100000000000) >> 11,
        .min  = ((uint)input & (uint)0x0000011111100000) >> 5,
        .sec  = ((uint)input & (uint)0x0000000000011111) * 2
    };
    return time;
}

const char* dirEntryTimeToStr(const DirEntryTime* input)
{
    char* buffer = malloc(9);
    if (snprintf(buffer, 9, "%02i-%02i-%02i", input->hour, input->min, input->sec))
    {
        // If no space for time, fill the output with ?s
        strcpy(buffer, "\?\?-\?\?-\?\?");
    }
    return buffer;
}

//------------------------------------------------------------------------------

typedef struct DirEntryDate
{
    int year;
    int month;
    int day;
} PACKED DirEntryDate;

DirEntryDate toDirEntryDate(uint16_t input)
{
    DirEntryDate date = {
        .year  = (input & 0x1111111000000000) >> 9,
        .month = (input & 0x0000000111100000) >> 5,
        .day   = (input & 0x0000000000011111)
    };
    return date;
}

const char* dirEntryDateToStr(const DirEntryDate* input)
{
    char* buffer = malloc(9);
    if (snprintf(buffer, 9, "%02i-%02i-%02i", input->year, input->month, input->day))
    {
        // If no space for date, fill the output with ?s
        strcpy(buffer, "\?\?-\?\?-\?\?");
    }
    return buffer;
}

//------------------------------------------------------------------------------

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE* file = fopen(argv[1], "r");
    if (!file)
    {
        fprintf(stderr, "Failed to open file: %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    fseek(file, 0, SEEK_END);
    const long diskSize = ftell(file);
    printf("Disk size is %li bytes = %fKb = %fMb = %fGb)\n",
            diskSize, diskSize/1024.f, diskSize/1024.f/1024.f, diskSize/1024.f/1024.f/1024.f);
    fseek(file, 0, SEEK_SET);

    BPB bpb;
    fread(&bpb, sizeof(bpb), 1, file);
    printf("OEM:                    %.*s\n", BPB_OEM_LEN, bpb.oemIdentifier);
    printf("Bytes/sector:           %u\n", bpb.sectorSize);
    printf("Sectors/cluster:        %u\n", bpb.sectorsPerClusters);
    printf("Reserved sectors:       %u\n", bpb.reservedSectorCount);
    printf("Number of FATs:         %u\n", bpb.fatCount);
    printf("Number of dir entries:  %u\n", bpb.dirEntryCount);
    printf("Media type:             0x%x\n", bpb.mediaType);
    printf("Sectors/track:          %u\n", bpb.sectorsPerTrack);
    printf("Heads:                  %u\n", bpb.headCount);
    printf("Hidden sectors:         %u\n", bpb.hiddenSectCount);
    printf("Sector count:           %u\n", getSectorCount(&bpb));
    printf("\n");

    EBPB ebpb;
    fseek(file, sizeof(bpb), SEEK_SET);
    fread(&ebpb, sizeof(ebpb), 1, file);
    printf("Sectors/FAT:            %u\n", ebpb.sectorsPerFat);
    printf("Flags:                  0x%x\n", ebpb.flags);
    printf("FAT version:            0x%x\n", ebpb.fatVersion);
    printf("Root dir cluster:       %u\n", ebpb.rootDirClusterNum);
    printf("FSInfo sector:          %u\n", ebpb.fsInfoSectorNum);
    printf("Backup boot sector:     %u\n", ebpb.backupSectorNum);
    printf("Drive number:           %u\n", ebpb.driveNum);
    printf("NT Flags:               0x%x\n", ebpb.ntFlags);
    printf("Signature:              0x%u\n", ebpb.signature);
    printf("Serial number:          0x%x\n", ebpb.serialNum);
    printf("Label:                  %.*s\n", EBPB_LABEL_LEN, ebpb.label);
    printf("System ID:              %.*s\n", EBPB_SYS_ID_LEN, ebpb.systemId);
    printf("\n");

    uint16_t mbrSignature;
    fseek(file, 510, SEEK_SET);
    fread(&mbrSignature, 2, 1, file);
    printf("MBR Signature:          0x%x (%s)\n", mbrSignature, (mbrSignature == 0xaa55 ? "OK" : "BAD"));


    const size_t rootDirStart = (bpb.reservedSectorCount+bpb.fatCount*ebpb.sectorsPerFat)*bpb.sectorSize;
    printf("Root dir. starts at 0x%lx\n", rootDirStart);
    DirEntry rootDir;
    fseek(file, rootDirStart, SEEK_SET);
    fread(&rootDir, sizeof(rootDir), 1, file);
    char* attrs = dirEntryAttrsToStr(rootDir.attributes);
    printf("File name: %-11.11s     Attrs.: %s\n", rootDir.fileName, attrs);
    free(attrs);

    fclose(file);
    return 0;
}
