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

/*
 * 4 most significant bits: reserved.
 * 28 least significant bits: address.
 */
typedef uint32_t ClusterEntry;

uint32_t clusterEntryGetAddress(ClusterEntry entry)
{
    return entry & 0x0fffffff;
}

bool clusterEntryIsBadCluster(ClusterEntry entry)
{
    return clusterEntryGetAddress(entry) == 0x0ffffff7;
}

bool clusterEntryIsLastCluster(ClusterEntry entry)
{
    return clusterEntryGetAddress(entry) >= 0x0ffffff8;
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
    char* str = malloc(7);

    if (isLongFileNameEntry(attrs))
    {
        strncpy(str, "__LFE_", 7);
        return str;
    }

    if (attrs & DIRENTRY_ATTR_FLAG_READONLY)    str[0] = 'R'; else str[0] = '-';
    if (attrs & DIRENTRY_ATTR_FLAG_HIDDEN)      str[1] = 'H'; else str[1] = '-';
    if (attrs & DIRENTRY_ATTR_FLAG_SYSTEM)      str[2] = 'S'; else str[2] = '-';
    if (attrs & DIRENTRY_ATTR_FLAG_VOLUME_ID)   str[3] = 'V'; else str[3] = '-';
    if (attrs & DIRENTRY_ATTR_FLAG_DIRECTORY)   str[4] = 'D'; else str[4] = '-';
    if (attrs & DIRENTRY_ATTR_FLAG_ARCHIVE)     str[5] = 'A'; else str[5] = '-';
    str[6] = 0;
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

#define LFE_ENTRY_NAME_LEN 13
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

uint16_t* lfeGetNameUTF16(const LfeEntry* entry)
{
    uint16_t* buffer = calloc(LFE_ENTRY_NAME_LEN+1, 2);
    for (int i=0; i < 5; ++i)
    {
        if (entry->_name0[i] != 0xff)
            buffer[i] = entry->_name0[i];
    }
    for (int i=0; i < 6; ++i)
    {
        if (entry->_name1[i] != 0xff)
            buffer[5+i] = entry->_name1[i];
    }
    for (int i=0; i < 2; ++i)
    {
        if (entry->_name2[i] != 0xff)
            buffer[11+i] = entry->_name2[i];
    }
    return buffer;
}

char* lfeGetNameASCII(const LfeEntry* entry)
{
    uint16_t* buffer = lfeGetNameUTF16(entry);
    char* output = malloc(LFE_ENTRY_NAME_LEN+1);
    for (int i=0; i < LFE_ENTRY_NAME_LEN; ++i)
    {
        output[i] = buffer[i];
    }
    free(buffer);
    output[LFE_ENTRY_NAME_LEN] = 0;
    return output;
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


    //const int rootCluster = ebpb.rootDirClusterNum;
    const int firstDataSector = bpb.reservedSectorCount + (bpb.fatCount*ebpb.sectorsPerFat);
    //const int firstFatSector = bpb.reservedSectorCount;

    //const int cluster = 0;
    //const int firstSectorOfCluster = ((cluster - 2)*bpb.sectorsPerClusters) + firstDataSector;

    uint32_t dirStart = firstDataSector*bpb.sectorSize;
    char* longFilename = calloc(LFE_ENTRY_NAME_LEN*16+1, 1);
    while (true)
    {
        //printf("Reading dir. entry at 0x%x\n", dirStart);
        DirEntry directory;
        fseek(file, dirStart, SEEK_SET);
        fread(&directory, sizeof(directory), 1, file);
        if (directory.fileName[0] == 0) // End of directory
        {
            printf("===== End of directory listing =====\n");
            break;
        }
        if (directory.fileName[0] == 0xe5) // Unused entry
        {
            goto increment;
        }

        if (isLongFileNameEntry(directory.attributes))
        {
            // FIXME: Improve LFE support. (fix truncated file name, recognize more flags, etc.)
            // See: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#VFAT_long_file_names
            const LfeEntry* entry = (LfeEntry*)&directory;
            char* lfeVal = lfeGetNameASCII(entry);
            strcpy(longFilename+((entry->nameStrIndex&0x0f)-1)*LFE_ENTRY_NAME_LEN, lfeVal);
            //printf("LFE entry: %s (fragment index: %i)\n", lfeVal, ((entry->nameStrIndex&0x0f)-1)*13);
            free(lfeVal);
        }
        else
        {
            char* attrs = dirEntryAttrsToStr(directory.attributes);
            printf("File name: %-11.11s  |  %255.255s  |  Attrs.: %s\n",
                    directory.fileName, longFilename, attrs);
            free(attrs);
        }

increment:
        ;
        dirStart += sizeof(DirEntry);
    }
    free(longFilename);


    fclose(file);
    return 0;
}
