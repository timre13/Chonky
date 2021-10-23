/*
 * Chonky - A FAT32 file system library.
 * Author: timre13
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>

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
    uint hour;
    uint min;
    uint sec;
} PACKED DirEntryTime;

DirEntryTime toDirEntryTime(uint16_t input)
{
    DirEntryTime time = {
        .hour = (input & 0xf800) >> 11,
        .min  = (input & 0x07e0) >> 5,
        .sec  = (input & 0x001f) * 2
    };
    return time;
}

char* dirEntryTimeToStr(const DirEntryTime* input)
{
    char* buffer = malloc(9);
    if (input->hour > 23
     || input->min > 59
     || input->sec > 59
     || snprintf(buffer, 9, "%02i:%02i:%02i", input->hour+1, input->min+1, input->sec) > 8)
    {
        // If no space for time, fill the output with ?s
        strcpy(buffer, "\?\?:\?\?:\?\?");
    }
    return buffer;
}

//------------------------------------------------------------------------------

typedef struct DirEntryDate
{
    uint year;
    uint month;
    uint day;
} PACKED DirEntryDate;

DirEntryDate toDirEntryDate(uint16_t input)
{
    DirEntryDate date = {
        .year  = (input & 0xfe00) >> 9,
        .month = (input & 0x01e0) >> 5,
        .day   = (input & 0x001f)
    };
    return date;
}

char* dirEntryDateToStr(const DirEntryDate* input)
{
    char* buffer = malloc(11);
    if (input->month == 0 || input->month > 12
     || input->day == 0 || input->day > 31
     || snprintf(buffer, 11, "%04i-%02i-%02i", 1980+input->year, input->month, input->day) > 10)
    {
        // If invalid, fill the output with ?s
        strcpy(buffer, "\?\?\?\?-\?\?-\?\?");
    }
    return buffer;
}

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

uint16_t* lfeGetNameUCS2(const LfeEntry* entry)
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
    uint16_t* buffer = lfeGetNameUCS2(entry);
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

FILE* file;
BPB bpb;
EBPB ebpb;
int firstDataSector;

//------------------------------------------------------------------------------

typedef struct DirIterator
{
    uint64_t _address;
    char* _longFilename;

} DirIterator;

typedef struct DirIteratorEntry
{
    DirEntry* entry;
    char* longFilename;
    uint64_t address;
} DirIteratorEntry;

void dirIteratorEntryFree(DirIteratorEntry** entryP)
{
    free((*entryP)->entry);
    free((*entryP)->longFilename);
    free(*entryP);
    *entryP = NULL;
}

const char* dirIteratorEntryGetFileName(DirIteratorEntry* entry)
{
    return (entry->longFilename[0] != 0) ? entry->longFilename : (char*)entry->entry->fileName;
}

void dirIteratorRewind(DirIterator* it)
{
    it->_address = firstDataSector*bpb.sectorSize;
}

DirIterator* dirIteratorNew()
{
    DirIterator* it = malloc(sizeof(DirIterator));
    dirIteratorRewind(it);
    it->_longFilename = calloc(LFE_FULL_NAME_LEN+1, 1);
    return it;
}

void dirIteratorFree(DirIterator** itP)
{
    free((*itP)->_longFilename);
    free(*itP);
    *itP = NULL;
}

DirIteratorEntry* dirIteratorNext(DirIterator* it)
{
    if (it->_address == 0) // If the iterator ended
    {
        return NULL;
    }

    DirEntry* directory = malloc(sizeof(DirEntry));
    assert(directory);
    while (true)
    {
        //printf("Reading dir. entry at 0x%lx\n", it->_address);
        fseek(file, it->_address, SEEK_SET);
        fread(directory, sizeof(DirEntry), 1, file);
        it->_address += sizeof(DirEntry);

        if (directory->fileName[0] == 0) // End of directory
        {
            it->_address = 0;
            free(directory);
            return NULL;
        }

        if (directory->fileName[0] == 0xe5) // Unused entry, skip
        {
            continue;
        }

        if (isLongFileNameEntry(directory->attributes)) // LFE Entry
        {
            const LfeEntry* lfeEntry = (LfeEntry*)directory;
            char* lfeVal = lfeGetNameASCII(lfeEntry);
            strncpy(it->_longFilename+((lfeEntry->nameStrIndex&0x0f)-1)*LFE_ENTRY_NAME_LEN, lfeVal, LFE_ENTRY_NAME_LEN);
            //printf("LFE entry: %s (fragment index: %i)\n", lfeVal, ((entry->nameStrIndex&0x0f)-1)*13);
            it->_longFilename[LFE_FULL_NAME_LEN] = 0; // Ensure null terminator
            free(lfeVal);
        }
        else // Regular directory entry
        {
            DirIteratorEntry* dirItEntry = malloc(sizeof(DirIteratorEntry));
            assert(dirItEntry);
            dirItEntry->entry = directory;
            dirItEntry->longFilename = calloc(LFE_FULL_NAME_LEN+1, 1);
            dirItEntry->address = it->_address-sizeof(DirEntry);
            strncpy(dirItEntry->longFilename, it->_longFilename, LFE_FULL_NAME_LEN);
            it->_longFilename[0] = 0; // Clear buffer
            return dirItEntry;
        }
    }
}

DirIteratorEntry* dirIteratorFind(const char* fileName)
{
    DirIterator* it = dirIteratorNew();
    DirIteratorEntry* result;
    while (true)
    {
        result = dirIteratorNext(it);
        if (result == NULL || strcmp(dirIteratorEntryGetFileName(result), fileName) == 0)
        {
            break;
        }
        dirIteratorEntryFree(&result);
    }
    dirIteratorFree(&it);
    return result;
}

//------------------------------------------------------------------------------

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    file = fopen(argv[1], "r");
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

    printf("\n");

    //const int rootCluster = ebpb.rootDirClusterNum;
    firstDataSector = bpb.reservedSectorCount + (bpb.fatCount*ebpb.sectorsPerFat);
    //const int firstFatSector = bpb.reservedSectorCount;

    //const int cluster = 0;
    //const int firstSectorOfCluster = ((cluster - 2)*bpb.sectorsPerClusters) + firstDataSector;


    // Print table heading
    printf("%-11.11s  |  %50s  |  %10s  |  %s  |  %s\n",
            "FILE NAME", "LONG FILE NAME", "SIZE", "ATTRS.", "CREAT. DATE & TIME");
    for (int i=0; i < 116; ++i) putchar((i == 13 || i == 68 || i == 83 || i == 94) ? '|' : '-');
    putchar('\n');

    // List directory
    DirIterator* it = dirIteratorNew();
    int fileCount = 0;
    while (true)
    {
        DirIteratorEntry* dirEntry = dirIteratorNext(it);
        if (dirEntry == NULL)
            break;

        char* attrs = dirEntryAttrsToStr(dirEntry->entry->attributes);
        DirEntryDate cDate = toDirEntryDate(dirEntry->entry->_creationDate);
        char* cDateStr = dirEntryDateToStr(&cDate);
        DirEntryTime cTime = toDirEntryTime(dirEntry->entry->_creationTime);
        char* cTimeStr = dirEntryTimeToStr(&cTime);
        printf("%-11.11s  |  %50s  |  ", dirEntry->entry->fileName, dirEntry->longFilename);
        if (dirEntry->entry->attributes & DIRENTRY_ATTR_FLAG_DIRECTORY) { printf("     <DIR>"); }
        else { printf("%10i", dirEntry->entry->fileSize); }
        printf("  |  %s  |  %s %s\n", attrs, cDateStr, cTimeStr);
        free(attrs);
        free(cDateStr);
        free(cTimeStr);
        dirIteratorEntryFree(&dirEntry);
        ++fileCount;
    }
    dirIteratorFree(&it);
    printf("%i items in directory\n", fileCount);

    DirIteratorEntry* found = dirIteratorFind("test.txt");
    if (found)
    {
        printf("Found a file of %i bytes\n", found->entry->fileSize);
        dirIteratorEntryFree(&found);
    }
    else
    {
        printf("\"test.txt\" Not found\n");
    }

    fclose(file);
    return 0;
}
