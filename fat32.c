/*
 * Chonky - A FAT32 file system library.
 * Author: timre13
 */

#include "fat32.h"
#include <stdarg.h>

//------------------------------------------------------------------------------

static int _chonkyErr(const char* fmt, ...)
{
    fprintf(stderr, "\033[1m\033[31mERR\033[m: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return 0;
}

static int _chonkyDbg(const char* fmt, ...)
{
    printf("\033[36mDBG\033[m: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return 0;
}

chonkyOutFun_t chout = &printf;
chonkyOutFun_t cherr = &_chonkyErr;
chonkyOutFun_t chdbg = &_chonkyDbg;

//------------------------------------------------------------------------------

static inline ulong umin(ulong a, ulong b)
{
    return (a < b) ? a : b;
}

void printHex(unsigned char* buffer, int n)
{
    for (int i=0; i < n; ++i)
    {
        chout("%02x ", buffer[i]);
        if (i % 32 == 31)
        {
            chout("\n");
        }
    }
}

//------------------------------------------------------------------------------

uint32_t BPBGetSectorCount(const BPB* input)
{
    // If _sectorCount is 0, there are more than 65535 sectors,
    // so the number is stored in _largeSectCount
    return input->_sectorCount == 0 ? input->_largeSectCount : input->_sectorCount;
}

//------------------------------------------------------------------------------

uint32_t clusterPtrGetIndex(ClusterPtr ptr)
{
    return ptr & 0x0fffffff;
}

bool clusterPtrIsBadCluster(ClusterPtr ptr)
{
    return clusterPtrGetIndex(ptr) == 0x0ffffff7;
}

bool clusterPtrIsLastCluster(ClusterPtr ptr)
{
    return clusterPtrGetIndex(ptr) >= 0x0ffffff8;
}

bool clusterPtrIsNull(ClusterPtr ptr)
{
    return clusterPtrGetIndex(ptr) == 0;
}

uint32_t fatGetNextClusterPtr(const Fat32Context* cont, ClusterPtr current)
{
    const uint fatOffset = clusterPtrGetIndex(current) * 4;
    // TODO: Clean up
    //const uint fatIndex = fatOffset / cont->fatSizeBytes; // Index of the FAT
    //const uint entry = fatOffset % cont->fatSizeBytes; // Offset inside the FAT
    //assert(fatIndex == 0); // TODO: Support multiple FATs
    //assert(entry < cont->fatSizeBytes/4);
    //printHex((uint8_t*)cont->fat+current, 4);
    //chdbg("\n0x%x -> 0x%02x\n", current, cont->fat[current+0]);
    return *(uint32_t*)&cont->fat[fatOffset];
}

//------------------------------------------------------------------------------

bool dirEntryIsVolumeLabel(const DirEntry* entry)
{
    if (!dirEntryIsLFE(entry->attributes)
    && (entry->attributes & (DIRENTRY_ATTR_VOLUME_ID | DIRENTRY_ATTR_DIRECTORY)) == DIRENTRY_ATTR_VOLUME_ID)
    {
        assert(entry->_entryFirstClusterNum1 == 0);
        assert(entry->_entryFirstClusterNum2 == 0);
        return true;
    }
    return false;
}

bool dirEntryIsLFE(uint8_t attrs)
{
    return (attrs & DIRENTRY_MASK_LONG_NAME) == DIRENTRY_ATTR_LONG_NAME;
}

bool dirEntryIsDir(const DirEntry* entry)
{
    if (!dirEntryIsLFE(entry->attributes)
    && (entry->attributes & (DIRENTRY_ATTR_VOLUME_ID | DIRENTRY_ATTR_DIRECTORY)) == DIRENTRY_ATTR_DIRECTORY)
    {
        assert(entry->fileSize == 0);
        return true;
    }
    return false;
}

bool dirEntryIsFile(const DirEntry* entry)
{
    return (!dirEntryIsLFE(entry->attributes)
        && (entry->attributes & (DIRENTRY_ATTR_VOLUME_ID | DIRENTRY_ATTR_DIRECTORY))) == 0;
}

bool dirEntryIsEmpty(const DirEntry* entry)
{
    return clusterPtrIsNull(dirEntryGetClusterPtr(entry));
}

uint32_t dirEntryGetClusterPtr(const DirEntry* entry)
{
    return ((uint32_t)entry->_entryFirstClusterNum1 << 16)
          | (uint32_t)entry->_entryFirstClusterNum2;
}

uint32_t dirEntryGetFirstClusterNumber(const DirEntry* input)
{
    return clusterPtrGetIndex(dirEntryGetClusterPtr(input));
}

uint64_t dirEntryGetDataAddress(const Fat32Context* cont, const DirEntry* entry)
{
    return fat32GetFirstSectorOfCluster(cont, dirEntryGetFirstClusterNumber(entry)) * cont->bpb->sectorSize;
}

char* dirEntryAttrsToStr(uint8_t attrs)
{
    char* str = malloc(7);

    if (dirEntryIsLFE(attrs))
    {
        strncpy(str, "__LFE_", 7);
        return str;
    }

    str[0] = (attrs & DIRENTRY_ATTR_READONLY)  ? 'R' : '-';
    str[1] = (attrs & DIRENTRY_ATTR_HIDDEN)    ? 'H' : '-';
    str[2] = (attrs & DIRENTRY_ATTR_SYSTEM)    ? 'S' : '-';
    str[3] = (attrs & DIRENTRY_ATTR_VOLUME_ID) ? 'V' : '-';
    str[4] = (attrs & DIRENTRY_ATTR_DIRECTORY) ? 'D' : '-';
    str[5] = (attrs & DIRENTRY_ATTR_ARCHIVE)   ? 'A' : '-';
    str[6] = 0;
    return str;
}

// TODO: Using offset
// TODO: Allocate buffer?
int dirEntryReadFileData(Fat32Context* cont, const DirEntry* entry, uint8_t* buffer, size_t bufferSize)
{
    assert(dirEntryIsDir(entry));

    // Don't do anything if the file is empty
    // or it is on a bad cluster
    if (dirEntryIsEmpty(entry) || clusterPtrIsBadCluster(dirEntryGetClusterPtr(entry)))
    {
        return 0;
    }

    // FIXME: Reading large files is probably broken
    //        Follow cluster chains

    const uint64_t address = dirEntryGetDataAddress(cont, entry);
    fseek(cont->file, address, SEEK_SET);
    return fread(buffer, 1, umin(bufferSize, entry->fileSize), cont->file);
}

//------------------------------------------------------------------------------

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

uint16_t* lfeEntryGetNameUCS2(const LfeEntry* entry)
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


char* lfeEntryGetNameASCII(const LfeEntry* entry)
{
    uint16_t* buffer = lfeEntryGetNameUCS2(entry);
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

void dirIteratorEntryFree(DirIteratorEntry** entryP)
{
    free((*entryP)->entry);
    free((*entryP)->longFilename);
    free(*entryP);
    *entryP = NULL;
}

char* dirIteratorEntryGetFileName(DirIteratorEntry* entry)
{
    char* fileName;
    // If we have a long filename, return it
    if (entry->longFilename[0] != 0)
    {
        const size_t len = strlen(entry->longFilename);
        fileName = malloc(len+1);
        strcpy(fileName, entry->longFilename);
        fileName[len] = 0;
    }
    // Only remove padding when this is a file (directories don't have extensions)
    else if (dirEntryIsFile(entry->entry))
    {
        chdbg("Filename: %.*s\n", DIRENTRY_FILENAME_LEN, entry->entry->fileName);

        // Count extension length
        int extLen = 0;
        for (int i=DIRENTRY_FILENAME_LEN-1; i >= 0; --i)
        {
            if (entry->entry->fileName[i] == ' ')
                break;
            ++extLen;
        }
        chdbg("Extension length: %i\n", extLen);

        int outLen;
        int paddingCount = 0;
        { // Count length without padding spaces
            int i=DIRENTRY_FILENAME_LEN-1-extLen;
            // Skip padding spaces
            for (; i >= 0; --i)
            {
                if (entry->entry->fileName[i] != ' ')
                {
                    break;
                }
                ++paddingCount;
            }
            chdbg("Padding: %i\n", paddingCount);
        }
        // If we have an extension, leave space for the dot
        outLen = DIRENTRY_FILENAME_LEN-paddingCount+(extLen ? 1 : 0);

        chdbg("Output length: %i\n", outLen);
        fileName = malloc(outLen+1);
        // Copy string without padding spaces
        {
            // Copy extension
            for (int i=0; i < extLen; ++i)
                fileName[outLen-i-1] = entry->entry->fileName[DIRENTRY_FILENAME_LEN-1-i];

            // Put dot if there is an extension
            if (extLen)
                fileName[outLen-extLen-1] = '.';

            // Copy prefix
            for (int i=0; i < DIRENTRY_FILENAME_LEN-paddingCount-extLen; ++i)
                fileName[i] = entry->entry->fileName[i];
        }
        fileName[outLen] = 0;
    }
    // Directory without a long filename, return as it is
    else
    {
        fileName = malloc(DIRENTRY_FILENAME_LEN+1);
        strncpy(fileName, (const char*)entry->entry->fileName, DIRENTRY_FILENAME_LEN);
        fileName[DIRENTRY_FILENAME_LEN] = 0;
    }
    chdbg("Output: \"%s\"\n", fileName);
    return fileName;
}

DirIterator* dirIteratorNew(uint64_t addr)
{
    DirIterator* it = malloc(sizeof(DirIterator));
    it->_initAddr = addr;
    it->_address = addr;
    it->_longFilename = calloc(LFE_FULL_NAME_LEN+1, 1);
    return it;
}

DirIteratorEntry* dirIteratorNext(Fat32Context* cont, DirIterator* it)
{
    if (it->_address == 0) // If the iterator ended
    {
        return NULL;
    }

    DirEntry* directory = malloc(sizeof(DirEntry));
    assert(directory);
    const uint clusterSizeBytes = cont->bpb->sectorsPerClusters * cont->bpb->sectorSize;
    while (true)
    {
        uint64_t newAddr = it->_address+sizeof(DirEntry);

        //chdbg("Reading dir. entry at 0x%lx\n", it->_address);
        fseek(cont->file, it->_address, SEEK_SET);
        fread(directory, sizeof(DirEntry), 1, cont->file);

        // If we are at a cluster boundary
        if (newAddr % clusterSizeBytes == 0)
        {
            // TODO: Works, but WTF
            const ClusterPtr clusterI = (newAddr-cont->bpb->reservedSectorCount*cont->bpb->sectorSize)/clusterSizeBytes-cont->bpb->sectorSize+1;
            //chdbg("End of cluster: 0x%x\n", clusterI);
            const ClusterPtr nextCluster = fatGetNextClusterPtr(cont, clusterI);
            assert(!clusterPtrIsNull(nextCluster));
            assert(!clusterPtrIsBadCluster(nextCluster));
            if (clusterPtrIsLastCluster(nextCluster))
            {
                chdbg("End of cluster chain (next: 0x%x)\n", nextCluster);
                it->_address = 0;
                free(directory);
                return NULL;
            }
            else
            {
                //chdbg("Next cluster is 0x%x\n", nextCluster);
                newAddr = cont->rootDirAddr+(nextCluster-cont->ebpb->rootDirClusterNum)*cont->bpb->sectorsPerClusters*cont->bpb->sectorSize;
            }
        }

        if (directory->fileName[0] == 0) // End of directory
        {
            chdbg("End of dir\n");
            it->_address = 0;
            free(directory);
            return NULL;
        }

        if (directory->fileName[0] == 0xe5) // Unused entry, skip
        {
            chdbg("Unused entry\n");
            continue;
        }

        if (dirEntryIsLFE(directory->attributes)) // LFE Entry
        {
            const LfeEntry* lfeEntry = (LfeEntry*)directory;
            char* lfeVal = lfeEntryGetNameASCII(lfeEntry);
            strncpy(it->_longFilename+((lfeEntry->nameStrIndex&0x0f)-1)*LFE_ENTRY_NAME_LEN, lfeVal, LFE_ENTRY_NAME_LEN);
            //chdbg("LFE entry: %s (fragment index: %i)\n", lfeVal, ((entry->nameStrIndex&0x0f)-1)*13);
            //chdbg("LFE Entry\n");
            it->_longFilename[LFE_FULL_NAME_LEN] = 0; // Ensure null terminator
            free(lfeVal);
        }
        else // Regular directory entry
        {
            DirIteratorEntry* dirItEntry = malloc(sizeof(DirIteratorEntry));
            assert(dirItEntry);
            dirItEntry->entry = directory;
            dirItEntry->longFilename = calloc(LFE_FULL_NAME_LEN+1, 1);
            dirItEntry->address = it->_address;
            strncpy(dirItEntry->longFilename, it->_longFilename, LFE_FULL_NAME_LEN);
            memset(it->_longFilename, 0, LFE_FULL_NAME_LEN+1);
            it->_address = newAddr;
            return dirItEntry;
        }

        it->_address = newAddr;
    }
}

void dirIteratorSetAddress(DirIterator* it, uint64_t addr)
{
    it->_initAddr = addr;
    it->_address = addr;
}

void dirIteratorRewind(DirIterator* it)
{
    it->_address = it->_initAddr;
}

void dirIteratorFree(DirIterator** itP)
{
    free((*itP)->_longFilename);
    free(*itP);
    *itP = NULL;
}

//------------------------------------------------------------------------------

Fat32Context* fat32ContextNew(const char* devFilePath)
{
    Fat32Context* context = malloc(sizeof(Fat32Context));
    context->file = fopen(devFilePath, "r");
    if (!context->file)
    {
        cherr("Failed to open device: %s: %s\n", devFilePath, strerror(errno));
        free(context);
        return NULL;
    }
    context->bpb = malloc(sizeof(BPB));
    fseek(context->file, 0, SEEK_SET);
    fread(context->bpb, sizeof(BPB), 1, context->file);

    context->ebpb = malloc(sizeof(EBPB));
    fseek(context->file, sizeof(BPB), SEEK_SET);
    fread(context->ebpb, sizeof(EBPB), 1, context->file);

    context->fatSizeBytes = context->ebpb->sectorsPerFat*context->bpb->sectorSize;
    context->fat = malloc(context->fatSizeBytes);
    assert(context->fat);
    const uint fatStart = context->bpb->reservedSectorCount*context->bpb->sectorSize;
    chout("FAT start: 0x%x\n", fatStart);
    fseek(context->file, fatStart, SEEK_SET);
    //fread(context->fat, sizeof(uint32_t), context->fatSizeBytes/sizeof(uint32_t), context->file);
    fread(context->fat, 1, context->fatSizeBytes, context->file);

    context->firstDataSector =
        context->bpb->reservedSectorCount
        + (context->bpb->fatCount*context->ebpb->sectorsPerFat);
    context->rootDirAddr =
        context->firstDataSector*context->bpb->sectorSize;
    return context;
}

void fat32ContextFree(Fat32Context** contextP)
{
    fclose((*contextP)->file);
    free((*contextP)->bpb);
    free((*contextP)->ebpb);
    free((*contextP)->fat);
    free(*contextP);
    *contextP = NULL;
}

uint32_t fat32GetFirstSectorOfCluster(const Fat32Context* cont, uint32_t cluster)
{
    return (cluster - 2) * cont->bpb->sectorsPerClusters + cont->firstDataSector;
}

void fat32PrintInfo(Fat32Context* cont)
{
    fseek(cont->file, 0, SEEK_END);
    const long diskSize = ftell(cont->file);
    chout("Disk size:              %li bytes = %fKb = %fMb = %fGb\n",
            diskSize, diskSize/1024.f, diskSize/1024.f/1024.f, diskSize/1024.f/1024.f/1024.f);
    chout("\n");

    chout("OEM:                    %.*s\n", BPB_OEM_LEN, cont->bpb->oemIdentifier);
    chout("Bytes/sector:           %u\n",   cont->bpb->sectorSize);
    chout("Sectors/cluster:        %u\n",   cont->bpb->sectorsPerClusters);
    chout("Reserved sectors:       %u\n",   cont->bpb->reservedSectorCount);
    chout("Number of FATs:         %u\n",   cont->bpb->fatCount);
    chout("Number of dir entries:  %u\n",   cont->bpb->dirEntryCount);
    chout("Media type:             0x%x\n", cont->bpb->mediaType);
    chout("Sectors/track:          %u\n",   cont->bpb->sectorsPerTrack);
    chout("Heads:                  %u\n",   cont->bpb->headCount);
    chout("Hidden sectors:         %u\n",   cont->bpb->hiddenSectCount);
    chout("Sector count:           %u\n",   BPBGetSectorCount(cont->bpb));
    chout("\n");

    chout("Sectors/FAT:            %u\n",   cont->ebpb->sectorsPerFat);
    chout("Flags:                  0x%x\n", cont->ebpb->flags);
    chout("FAT version:            0x%x\n", cont->ebpb->fatVersion);
    chout("Root dir cluster:       %u\n",   cont->ebpb->rootDirClusterNum);
    chout("FSInfo sector:          %u\n",   cont->ebpb->fsInfoSectorNum);
    chout("Backup boot sector:     %u\n",   cont->ebpb->backupSectorNum);
    chout("Drive number:           0x%x\n", cont->ebpb->driveNum);
    chout("NT Flags:               0x%x\n", cont->ebpb->ntFlags);
    chout("Signature:              0x%u\n", cont->ebpb->signature);
    chout("Serial number:          0x%x\n", cont->ebpb->serialNum);
    chout("Label:                  %.*s\n", EBPB_LABEL_LEN, cont->ebpb->label);
    chout("System ID:              %.*s\n", EBPB_SYS_ID_LEN, cont->ebpb->systemId);
    chout("\n");

    uint16_t mbrSignature;
    fseek(cont->file, 510, SEEK_SET);
    fread(&mbrSignature, 2, 1, cont->file);
    chout("MBR Signature:          0x%x (%s)\n", mbrSignature, (mbrSignature == 0xaa55 ? "OK" : "BAD"));
    chout("\n");
}

void fat32ListDir(Fat32Context* cont, uint64_t addr)
{
    chout("Listing of 0x%lx:\n", addr);
    // Print table heading
    chout("%-11.11s  |  %50s  |  %10s  |  %s  |  %s\n",
            "FILE NAME", "LONG FILE NAME", "SIZE", "ATTRS.", "CREAT. DATE & TIME");
    for (int i=0; i < 116; ++i) chout((i == 13 || i == 68 || i == 83 || i == 94) ? "|" : "-");
    chout("\n");

    // List directory
    DirIterator* it = dirIteratorNew(addr);
    int fileCount = 0;
    while (true)
    {
        DirIteratorEntry* dirEntry = dirIteratorNext(cont, it);
        if (dirEntry == NULL)
            break;

        char* attrs = dirEntryAttrsToStr(dirEntry->entry->attributes);
        DirEntryDate cDate = toDirEntryDate(dirEntry->entry->_creationDate);
        char* cDateStr = dirEntryDateToStr(&cDate);
        DirEntryTime cTime = toDirEntryTime(dirEntry->entry->_creationTime);
        char* cTimeStr = dirEntryTimeToStr(&cTime);
        chout("%-11.11s  |  %50s  |  ", dirEntry->entry->fileName, dirEntry->longFilename);
        if (dirEntryIsDir(dirEntry->entry)) { chout("     <DIR>"); }
        else { chout("%10i", dirEntry->entry->fileSize); }
        chout("  |  %s  |  %s %s\n", attrs, cDateStr, cTimeStr);
        free(attrs);
        free(cDateStr);
        free(cTimeStr);
        dirIteratorEntryFree(&dirEntry);
        ++fileCount;
    }
    dirIteratorFree(&it);
    chout("%i items in directory\n", fileCount);
}

DirIteratorEntry* fat32Find(Fat32Context* cont, uint64_t addr, const char* fileName)
{
    DirIterator* it = dirIteratorNew(addr);
    DirIteratorEntry* result;
    while (true)
    {
        result = dirIteratorNext(cont, it);
        if (result == NULL || strcmp(dirIteratorEntryGetFileName(result), fileName) == 0)
        {
            break;
        }
        dirIteratorEntryFree(&result);
    }
    dirIteratorFree(&it);
    return result;
}
