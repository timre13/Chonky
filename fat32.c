/*
 * Chonky - A FAT32 file system library.
 * Author: timre13
 */

#include "fat32.h"

//------------------------------------------------------------------------------

uint32_t getSectorCount(const BPB* input)
{
    // If _sectorCount is 0, there are more than 65535 sectors,
    // so the number is stored in _largeSectCount
    return input->_sectorCount == 0 ? input->_largeSectCount : input->_sectorCount;
}

//------------------------------------------------------------------------------

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

DirIterator* dirIteratorNewAtRoot(Fat32Context* cont)
{
    return dirIteratorNew(cont->firstDataSector*cont->bpb->sectorSize);
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
    while (true)
    {
        //printf("Reading dir. entry at 0x%lx\n", it->_address);
        fseek(cont->file, it->_address, SEEK_SET);
        fread(directory, sizeof(DirEntry), 1, cont->file);
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
            memset(it->_longFilename, 0, LFE_FULL_NAME_LEN+1);
            return dirItEntry;
        }
    }
}

DirIteratorEntry* dirIteratorFind(Fat32Context* cont, const char* fileName)
{
    DirIterator* it = dirIteratorNewAtRoot(cont);
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
        fprintf(stderr, "Failed to open device: %s: %s\n", devFilePath, strerror(errno));
        free(context);
        return NULL;
    }
    context->bpb = malloc(sizeof(BPB));
    fseek(context->file, 0, SEEK_SET);
    fread(context->bpb, sizeof(BPB), 1, context->file);

    context->ebpb = malloc(sizeof(EBPB));
    fseek(context->file, sizeof(BPB), SEEK_SET);
    fread(context->ebpb, sizeof(EBPB), 1, context->file);

    context->firstDataSector =
        context->bpb->reservedSectorCount
        + (context->bpb->fatCount*context->ebpb->sectorsPerFat);
    return context;
}

void fat32ContextFree(Fat32Context** contextP)
{
    fclose((*contextP)->file);
    free((*contextP)->bpb);
    free((*contextP)->ebpb);
    free(*contextP);
    *contextP = NULL;
}

void fat32PrintInfo(Fat32Context* cont)
{
    fseek(cont->file, 0, SEEK_END);
    const long diskSize = ftell(cont->file);
    printf("Disk size:              %li bytes = %fKb = %fMb = %fGb\n",
            diskSize, diskSize/1024.f, diskSize/1024.f/1024.f, diskSize/1024.f/1024.f/1024.f);
    putchar('\n');

    printf("OEM:                    %.*s\n", BPB_OEM_LEN, cont->bpb->oemIdentifier);
    printf("Bytes/sector:           %u\n",   cont->bpb->sectorSize);
    printf("Sectors/cluster:        %u\n",   cont->bpb->sectorsPerClusters);
    printf("Reserved sectors:       %u\n",   cont->bpb->reservedSectorCount);
    printf("Number of FATs:         %u\n",   cont->bpb->fatCount);
    printf("Number of dir entries:  %u\n",   cont->bpb->dirEntryCount);
    printf("Media type:             0x%x\n", cont->bpb->mediaType);
    printf("Sectors/track:          %u\n",   cont->bpb->sectorsPerTrack);
    printf("Heads:                  %u\n",   cont->bpb->headCount);
    printf("Hidden sectors:         %u\n",   cont->bpb->hiddenSectCount);
    printf("Sector count:           %u\n",   getSectorCount(cont->bpb));
    putchar('\n');

    printf("Sectors/FAT:            %u\n",   cont->ebpb->sectorsPerFat);
    printf("Flags:                  0x%x\n", cont->ebpb->flags);
    printf("FAT version:            0x%x\n", cont->ebpb->fatVersion);
    printf("Root dir cluster:       %u\n",   cont->ebpb->rootDirClusterNum);
    printf("FSInfo sector:          %u\n",   cont->ebpb->fsInfoSectorNum);
    printf("Backup boot sector:     %u\n",   cont->ebpb->backupSectorNum);
    printf("Drive number:           %u\n",   cont->ebpb->driveNum);
    printf("NT Flags:               0x%x\n", cont->ebpb->ntFlags);
    printf("Signature:              0x%u\n", cont->ebpb->signature);
    printf("Serial number:          0x%x\n", cont->ebpb->serialNum);
    printf("Label:                  %.*s\n", EBPB_LABEL_LEN, cont->ebpb->label);
    printf("System ID:              %.*s\n", EBPB_SYS_ID_LEN, cont->ebpb->systemId);
    putchar('\n');

    uint16_t mbrSignature;
    fseek(cont->file, 510, SEEK_SET);
    fread(&mbrSignature, 2, 1, cont->file);
    printf("MBR Signature:          0x%x (%s)\n", mbrSignature, (mbrSignature == 0xaa55 ? "OK" : "BAD"));
    putchar('\n');
}

void fat32ListDir(Fat32Context* cont)
{
    // Print table heading
    printf("%-11.11s  |  %50s  |  %10s  |  %s  |  %s\n",
            "FILE NAME", "LONG FILE NAME", "SIZE", "ATTRS.", "CREAT. DATE & TIME");
    for (int i=0; i < 116; ++i) putchar((i == 13 || i == 68 || i == 83 || i == 94) ? '|' : '-');
    putchar('\n');

    // List directory
    DirIterator* it = dirIteratorNewAtRoot(cont);
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
}