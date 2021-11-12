/*
 * Chonky - A FAT32 file system library.
 * Author: timre13
 */

#include <stdio.h>
#include "fat32.h"

void listDirsRecursively(Fat32Context* cont, uint64_t addr)
{
    if (addr == cont->rootDirAddr)
        printf("Listing root dir\n");

    fat32ListDir(cont, addr);
    putchar('\n'); putchar('\n');

    DirIterator* it = dirIteratorNew(addr);
    while (true)
    {
        DirIteratorEntry* entry = dirIteratorNext(cont, it);
        if (!entry)
        {
            break;
        }

        if ((entry->entry->attributes & DIRENTRY_ATTR_FLAG_DIRECTORY)
         && (strncmp((char*)entry->entry->fileName, ".          ", DIRENTRY_FILENAME_LEN) != 0)
         && (strncmp((char*)entry->entry->fileName, "..         ", DIRENTRY_FILENAME_LEN) != 0))
        {
            printf("Listing subdir: %s\n", dirIteratorEntryGetFileName(entry));
            listDirsRecursively(cont, dirEntryGetDataAddress(cont, entry->entry));
        }
        dirIteratorEntryFree(&entry);
    }
    dirIteratorFree(&it);
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    Fat32Context* cont = fat32ContextNew(argv[1]);
    if (!cont)
    {
        return 1;
    }

    //fat32PrintInfo(cont);
    //listDirsRecursively(cont, cont->rootDirAddr);

    DirIteratorEntry* found = fat32Find(cont, cont->rootDirAddr, "test.txt");
    if (!found)
    {
        printf("File not found\n");
    }
    else
    {
        printf("Found file at 0x%lx\n", found->address);

        printf("Reading file of %i bytes\n", found->entry->fileSize);
        uint8_t* buffer = calloc(found->entry->fileSize, 1);
        assert(buffer);
        int readCount = dirEntryReadFileData(cont, found->entry, buffer, found->entry->fileSize);
        printf("Read %i bytes\n", readCount);
        printf("File content:\n%.*s", found->entry->fileSize, buffer);
        free(buffer);
        dirIteratorEntryFree(&found);
    }

    fat32ContextFree(&cont);
    return 0;
}
