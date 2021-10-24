/*
 * Chonky - A FAT32 file system library.
 * Author: timre13
 */

#include <stdio.h>
#include "fat32.h"

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

    fat32PrintInfo(cont);

    /*
    const int rootCluster = ebpb.rootDirClusterNum;
    const int firstFatSector = bpb.reservedSectorCount;

    const int cluster = 0;
    const int firstSectorOfCluster = ((cluster - 2)*bpb.sectorsPerClusters) + firstDataSector;
    */

    fat32ListDir(cont);
    putchar('\n');

    DirIteratorEntry* found = dirIteratorFind(cont, "test.txt");
    if (found)
    {
        printf("Found a file of %i bytes\n", found->entry->fileSize);
        dirIteratorEntryFree(&found);
    }
    else
    {
        printf("\"test.txt\" Not found\n");
    }

    fat32ContextFree(&cont);
    return 0;
}
