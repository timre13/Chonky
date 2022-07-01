/*
 * Chonky - A FAT32 file system library.
 * Author: timre13
 */

#include <stdio.h>
#include <ctype.h>
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

        if ((dirEntryIsDir(entry->entry))
         && (strncmp((char*)entry->entry->fileName, ".          ", DIRENTRY_FILENAME_LEN) != 0)
         && (strncmp((char*)entry->entry->fileName, "..         ", DIRENTRY_FILENAME_LEN) != 0))
        {
            char* fileName = dirIteratorEntryGetFileName(entry);
            printf("Listing subdir: %s\n", fileName);
            free(fileName);
            uint64_t childAddr = dirEntryGetDataAddress(cont, entry->entry);
            if (clusterPtrIsLastCluster(childAddr))
            {
                printf("Last cluster reached\n");
                return;
            }
            else if (clusterPtrIsBadCluster(childAddr))
            {
                printf("Reached a bad cluster\n");
                return;
            }
            listDirsRecursively(cont, childAddr);
        }
        dirIteratorEntryFree(&entry);
    }
    dirIteratorFree(&it);
}

static char* readCmd()
{
    printf("\n> ");
    char* cmd = malloc(1024);
    if (!fgets(cmd, 1024, stdin))
    {
        free(cmd);
        return NULL;
    }
    const size_t len = strlen(cmd);
    if (cmd[len-1] == '\n')
        cmd[len-1] = 0; // Remove newline from the end of line
    return cmd;
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    Fat32Context* cont = fat32ContextNew(argv[1]);
    assert(cont);

    fat32PrintInfo(cont);

    while (true)
    {
        char* input = readCmd();
        if (!input) return 1;

        size_t cmdLen = 0;
        while (input[cmdLen] && !isspace(input[cmdLen]))
            ++cmdLen;

        if (!cmdLen)
        {
            free(input);
            continue;
        }

        char* cmd = malloc(cmdLen+1);
        strncpy(cmd, input, cmdLen);
        cmd[cmdLen] = 0;

        if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0)
        {
            printf( "help           Print this message\n"
                    "?              Same as 'help'\n"
                    "info           Print file system and volume info\n"
                    "list <path>    List a directory at `path` or the root folder if no argument is given\n"
                    "print <path>   Show contents of file at `path`\n"
                    "dump <path>    Show hexdump of file at `path`\n"
                    "tree           Recursively list all the directories\n"
                    // Add new here
                    "exit           Exit program\n"
                    "quit           Same as 'exit'\n"
            );
        }
        else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0)
        {
            free(input);
            free(cmd);
            break;
        }
        else if (strcmp(cmd, "info") == 0)
        {
            fat32PrintInfo(cont);
        }
        else if (strcmp(cmd, "list") == 0)
        {
            const char* arg = input+cmdLen+1;
            uint64_t addrToList;
            if (strlen(arg) == 0) // If root dir
            {
                printf("Listing root\n");
                addrToList = cont->rootDirAddr;
            }
            else
            {
                printf("Finding: '%s'...\n", arg);
                DirIteratorEntry* found = fat32OpenFile(cont, arg);
                if (!found)
                {
                    fprintf(stderr, "Error: Directory '%s' not found\n", arg);
                    continue;
                }

                if (!dirEntryIsDir(found->entry))
                {
                    fprintf(stderr, "Error: '%s' is not a directory\n", arg);
                    dirIteratorEntryFree(&found);
                    continue;
                }

                addrToList = dirEntryGetDataAddress(cont, found->entry);
                dirIteratorEntryFree(&found);
            }

            fat32ListDir(cont, addrToList);
        }
        else if (strcmp(cmd, "print") == 0)
        {
            const char* arg = input+cmdLen+1;
            printf("Finding: '%s'...\n", arg);
            if (strlen(arg) == 0)
            {
                fprintf(stderr, "Error: Argument required\n");
                continue;
            }

            DirIteratorEntry* found = fat32OpenFile(cont, arg);
            if (!found)
            {
                fprintf(stderr, "Error: File '%s' not found\n", arg);
                continue;
            }

            if (!dirEntryIsFile(found->entry))
            {
                fprintf(stderr, "Error: '%s' is not a file\n", arg);
                dirIteratorEntryFree(&found);
                continue;
            }

            uint8_t* buffer = calloc(found->entry->fileSize, 1);
            assert(buffer);
            int readCount = dirEntryReadFileData(cont, found->entry, buffer, found->entry->fileSize);
            printf("Read %i bytes\n", readCount);
            printf("File content:\n%.*s", found->entry->fileSize, buffer);
            free(buffer);

            dirIteratorEntryFree(&found);
        }
        else if (strcmp(cmd, "dump") == 0)
        {
            const char* arg = input+cmdLen+1;
            printf("Finding: '%s'...\n", arg);
            if (strlen(arg) == 0)
            {
                fprintf(stderr, "Error: Argument required\n");
                continue;
            }

            DirIteratorEntry* found = fat32OpenFile(cont, arg);
            if (!found)
            {
                fprintf(stderr, "Error: File '%s' not found\n", arg);
                continue;
            }

            if (!dirEntryIsFile(found->entry))
            {
                fprintf(stderr, "Error: '%s' is not a file\n", arg);
                dirIteratorEntryFree(&found);
                continue;
            }

            uint8_t* buffer = calloc(found->entry->fileSize, 1);
            assert(buffer);
            int readCount = dirEntryReadFileData(cont, found->entry, buffer, found->entry->fileSize);
            printf("Read %i bytes\n", readCount);
            printHex(buffer, readCount);
            free(buffer);

            dirIteratorEntryFree(&found);
        }
        else if (strcmp(cmd, "tree") == 0)
        {
            listDirsRecursively(cont, cont->rootDirAddr);
        }
        else
        {
            fprintf(stderr, "Error: Invalid command: '%s'\n", cmd);
        }

        free(input);
        free(cmd);
    }


#if 0
    //const char* toFind = "assets";
    //const char* toFind = "test.txt";
    //
    //DirIteratorEntry* found = fat32OpenFile(cont, "assets/sounds/chaingun/chaingun_data/eff/d1f/eff1f724.au", cont->rootDirAddr);
    DirIteratorEntry* found = fat32OpenFile(cont, "assets/textures/http_server/icon_with_text.plain.svg");
    //DirIteratorEntry* found = fat32OpenFile(cont, "assets/sounds/chaingun/chaingun_data/eff/d1f");
    //printf("Looking up: \"%s\"\n", toFind);
    //DirIteratorEntry* found = fat32OpenFile(cont, "assets/sounds/chaingun/chaingun_data/eff/d1f/notfound");
    //DirIteratorEntry* found = fat32OpenFile(cont, cont->rootDirAddr, toFind);
    if (!found)
    {
        printf("File or directory not found\n");
    }
    else if (dirEntryIsDir(found->entry))
    {
        char* attrs = dirEntryAttrsToStr(found->entry->attributes);
        printf("Found a directory at 0x%lx, attributes: %s\n", found->address, attrs);
        free(attrs);

        fat32ListDir(cont, dirEntryGetDataAddress(cont, found->entry));
    }
    else if (dirEntryIsFile(found->entry))
    {
        char* attrs = dirEntryAttrsToStr(found->entry->attributes);
        printf("Found a file at 0x%lx, attributes: %s\n", found->address, attrs);
        free(attrs);

        printf("Reading file of %i bytes\n", found->entry->fileSize);
        uint8_t* buffer = calloc(found->entry->fileSize, 1);
        assert(buffer);
        int readCount = dirEntryReadFileData(cont, found->entry, buffer, found->entry->fileSize);
        printf("Read %i bytes\n", readCount);
        printf("File content:\n%.*s", found->entry->fileSize, buffer);
        free(buffer);
    }
    else
    {
        char* attrs = dirEntryAttrsToStr(found->entry->attributes);
        printf("Found a special object at 0x%lx, attributes: %s\n", found->address, attrs);
        free(attrs);
    }
    if (found) dirIteratorEntryFree(&found);
#endif

    fat32ContextFree(&cont);
    return 0;
}
