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
typedef struct
{
    uint8_t     _r1[3];
    uint8_t     oemIdentifier[BPB_OEM_LEN];
    uint16_t    sectorSize;
    uint8_t     sectorsPerClusters;
    uint16_t    reservedSectorCount;
    uint8_t     fatCount;
    uint16_t    dirEntryCount;
    uint16_t    sectorCount;
    uint8_t     mediaType;
    uint16_t    sectorsPerFat;
    uint16_t    sectorsPerTrack;
    uint16_t    headCount;
    uint32_t    hiddenSectCount;
    uint32_t    largeSectCount;
} __attribute__((packed)) BPB;

//------------------------------------------------------------------------------

#define EBPB_LABEL_LEN 11
#define EBPB_SYS_ID_LEN 8

/* Extended BIOS Parameter Block */
typedef struct
{
    uint8_t     driveNum;
    uint8_t     ntFlags;
    uint8_t     signature;
    uint32_t    serialNum;
    uint8_t     label[EBPB_LABEL_LEN];
    uint8_t     systemId[EBPB_SYS_ID_LEN];
    /* 448 bytes of boot code */
    /* MBR signature (0xAA55) */
} __attribute__((packed)) EBPB;

//------------------------------------------------------------------------------

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE* file = fopen(argv[1], "r");
    if (!file)
    {
        printf("Failed to open file: %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char* buffer = malloc(fileSize);
    printf("Read %lu bytes\n",
            fread(buffer, 1, fileSize, file));

    for (int i=0; i < 45; ++i) printf("=");
    printf(" MBR ");
    for (int i=0; i < 45; ++i) printf("=");
    printf("\n");
    printHex(buffer, 1024);
    for (int i=0; i < 95; ++i) printf("=");
    printf("\n\n");

    BPB bpb;
    memcpy(&bpb, buffer, sizeof(bpb));
    printf("OEM:                    %.*s\n", BPB_OEM_LEN, bpb.oemIdentifier);
    printf("Bytes/sector:           %i\n", bpb.sectorSize);
    printf("Sectors/cluster:        %i\n", bpb.sectorsPerClusters);
    printf("Reserved sectors:       %i\n", bpb.reservedSectorCount);
    printf("Number of FATs:         %i\n", bpb.fatCount);
    printf("Number of dir entries:  %i\n", bpb.dirEntryCount);
    printf("Sectors:                %i\n", bpb.sectorCount);
    printf("Media type:             0x%x\n", bpb.mediaType);
    printf("Sectors/FAT:            %i\n", bpb.sectorsPerFat);
    printf("Sectors/track:          %i\n", bpb.sectorsPerTrack);
    printf("Heads:                  %i\n", bpb.headCount);
    printf("Hidden sectors:         %i\n", bpb.hiddenSectCount);
    printf("Large sector count:     %i\n", bpb.largeSectCount);
    printf("\n");

    EBPB ebpb;
    memcpy(&ebpb, buffer+sizeof(bpb)+0x1c, sizeof(ebpb));
    printf("Drive number:           %i\n", ebpb.driveNum);
    printf("NT Flags:               0x%x\n", ebpb.ntFlags);
    printf("Signature:              0x%i\n", ebpb.signature);
    printf("Serial number:          0x%x\n", ebpb.serialNum);
    printf("Label:                  %.*s\n", EBPB_LABEL_LEN, ebpb.label);
    printf("System ID:              %.*s\n", EBPB_SYS_ID_LEN, ebpb.systemId);
    printf("\n");

    uint16_t mbrSignature;
    memcpy(&mbrSignature, buffer+510, 2);
    printf("MBR Signature:          0x%x (%s)\n", mbrSignature, (mbrSignature == 0xaa55 ? "OK" : "BAD"));

    free(buffer);
    fclose(file);
    return 0;
}
