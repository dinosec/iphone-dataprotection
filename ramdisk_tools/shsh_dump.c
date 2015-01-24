#include <stdio.h>
#include <sys/types.h>
//#include <sys/mount.h>
//#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include "ioflash/ioflash.h"
#include "util.h"

struct IMG2
{
    uint32_t magic;
    uint32_t block_size;
    uint32_t images_offset;
    uint32_t images_block;
    uint32_t images_length;
    uint8_t padding[0x1c];
    uint32_t crc32;
};

struct IMG3
{
    uint32_t magic;
    uint32_t fullSize;
    uint32_t sizeNoPack;
    uint32_t sigCheckArea;
    uint32_t iden;
};

struct IMG3_TLV
{
    uint32_t tag;
    uint32_t total_length;
    uint32_t data_length;
    uint8_t payload[1];
};

void printIMG2(struct IMG2* s)
{
    printf("magic= %x\n", s->magic);
    printf("block_size= %x\n", s->block_size);
    printf("images_offset= %x\n", s->images_offset);
    printf("images_block= %x\n", s->images_block);
    printf("images_length= %x\n", s->images_length);
}
void printIMG3(struct IMG3* s)
{
    char iden[10]={0};
    memcpy(iden, &s->iden, 4);
    printf("magic= %x\n", s->magic);
    printf("fullSize= %x\n", s->fullSize);
    printf("iden= %s\n", iden);
}

CFDataRef getIMG3Data(struct IMG3* img3)
{
    CFDataRef data = NULL;
    uint8_t* p = (uint8_t*) img3;
    uint8_t* z = &p[20];
    
    if(img3->magic != 'Img3')
        return NULL;
            
    while(z < &p[img3->fullSize])
    {
        struct IMG3_TLV* item = (struct IMG3_TLV*) z;
        if( item->tag == 'DATA')
        {
            data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, item->payload, item->data_length, NULL);
            return data;
        }
        z += item->total_length;
    }
    return NULL;
}


extern uint32_t gPagesPerBlock;
extern uint32_t gBytesPerPage ;
extern uint32_t gBootloaderBytes ;

int main(int argc, char* argv[])
{
    int one=1;
    int cmd=0;

    CFMutableDictionaryRef dict = FSDGetInfo(1);
    if (dict == NULL)
    {
        fprintf(stderr, "FAILed to get NAND infos");
        return -1;
    }
    if(!IOFlashStorage_kernel_patch())
        return -1;

    struct kIOFlashControllerOut out;
    uint32_t bootSize = gBootloaderBytes * gPagesPerBlock * 8;
    
    printf("Mallocing %x bytes for boot partition\n", bootSize);
    uint8_t* boot = malloc(bootSize);
    if( boot == NULL)
    {
        return -1;
    }
    
    uint8_t* buffer = malloc(gBytesPerPage);
    if( buffer == NULL)
    {
        return -1;
    }
    
    uint32_t block, page, off=0;
    
    for(block=8; block < 16; block++)
    {
        for(page=0; page < gPagesPerBlock; page++)
        {
            if(FSDReadBootPage(0, block*gPagesPerBlock + page, buffer, &out))
            {
                //printf("FSDReadBootPage error %x\n", block*gPagesPerBlock + page);
                //return -1;
            }
            memcpy(&boot[off], buffer, gBootloaderBytes);
            off += gBootloaderBytes;
        }
    }
    
    printIMG2((struct IMG2*) boot);
    struct IMG2* img2 = (struct IMG2*) boot;
    
    if( img2->magic != 0x494d4732)
    {
        printf("Bag IMG2 magic : %x\n", img2->magic);
        return -1;
    }
    uint32_t start = img2->block_size * img2->images_block;
    
    uint32_t end = start + img2->block_size * img2->images_length;
    
    if( end < start)
    {
        return -1;
    }
    printf("start %x end %x\n", start, end);
    uint8_t* p = &boot[start];
    
    CFMutableDictionaryRef resultsDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,  &kCFTypeDictionaryValueCallBacks);
    
    if(dict == NULL)
    {
        return -1;
    }

    while(p < &boot[end])
    {
        struct IMG3* img3 = (struct IMG3*) p;
        if(img3->magic != 'Img3')
            break;
        printIMG3(img3);
        
        if(img3->iden == 'SCAB')
        {
            CFDataRef data = getIMG3Data(img3);
            if(data)
            {
                CFDictionaryAddValue(resultsDict, CFSTR("APTicket"), data);
                writePlistToStdout(resultsDict);
                CFRelease(data);
            }
        }
        p += img3->fullSize;
    
    }
    return 0;
}