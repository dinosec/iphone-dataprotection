#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <CoreFoundation/CoreFoundation.h>
#include "util.h"

void printBytesToHex(const uint8_t* buffer, size_t bytes)
{
    while(bytes > 0) {
        printf("%02x", *buffer);
        buffer++;
        bytes--;
    }
}

void printHexString(const char* description, const uint8_t* buffer, size_t bytes)
{
    printf("%s : ", description);
    printBytesToHex(buffer, bytes);
    printf("\n");
}

int write_file(const char* filename, uint8_t* data, size_t len)
{
    int fd = open(filename, O_CREAT | O_RDWR);
    if (fd < 0)
        return -1;
    if (write(fd, data, len) != len)
        return -1;
    close(fd);
    return 0;
}

void writePlistToStdout(CFDictionaryRef out)
{
    CFDataRef d = CFPropertyListCreateData(kCFAllocatorDefault, out, kCFPropertyListXMLFormat_v1_0, 0, NULL);
    if (d == NULL)
        return;
    write(1, CFDataGetBytePtr(d), CFDataGetLength(d));
}

int mountDataPartition(const char* mountpoint)
{
    char* diskname = "/dev/disk0s2s1";
    int err;
    printf("Trying to mount data partition\n");
    err = mount("hfs","/mnt2", MNT_RDONLY | MNT_NOATIME | MNT_NODEV | MNT_LOCAL, &diskname);
    if (!err)
        return 0;
    
    diskname = "/dev/disk0s1s2";
    err = mount("hfs","/mnt2", MNT_RDONLY | MNT_NOATIME | MNT_NODEV | MNT_LOCAL, &diskname);
    if (!err)
        return 0;
    diskname = "/dev/disk0s2";
    err = mount("hfs","/mnt2", MNT_RDONLY | MNT_NOATIME | MNT_NODEV | MNT_LOCAL, &diskname);

    return err;
}


int getHFSInfos(struct HFSInfos *infos)
{
    char buf[8192] = {0};
    struct HFSPlusVolumeHeader* header;
    unsigned int i;
    
    int fd = open("/dev/rdisk0s2", O_RDONLY);
    if (fd < 0 )
        fd = open("/dev/rdisk0s1s2", O_RDONLY); //ios5 lwvm
    if (fd < 0 )
        return fd;
    lseek(fd, 0, SEEK_SET);
    
    if (read(fd, buf, 8192) != 8192)
        return -1;
    close(fd);
        
    header = (struct HFSPlusVolumeHeader*) &buf[0x400];
    
    uint32_t blockSize = CFSwapInt32BigToHost(header->blockSize);
    
    infos->volumeUUID = header->volumeUUID;
    infos->blockSize = blockSize;
    
    if (blockSize != 0x1000 && blockSize != 0x2000)
    {
        fprintf(stderr, "getHFSInfos: Unknown block size %x\n", blockSize);
    }
    else
    {
        fd = open("/dev/rdisk0", O_RDONLY);
        if (fd < 0 )
            return fd;
        
        if (read(fd, buf, 8192) != 8192)
            return -1;
        
        if (!memcmp(buf, LwVMType, 16))
        {
            LwVM* lwvm = (LwVM*) buf;
            
            if (lwvm->chunks[0] != 0xF000)
            {
                fprintf(stderr, "getHFSInfos: lwvm->chunks[0] != 0xF000\n");
                return -1;
            }

            for(i=0; i < 0x400; i++)
            {
                if(lwvm->chunks[i] == 0x1000) //partition 1 block 0
                {
                    break;
                }
            }
            uint32_t LwVM_rangeShiftValue  = 32 - __builtin_clz((lwvm->mediaSize - 1) >> 10);

            infos->dataVolumeOffset = (i << LwVM_rangeShiftValue) / blockSize;
        }
        else
        {
            lseek(fd, 2*blockSize, SEEK_SET);
        
            if (read(fd, buf, 8192) != 8192)
                return -1;
            close(fd);
        
            infos->dataVolumeOffset = ((unsigned int*)buf)[0xA0/4];
        }
    }
    return 0;
}

CFMutableStringRef CreateHexaCFString(uint8_t* buffer, size_t len)
{
    int i;
    
    CFMutableStringRef s = CFStringCreateMutable(kCFAllocatorDefault, len*2);
    
    for(i=0; i < len; i++)
    {
        CFStringAppendFormat(s, NULL, CFSTR("%02x"), buffer[i]);
    }
    return s;
}

void addHexaString(CFMutableDictionaryRef out, CFStringRef key, uint8_t* buffer, size_t len)
{
    CFMutableStringRef s = CreateHexaCFString(buffer, len);
    CFDictionaryAddValue(out, key, s);
    CFRelease(s);
}

void saveResults(CFStringRef filename, CFMutableDictionaryRef out)
{
    CFURLRef fileURL = CFURLCreateWithFileSystemPath( NULL, filename, kCFURLPOSIXPathStyle, FALSE);
    CFWriteStreamRef stream = CFWriteStreamCreateWithFile( NULL, fileURL);
    CFWriteStreamOpen(stream);
    CFPropertyListWriteToStream(out, stream, kCFPropertyListXMLFormat_v1_0, NULL);
    CFWriteStreamClose(stream);
    
    CFRelease(stream);
    CFRelease(fileURL);
}

int create_listening_socket(int port)
{
    struct sockaddr_in listen_addr;
    int s, one = 1;
    
    memset(&listen_addr, 0, sizeof(struct sockaddr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(port);
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    
    if (bind(s, (struct sockaddr *)&listen_addr, sizeof(struct sockaddr)) < 0)
    {
        perror("bind");
        return -1;
    }
    listen(s, 10);

    return s;
}
