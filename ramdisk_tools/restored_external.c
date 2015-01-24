/**
https://github.com/comex/bloggy/wiki/Redsn0w%2Busbmux
**/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <assert.h>
#include <CoreFoundation/CoreFoundation.h>
#include <AvailabilityMacros.h>
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_5
#include <IOKit/IOCFPlugIn.h>
#include "IOUSBDeviceControllerLib.h"
#include "plist_server.h"
#include "remote_functions.h"
#include "device_info.h"
#include "registry.h"

#define kIOSomethingPluginID CFUUIDGetConstantUUIDWithBytes(NULL, \
    0x9E, 0x72, 0x21, 0x7E, 0x8A, 0x60, 0x11, 0xDB, \
    0xBF, 0x57, 0x00, 0x0D, 0x93, 0x6D, 0x06, 0xD2)
#define kIOWhatTheFuckID CFUUIDGetConstantUUIDWithBytes(NULL, \
    0xEA, 0x33, 0xBA, 0x4F, 0x8A, 0x60, 0x11, 0xDB, \
    0x84, 0xDB, 0x00, 0x0D, 0x93, 0x6D, 0x06, 0xD2)

void init_usb(CFStringRef serialString) {
    IOUSBDeviceDescriptionRef desc = IOUSBDeviceDescriptionCreateFromDefaults(kCFAllocatorDefault);
    IOUSBDeviceDescriptionSetSerialString(desc, serialString == NULL ? CFSTR("ramdisk - udid fail?") : serialString);
    
    /*CFArrayRef usb_interfaces = IOUSBDeviceDescriptionCopyInterfaces(desc);
    int i;
    for(i=0; i < CFArrayGetCount(usb_interfaces); i++)
    {
        CFArrayRef arr1 = CFArrayGetValueAtIndex(usb_interfaces, i);
        
        if( CFArrayContainsValue(arr1, CFRangeMake(0,CFArrayGetCount(arr1)), CFSTR("PTP")))
        {
            printf("Found PTP interface\n");
            break;
        }
    }*/
    
    IOUSBDeviceControllerRef controller;
    while (IOUSBDeviceControllerCreate(kCFAllocatorDefault, &controller))
    {
        printf("Unable to get USB device controller\n");
        sleep(3);    
    }
    IOUSBDeviceControllerSetDescription(controller, desc);
    
    CFMutableDictionaryRef match = IOServiceMatching("IOUSBDeviceInterface");
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(dict, CFSTR("USBDeviceFunction"), CFSTR("PTP"));
    CFDictionarySetValue(match, CFSTR("IOPropertyMatch"), dict);
    io_service_t service;
    while(1) {
        CFRetain(match);
        service = IOServiceGetMatchingService(kIOMasterPortDefault, match);
        if(!service) {
            printf("Didn't find, trying again\n");
            sleep(1);
        } else {
            break;
        }
    }
    CFRelease(match);
    IOCFPlugInInterface **iface;
    SInt32 score;
    printf("123\n");
    assert(!IOCreatePlugInInterfaceForService(
        service,
        kIOSomethingPluginID,
        kIOCFPlugInInterfaceID,
        &iface,
        &score
        ));
    void *thing;
    
    assert(!((*iface)->QueryInterface)(iface,
                CFUUIDGetUUIDBytes(kIOWhatTheFuckID),
                &thing));
                
    IOReturn (**table)(void *, ...) = *((void **) thing);
    printf("%p\n", table[0x10/4]);
    
    //open IOUSBDeviceInterfaceInterface
    table[0x10/4](thing, 0);
    //set IOUSBDeviceInterfaceInterface class
    table[0x2c/4](thing, 0xff, 0);
    //set IOUSBDeviceInterfaceInterface sub-class
    table[0x30/4](thing, 0x50, 0);
    //set IOUSBDeviceInterfaceInterface protocol
    table[0x34/4](thing, 0x43, 0);
    //commit IOUSBDeviceInterfaceInterface configuration
    table[0x44/4](thing, 0);
    IODestroyPlugInInterface(iface);
    //assert(!table[0x14/4](thing, 0));
}

void init_tcp() {
    // from launchd
    struct ifaliasreq ifra;
    struct ifreq ifr;
    int s;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "lo0");

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        return;

    if (ioctl(s, SIOCGIFFLAGS, &ifr) != -1) {
        ifr.ifr_flags |= IFF_UP;
        assert(ioctl(s, SIOCSIFFLAGS, &ifr) != -1);
    }

    memset(&ifra, 0, sizeof(ifra));
    strcpy(ifra.ifra_name, "lo0");
    ((struct sockaddr_in *)&ifra.ifra_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ((struct sockaddr_in *)&ifra.ifra_addr)->sin_len = sizeof(struct sockaddr_in);
    ((struct sockaddr_in *)&ifra.ifra_mask)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr.s_addr = htonl(IN_CLASSA_NET);
    ((struct sockaddr_in *)&ifra.ifra_mask)->sin_len = sizeof(struct sockaddr_in);

    assert(ioctl(s, SIOCAIFADDR, &ifra) != -1);

    assert(close(s) == 0);

}

CFDictionaryRef reboot__(int socket, CFDictionaryRef dict)
{
    reboot(0);
    return NULL;
}


char* execve_env[]= {NULL};
char* execve_params[]={"/sbin/sshd", NULL};
char* ioflash[]={"/var/root/ioflashstoragekit", NULL};

size_t bootargs_len = 255;
char bootargs[256]={0};

int main(int argc, char* argv[])
{
    int i;
    int nandReadOnly=0;
    struct stat st;
    
    printf("Starting ramdisk tool\n");
    printf("Compiled " __DATE__ " " __TIME__ "\n");
    printf("Revision " HGVERSION "\n");
    
    CFMutableDictionaryRef matching;
    io_service_t service = 0;
    matching = IOServiceMatching("IOWatchDogTimer");
    if (matching == NULL) {
        printf("unable to create matching dictionary for class IOWatchDogTimer\n");
    }
    
    service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
    if (service == 0) {
        printf("unable to create matching dictionary for class IOWatchDogTimer\n");
    }
    uint32_t zero = 0;
    CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &zero);
    IORegistryEntrySetCFProperties(service, n);
    IOObjectRelease(service);
    
    CFMutableDictionaryRef deviceInfos = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                            0,
                                                            &kCFTypeDictionaryKeyCallBacks,
                                                            &kCFTypeDictionaryValueCallBacks);	
    
    get_device_infos(deviceInfos);
    init_tcp();

    sysctlbyname("kern.bootargs", bootargs, &bootargs_len, NULL, 0);
    
    if (strstr(bootargs, "nand-readonly") || strstr(bootargs, "nand-disable"))
    {
        printf("NAND read only mode, data partition wont be mounted\n");
        nandReadOnly = 1;
    }
    else
    {
        printf("Waiting for data partition\n");
        for(i=0; i < 10; i++)
        {
            if(!stat("/dev/disk0s2s1", &st))
            {
                system("/sbin/fsck_hfs  /dev/disk0s2s1");
                break;
            }
            if(!stat("/dev/disk0s1s2", &st))
            {
                system("/sbin/fsck_hfs  /dev/disk0s1s2");
                break;
            }
            if(!stat("/dev/disk0s2", &st))
            {
                system("/sbin/fsck_hfs  /dev/disk0s2");
                break;
            }
            sleep(5);
        }
    }
    init_usb(CFDictionaryGetValue(deviceInfos, CFSTR("udid")));
    printf("USB init done\n");

    system("mount /"); //make ramdisk writable
   
    chmod("/var/root/.ssh/authorized_keys", 0600); 
    chown("/var/root/.ssh/authorized_keys", 0, 0); 
    chown("/var/root/.ssh", 0, 0); 
    chown("/var/root/", 0, 0); 

    printf(" #######  ##    ##\n");
    printf("##     ## ##   ## \n");
    printf("##     ## ##  ##  \n");
    printf("##     ## #####   \n");
    printf("##     ## ##  ##  \n");
    printf("##     ## ##   ## \n"); 
    printf(" #######  ##    ##\n");
    printf("iphone-dataprotection ramdisk\n");
    printf("revision: " HGVERSION " "  __DATE__ " " __TIME__ "\n");
    
    if(!stat(execve_params[0], &st))
    {
        printf("Running %s\n", execve_params[0]);
        if((i = posix_spawn(NULL, execve_params[0], NULL, NULL, execve_params, execve_env)))
            printf("posix_spawn(%s) returned %d\n", execve_params[0], i);
    }
    else
    {
        printf("%s is missing\n", execve_params[0]);
    }
    
    /*if (nandReadOnly)
    {*/
        if(!stat(ioflash[0], &st))
        {
            printf("Running %s\n", ioflash[0]);
            if((i = posix_spawn(NULL, ioflash[0], NULL, NULL, ioflash, execve_env)))
                printf("posix_spawn(%s) returned %d\n", execve_params[0], i);
        }
    /*}*/
    
    CFMutableDictionaryRef handlers = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, NULL);
    CFDictionaryAddValue(handlers, CFSTR("DeviceInfo"), device_info);
    CFDictionaryAddValue(handlers, CFSTR("GetSystemKeyBag"), load_system_keybag);
    CFDictionaryAddValue(handlers, CFSTR("BruteforceSystemKeyBag"), bruteforce_system_keybag);
    CFDictionaryAddValue(handlers, CFSTR("KeyBagGetPasscodeKey"), keybag_get_passcode_key);
    CFDictionaryAddValue(handlers, CFSTR("GetEscrowRecord"), get_escrow_record);
    CFDictionaryAddValue(handlers, CFSTR("DownloadFile"), download_file);
    CFDictionaryAddValue(handlers, CFSTR("AES"), remote_aes);
    CFDictionaryAddValue(handlers, CFSTR("Reboot"), reboot__);

    serve_plist_rpc(1999, handlers);
    return 0;
}
