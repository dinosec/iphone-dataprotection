/**
https://github.com/Gojohnnyboi/restored_pwn
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <CommonCrypto/CommonDigest.h>
#include "util.h"

//from libmobilegestalt.dylib
CFDataRef copyDataFromChosen(CFStringRef key)
{
    io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    if (chosen)
    {
        CFDataRef res = IORegistryEntryCreateCFProperty(chosen, key, kCFAllocatorDefault, 0);
        IOObjectRelease(chosen);
        return res;
    }
    return NULL;
}
CFStringRef copyStringFromChosen(CFStringRef key)
{
    CFStringRef s = NULL;
    CFDataRef data = copyDataFromChosen(key);
    if(data == NULL)
        return NULL;

    if(CFGetTypeID(data) == CFDataGetTypeID())
    {
        s = CFStringCreateWithCString(kCFAllocatorDefault, (const char*) CFDataGetBytePtr(data), kCFStringEncodingUTF8);
    }
    CFRelease(data);
    return s;
}

CFNumberRef copyNumberFromChosen(CFStringRef key)
{
    CFNumberRef num = NULL;
    CFDataRef data = copyDataFromChosen(key);
    
    if(data == NULL)
        return NULL;
    if(CFGetTypeID(data) == CFDataGetTypeID())
    {
        int len = CFDataGetLength(data);
        
        num = CFNumberCreate(kCFAllocatorDefault,
                             len == 4 ? kCFNumberSInt32Type : kCFNumberSInt64Type,
                             CFDataGetBytePtr(data)
                             );
    }
    CFRelease(data);
    return num;
}

io_service_t get_io_service(const char *name) {
    CFMutableDictionaryRef matching;
    io_service_t service = 0;
    
    matching = IOServiceMatching(name);
    if(matching == NULL) {
        printf("unable to create matching dictionary for class '%s'\n", name);
        return 0;
    }
    
    while(!service) {
        CFRetain(matching);
        service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
        if(service) break;
        
        printf("waiting for matching IOKit service: %s\n", name);
        sleep(1);
        CFRelease(matching);
    }
    
    CFRelease(matching);
    
    return service;
}

CFStringRef copy_device_imei() {
    CFMutableDictionaryRef matching;
    io_service_t service;
    CFDataRef imeiData;
    const void *imeiDataPtr;
    CFStringRef imeiString;
    
    matching = IOServiceNameMatching("baseband");
    service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
    
    if(!service) {
        return NULL;
    }
    
    imeiData = IORegistryEntryCreateCFProperty(service, CFSTR("device-imei"), kCFAllocatorDefault, 0);
    if(!imeiData) {
        printf("unable to find device-imei property\n");
        IOObjectRelease(service);
        return NULL;
    }
    
    imeiDataPtr = CFDataGetBytePtr(imeiData);
    imeiString = CFStringCreateWithCString(kCFAllocatorDefault, imeiDataPtr, kCFStringEncodingUTF8);
    
    CFRelease(imeiData);
    IOObjectRelease(service);
    
    return imeiString;
}

CFStringRef copy_device_serial_number() {
    io_service_t service;
    CFStringRef serialNumber;
    
    service = get_io_service("IOPlatformExpertDevice");
    if(!service) {
        printf("unable to find IOPlatformExpertDevice service\n");
        return NULL;
    }
    
    serialNumber = IORegistryEntryCreateCFProperty(service, CFSTR("IOPlatformSerialNumber"), kCFAllocatorDefault, 0);
    IOObjectRelease(service);
    
    return serialNumber;
}

CFStringRef copy_devicetree_option(CFStringRef key) {
    io_registry_entry_t entry;
    CFStringRef option;
    
    entry = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/options");
    if(!entry) {
        printf("unable to get registry entry for IODeviceTree:/options\n");
        return NULL;
    }
    
    option = IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0);
    IOObjectRelease(entry);
    
    return option;
}

CFStringRef copy_hardware_model() {
    size_t buflen = 0x80;
    char buf[buflen];
    CFStringRef model;
    
    if(sysctlbyname("hw.model", buf, &buflen, NULL, 0) != 0) {
        printf("sysctlbyname for hw.model failed: %s\n", strerror(errno));
        return NULL;
    }
    
    model = CFStringCreateWithCString(kCFAllocatorDefault, buf, kCFStringEncodingUTF8);
    
    return model;
}

CFStringRef copy_hardware_platform() {
    io_service_t service;
    CFStringRef platform;
    char *platformPtr;
    
    service = get_io_service("IOPlatformExpertDevice");
    if(!service) {
        printf("unable to find IOPlatformExpertDevice service\n");
        return NULL;
    }
    
    platform= IORegistryEntryCreateCFProperty(service, CFSTR("platform-name"), kCFAllocatorDefault, 0);
    if(platform == NULL) {
        printf("platform-name not found in device tree\n");
        IOObjectRelease(service);
        return NULL;
    }
    
    platformPtr = calloc(1, CFStringGetLength(platform)+1);
    if(!CFStringGetCString(platform, platformPtr, CFStringGetLength(platform)+1, kCFStringEncodingUTF8)) {
        printf("unable to obtain platform-name string\n");
        IOObjectRelease(service);
        return NULL;
    }
    
    printf("platform-name = %s\n", platformPtr);
    free(platformPtr);
    
    return platform;
}

CFStringRef copy_bluetooth_mac_address() {
    io_service_t service;
    CFDataRef macaddrData;
    CFStringRef macaddr;
    unsigned char macaddrBytes[6];
    
    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceNameMatching("bluetooth"));
    if(!service) {
        printf("unable to find bluetooth service\n");
        return NULL;
    }
    
    macaddrData= IORegistryEntryCreateCFProperty(service, CFSTR("local-mac-address"), kCFAllocatorDefault, 0);
    if(macaddrData == NULL) {
        printf("bluetooth local-mac-address not found\n");
        IOObjectRelease(service);
        return NULL;
    }
    CFDataGetBytes(macaddrData, CFRangeMake(0,6), macaddrBytes);
    
    macaddr = CFStringCreateWithFormat(kCFAllocatorDefault,
                                        NULL,
                                        CFSTR("%02x:%02x:%02x:%02x:%02x:%02x"),
                                        macaddrBytes[0],
                                        macaddrBytes[1],
                                        macaddrBytes[2],
                                        macaddrBytes[3],
                                        macaddrBytes[4],
                                        macaddrBytes[5]);

    return macaddr;
}

void search_wifi_mac_callback(void** context, io_iterator_t iterator) {
    unsigned char macaddrBytes[6];
    io_iterator_t iterator2=0;
    io_object_t obj2=0;
    io_name_t name;
    CFDataRef t1=0;
    io_object_t next;
    
    while ((next = IOIteratorNext(iterator)) != 0)
    {
        if (!IORegistryEntryCreateIterator(next, "IOService", 3, &iterator2))
        {
            while((obj2 = IOIteratorNext(iterator2)) != 0)
            {
                if (!IORegistryEntryGetName(obj2,name))
                {
                    if (!strcmp(name, "sdio") || !strcmp(name, "wlan"))
                    {
                        if((t1 = IORegistryEntryCreateCFProperty(obj2, CFSTR("local-mac-address"), kCFAllocatorDefault, 0)) != 0)
                        {
                            CFDataGetBytes(t1, CFRangeMake(0,6), macaddrBytes);
                            *context = (void*) CFStringCreateWithFormat(kCFAllocatorDefault,
                                        NULL,
                                        CFSTR("%02x:%02x:%02x:%02x:%02x:%02x"),
                                        macaddrBytes[0],
                                        macaddrBytes[1],
                                        macaddrBytes[2],
                                        macaddrBytes[3],
                                        macaddrBytes[4],
                                        macaddrBytes[5]);
                            CFRelease(t1);
                        }  
                    }
                }

            }
            IOObjectRelease(iterator2);
        }
        IOObjectRelease(next);
        if (*context != NULL)
            break;
    }
}

CFStringRef lookup_mac_address(const char* serviceName)
{
    unsigned char macaddrBytes[6];
    CFStringRef res = NULL;

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceNameMatching(serviceName));
    
    if(service)
    {
        CFDataRef macData = IORegistryEntryCreateCFProperty(service, CFSTR("local-mac-address"), kCFAllocatorDefault, 0);
        if(macData != NULL)
        {
            CFDataGetBytes(macData, CFRangeMake(0,6), macaddrBytes);
    
            res = CFStringCreateWithFormat(kCFAllocatorDefault,
                                        NULL,
                                        CFSTR("%02x:%02x:%02x:%02x:%02x:%02x"),
                                        macaddrBytes[0],
                                        macaddrBytes[1],
                                        macaddrBytes[2],
                                        macaddrBytes[3],
                                        macaddrBytes[4],
                                        macaddrBytes[5]);
            CFRelease(macData);
        }
        IOObjectRelease(service);
    }
    return res;
}

CFStringRef copy_wifi_mac_address() {
    CFStringRef wifimac = NULL;
    IONotificationPortRef notify_port = 0;
    io_iterator_t iterator = 0;
    
    wifimac = lookup_mac_address("sdio");
    if (wifimac != NULL)
        return wifimac;

    wifimac = lookup_mac_address("wlan");
    if (wifimac != NULL)
        return wifimac;
    
    notify_port = IONotificationPortCreate(kIOMasterPortDefault);
    
    CFRunLoopSourceRef  runLoopSource = IONotificationPortGetRunLoopSource(notify_port);
    
    CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopDefaultMode);

    if (!IOServiceAddMatchingNotification( notify_port,
          kIOMatchedNotification,
          IOServiceMatching("IONetworkController"),
          (IOServiceMatchingCallback) search_wifi_mac_callback,
          &wifimac,
          &iterator
          ))
    {
        search_wifi_mac_callback((void**)&wifimac, iterator);
        while( wifimac == NULL)
        {
            if( CFRunLoopRunInMode(kCFRunLoopDefaultMode,0, TRUE) != kCFRunLoopRunHandledSource)
            {
                printf("giving up on wifi mac address\n");
                break;
            }
        }
    }
    IONotificationPortDestroy(notify_port);
    return wifimac;
}

int useNewUDID(CFStringRef hw)
{
    return CFEqual(hw, CFSTR("K93AP")) ||
            CFEqual(hw, CFSTR("K94AP")) ||
            CFEqual(hw, CFSTR("K95AP")) ||
            CFEqual(hw, CFSTR("N92AP")) ||
            CFEqual(hw, CFSTR("N94AP"));
}

//http://iphonedevwiki.net/index.php/Lockdownd
void get_device_infos(CFMutableDictionaryRef out) {
    CC_SHA1_CTX sha1ctx;
    uint8_t udid[20];
    char udid1[100];
    CFStringRef serial;
    CFStringRef imei;
    CFStringRef macwifi;
    CFStringRef macbt;
    
    CFStringRef hw = copy_hardware_model(); 
    if (hw != NULL)
    {
        CFDictionaryAddValue(out, CFSTR("hwModel"), hw);
        CFRelease(hw);
    }
    
    serial = copy_device_serial_number();
    imei = copy_device_imei();
    macwifi = copy_wifi_mac_address();
    macbt = copy_bluetooth_mac_address();
    
    CFMutableStringRef udidInput = CFStringCreateMutable(kCFAllocatorDefault, 0);
    if (serial != NULL)
    {
        CFStringAppend(udidInput, serial);
        CFDictionaryAddValue(out, CFSTR("serialNumber"), serial);
        CFRelease(serial);
    }
    
    uint64_t _ecid = 0;
    CFNumberRef ecid = copyNumberFromChosen(CFSTR("unique-chip-id"));
    if (ecid != NULL)
    {
        CFDictionaryAddValue(out, CFSTR("ECID"), ecid);
    }
    
    if (ecid != NULL && useNewUDID(hw))
    {
        CFNumberGetValue(ecid, kCFNumberSInt64Type, &_ecid);
        CFStringAppendFormat(udidInput, NULL, CFSTR("%llu"), _ecid);
    }
    else if (imei != NULL)
    {
        CFStringAppend(udidInput, imei);
        CFDictionaryAddValue(out, CFSTR("imei"), imei);
        CFRelease(imei);
    }
    if (macwifi != NULL)
    {
        CFStringAppend(udidInput, macwifi);
        CFDictionaryAddValue(out, CFSTR("wifiMac"), macwifi);
        CFRelease(macwifi);
    }
    if (macbt != NULL)
    {
        CFStringAppend(udidInput, macbt);
        CFDictionaryAddValue(out, CFSTR("btMac"), macbt);
        CFRelease(macbt);
    }
    
    CFStringGetCString(udidInput, udid1, 99, kCFStringEncodingASCII);
    
    CC_SHA1_Init(&sha1ctx);
    CC_SHA1_Update(&sha1ctx, udid1, CFStringGetLength(udidInput));
    CC_SHA1_Final(udid, &sha1ctx);
    
    CFRelease(udidInput);
    addHexaString(out, CFSTR("udid"), udid, 20);

}