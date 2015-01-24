#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include "IOAESAccelerator.h"
#include "AppleEffaceableStorage.h"
#include "bsdcrypto/rijndael.h"
#include "bsdcrypto/key_wrap.h"
#include "device_info.h"
#include "registry.h"
#include "util.h"
#include "ioflash/ioflash.h"

uint8_t lockers[960]={0};
uint8_t lwvm[80]={0};

CFMutableDictionaryRef device_info(int socket, CFDictionaryRef request)
{
    uint8_t dkey[40]={0};
    uint8_t emf[36]={0};
    size_t bootargs_len = 255;
    char bootargs[256]={0};

    struct HFSInfos hfsinfos={0};
    
    CFMutableDictionaryRef out  = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                            0,
                                                            &kCFTypeDictionaryKeyCallBacks,
                                                            &kCFTypeDictionaryValueCallBacks);	
    
    get_device_infos(out);
    
    CFMutableDictionaryRef nand = FSDGetInfo();
    if (nand != NULL)
        CFDictionaryAddValue(out, CFSTR("nand"), nand);

    getHFSInfos(&hfsinfos);

    uint8_t* key835 = IOAES_key835();
    uint8_t* key89A = IOAES_key89A();
    uint8_t* key89B = IOAES_key89B();
    
    if (!AppleEffaceableStorage__getBytes(lockers, 960))
    {
        CFDataRef lockersData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, lockers, 960, kCFAllocatorNull);
        CFDictionaryAddValue(out, CFSTR("lockers"), lockersData);
        CFRelease(lockersData);
        
        if (!AppleEffaceableStorage__getLockerFromBytes(LOCKER_DKEY, lockers, 960, dkey, 40))
        {
            aes_key_wrap_ctx ctx;

            aes_key_wrap_set_key(&ctx, key835, 16);

            if(aes_key_unwrap(&ctx, dkey, dkey, 32/8))
                printf("FAIL unwrapping DKey with key 0x835\n");
            else
                addHexaString(out, CFSTR("DKey"), dkey, 32);
        }
        if (!AppleEffaceableStorage__getLockerFromBytes(LOCKER_EMF, lockers, 960, emf, 36))
        {
            doAES(&emf[4], &emf[4], 32, kIOAESAcceleratorCustomMask, key89B, NULL, kIOAESAcceleratorDecrypt, 128);
            addHexaString(out, CFSTR("EMF"), &emf[4], 32);
        }
        else if (!AppleEffaceableStorage__getLockerFromBytes(LOCKER_LWVM, lockers, 960, lwvm, 0x50))
        {
            doAES(lwvm, lwvm, 0x50, kIOAESAcceleratorCustomMask, key89B, NULL, kIOAESAcceleratorDecrypt, 128);
            memcpy(&emf[4], &lwvm[32+16], 32);
            addHexaString(out, CFSTR("EMF"), &emf[4], 32);
        }
    }
    
    CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &hfsinfos.dataVolumeOffset);
    CFDictionaryAddValue(out, CFSTR("dataVolumeOffset"), n);
    CFRelease(n);
    addHexaString(out, CFSTR("dataVolumeUUID"), (uint8_t*) &hfsinfos.volumeUUID, 8);
    addHexaString(out, CFSTR("key835"), key835, 16);
    addHexaString(out, CFSTR("key89A"), key89A, 16);
    addHexaString(out, CFSTR("key89B"), key89B, 16);
    
    sysctlbyname("kern.bootargs", bootargs, &bootargs_len, NULL, 0);
    if (bootargs_len > 1)
    {
        CFStringRef bootargsString = CFStringCreateWithBytes(kCFAllocatorDefault, (const UInt8*) bootargs, bootargs_len - 1, kCFStringEncodingASCII, 0);
        CFDictionaryAddValue(out, CFSTR("kern.bootargs"), bootargsString);
        CFRelease(bootargsString);
    }
    
    CFDictionaryAddValue(out, CFSTR("ramdisk revision"), CFSTR(HGVERSION));
    CFDictionaryAddValue(out, CFSTR("ramdisk compile time"), CFSTR(__DATE__ " " __TIME__ ));

    return out;
}
