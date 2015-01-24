#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCryptor.h> 
#include <CommonCrypto/CommonHMAC.h>
#include "IOKit.h"
#include "IOAESAccelerator.h"
#include "AppleEffaceableStorage.h"
#include "AppleKeyStore.h"
#include "util.h"
#include "bsdcrypto/rijndael.h"
#include "bsdcrypto/key_wrap.h"

CFDictionaryRef AppleKeyStore_loadKeyBag(const char* folder, const char* filename)
{
    char keybagPath[100];
    struct BAG1Locker bag1_locker={0};
    //unsigned char buffer_bag1[52] = {0};
    
    snprintf(keybagPath, 99, "%s/%s.kb", folder, filename);

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
                                                           (const UInt8*)keybagPath,
                                                           strlen(keybagPath),
                                                           0);
    
    if (url == NULL)
        return NULL;
    
    CFReadStreamRef stream = CFReadStreamCreateWithFile (kCFAllocatorDefault, url);
    
    if (stream == NULL)
        return NULL;
    
    if (CFReadStreamOpen(stream) != TRUE)
        return NULL;
    
    CFPropertyListRef plist =  CFPropertyListCreateWithStream (kCFAllocatorDefault, 
                                                               stream,
                                                               0,
                                                               kCFPropertyListImmutable,
                                                               NULL,
                                                               NULL
                                                               );
    if (plist == NULL)
        return NULL;
    
    CFDataRef data = CFDictionaryGetValue(plist, CFSTR("_MKBPAYLOAD"));
    
    if (data == NULL)
        return NULL;
    
    uint8_t* mkbpayload = valloc(CFDataGetLength(data));
    CFDataGetBytes(data, CFRangeMake(0,CFDataGetLength(data)), mkbpayload);
    int length = CFDataGetLength(data);
    
    if (length < 16)
    {
        free(mkbpayload);
        return NULL;
    }
    
    if (AppleEffaceableStorage__getLocker(LOCKER_BAG1, (uint8_t*) &bag1_locker, sizeof(struct BAG1Locker)))
    {
        free(mkbpayload);
        return NULL;
    }
    
    if (bag1_locker.magic != 'BAG1')
        fprintf(stderr, "AppleKeyStore_loadKeyBag: bad BAG1 magic\n");

    size_t decryptedSize = 0; 

    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, 
                                          kCCAlgorithmAES128, 
                                          kCCOptionPKCS7Padding, 
                                          bag1_locker.key, 
                                          kCCKeySizeAES256, 
                                          bag1_locker.iv,
                                          mkbpayload,
                                          length,
                                          mkbpayload,
                                          length,
                                          &decryptedSize); 

    if (cryptStatus != kCCSuccess)
    { 
        fprintf(stderr, "AppleKeyStore_loadKeyBag CCCrypt kCCDecrypt with BAG1 key failed, return code=%x\n", cryptStatus);
        free(mkbpayload);
        return NULL;
    }
        
    CFDataRef data2 = CFDataCreate(kCFAllocatorDefault,
                                  mkbpayload,
                                  decryptedSize
                                  );
    
    if (data2 == NULL)
    {
        free(mkbpayload);
        return NULL;
    }

    CFErrorRef e=NULL;
    CFPropertyListRef plist2 = CFPropertyListCreateWithData(kCFAllocatorDefault, data2, kCFPropertyListImmutable, NULL, &e);
    if (plist2 == NULL)
    {
        fprintf(stderr, "AppleKeyStore_loadKeyBag failed to create plist, AES fail ? decryptedSize=%zx\n", decryptedSize);
        
        CFShow(e);
    }
    free(mkbpayload);
    CFRelease(data2);
    return plist2;
}

int AppleKeyStoreKeyBagInit()
{
    uint64_t out = 0;
    uint32_t one = 1;
    return IOKit_call("AppleKeyStore",
                      kAppleKeyStoreInitUserClient,
                      NULL,
                      0,
                      NULL,
                      0,
                      &out,
                      &one,
                      NULL,
                      NULL);
}

int AppleKeyStoreKeyBagCreateWithData(CFDataRef data, uint64_t* keybagId)
{
    uint32_t outCnt = 1;
    uint32_t retcode = 0;
    aes_key_wrap_ctx ctx;
    uint8_t hmckkey[32] = {0};

    retcode = IOKit_call("AppleKeyStore",
                      kAppleKeyStoreKeyBagCreateWithData,
                      NULL,
                      0,
                      CFDataGetBytePtr(data),
                      CFDataGetLength(data),
                      keybagId,
                      &outCnt,
                      NULL,
                      NULL
                      );
    if (retcode != 0xE00002C9)
        return retcode;

    //HAX to load new iOS 7 keybags on previous iOS kernels
    printf("Trying to remove iOS 7 keybag tags before loading into AppleKeyStore\n");

    aes_key_wrap_set_key(&ctx, IOAES_key835(), 16);

    uint8_t* kbdata = (uint8_t*) CFDataGetBytePtr(data);

    assert(((uint32_t*) kbdata)[0] == 'ATAD');
    uint32_t data_length = CFSwapInt32BigToHost(((uint32_t*) kbdata)[1]);
    uint8_t* kbdata_end = kbdata + 8 + data_length;

    assert(data_length < CFDataGetLength(data));
    //+ DATA header + SIGN header + SIGN payload
    uint8_t* keybag2 = (uint8_t*) malloc(data_length + 8 + 8 + 20);

    if (!keybag2)
        return -1;

    uint32_t off = 8;
    kbdata += 8;

    while (kbdata < kbdata_end)
    {
        uint32_t tag = CFSwapInt32BigToHost(((uint32_t*) kbdata)[0]);
        uint32_t len = CFSwapInt32BigToHost(((uint32_t*) kbdata)[1]);
        assert((kbdata + 8 + len) <= kbdata_end);

        if (tag != 'VERS' &&
            tag != 'TYPE' &&
            tag != 'UUID' &&
            tag != 'HMCK' &&
            tag != 'WRAP' &&
            tag != 'SALT' &&
            tag != 'ITER' &&
            tag != 'CLAS' &&
            tag != 'KTYP' &&
            tag != 'PBKY' &&
            tag != 'WPKY')
        {
            printf("Removing unknown keybag tag %.4s\n", kbdata);
        }
        else
        {
            memcpy(keybag2 + off, kbdata, 8 + len);
            off += (8 + len);
        }
        if (tag == 'HMCK')
        {
            assert(!aes_key_unwrap(&ctx, (const uint8_t*) &kbdata[8], hmckkey, 4));
            printf("Unwrapped HMCK key\n");
        }
        kbdata += (8 + len);
    }
    uint32_t new_data_length = off - 8;
    ((uint32_t*) keybag2)[0] = 'ATAD';
    ((uint32_t*) keybag2)[1] = CFSwapInt32BigToHost(new_data_length);//fix DATA size

    ((uint32_t*) &keybag2[off])[0] = 'NGIS';
    ((uint32_t*) &keybag2[off])[1] = CFSwapInt32BigToHost(20);
    off += 8;

    printf("Fixing SIGN HMAC\n");

    CCHmac(kCCHmacAlgSHA1,
           (const void *) &keybag2[8],
           new_data_length,
           hmckkey,
           sizeof(hmckkey),
           &keybag2[off]);
    off += 20;

    outCnt = 1;
    retcode = IOKit_call("AppleKeyStore",
                      kAppleKeyStoreKeyBagCreateWithData,
                      NULL,
                      0,
                      keybag2,
                      off,
                      keybagId,
                      &outCnt,
                      NULL,
                      NULL
                      );
    free(keybag2);
    return retcode;
}

int AppleKeyStoreKeyBagSetSystem(uint64_t keybagId)
{
    return IOKit_call("AppleKeyStore",
                      kAppleKeyStoreKeyBagSetSystem,
                      &keybagId,
                      1,
                      NULL,
                      0,
                      NULL,
                      NULL,
                      NULL,
                      NULL);
}

int AppleKeyStoreUnlockDevice(io_connect_t conn, CFDataRef passcode)
{
    return IOConnectCallMethod(conn,
                      kAppleKeyStoreUnlockDevice,
                      NULL,
                      0,
                      CFDataGetBytePtr(passcode),
                      CFDataGetLength(passcode),
                      NULL,
                      NULL,
                      NULL,
                      NULL);
}

KeyBag* AppleKeyStore_parseBinaryKeyBag(CFDataRef kb)
{
    const uint8_t* ptr = CFDataGetBytePtr(kb);
    unsigned int len = CFDataGetLength(kb);
    struct KeyBagBlobItem* p = (struct KeyBagBlobItem*) ptr;
    const uint8_t* end;
    
    if (p->tag != 'ATAD') {
        printf("Keybag does not start with DATA\n");
        return NULL;
    }
    if (8 + CFSwapInt32BigToHost(p->len) > len) {
        return NULL;
    }
    
    KeyBag* keybag = malloc(sizeof(KeyBag));
    if (keybag == NULL)
        return NULL;

    memset(keybag, 0, sizeof(KeyBag));
    
    end = ptr + 8 + CFSwapInt32BigToHost(p->len);
    p = (struct KeyBagBlobItem*) p->data.bytes;
    int kbuuid=0;
    int i = -1;
    
    while ((uint8_t*)p < end) {
        //printf("%x\n", p->tag);
        len = CFSwapInt32BigToHost(p->len);
        
        if (p->tag == 'SREV') {
            keybag->version = CFSwapInt32BigToHost(p->data.intvalue);
        }
        else if (p->tag == 'EPYT') {
            keybag->type = CFSwapInt32BigToHost(p->data.intvalue);
        }
        else if (p->tag == 'TLAS') {
            memcpy(keybag->salt, p->data.bytes, 20);
        }
        else if (p->tag == 'RETI') {
            keybag->iter = CFSwapInt32BigToHost(p->data.intvalue);
        }
        else if (p->tag == 'DIUU') {
            if (!kbuuid)
            {
                memcpy(keybag->uuid, p->data.bytes, 16);
                kbuuid = 1;
            }
            else
            {
                i++;
                if (i >= MAX_CLASS_KEYS)
                    break;
                memcpy(keybag->keys[i].uuid, p->data.bytes, 16);
            }
        }
        else if (p->tag == 'SALC')
        {
            keybag->keys[i].clas = CFSwapInt32BigToHost(p->data.intvalue);
        }
        else if (p->tag == 'PARW' && kbuuid)
        {
            keybag->keys[i].wrap = CFSwapInt32BigToHost(p->data.intvalue);
        }
        else if (p->tag == 'YKPW')
        {
            memcpy(keybag->keys[i].wpky, p->data.bytes, (len > 40)  ? 40 : len);
        }
        p = (struct KeyBagBlobItem*) &p->data.bytes[len];
    }
    keybag->numKeys = i + 1;
    
    return keybag;
}

void AppleKeyStore_printKeyBag(KeyBag* kb)
{
    int i;
    printf("Keybag version : %d\n", kb->version);
    printf("Keybag keys : %d\n", kb->numKeys);
    printf("Class\tWrap\tKey\n");
    for (i=0; i < kb->numKeys; i++)
    {
        printf("%d\t%d\t", kb->keys[i].clas, kb->keys[i].wrap);
        printBytesToHex(kb->keys[i].wpky, kb->keys[i].wrap & 2 ? 40 : 32);
        printf("\n");
    }
    printf("\n");
}

CFMutableDictionaryRef AppleKeyStore_getClassKeys(KeyBag* kb)
{
    int i;
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, kb->numKeys, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef key;
    
    for (i=0; i < kb->numKeys; i++)
    {
        if(kb->keys[i].wrap == 0)
        {
            key = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%d"), kb->keys[i].clas);
            addHexaString(dict, key, kb->keys[i].wpky, 32);
            CFRelease(key);
        }
    }
    return dict;
}
