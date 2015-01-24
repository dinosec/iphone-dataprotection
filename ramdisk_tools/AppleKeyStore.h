#include "IOKit.h"

/*
 AppleKeyStore
 0 : initUserClient scalarOutSize=1
 1 :
 2 : AppleKeyStoreKeyBagCreate
 3 : AppleKeyStoreKeyBagCopyData inscalars=id structOutSize=0x8000
 4 : keybagrelease inscalars":[0]}
 5 : AppleKeyStoreKeyBagSetSystem
 6 : AppleKeyStoreKeyBagCreateWithData
 7 : getlockstate "inscalars":[0], "scalarOutSize":1}
 8 : AppleKeyStoreLockDevice
 9 : AppleKeyStoreUnlockDevice instruct
 10: AppleKeyStoreKeyWrap
 11: AppleKeyStoreKeyUnwrap
 12: AppleKeyStoreKeyBagUnlock
 13: AppleKeyStoreKeyBagLock
 14: AppleKeyStoreKeyBagGetSystem scalarOutSize=1
 15: AppleKeyStoreKeyBagChangeSecret
 17: AppleKeyStoreGetDeviceLockState scalarOutSize=1
 18: AppleKeyStoreRecoverWithEscrowBag
 19: AppleKeyStoreOblitClassD
 */
#define kAppleKeyStoreInitUserClient        0
#define kAppleKeyStoreKeyBagSetSystem       5
#define kAppleKeyStoreKeyBagCreateWithData  6
#define kAppleKeyStoreUnlockDevice          9

#define MAX_CLASS_KEYS                      20

struct KeyBagBlobItem
{
    unsigned int tag;
    unsigned int len;
    union
    {
        unsigned int intvalue;
        unsigned char bytes[1];
    } data;
};

typedef struct ClassKey
{
    unsigned char uuid[16];
    unsigned int clas;
    unsigned int wrap;
    unsigned char wpky[40];
} ClassKey;

typedef struct KeyBag
{
    unsigned int version;
    unsigned int type;
    unsigned char uuid[16];
    unsigned char hmck[40];
    unsigned char salt[20];
    unsigned int iter;
    
    unsigned int numKeys;
    
    struct ClassKey keys[MAX_CLASS_KEYS];
} KeyBag;


int AppleKeyStoreKeyBagInit();
CFDictionaryRef AppleKeyStore_loadKeyBag(const char* folder, const char* filename);
int AppleKeyStoreKeyBagCreateWithData(CFDataRef data, uint64_t* keybagId);
int AppleKeyStoreKeyBagSetSystem(uint64_t keybagId);
int AppleKeyStoreUnlockDevice(io_connect_t conn, CFDataRef passcode);

KeyBag* AppleKeyStore_parseBinaryKeyBag(CFDataRef kb);
void AppleKeyStore_printKeyBag(KeyBag* kb);

int AppleKeyStore_getPasscodeKey(KeyBag* keybag,
                                 const char* passcode,
                                 size_t passcodeLen,
                                 uint8_t* passcodeKey);

int AppleKeyStore_unlockKeybagFromUserland(KeyBag* kb,
                                            const char* passcode,
                                            size_t passcodeLen,
                                            uint8_t* key835);

CFMutableDictionaryRef AppleKeyStore_getClassKeys(KeyBag*);
