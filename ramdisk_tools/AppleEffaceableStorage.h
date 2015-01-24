/*
AppleEffaceableStorage
0 : getCapacity
1 : getBytes (kernel debug)
2 : setBytes (kernel debug)
3 : isFormatted
4 : format
5 : getLocker
6 : setLocker
7 : effaceLocker
8 : lockerSpace
*/
#define kAppleEffaceableStorageGetBytes     1
#define kAppleEffaceableStorageGetLocker    5


#define LOCKER_DKEY 0x446B6579
#define LOCKER_EMF  0x454D4621
#define LOCKER_BAG1 0x42414731
#define LOCKER_LWVM 0x4C77564d

struct EffaceableLocker
{
    unsigned short magic;   //0x4c6B = "kL"
    unsigned short len;
    unsigned int tag;       //BAG1, EMF, Dkey, DONE
    unsigned char data[1];    
};

struct BAG1Locker
{
    unsigned int magic;//'BAG1';
    unsigned char iv[16];
    unsigned char key[32];
};

int AppleEffaceableStorage__getLocker(uint32_t lockerId, uint8_t* buffer, size_t len);
int AppleEffaceableStorage__getBytes(uint8_t* buffer, size_t len);
int AppleEffaceableStorage__getLockerFromBytes(uint32_t tag, uint8_t* lockers, size_t lockers_len, uint8_t* buffer, size_t len);

