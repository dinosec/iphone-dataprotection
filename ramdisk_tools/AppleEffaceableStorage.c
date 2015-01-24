#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "AppleEffaceableStorage.h"
#include "IOKit.h"

int AppleEffaceableStorage__getLocker(uint32_t lockerId, uint8_t* buffer, size_t len) {
    uint64_t outScalar = 0;
    uint32_t one = 1;
    uint64_t inScalar = lockerId;

    return IOKit_call("AppleEffaceableStorage", 
               kAppleEffaceableStorageGetLocker,
               &inScalar,
               1,
               NULL,
               0,
               &outScalar,
               &one,
               buffer,
               &len);
}

int AppleEffaceableStorage__getBytes(uint8_t* buffer, size_t len) 
{
    const uint64_t offset = 0;

    return IOKit_call("AppleEffaceableStorage",
                      kAppleEffaceableStorageGetBytes,
                      &offset,
                      1,
                      NULL,
                      0,
                      NULL,
                      NULL,
                      buffer,
                      &len);
}


int AppleEffaceableStorage__getLockerFromBytes(uint32_t tag, uint8_t* lockers, size_t lockers_len, uint8_t* buffer, size_t len)
{
    struct EffaceableLocker* p = (struct EffaceableLocker*) lockers;
    unsigned int i=0;
    
    while (i < lockers_len)
    {
        //printf("p->magic=%x\n", p->magic);
        if (p->magic != 0x4c6B) //'Lk'
            break;
        if (p->len == 0 || ((i+8+p->len) > lockers_len))
            break;
        //printf("p->tag=%x\n", p->tag);
        if ((p->tag & ~0x80000000) ==  tag)
        {
            len = len < p->len ? len : p->len;
            memcpy(buffer, p->data, len);
            return 0;
        }
        i = i + 8 + p->len;
        p = (struct EffaceableLocker*) (&lockers[i]);   
    }
    return -1;

}
