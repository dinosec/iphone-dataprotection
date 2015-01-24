/**
https://github.com/planetbeing/xpwn/blob/master/crypto/aes.c
**/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <IOKit/IOKitLib.h>
#include <pthread.h>
#include "IOKit.h"
#include "IOAESAccelerator.h"

io_connect_t conn = 0;
size_t IOAESStructSize = sizeof(IOAESStruct) - sizeof(IOAES_UIDPlus_Params);
pthread_once_t once_control = PTHREAD_ONCE_INIT;

//see com.apple.driver.AppleCDMA
typedef struct
{
    uint32_t key_id;
    uint32_t hw_key_id;
    uint8_t  nonce_to_encrypt_with_hw_key[16];
    uint8_t* value;
} device_key_descriptor;

#define NUM_DEVICE_KEYS 4
device_key_descriptor ios_device_keys[NUM_DEVICE_KEYS]= {
    {0x835, kIOAESAcceleratorUIDMask, {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, NULL},
    {0x899, kIOAESAcceleratorUIDMask, {0xD1, 0xE8, 0xFC, 0xB5, 0x39, 0x37, 0xBF, 0x8D, 0xEF, 0xC7, 0x4C, 0xD1, 0xD0, 0xF1, 0xD4, 0xB0}, NULL},
    {0x89B, kIOAESAcceleratorUIDMask, {0x18, 0x3E, 0x99, 0x67, 0x6B, 0xB0, 0x3C, 0x54, 0x6F, 0xA4, 0x68, 0xF5, 0x1C, 0x0C, 0xBD, 0x49}, NULL},
    {0x89A, kIOAESAcceleratorUIDMask, {0xDB, 0x1F, 0x5B, 0x33, 0x60, 0x6C, 0x5F, 0x1C, 0x19, 0x34, 0xAA, 0x66, 0x58, 0x9C, 0x06, 0x61}, NULL},
};

void aes_init()
{
    conn = IOKit_getConnect("IOAESAccelerator");
}

io_connect_t IOAESAccelerator_getIOconnect()
{
    pthread_once(&once_control, aes_init);
    return conn;
}


int doAES(void* cleartext, void *ciphertext, uint32_t size, uint32_t keyMask, void* key, void* iv, int mode, int bits) {
    IOReturn ret;
    IOAESStruct in;

    pthread_once(&once_control, aes_init);

    in.mode = mode;
    in.bits = bits;
    in.cleartext = cleartext;
    in.ciphertext = ciphertext;
    in.size = size;
    in.mask = keyMask;
    in.length_of_uidplus_params = 0;

    memset(in.keybuf, 0, sizeof(in.keybuf));

    if(key)
        memcpy(in.keybuf, key, in.bits / 8);

    if(iv)
        memcpy(in.iv, iv, 16);
    else
        memset(in.iv, 0, 16);

    ret = IOConnectCallStructMethod(conn, kIOAESAcceleratorTask, &in, IOAESStructSize, &in, &IOAESStructSize);
    if(ret == kIOReturnBadArgument) {
        IOAESStructSize = IOAESStruct_sizeold;
        ret = IOConnectCallStructMethod(conn, kIOAESAcceleratorTask, &in, IOAESStructSize, &in, &IOAESStructSize);
    }
            
    if(iv)
        memcpy(iv, in.iv, 16);

    return ret;
}

IOReturn doAES_wrapper(void* thisxxx, int mode, void* iv, void* outbuf, void *inbuf, uint32_t size, uint32_t keyMask)
{
    int x = doAES(inbuf, outbuf, size, keyMask, NULL, iv, mode, 128);
    return !x;
}

int patch_IOAESAccelerator();

int AES_UID_Encrypt(void* cleartext, void* ciphertext, size_t len)
{
    IOAESStruct in;
    IOReturn ret;
    static int triedToPatchKernelAlready = 0;

    //prevent weird bug on old armv6 devices where cleartext and ciphertext are the same buffer
    unsigned char* cleartextCopy = valloc(16);
    memcpy(cleartextCopy, cleartext, 16);

    pthread_once(&once_control, aes_init);

    in.mode = kIOAESAcceleratorEncrypt;
    in.mask = kIOAESAcceleratorUIDMask;
    in.bits = 128;
    in.cleartext = cleartextCopy;
    in.ciphertext = ciphertext;
    in.size = len;
    
    memset(in.keybuf, 0, sizeof(in.keybuf));
    memset(in.iv, 0, 16);

    ret = IOConnectCallStructMethod(conn, kIOAESAcceleratorTask, &in, IOAESStructSize, &in, &IOAESStructSize);
    if(ret == kIOReturnBadArgument) {
        IOAESStructSize = IOAESStruct_sizeold;
        ret = IOConnectCallStructMethod(conn, kIOAESAcceleratorTask, &in, IOAESStructSize, &in, &IOAESStructSize);
    }

    if(ret == kIOReturnNotPrivileged && !triedToPatchKernelAlready) {
        triedToPatchKernelAlready = 1;
        fprintf(stderr, "Trying to patch IOAESAccelerator kernel extension to allow UID key usage\n");
        //patch_IOAESAccelerator();
        ret = AES_UID_Encrypt(cleartext, ciphertext, len);
    }
    if(ret != kIOReturnSuccess) {
        fprintf(stderr, "IOAESAccelerator returned: %x\n", ret);
    }
    return ret;
}

uint8_t* IOAES_get_device_key(uint32_t id)
{
    static uint8_t nullkey[16] = {0};
    int i;
    for(i=0; i < NUM_DEVICE_KEYS; i++)
    {
        if (ios_device_keys[i].key_id != id)
            continue;
        if (ios_device_keys[i].value != NULL)
            return ios_device_keys[i].value;
        
        ios_device_keys[i].value = (uint8_t*) valloc(16); //on ARMv6 devices stuff needs to be aligned
        memcpy(ios_device_keys[i].value, ios_device_keys[i].nonce_to_encrypt_with_hw_key, 16);
        AES_UID_Encrypt(ios_device_keys[i].value, ios_device_keys[i].value, 16);
        return ios_device_keys[i].value;
    }
    return nullkey;

}
uint8_t* IOAES_key835()
{
    return IOAES_get_device_key(0x835);
}

uint8_t* IOAES_key89B()
{
    return IOAES_get_device_key(0x89B);
}

uint8_t* IOAES_key89A()
{
    return IOAES_get_device_key(0x89A);
}
