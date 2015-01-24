#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "IOKit.h"
#include "IOAESAccelerator.h"
#include "AppleEffaceableStorage.h"
#include "AppleKeyStore.h"
#include "bsdcrypto/pbkdf2.h"
#include "bsdcrypto/rijndael.h"
#include "bsdcrypto/key_wrap.h"

int AppleKeyStore_derivation(KeyBag* kb, void* data, uint32_t dataLength, uint32_t iter, uint32_t vers);
uint32_t AppleKeyStore_xorExpand(uint32_t* dst, uint32_t dstLen, uint32_t* input, uint32_t inLen, uint32_t xorKey);
void AppleKeyStore_xorCompress(uint32_t* input, uint32_t inputLen, uint32_t* output, uint32_t outputLen);

#define DERIVATION_BUFFER_SIZE  4096
uint8_t buf1[DERIVATION_BUFFER_SIZE];
uint8_t buf2[DERIVATION_BUFFER_SIZE];

size_t IOAESStructSize1 = sizeof(IOAESStruct) - sizeof(IOAES_UIDPlus_Params);
size_t IOAESStructSize2 = sizeof(IOAESStruct) - sizeof(IOAES_UIDPlus_Params);;
IOAESStruct in ={buf1,buf2,DERIVATION_BUFFER_SIZE,{0},0,128,{0},kIOAESAcceleratorUIDMask,0};
IOAESStruct out = {0};

int AppleKeyStore_getPasscodeKey(KeyBag* keybag,
                                 const char* passcode,
                                 size_t passcodeLen,
                                 uint8_t* passcodeKey)
{
    //One PBKDF2 iter, hardcoded salt length
    pkcs5_pbkdf2(passcode, passcodeLen, (const char*) keybag->salt, 20, passcodeKey, 32, 1);

    return AppleKeyStore_derivation(keybag, passcodeKey, 32, keybag->iter, keybag->version);
}
    
int AppleKeyStore_derivation(KeyBag* keybag, void* data, uint32_t dataLength, uint32_t iter, uint32_t vers)
{
    IOReturn ret;
    io_connect_t conn = IOAESAccelerator_getIOconnect();
    memset(in.iv, 0, 16);
    
    uint32_t r4;
    uint32_t nBlocks = DERIVATION_BUFFER_SIZE / dataLength;    //4096/32=128
    uint32_t xorkey = 1;
   
    uint32_t* buffer2 = data;
    if (vers >= 2)
    {
        buffer2 = valloc(dataLength);
        memcpy(buffer2, data, dataLength);
    }
    if (keybag->type & 0x40000000)
    {
        fprintf(stderr, "Tangling: using UIDPlus\n");
        IOAESStructSize1 = sizeof(IOAESStruct);
        IOAESStructSize2 = sizeof(IOAESStruct);
        in.mode = 2;
        in.mask = kIOAESAcceleratorUIDPlusMask;
        in.length_of_uidplus_params = sizeof(IOAES_UIDPlus_Params);
        in.uidplus_params.one = 1;
        in.uidplus_params.zzz = 0;
        //XXX salt length is always 20
        in.uidplus_params.data_length = 20;
        memcpy(in.uidplus_params.data, keybag->salt, 20);
    }
    while (iter > 0) 
    {
        //version=1 xorKey alawys=1, buffer2 changes at each iter
        //version=2 xorKey changes at each iter, buffer2 is always the input (pbkdf2(passcode))
        r4 = AppleKeyStore_xorExpand((uint32_t*)buf1, DERIVATION_BUFFER_SIZE, buffer2, dataLength, xorkey);
        if (vers >= 2)
            xorkey = r4;

        if((ret = IOConnectCallStructMethod(conn, kIOAESAcceleratorTask, &in, IOAESStructSize1, &out, &IOAESStructSize2)) != kIOReturnSuccess)
        {
            fprintf(stderr, "Tangling: IOConnectCallStructMethod fail : %x\n", ret);
            return -1;
        }
        memcpy(in.iv, out.iv, 16);

        r4 = nBlocks;
        if (r4 >= iter)
        {
            r4 = iter;
        }
        AppleKeyStore_xorCompress((uint32_t*) buf2,  r4 * dataLength, data, dataLength);
        iter -= r4;
    }
    if (vers >= 2)
    {
        free(buffer2);
    }
    return 0;
}

/*
uint32_t paddedLen = (inLen + 3) & (~3);//aligne sur 4 octets
if (dstLen % paddedLen)
    return;
uint32_t localBuf[inLen/4];

memcpy(localBuf, input, inLen);
memset(&localBuf[inLen], 0, paddedLen - inLen);*/
uint32_t AppleKeyStore_xorExpand(uint32_t* dst, uint32_t dstLen, uint32_t* input, uint32_t inLen, uint32_t xorKey)
{
    uint32_t* dstEnd = &dst[dstLen/4];
    uint32_t i = 0;

    while (dst < dstEnd)
    {
        i = 0;
        while (i < inLen/4)
        {
            *dst = input[i] ^ xorKey;
            dst++;
            i++;
        }
        xorKey++;
    }
    return xorKey;
}

void AppleKeyStore_xorCompress(uint32_t* input, uint32_t inputLen, uint32_t* output, uint32_t outputLen)
{
    uint32_t i;

    for (i=0; i < (inputLen/4); i++)
    {
        output[i%(outputLen/4)] ^= input[i];
    }
}

int AppleKeyStore_unlockKeybagFromUserland(KeyBag* kb, const char* passcode, size_t passcodeLen, uint8_t* key835)
{
    u_int8_t passcodeKey[32]={0};
    u_int8_t unwrappedKey[40]={0};
    aes_key_wrap_ctx ctx;
    int i;

    AppleKeyStore_getPasscodeKey(kb, passcode, passcodeLen, passcodeKey);
    aes_key_wrap_set_key(&ctx, passcodeKey, 32);

    for (i=0; i < kb->numKeys; i++)
    {
        if (kb->keys[i].wrap & 2)
        {
            if(aes_key_unwrap(&ctx, kb->keys[i].wpky, unwrappedKey, 4))
                return 0;
            memcpy(kb->keys[i].wpky, unwrappedKey, 32);
            kb->keys[i].wrap &= ~2;
        }
        if (kb->keys[i].wrap & 1)
        {
            doAES(kb->keys[i].wpky, kb->keys[i].wpky, 32, kIOAESAcceleratorCustomMask, key835, NULL, kIOAESAcceleratorDecrypt, 128);
            kb->keys[i].wrap &= ~1;
        }
    }
    return 1;
}
