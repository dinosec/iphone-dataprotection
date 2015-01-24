//#include <IOKit/IOKitLib.h>
#include "IOKit.h"

typedef struct IOFlashController_client
{
    io_service_t    iofc_service;
    io_connect_t    iofc_connect;

    CFMutableDictionaryRef iofsd_properties;

    uint32_t    num_ce;
    uint32_t    ce_blocks;
    uint32_t    block_pages;
    uint32_t    page_bytes;
    uint32_t    spare_bytes;
    uint32_t    bootloader_bytes;
    uint32_t    boot_from_nand;
    uint32_t    pages_per_ce;
    uint32_t    total_blocks;
    uint32_t    logical_page_size;
    uint32_t    meta_per_logical_page;
    uint32_t    valid_meta_per_logical_page;
    uint32_t    bank_address_space;
    uint32_t    blocks_per_bank;
    uint32_t    dump_page_size;
    uint64_t    total_size;

    uint32_t    banksPerCEphysical;

    //ppn
    uint32_t    ppn_device;
    uint32_t    slc_pages;
    uint32_t    mlc_pages;
    uint32_t    cau_bits;
    uint32_t    page_bits;
    uint32_t    block_bits;
    uint32_t    caus_ce;
} IOFlashController_client;

//userclient options
#define kIOFlashStorageOptionBootPageIO     0x100
#define kIOFlashStorageOptionRawPageIO      0x002
#define kIOFlashStorageOptionXXXX           0x004
//0xC0 == kIOFlashStorageOptionUseAES | kIOFlashStorageOptionHomogenize

typedef enum
{
    kIOFlashControllerUserClientReadPage          = 0x1,
    kIOFlashControllerUserClientWritePage         = 0x2,
    kIOFlashControllerUserClientEraseBlock        = 0x3,
    kIOFlashControllerUserClientDisableKeepout    = 0xa,
    kIOFlashControllerUserClientUpdateFirmware    = 0xb,
} IOFlashControllerUserClient_selector;

//sizeof = 0x1C
typedef struct
{
    uint32_t        page;
    uint32_t        ce;
    uint32_t        options;

    void*           buffer;
    uint32_t        bufferSize;

    void*           spare;
    uint32_t        spareSize;
} IOFlashControllerUserClient_InputStruct;

//sizeof=0x8
typedef struct
{
    uint32_t ret1;
    uint32_t ret2;
} IOFlashControllerUserClient_OutputStruct;

//AppleIOPFMI commands
typedef enum
{
    kIOFlashControllerReadNormal=0,
    kIOFlashControllerWriteNormal=1,

    kIOFlashControllerErase=2,
    
    kIOFlashControllerSetActive=4,
    kIOFlashControllerSetIdle=5,

    kIOFlashControllerReadRaw=7,
    kIOFlashControllerWriteRaw=8,

    kIOFlashControllerReadBootloader=9,
    kIOFlashControllerWriteBootloader=10,

    kIOFlashControllerUpdateParameters=0xB,
    kIOFlashControllerUnknown0xC=0xC,

    kIOFlashControllerUpdateFirmware=0xE,
    kIOFlashControllerPpnOperation=0xF
} IOFlashControllerCommand;

//sizeof=0x50
typedef struct IOFlashCommandStruct
{
    IOFlashControllerCommand    command;
    uint32_t                    optionBits;
    uint32_t                    pageCount;
    uint32_t                    fieldC;
    uint32_t*                   pageList;
    void*                       bufferDesc;//IOMemoryDescriptor*
    uint32_t                    field18;
    uint32_t                    field1C;
    uint32_t                    field20;
    uint32_t*                   bankList;
    void*                       spareVA;
    uint32_t                    spareSize;
    uint32_t                    field30;
    uint32_t                    field34;
    uint32_t                    field38;
    uint32_t                    bitflip_corrected;
    uint32_t                    field40;
    void*                       aes_key_ptr_44;
    uint32_t                    field48;
    uint32_t                    field4C;
} IOFlashCommandStruct;

typedef struct IOExternalMethodArguments
{
    uint32_t        version;

    uint32_t        selector;

    mach_port_t           asyncWakePort;
    io_user_reference_t * asyncReference;
    uint32_t              asyncReferenceCount;

    const uint64_t *    scalarInput;
    uint32_t        scalarInputCount;

    const void *    structureInput;
    uint32_t        structureInputSize;

    //IOMemoryDescriptor * structureInputDescriptor;
    void * structureInputDescriptor;
   
    uint64_t *        scalarOutput;
    uint32_t        scalarOutputCount;

    void *        structureOutput;
    uint32_t        structureOutputSize;

    void * structureOutputDescriptor;
    uint32_t         structureOutputDescriptorSize;

    uint32_t        __reservedA;

    //OSObject **         structureVariableOutputData;
    void **         structureVariableOutputData;

    uint32_t        __reserved[30];
} IOExternalMethodArguments;

typedef struct proxy_read_cmd
{
    uint32_t ce;
    uint32_t page;
    uint32_t spareSize;
    uint32_t options;
} proxy_read_cmd;

CFMutableDictionaryRef FSDGetInfo();

IOFlashController_client* IOFlashController_init();
void IOFlashController_print(IOFlashController_client*);


IOReturn FSDReadPageWithOptions(IOFlashController_client*, uint32_t, uint32_t, void*, void*, uint32_t, uint32_t, IOFlashControllerUserClient_OutputStruct*);

IOReturn FSDReadBootPage(IOFlashController_client* iofc, uint32_t, uint32_t, uint8_t*, IOFlashControllerUserClient_OutputStruct*);

int FSDGetPropertyForKey(io_object_t, CFStringRef, void*, uint32_t, CFMutableDictionaryRef);

int IOFlashStorage_kernel_patch();

void check_special_pages(IOFlashController_client* iofc);

CFDictionaryRef nand_dump(IOFlashController_client*, int fd);
int dump_nand_to_socket(IOFlashController_client*, int fd);
int nand_proxy(IOFlashController_client*, int fd);
