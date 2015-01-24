#include <stdio.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <signal.h>
#include "ioflash.h"

CF_EXPORT const CFStringRef _kCFSystemVersionProductVersionKey;
CF_EXPORT CFDictionaryRef _CFCopySystemVersionDictionary(void);

mach_port_t kernel_task=0;

void* externalMethod_original = NULL;
void** externalMethod_ptr = NULL;

void* (*IOMemoryDescriptor__withAddress)(void*, uint32_t, uint32_t, task_t) = 0x0;

typedef int (*methodptr)(void*, ...);

#define CALL_VTABLE(this, vtableoff, ...) \
    ((methodptr) (*(uint32_t**)this)[vtableoff/4]) (this, ##__VA_ARGS__)
  
//IOReturn externalMethod( uint32_t selector, IOExternalMethodArguments * arguments,IOExternalMethodDispatch * dispatch = 0, OSObject * target = 0, void * reference = 0 );
int myIOFlashStorage_externalMethod(uint32_t* this, uint32_t selector, IOExternalMethodArguments* arguments)
{
    struct IOFlashCommandStruct command = {0};
    uint32_t** bufferDesc = NULL;
    uint32_t** spareDesc = NULL;
    uint32_t** md = NULL;

    if (selector != kIOFlashControllerUserClientReadPage) //only support read
        return 0xE00002C2;

    if (IOMemoryDescriptor__withAddress == 0x0)
        return 0xdeadbeef;

    void* iofc = (void*) this[0x78/4]; //IOFlashController object (AppleIOPFMI)
    task_t task = (task_t) this[0x7C/4];

    IOFlashControllerUserClient_InputStruct* in = (IOFlashControllerUserClient_InputStruct*) arguments->structureInput;
    IOFlashControllerUserClient_OutputStruct* out = (IOFlashControllerUserClient_OutputStruct*) arguments->structureOutput;

    uint32_t page = in->page;
    uint32_t ce = in->ce;

    if (in->options & kIOFlashStorageOptionBootPageIO)
    {
        if(in->spare != NULL)
            return 0xE00002C2; //spare buffer is not used with bootloader page I/O
        command.command = kIOFlashControllerReadBootloader;
    }
    else
    {
        command.command = kIOFlashControllerReadNormal;
    }
    command.optionBits = 1;
    command.optionBits |= in->options & 4;
    command.fieldC = 0;
    command.field34 = 0;
    command.pageCount = 1;
    command.pageList = &page;
    command.bankList = &ce;

    bufferDesc = IOMemoryDescriptor__withAddress(in->buffer, in->bufferSize, 1, task);
    if (bufferDesc == NULL)
        return 0xE00002C2;

    command.bufferDesc = bufferDesc;
    command.field18 = 0;
    command.bitflip_corrected = 0;

    if (in->spare != NULL)
    {
        spareDesc = IOMemoryDescriptor__withAddress(in->spare, in->spareSize, 1, task);
        if (spareDesc == NULL)
            return 0xE00002C2;

        //0xAC -> desc2 __ZN25IOGeneralMemoryDescriptor5doMapEP7_vm_mapPjmmm
        //virtual IOMemoryMap * 	map(	IOOptionBits		options = 0 );
        md = (void*) CALL_VTABLE(spareDesc, 0x98); //IOGeneralMemoryDescriptor_map
     
        command.spareSize = in->spareSize;
        command.spareVA = (void*) CALL_VTABLE(md, 0x38);//IOMemoryMap::getVirtualAddress
    }
    else
    {
        command.spareSize = 0;
        command.spareVA = NULL;
    }

    out->ret1 = CALL_VTABLE(iofc, 0x344, 0, &command);//0x344 => valid offset for ios 5 and below

    CALL_VTABLE(bufferDesc, 0x14); //IOGeneralMemoryDescriptor_release

    if (md != NULL)
    {
        CALL_VTABLE(md, 0x14); //IOGeneralMemoryDescriptor_release
    }
    if (spareDesc != NULL)
    {
        CALL_VTABLE(spareDesc, 0x14); //IOGeneralMemoryDescriptor_release
    }
    out->ret2 = command.bitflip_corrected;
    return 0;
}

kern_return_t write_kernel(mach_port_t p, void* addr, uint32_t value)
{
    kern_return_t r = vm_write(p, (vm_address_t)addr, (vm_address_t)&value, sizeof(value ));
    if (r)
        fprintf(stderr, "vm_write into kernel_task failed\n");
    else
        fprintf(stderr, "vm_write into kernel_task OK\n");
    return r;
}

void __attribute__((destructor)) restore_handler()
{
    if (kernel_task != 0 && externalMethod_ptr != NULL && externalMethod_original != NULL)
    {
        fprintf(stderr, "Restoring IOFlashStorageControler::externalMethod ptr\n");
        write_kernel(kernel_task, externalMethod_ptr, (uint32_t) externalMethod_original+1);
    }
}

void signal_handler(int sig)
{
    restore_handler();
    signal(sig, SIG_DFL);
    raise(sig);
}

int IOFlashStorage_kernel_patch()
{
    CFStringRef version = NULL;
    CFDictionaryRef versionDict = _CFCopySystemVersionDictionary();
    
    if (versionDict != NULL)
    {
        version = CFDictionaryGetValue(versionDict, _kCFSystemVersionProductVersionKey);
    }
    if (version == NULL)
    {
        fprintf(stderr, "FAILed to get current version\n");
        return 0;
    }
    if (CFStringCompare(version, CFSTR("4.3.5"), 0) <= 0)
    {
        fprintf(stderr, "iOS 4 kernel detected, no kernel patching required\n");
        return 1;
    }
    if (CFStringCompare(version, CFSTR("5.1.1"), 0) > 0)
    {
        fprintf(stderr, "Run-time kernel patching only supported on iOS 5, use ttbthingy for ios 6/7\n");
        return 1;
    }
    fprintf(stderr, "Trying to patch IOFlashControlerUserClient::externalMethod\n");

    
    kern_return_t r = task_for_pid(mach_task_self(), 0, &kernel_task);
    
    if( r != 0)
    {
        fprintf(stderr, "task_for_pid returned %x : missing tfp0 kernel patch (use latest kernel_patcher.py) or wrong entitlements\n", r);
        return 0;
    }
    uint32_t i;
    pointer_t buf;
    unsigned int sz;
    int ok = 0;
    
    vm_address_t addr = 0x80002000;
    
    while( addr < (0x80002000 + 0xA00000))
    {
        vm_read(kernel_task, addr, 2048, &buf, &sz);
        if( buf == 0 || sz == 0)
            continue;
        
        uint32_t* p = (uint32_t*) buf;
        
        for(i=0; i < sz/sizeof(uint32_t); i++)
        {
            if (externalMethod_original != NULL)
            {
                if (p[i] == (uint32_t) (externalMethod_original+1))
                {
                    externalMethod_ptr = (void*) (addr + i*4);
                    fprintf(stderr, "Found externalMethod ptr at %x\n", (uint32_t) externalMethod_ptr);
                    write_kernel(kernel_task, externalMethod_ptr, (uint32_t) myIOFlashStorage_externalMethod);
                    
                    signal(SIGINT, signal_handler);//handle ctrl+c
                    signal(SIGABRT, signal_handler);
                    signal(SIGTERM, signal_handler);
                    ok = 1;
                }
                else if(IOMemoryDescriptor__withAddress == NULL && !memcmp(&p[i], "\x20\x46\x26\xB0\x5D\xF8\x04\x8B\xF0\xBD", 10))
                {
                    IOMemoryDescriptor__withAddress = (void*) p[i+5];
                    fprintf(stderr, "IOMemoryDescriptor__withAddress=%x\n", (uint32_t) IOMemoryDescriptor__withAddress);
                }
            }
            else if(!memcmp(&p[i], "\xF0\xB5\x03\xAF\x4D\xF8\x04\x8D\xA6\xB0\x40\xF2\xC2\x24\x13\x6A", 16))
            {
                externalMethod_original = (void*) (addr + i*4);
                fprintf(stderr, "Found IOFlashControlerUserClient::externalMethod at %x\n", (uint32_t) externalMethod_original);
            }
            if(!memcmp(&p[i], "\xF0\xB5\x03\xAF\x81\xB0\x1C\x46\x15\x46\x0E\x46\xB5\x42\x09\xD9", 16))
            {
                fprintf(stderr, "Found AppleIOPFMI::_fmiPatchMetaFringe at %p\n", (void*) (addr + i*4));
                write_kernel(kernel_task, (void*) (addr + i*4), 0x47704770);//70 47 bx lr (thumb)
            }
        }
        addr += 2048;
    }
    if (!ok)
        fprintf(stderr, "Kernel patching failed\n");
    return ok;
}
