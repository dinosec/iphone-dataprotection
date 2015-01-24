#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCryptor.h>
#include <IOKit/IOKitLib.h>
#include "ioflash.h"
#include "IOFlashPartitionScheme.h"

/**
used to decrypt special pages when checking if the physical banks parameter is correct
when reading/dumping pages are not decrypted
**/
uint8_t META_KEY[16] = {0x92, 0xa7, 0x42, 0xab, 0x08, 0xc9, 0x69, 0xbf, 0x00, 0x6c, 0x94, 0x12, 0xd3, 0xcc, 0x79, 0xa5};

int FSDGetPropertyForKey(io_object_t obj, CFStringRef name, void* out, uint32_t outLen, CFMutableDictionaryRef dict)
{
    CFTypeRef data = IORegistryEntryCreateCFProperty(obj, name, kCFAllocatorDefault, 0);
    
    if (!data)
    {
        return 0;
    }
    if (dict != NULL)
    {
        CFDictionaryAddValue(dict, name, data);
    }
    if (out == NULL)
        return 0;
    if(CFGetTypeID(data) == CFNumberGetTypeID())
    {
        CFNumberGetValue((CFNumberRef)data, kCFNumberIntType, out);
        return 1;
    }
    else if(CFGetTypeID(data) == CFDataGetTypeID())
    {
        CFIndex dataLen = CFDataGetLength(data);
        CFDataGetBytes(data, CFRangeMake(0,dataLen < outLen ? dataLen : outLen), out);
        return 1;
    }
    else if(CFGetTypeID(data) == CFBooleanGetTypeID() && outLen > 0)
    {
        *((uint8_t*)out) = CFBooleanGetValue(data);
    }
    else
    {
        CFShow(name);
    }
    return 0;
}

IOReturn FSDReadPageWithOptions(IOFlashController_client* iofc,
                            uint32_t ceNum,
                            uint32_t pageNum,
                            void* buffer,
                            void* spareBuffer,
                            uint32_t spareSize,
                            uint32_t options,
                            IOFlashControllerUserClient_OutputStruct* out
                            )
{
    IOFlashControllerUserClient_InputStruct in;
    size_t outLen = sizeof(IOFlashControllerUserClient_OutputStruct);

    in.page = pageNum;
    in.ce = ceNum;
    in.options = options;
    in.buffer = buffer;
    in.bufferSize = iofc->page_bytes;
    in.spare = spareBuffer;
    in.spareSize = spareSize;

    IOReturn ret = IOConnectCallStructMethod(iofc->iofc_connect,
                              kIOFlashControllerUserClientReadPage,
                              (const void*) &in,
                              sizeof(IOFlashControllerUserClient_InputStruct),
                              out,
                              &outLen);
    if (!ret)
        return out->ret1;
    return ret;
}

IOReturn FSDReadBootPage(IOFlashController_client* iofc,
                         uint32_t ceNum,
                         uint32_t pageNum,
                         uint8_t* buffer,
                         IOFlashControllerUserClient_OutputStruct* out)
{
    return FSDReadPageWithOptions(iofc,
                                   ceNum,
                                   pageNum,
                                   buffer,
                                   NULL,
                                   0,
                                   kIOFlashStorageOptionBootPageIO,
                                   out);
}

//openiBoot/util.c
uint32_t next_power_of_two(uint32_t n) {    
    uint32_t val = 1 << (31 - __builtin_clz(n));

    if (n % val)
        val *= 2;

    return val;
}

void generate_IV(uint32_t lbn, uint32_t *iv)
{
    uint32_t i;
    for(i = 0; i < 4; i++)
    {
        if(lbn & 1)
            lbn = 0x80000061 ^ (lbn >> 1);
        else
            lbn = lbn >> 1;
        iv[i] = lbn;
    }
}

void decrypt_page(uint8_t* data, uint32_t dataLength, uint8_t* key, uint32_t keyLength, uint32_t pn)
{
    char iv[16];
    size_t dataOutMoved=dataLength;
    generate_IV(pn, (uint32_t*) iv);
    
    CCCryptorStatus s = CCCrypt(kCCDecrypt,
                                kCCAlgorithmAES128,
                                0,
                                (const void*) key,
                                keyLength,
                                (const void*) iv,
                                (const void*) data,
                                dataLength,
                                (void*) data,
                                dataLength,
                                &dataOutMoved);
    if (s != kCCSuccess)
    {
        fprintf(stderr, "decrypt_page: CCCrypt error %x\n", s);
    }
}

void set_physical_banks(IOFlashController_client* iofc, uint32_t n)
{
    iofc->banksPerCEphysical = n;
    iofc->blocks_per_bank = iofc->ce_blocks / iofc->banksPerCEphysical;
    
    if((iofc->ce_blocks & (iofc->ce_blocks-1)) == 0)
    {
        // Already a power of two.
        iofc->bank_address_space = iofc->blocks_per_bank;
        //total_block_space = ce_blocks;
    }
    else
    {
        // Calculate the bank address space.
        iofc->bank_address_space = next_power_of_two(iofc->blocks_per_bank);
        //total_block_space = ((banksPerCEphysical-1)*bank_address_space) + blocks_per_bank;
    }
}

//"bruteforce" the number of physical banks
//except for PPN devices, DEVICEINFOBBT special pages should always be somewhere at the end
void check_special_pages(IOFlashController_client* iofc)
{
    uint32_t i,x=1;
    uint32_t ok = 0;
    uint32_t bank, block, page;
    uint8_t* pageBuffer;
    
    pageBuffer = (uint8_t*) valloc(iofc->dump_page_size);
    IOFlashControllerUserClient_OutputStruct *out = (IOFlashControllerUserClient_OutputStruct*) (&pageBuffer[iofc->page_bytes + iofc->meta_per_logical_page]);
    
    printf("Trying to read page 0\n");
    IOReturn r = FSDReadBootPage(iofc, 0, 0, pageBuffer, out);
    if(r)
    {
        printf("Failed to read page 0, error code 0x%08x, missing kernel patch ?\n", r);
        free(pageBuffer);
        exit(0);
        return;
    }
    printf("First page magic: '%4s'\n", (char*) pageBuffer);

    if(iofc->ppn_device)
    {
        set_physical_banks(iofc, iofc->caus_ce);
        fprintf(stderr, "PPN device, caus-ce=%d bank_address_space=0x%x\n", iofc->caus_ce, iofc->bank_address_space);
        free(pageBuffer);
        return;
    }


    printf("Searching for special pages ...\n");

    while(!ok && x < 10)
    {
        set_physical_banks(iofc, x);
        bank = iofc->banksPerCEphysical - 1;
        
        for(block = iofc->blocks_per_bank-1; !ok && block > iofc->blocks_per_bank-10 ; block--)
        {
            page = (iofc->bank_address_space * bank +  block) * iofc->block_pages;

         
            for(i=0; i < iofc->block_pages; i++)
            {
                if(FSDReadPageWithOptions(iofc, 0, page + i, pageBuffer, &pageBuffer[iofc->page_bytes], iofc->meta_per_logical_page, 0, out))
                    continue;
                if(pageBuffer[iofc->page_bytes] != 0xA5)
                    continue;
                if(!memcmp(pageBuffer, "DEVICEINFOBBT", 13))
                {
                    printf("Found cleartext DEVICEINFOBBT at block %d page %d with banksPerCEphyiscal=%d\n", iofc->blocks_per_bank*bank +block, i, iofc->banksPerCEphysical);
                    ok = 1;
                    break;
                }
                decrypt_page(pageBuffer, iofc->page_bytes, META_KEY, kCCKeySizeAES128, page + i);
                if(!memcmp(pageBuffer, "DEVICEINFOBBT", 13))
                {
                    printf("Found encrypted DEVICEINFOBBT at block %d page %d with banksPerCEphyiscal=%d\n", iofc->blocks_per_bank*bank +block, i, iofc->banksPerCEphysical);
                    ok = 1;
                    break;
                }
            }
        }
        x++;
    }
    if(!ok)
    {
        fprintf(stderr, "!!!! Couldnt guess the number of physical banks, assuming 1 !!!!\n");
        set_physical_banks(iofc, 1);
    }
    free(pageBuffer);
    return;
}


IOFlashPartitionScheme* find_boot_blocks(IOFlashController_client* iofc)
{
    IOFlashPartitionScheme* fps = NULL;
    int ceNum=0,pageNum=0;
    IOFlashControllerUserClient_OutputStruct out = {0};

    uint8_t* pageBuffer = (uint8_t*) valloc(iofc->page_bytes);
    
    if (pageBuffer == NULL)
    {
        fprintf(stderr, "find_boot_blocks valloc(%d) FAIL", iofc->page_bytes);
        return NULL;
    }

    //find partition table
    for(ceNum=0; ceNum < iofc->num_ce; ceNum++)
    {
        for(pageNum=0; pageNum < iofc->block_pages; pageNum++)
        {
            if (FSDReadBootPage(iofc, ceNum, pageNum, pageBuffer, &out) != 0)
                continue;
            
            fps = IOFlashPartitionScheme_init(iofc, pageBuffer);
            if (fps != NULL)
                break;
        }
    }
    free(pageBuffer);
    return fps;
}

CFMutableDictionaryRef FSDGetInfo()
{
    CFMutableDictionaryRef      iofsd_properties;
    IOFlashController_client* iofc = IOFlashController_init();

    if(!iofc)
        return NULL;
    
    iofsd_properties = iofc->iofsd_properties;

    CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &iofc->dump_page_size);
    CFDictionarySetValue(iofsd_properties, CFSTR("dumpedPageSize"), n);
    CFRelease(n);
    
    return iofsd_properties;
}

//XXX dont read the NAND from this function as it can be called from multiple processes

IOFlashController_client* IOFlashController_init()
{
    IOFlashController_client*   iofc;
    CFMutableDictionaryRef      iofsd_properties;
    CFMutableDictionaryRef      matchingDict;
    kern_return_t               status;
    io_service_t                fsd, fc;
    io_connect_t                conn;
    io_iterator_t               iterator = 0;
    
    //open IOFlashController 
    matchingDict = IOServiceMatching("IOFlashController");
    fc = IOServiceGetMatchingService(kIOMasterPortDefault, matchingDict);
    if (!fc)
    {
        fprintf(stderr, "IOServiceGetMatchingService IOFlashController failed\n");
        return NULL;
    }
    status = IOServiceOpen(fc, mach_task_self(), 0, &conn);
    if (status != KERN_SUCCESS)
    {
        fprintf(stderr, "IOServiceOpen IOFlashController failed %x\n", status);
        return NULL;
    }
    
    if(IORegistryEntryCreateIterator(fc, "IOService",0, &iterator))
    {
        fprintf(stderr, "IORegistryEntryCreateIterator failed\n");
        return NULL;
    }

    while(1)
    {
        fsd = IOIteratorNext(iterator);
        if (!fsd)
        {
            printf("IOFlashStorageDevice not found\n");
            return NULL;
        }
        if(IOObjectConformsTo(fsd, "IOFlashStorageDevice"))
        {
            break;
        }
    }

    iofc = malloc(sizeof(IOFlashController_client));

    if (iofc == NULL)
    {
        fprintf(stderr, "IOFlashController_client malloc failed\n");
        return NULL;
    }
    memset((void*) iofc, 0, sizeof(IOFlashController_client));

    iofc->iofc_connect = conn;

    status = IORegistryEntryCreateCFProperties(fsd, &iofsd_properties, kCFAllocatorDefault, kNilOptions);
    assert( KERN_SUCCESS == status );
    assert( CFDictionaryGetTypeID() == CFGetTypeID(iofsd_properties));

    iofc->iofsd_properties = iofsd_properties;

    FSDGetPropertyForKey(fsd, CFSTR("#ce"), &iofc->num_ce, sizeof(iofc->num_ce), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("#ce-blocks"), &iofc->ce_blocks, sizeof(iofc->ce_blocks), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("#block-pages"), &iofc->block_pages, sizeof(iofc->block_pages), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("#page-bytes"), &iofc->page_bytes, sizeof(iofc->page_bytes), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("#spare-bytes"), &iofc->spare_bytes, sizeof(iofc->spare_bytes), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("#bootloader-bytes"), &iofc->bootloader_bytes, sizeof(iofc->bootloader_bytes), NULL);

    FSDGetPropertyForKey(fsd, CFSTR("logical-page-size"), &iofc->logical_page_size, sizeof(iofc->logical_page_size), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("boot-from-nand"), &iofc->boot_from_nand, sizeof(iofc->boot_from_nand), NULL);

    FSDGetPropertyForKey(fsd, CFSTR("valid-meta-per-logical-page"), &iofc->valid_meta_per_logical_page, sizeof(iofc->valid_meta_per_logical_page), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("meta-per-logical-page"), &iofc->meta_per_logical_page, sizeof(iofc->meta_per_logical_page), NULL);

    FSDGetPropertyForKey(fsd, CFSTR("ppn-device"), &iofc->ppn_device, sizeof(iofc->ppn_device), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("slc-pages"), &iofc->slc_pages, sizeof(iofc->slc_pages), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("cau-bits"), &iofc->cau_bits, sizeof(iofc->cau_bits), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("page-bits"), &iofc->page_bits, sizeof(iofc->page_bits), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("block-bits"), &iofc->block_bits, sizeof(iofc->block_bits), NULL);
    FSDGetPropertyForKey(fsd, CFSTR("caus-ce"), &iofc->caus_ce, sizeof(iofc->caus_ce), NULL);

    if (iofc->meta_per_logical_page == 0)
    {
        iofc->meta_per_logical_page = 12;//default value?
    }
    if (iofc->ppn_device)
    {
        //read full spare with AppleIOPFMI::_fmiPatchMetaFringe nopped
        iofc->meta_per_logical_page = iofc->spare_bytes;
    }

    IOObjectRelease(fsd);

    iofc->pages_per_ce = iofc->ce_blocks * iofc->block_pages;
    iofc->total_blocks = iofc->num_ce * iofc->ce_blocks;

    iofc->dump_page_size = iofc->page_bytes + iofc->meta_per_logical_page + sizeof(IOFlashControllerUserClient_OutputStruct);

    iofc->total_size = ((uint64_t)iofc->page_bytes) * ((uint64_t) (iofc->block_pages * iofc->ce_blocks * iofc->num_ce));

    set_physical_banks(iofc, 1);

    return iofc;
}

void IOFlashController_print(IOFlashController_client* iofc)
{
    fprintf(stderr, "NAND configuration: %uGiB (%d CEs of %d blocks of %d pages of %d bytes data, %d bytes spare\n",
        (uint32_t) (iofc->total_size / (1024*1024*1024)),
        iofc->num_ce,
        iofc->ce_blocks,
        iofc->block_pages,
        iofc->page_bytes,
        iofc->spare_bytes);
}

CFDictionaryRef nand_dump(IOFlashController_client* iofc, int fd)
{
    uint64_t totalSize = (uint64_t)iofc->block_pages * (uint64_t)iofc->ce_blocks * (uint64_t)iofc->num_ce * (uint64_t)iofc->dump_page_size;
    write(fd, &totalSize, sizeof(uint64_t));
    
    dump_nand_to_socket(iofc, fd);
    return NULL;
}

int dump_nand_to_socket(IOFlashController_client* iofc, int fd)
{
    uint32_t part_flags, slc_bit, blockNum,  ceNum=0,pageNum=0,bankNum=0;
    uint64_t totalPages = iofc->block_pages * iofc->ce_blocks * iofc->num_ce;
    uint64_t validPages = 0;
    uint64_t blankPages = 0;
    uint64_t errorPages = 0;
    uint64_t otherPages = 0;
    uint64_t counter = 0;
    IOReturn r;
    IOFlashPartitionScheme* fps = NULL;
    IOFlashControllerUserClient_OutputStruct *out;

    if (iofc->boot_from_nand)
    {
        fps = find_boot_blocks(iofc);
        assert(fps);
    }

    //page data + spare metadata + kernel return values
    uint8_t* pageBuffer = (uint8_t*) valloc(iofc->dump_page_size);

    if (pageBuffer == NULL)
    {
        fprintf(stderr, "valloc(%d) FAIL", iofc->dump_page_size);
        return 0;
    }
    out = (IOFlashControllerUserClient_OutputStruct *) (&pageBuffer[iofc->page_bytes + iofc->meta_per_logical_page]);

    time_t start = time(NULL);
    part_flags = 0;

    for(bankNum=0; bankNum < iofc->banksPerCEphysical; bankNum++)
    {
    uint32_t start_page = iofc->bank_address_space * bankNum * iofc->block_pages;
    uint32_t end_page = start_page + iofc->block_pages * iofc->blocks_per_bank;
    for(pageNum=start_page; pageNum < end_page; pageNum++)
    {
        for(ceNum=0; ceNum < iofc->num_ce; ceNum++)
        {
            blockNum = iofc->bank_address_space * bankNum + (pageNum-start_page) / iofc->block_pages;
            if (fps)
                part_flags = IOFlashPartitionScheme_get_flags_for_block(fps, ceNum, blockNum);

            slc_bit = (part_flags & kIOFlashPartitionSchemeUseSLCBlocks) ? (1 << (iofc->page_bits+iofc->block_bits+iofc->cau_bits)) : 0;

            if(slc_bit && ((pageNum % iofc->block_pages) >= (iofc->slc_pages)))
            {
                //XXX: filling remaining pages of slc block with 0xAB marker for debug
                memset(pageBuffer, 0xAB, iofc->page_bytes + iofc->meta_per_logical_page);
                r = 0;
                printf("SLC skip ce %d page %x\n", ceNum, pageNum);
            }
            else if(part_flags && !(part_flags & kIOFlashPartitionSchemeUseFullPages))
            {
                memset(pageBuffer, 0, iofc->dump_page_size);
                r = FSDReadBootPage(iofc, ceNum, pageNum | slc_bit, pageBuffer, out);
                printf("Boot block read ce %d page %x\n", ceNum, pageNum);
            }
            else
            {
                r = FSDReadPageWithOptions(iofc, ceNum, pageNum | slc_bit, pageBuffer, &pageBuffer[iofc->page_bytes], iofc->meta_per_logical_page, 0, out);
            }
            if(r == 0)
            {
                validPages++;
            }
            else
            {
                if (r == kIOReturnBadMedia)
                {
                    fprintf(stderr, "CE %x page %x : uncorrectable ECC error\n", ceNum, pageNum);
                    errorPages++;
                }
                else if (r == kIOReturnUnformattedMedia)
                {
                    memset(pageBuffer, 0xFF, iofc->page_bytes + iofc->meta_per_logical_page);
                    blankPages++;
                }
                else if (r == 0xdeadbeef)
                {
                    fprintf(stderr, "0xdeadbeef return code, something is wrong with injected kernel code\n");
                    exit(0);
                }
                else if (r == kIOReturnBadArgument || r == kIOReturnNotPrivileged)
                {
                    fprintf(stderr, "Error 0x%x (kIOReturnBadArgument/kIOReturnNotPrivileged)\n", r);
                    exit(0);
                }
                else
                {
                    fprintf(stderr, "CE %x page %x : unknown return code 0x%x\n", ceNum, pageNum, r);
                    otherPages++;
                }
            }
        
            if(write(fd, pageBuffer, iofc->dump_page_size) != iofc->dump_page_size)
            {
                pageNum = iofc->block_pages * iofc->ce_blocks;
                fprintf(stderr, "Abort dump\n");
                break;
            }
            if (ceNum == 0 && pageNum % iofc->block_pages == 0)
            {
                //fprintf(stderr, "Block %d/%d (%d%%)\n", (counter/block_pages), ce_blocks, (counter*100)/(block_pages*ce_blocks));
            }
        }
        counter++;
    }
    }
    if (ceNum == iofc->num_ce && (pageNum == (iofc->block_pages * iofc->ce_blocks)))
    {
        time_t duration = time(NULL) - start;
        fprintf(stderr, "Finished NAND dump in %lu hours %lu minutes %lu seconds\n", duration / 3600, (duration % 3600) / 60, (duration % 3600) % 60);
        fprintf(stderr, "Total pages %llu\n", totalPages);
        fprintf(stderr, "In-use pages %llu (%d%%)\n", validPages, (int) (validPages * 100 / totalPages));
        fprintf(stderr, "Blank pages %llu (%d%%)\n", blankPages, (int) (blankPages * 100 / totalPages));
        fprintf(stderr, "Error pages %llu (%d%%)\n", errorPages, (int) (errorPages * 100 / totalPages));
        fprintf(stderr, "Other pages %llu (%d%%)\n", otherPages, (int) (otherPages * 100 / totalPages));
        fprintf(stderr, "(those stats are incorrect for ppn devices)\n");
    }
    free(pageBuffer);
    return 0;
}

int nand_proxy(IOFlashController_client* iofc, int fd)
{
    IOFlashControllerUserClient_OutputStruct out;
    proxy_read_cmd cmd;
    uint32_t z, spareSize = 0;
    uint8_t* spareBuf = NULL;
    uint8_t* spareBuf2;

    uint8_t* pageBuffer = (uint8_t*) valloc(iofc->page_bytes);
    if( pageBuffer == NULL)
    {
        fprintf(stderr, "pageBuffer = valloc(%d) failed\n", iofc->page_bytes);
        return 0;
    }

    while(1)
    {
        z = read(fd, &cmd, sizeof(proxy_read_cmd));
        if (z != sizeof(proxy_read_cmd))
            break;

        if (cmd.spareSize > spareSize)
        {
            if (spareBuf != NULL)
            {
                free(spareBuf);
            }
            spareBuf = valloc(cmd.spareSize);
            if (spareBuf == NULL)
            {
                fprintf(stderr, "spareBuf = valloc(%d) failed\n", cmd.spareSize);
                break;
            }
            spareSize = cmd.spareSize;
        }
        spareBuf2 = (cmd.spareSize > 0) ? spareBuf : NULL;
        //fprintf(stderr, "read %d %d %d %x\n", cmd.ce, cmd.page, cmd.spareSize, spareBuf2);
        FSDReadPageWithOptions(iofc, cmd.ce, cmd.page, pageBuffer, spareBuf2, cmd.spareSize, cmd.options, &out);
        
        write(fd, pageBuffer, iofc->page_bytes);
        if (spareBuf2 != NULL)
        {
            write(fd, spareBuf2, cmd.spareSize);
        }
        write(fd, &out, sizeof(IOFlashControllerUserClient_OutputStruct));
    }
    if (spareBuf != NULL)
    {
        free(spareBuf);
    }
    free(pageBuffer);
    return 0;
}
