#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ioflash.h"
#include "IOFlashPartitionScheme.h"

//http://en.wikipedia.org/wiki/Fletcher's_checksum
uint16_t fletcher16( uint8_t const *data, size_t bytes )
{
    uint16_t sum1 = 0xff, sum2 = 0xff;

    while (bytes) {
            size_t tlen = bytes > 20 ? 20 : bytes;
            bytes -= tlen;
            do {
                    sum2 += sum1 += *data++;
            } while (--tlen);
            sum1 = (sum1 & 0xff) + (sum1 >> 8);
            sum2 = (sum2 & 0xff) + (sum2 >> 8);
    }
    /* Second reduction step to reduce sums to 8 bits */
    sum1 = (sum1 & 0xff) + (sum1 >> 8);
    sum2 = (sum2 & 0xff) + (sum2 >> 8);
    return sum2 << 8 | sum1;
}

IOFlashPartitionScheme* IOFlashPartitionScheme_init(IOFlashController_client* iofc, uint8_t* buffer)
{
    struct IOFlashPartitionTable* p = (struct IOFlashPartitionTable*) buffer;
    if (p->magic != 'Grdn')
    {
        fprintf(stderr, "Bad Grdn magic %x\n", p->magic);
        return NULL;
    }
    //TODO: check checksum1

    if (p->cemetary.magic != CEMETARY_GATE)
    {
        fprintf(stderr, "Bad cemetary gate %x\n", p->cemetary.magic);
        return NULL;
    }
    if (fletcher16((uint8_t*) &p->cemetary, 42) != p->cemetary.checksum)
    {
        fprintf(stderr, "Bad cemetary checksum\n");
        return NULL;
    }

    if (p->spares.magic != 'spAr')
    {
        fprintf(stderr, "Bad rAps magic %x\n", p->spares.magic);
        return NULL;
    }
    if (fletcher16((uint8_t*) &p->spares, 0x10A) != p->spares.checksum)
    {
        fprintf(stderr, "Bad spares checksum\n");
        return NULL;
    }

    if (p->subs.magic != 'subs')
    {
        fprintf(stderr, "Bad sbus magic %x\n", p->subs.magic);
        return NULL;
    }
    IOFlashPartitionScheme* fps = (IOFlashPartitionScheme*) malloc(sizeof(IOFlashPartitionScheme));

    fps->flash = iofc;
    fps->ceCount = iofc->num_ce;

    memcpy((void*) &fps->ptable, (void*) p, sizeof(struct IOFlashPartitionTable));

    uint32_t i, blk_offset;

    for(i=0,blk_offset=0; i < 32; i++)
    {
        if( fps->ptable.partitions[i].flags & kIOFlashPartitionSchemePool)
        {
            fps->ptable.partitions[i].num_blocks = (fps->ptable.partitions[i].start_block * fps->ptable.partitions[i].num_blocks) / fps->ceCount;
            fps->ptable.partitions[i].start_block = blk_offset;
        }
        blk_offset += fps->ptable.partitions[i].num_blocks;
    }

    return fps;
}

uint32_t get_partition_idx_for_block(IOFlashPartitionScheme* fps, uint32_t block)
{
    uint32_t i;
    for(i=0; i < 32; i++)
    {
        if( block >= fps->ptable.partitions[i].start_block
        && block < fps->ptable.partitions[i].start_block + fps->ptable.partitions[i].num_blocks)
        {
            return i;
        }
    }
    return -1;
}


uint32_t IOFlashPartitionScheme_get_flags_for_block(IOFlashPartitionScheme* fps, uint32_t ce, uint32_t block)
{
    uint32_t i,idx;
    uint32_t original_block;

    //uint32_t vblock = block * fps->ceCount + ce;
    //check if bad boot block
    /*if (block < 16)
    {
        uint8_t x = fps->ptable.cemetary.cemetary[vblock / 8];
        return (x & (1 << (vblock % 8))) == 0;
    }*/
    uint32_t sp = (block & 0xFFFFFF) | (ce << 24);
    //check if spare
    //printf("sp=%x\n", sp);
    for (i=0; i < fps->ptable.spares.num_spares; i++)
    {
        if (fps->ptable.spares.spares[i] == sp)
        {
            //check if spare is "in use"
            original_block = fps->ptable.subs.subs[i];
            if (original_block != 0)
            {
                idx = get_partition_idx_for_block(fps, original_block/fps->ceCount);
                if(idx != -1)
                {
                    //printf("lol %x %d %x\n", original_block, idx, ptable.partitions[idx].flags);
                    //return (fps->ptable.partitions[idx].flags & kIOFlashPartitionSchemeUseFullPages) == 0;
                    return fps->ptable.partitions[idx].flags;
                }
            }
        }
    }
    if (block >= 16)//HAX
        return kIOFlashPartitionSchemeUseFullPages;
    idx = get_partition_idx_for_block(fps, block);
    if(idx != -1)
        return fps->ptable.partitions[idx].flags;
    return 0;
}

uint32_t IOFlashPartitionScheme_remap_bootloader_block(IOFlashPartitionScheme* fps, uint32_t ce, uint32_t block, uint32_t flags, uint32_t* realCE, uint32_t* realBlock)
{
    uint32_t i;
    uint32_t vblock = block * fps->ceCount + ce;
    uint8_t x = fps->ptable.cemetary.cemetary[vblock / 8];

    uint32_t bad = (x & (1 << (vblock % 8)));

    if (!bad && !(flags & kIOFlashPartitionSchemePool))
    {
        *realCE = ce;
        *realBlock = block;
        return 0;
    }
    for (i=0; i < fps->ptable.subs.num_subs; i++)
    {
        if (fps->ptable.subs.subs[i] == vblock)
        {
            uint32_t spare = fps->ptable.spares.spares[i];
            *realCE = spare >> 24;
            *realBlock = spare & 0xFFFFFF;
            return 0;
        }
    }
    fprintf(stderr, "remap_bootloader_block: cannot find sub for ce %d block %d\n", ce, block);
    return -1;
}

uint32_t get_partition_idx(IOFlashPartitionScheme* fps, const char* name)
{
    uint32_t i;
    for(i=0; i < 32; i++)
    {
        if(fps->ptable.partitions[i].name == *((uint32_t*)name))
            return i;
    }
    return -1;
}


uint32_t IOFlashPartitionScheme_read_partition(IOFlashPartitionScheme* fps, const char* name, uint8_t** buffer, uint32_t* size)
{
    IOFlashControllerUserClient_OutputStruct out;
    uint32_t ce, block, page, off, pageAddr, remappedCE, remappedBlock;
    uint32_t pageSize, metaPerLogicalPage, partitionSize, pagesPerBlock;
    uint32_t page_bits, block_bits, cau_bits;
    uint32_t is_ppn, slc;
    IOReturn r;

    uint32_t partition_idx = get_partition_idx(fps, name);
    if (partition_idx == -1)
    {
        fprintf(stderr, "read_partition: cant find partition %s\n", name);
        return -1;
    }
    struct IOFlashPartitionDesc* partition = &fps->ptable.partitions[partition_idx];

    if (partition->flags & kIOFlashPartitionSchemeUseFullPages)
    {
        pageSize = fps->flash->page_bytes;
    }
    else
    {
        pageSize = fps->flash->bootloader_bytes;
    }
    metaPerLogicalPage = fps->flash->meta_per_logical_page;

    //XXX we only read in first CE
    ce = 0;

    slc = (partition->flags & kIOFlashPartitionSchemeUseSLCBlocks) != 0;
    page_bits = fps->flash->page_bits;
    block_bits = fps->flash->block_bits;
    cau_bits = fps->flash->cau_bits;
    is_ppn = fps->flash->ppn_device;

    pagesPerBlock = fps->flash->block_pages;

    if (partition->flags & kIOFlashPartitionSchemeUseSLCBlocks)
    {
        pagesPerBlock = fps->flash->slc_pages; //TODO get param
    }

    partitionSize = partition->num_blocks * pagesPerBlock * (pageSize);

    uint8_t* data = valloc(partitionSize);
    if( data == NULL)
    {
        fprintf(stderr, "read_partition: cant valloc %d bytes\n", partitionSize);
        return -1;
    }

    uint8_t* pageBuffer = valloc(pageSize);
    if( pageBuffer == NULL)
    {
        fprintf(stderr, "read_partition: cant valloc %d bytes\n", pageSize);
        return -1;
    }
    uint8_t* spareBuffer = valloc(metaPerLogicalPage);
    if( spareBuffer == NULL)
    {
        fprintf(stderr, "read_partition: cant valloc %d bytes\n", metaPerLogicalPage);
        return -1;
    }

    fprintf(stderr, "read_partition is_ppn %d pagesPerBlock %d pageSize %d slc %d\n", is_ppn, pagesPerBlock, pageSize, slc);

    for(off=0, block=partition->start_block; block < (partition->start_block + partition->num_blocks); block++)
    {
        IOFlashPartitionScheme_remap_bootloader_block(fps, ce, block, partition->flags, &remappedCE, &remappedBlock);

        for(page=0; page < pagesPerBlock; page++)
        {
            if (is_ppn)
            {
                pageAddr = (remappedBlock << page_bits) | page | (slc << (page_bits+block_bits+cau_bits));
            }
            else
            {
                pageAddr = remappedBlock*pagesPerBlock + page;
            }

            if (partition->flags & kIOFlashPartitionSchemeUseFullPages)
            {
                r = FSDReadPageWithOptions(fps->flash,
                                       remappedCE,
                                       pageAddr,
                                       pageBuffer,
                                       spareBuffer,
                                       metaPerLogicalPage,
                                       1,
                                       &out);
                if(r == 0 && spareBuffer[0] != (0x40 | (partition_idx & 0xF)))
                {
                    //fprintf(stderr, "skipping weird page at %d %d %x\n", remappedBlock, page, spareBuffer[0]);
                    continue;
                }
            }
            else
            {
                r = FSDReadBootPage(fps->flash, remappedCE, pageAddr, pageBuffer, &out);
            }

            memcpy(&data[off], pageBuffer, pageSize);
            off += pageSize;
        }
    }
    free(pageBuffer);
    free(spareBuffer);

    *buffer = data;
    *size = off;
    return 0;
}
