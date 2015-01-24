from construct import *
from structs import next_power_of_two, PAGETYPE_VFL, CEIL_DIVIDE
from vfl import vfl_check_checksum, _vfl_vsvfl_spare_data

"""
https://github.com/iDroid-Project/openiBoot/blob/master/vfl-vsvfl/vsvfl.c
https://github.com/iDroid-Project/openiBoot/blob/master/vfl-vsvfl/includes/vfl/vsvfl.h
"""

_vfl_vsvfl_context = Struct("_vfl_vsvfl_context",
                            ULInt32("usn_inc"),
                            ULInt32("usn_dec"),
                            ULInt32("ftl_type"),
                            ULInt16("usn_block"),
                            ULInt16("usn_page"),
                            ULInt16("active_context_block"),
                            ULInt16("write_failure_count"),
                            ULInt16("bad_block_count"),
                            Array(4, ULInt8("replaced_block_count")),
                            ULInt16("num_reserved_blocks"),
                            ULInt16("field_1C"),
                            ULInt16("total_reserved_blocks"),
                            Array(6, ULInt8("field_20")),
                            Array(820, ULInt16("reserved_block_pool_map")),
                            Array(4, ULInt16("vfl_context_block")),
                            ULInt16("usable_blocks_per_bank"),
                            ULInt16("reserved_block_pool_start"),
                            Array(3, ULInt16("control_block")),
                            ULInt16("scrub_list_length"),
                            Array(20, ULInt16("scrub_list")),
                            Array(4, ULInt32("field_6CA")),
                            ULInt32("vendor_type"),
                            Array(204, ULInt8("field_6DE")),
                            ULInt16("remapping_schedule_start"),
                            Array(0x48, ULInt8("unk3")),
                            ULInt32("version"),
                            ULInt32("checksum1"),
                            ULInt32("checksum2")
)


class VSVFL(object):
    def __init__(self, nand):
        self.nand = nand
        self.banks_per_ce_vfl = 1
        if self.nand.vendorType in [0x100010, 0x100014, 0x120014, 0x150011]:
            self.banks_per_ce_vfl = 2
        self.banks_total = nand.nCEs * self.banks_per_ce_vfl
        self.num_ce = nand.nCEs
        self.banks_per_ce = nand.banks_per_ce_physical
        self.blocks_per_ce = nand.blocksPerCE
        self.pages_per_block = nand.pagesPerBlock
        self.pages_per_block_2 = next_power_of_two(self.pages_per_block)
        self.pages_per_sublk = self.pages_per_block * self.banks_per_ce_vfl * self.num_ce
        self.blocks_per_bank = self.blocks_per_ce / self.banks_per_ce
        self.blocks_per_bank_vfl = self.blocks_per_ce / self.banks_per_ce_vfl
        self.vendorType = nand.vendorType
        if self.vendorType == 0x10001:
            self.virtual_to_physical = self.virtual_to_physical_10001
        elif self.vendorType == 0x150011:
            self.virtual_to_physical = self.virtual_to_physical_100014
        elif self.vendorType in [0x100010, 0x100014, 0x120014]:
            self.virtual_to_physical = self.virtual_to_physical_150011
        else:
            raise Exception("VSVFL: unsupported vendor 0x%x" % self.vendorType)
        self.bank_address_space = nand.bank_address_space
        self.vflContexts = []
        self.bbt = []
        self.current_version = 0
        reserved_blocks = 0
        if self.nand.bfn:
            reserved_blocks = 16
        fs_start_block = reserved_blocks+16 #XXX
        for ce in xrange(self.num_ce):
            vflctx = None
            for b in xrange(reserved_blocks, fs_start_block):
                s, d = nand.readMetaPage(ce, b, 0, _vfl_vsvfl_spare_data)
                if not d:
                    continue
                vflctx = _vfl_vsvfl_context.parse(d)
                if not vfl_check_checksum(vflctx, _vfl_vsvfl_context):
                    vflctx = None
                    continue
                break
            if not vflctx:
                raise Exception("Unable to find VSVFL context for CE %d" % ce)
            MostRecentVFLCxtBlock = -1
            minUsn = 0xFFFFFFFF
            for b in vflctx.vfl_context_block:
                s, d = nand.readMetaPage(ce, b, 0, _vfl_vsvfl_spare_data)
                if not d or s.type1 != PAGETYPE_VFL:
                    continue
                if s.foo.meta.usnDec > 0 and s.foo.meta.usnDec <= minUsn:
                    minUsn = s.foo.meta.usnDec;
                    MostRecentVFLCxtBlock = b
            if MostRecentVFLCxtBlock == -1:
                print "MostRecentVFLCxtBlock == -1"
                return
            last = None
            for pageNum in xrange(0, self.pages_per_block, 1):
                s,d = nand.readMetaPage(ce, MostRecentVFLCxtBlock, pageNum, _vfl_vsvfl_spare_data)
                if not d or s.type1 != PAGETYPE_VFL:
                    break
                last = d
            vflctx = _vfl_vsvfl_context.parse(last)
            if not vfl_check_checksum(vflctx, _vfl_vsvfl_context):
                print "VSVFL checksum FAIL"
            self.vflContexts.append(vflctx)
            if vflctx.version == 2 and vflctx.usn_inc >= self.current_version:
                self.current_version = vflctx.usn_inc
                self.context = vflctx
        if not self.context:
            raise Exception("VSVFL open FAIL")
        
        num_reserved = self.vflContexts[0].reserved_block_pool_start
        num_non_reserved = self.blocks_per_bank_vfl - num_reserved
        for ce in xrange(self.num_ce):
            bbt = [0xFF] * (CEIL_DIVIDE(self.blocks_per_ce, 8))
            ctx = self.vflContexts[ce]
            for bank in xrange(0, self.banks_per_ce_vfl):
                for i in xrange(0, num_non_reserved):
                    mapEntry = ctx.reserved_block_pool_map[bank*num_non_reserved + i]
                    if mapEntry == 0xFFF0:
                        continue
                    if mapEntry < self.blocks_per_ce:
                        pBlock = mapEntry
                    elif mapEntry > 0xFFF0:
                        pBlock = self.virtual_block_to_physical_block(ce + bank * self.num_ce, num_reserved + i)
                    else:
                        print "VSVFL: bad map table"
                    bbt[pBlock / 8] &= ~(1 << (pBlock % 8))
            self.bbt.append(bbt)
        print "VSVFL context open OK"

    def VFL_get_FTLCtrlBlock(self):
        for ctx in self.vflContexts:
            if ctx.usn_inc == self.current_version:
                return ctx.control_block
    
    def virtual_to_physical_10001(self, vBank, vPage):
        return vBank, vPage
    
    def virtual_to_physical_100014(self, vBank, vPage):
        pBank = vBank / self.num_ce;
        pPage = ((self.pages_per_block - 1) & vPage) | (2 * (~(self.pages_per_block - 1) & vPage))
        if (pBank & 1):
            pPage |= self.pages_per_block
        return vBank % self.num_ce, pPage
    
    def virtual_to_physical_150011(self, vBank, vPage):
        pBlock = 2 * (vPage / self.pages_per_block)
        if(vBank % (2 * self.num_ce) >= self.num_ce):
            pBlock += 1
        return vBank % self.num_ce, self.pages_per_block * pBlock | (vPage % 128)
    
    def virtual_block_to_physical_block(self, vBank, vBlock):
        ce, pPage = self.virtual_to_physical(vBank, self.pages_per_block * vBlock)
        return pPage / self.pages_per_block
    
    def vfl_is_good_block(self, bbt, block):
        if block > self.blocks_per_ce:
            raise Exception("vfl_is_good_block block %d out of bounds" % block)
        return (bbt[block / 8] & (1 << (block % 8))) != 0
    
    def remap_block(self, ce, pBlock):
        if self.vfl_is_good_block(self.bbt[ce], pBlock):
            return pBlock
        ctx = self.vflContexts[ce]
        for pwDesPbn in xrange(0, self.blocks_per_ce - ctx.reserved_block_pool_start * self.banks_per_ce_vfl):
            if ctx.reserved_block_pool_map[pwDesPbn] == pBlock:
                vBank = ce + self.num_ce * (pwDesPbn / (self.blocks_per_bank_vfl - ctx.reserved_block_pool_start))
                vBlock = ctx.reserved_block_pool_start + (pwDesPbn % (self.blocks_per_bank_vfl - ctx.reserved_block_pool_start))
                z = self.virtual_block_to_physical_block(vBank, vBlock)
                #print "remapped block %d => %d" % (pBlock, z)
                return z
        print "Bad block %d not remapped" % pBlock
        return pBlock
    
    def virtual_page_number_to_physical(self, vpn):
        vBank = vpn % self.banks_total
        ce = vBank % self.nand.nCEs
        
        pBlock = self.virtual_block_to_physical_block(vBank, vpn / self.pages_per_sublk)
        pBlock = self.remap_block(ce, pBlock)
        bank_offset = self.bank_address_space * (pBlock / self.blocks_per_bank)
        page = self.pages_per_block_2 * (bank_offset + (pBlock % self.blocks_per_bank)) \
            + ((vpn % self.pages_per_sublk) / self.banks_total)
        return ce, page
        
    def read_single_page(self, vpn, key=None, lpn=None):
        ce, pPage = self.virtual_page_number_to_physical(vpn)
        #print "VFL read_single_page %d => %d, %d" % (vpn,ce,pPage)
        return self.nand.readPage(ce, pPage, key, lpn)
