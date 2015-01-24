from array import array
from construct.core import Struct, Union
from construct.macros import *
from structs import next_power_of_two, CEIL_DIVIDE, PAGETYPE_VFL
import struct

"""
https://github.com/iDroid-Project/openiBoot/blob/master/plat-s5l8900/includes/s5l8900/ftl.h
https://github.com/iDroid-Project/openiBoot/blob/master/plat-s5l8900/ftl.c
https://github.com/iDroid-Project/openiBoot/blob/master/plat-s5l8900/nand.c

static const NANDDeviceType SupportedDevices[] = {
"""
SupportedDevices = {0x2555D5EC: [8192, 128, 4, 64, 4, 2, 4, 2, 7744, 4, 6],
                    0xB614D5EC: [4096, 128, 8, 128, 4, 2, 4, 2, 3872, 4, 6],
                    0xB655D7EC: [8192, 128, 8, 128, 4, 2, 4, 2, 7744, 4, 6],
                    0xA514D3AD: [4096, 128, 4, 64, 4, 2, 4, 2, 3872, 4, 6],
                    0xA555D5AD: [8192, 128, 4, 64, 4, 2, 4, 2, 7744, 4, 6],
                    0xB614D5AD: [4096, 128, 8, 128, 4, 2, 4, 2, 3872, 4, 6],
                    0xB655D7AD: [8192, 128, 8, 128, 4, 2, 4, 2, 7744, 4, 6],
                    0xA585D598: [8320, 128, 4, 64, 6, 2, 4, 2, 7744, 4, 6],
                    0xBA94D598: [4096, 128, 8, 216, 6, 2, 4, 2, 3872, 8, 8],
                    0xBA95D798: [8192, 128, 8, 216, 6, 2, 4, 2, 7744, 8, 8],
                    0x3ED5D789: [8192, 128, 8, 216, 4, 2, 4, 2, 7744, 8, 8],
                    0x3E94D589: [4096, 128, 8, 216, 4, 2, 4, 2, 3872, 8, 8],
                    0x3ED5D72C: [8192, 128, 8, 216, 4, 2, 4, 2, 7744, 8, 8],
                    0x3E94D52C: [4096, 128, 8, 216, 4, 2, 4, 2, 3872, 8, 8]
                    }

_vfl_vfl_context = Struct("_vfl_vfl_context",
                            ULInt32("usn_inc"),
                            Array(3, ULInt16("control_block")),
                            ULInt16("unk1"),
                            ULInt32("usn_dec"),
                            ULInt16("active_context_block"),
                            ULInt16("next_context_page"),
                            ULInt16("unk2"),
                            ULInt16("field_16"),
                            ULInt16("field_18"),
                            ULInt16("num_reserved_blocks"),
                            ULInt16("reserved_block_pool_start"),
                            ULInt16("total_reserved_blocks"),
                            Array(820, ULInt16("reserved_block_pool_map")),
                            Array(282, ULInt8("bad_block_table")),
                            Array(4, ULInt16("vfl_context_block")),
                            ULInt16("remapping_schedule_start"),
                            Array(0x48, ULInt8("unk3")),
                            ULInt32("version"),
                            ULInt32("checksum1"),
                            ULInt32("checksum2")
)

_vfl_vsvfl_spare_data = Struct("_vfl_vsvfl_spare_data",
                               Union("foo",
                                     Struct("user",ULInt32("logicalPageNumber"),ULInt32("usn")),
                                     Struct("meta",ULInt32("usnDec"),ULInt16("idx"), ULInt8("field_6"), ULInt8("field_7"))
                                     ),
                               ULInt8("type2"),
                               ULInt8("type1"),
                               ULInt8("eccMark"),
                               ULInt8("field_B"), 
)

def vfl_checksum(data):
    x = 0
    y = 0
    for z in array("I", data):
        x = (x + z) & 0xffffffff
        y = (y ^ z) & 0xffffffff
    return (x + 0xAABBCCDD) & 0xffffffff, (y ^ 0xAABBCCDD) & 0xffffffff

def vfl_check_checksum(ctx, ctxtype):
    c1, c2 = vfl_checksum(ctxtype.build(ctx)[:-8])
    return c1 == ctx.checksum1 and c2 == ctx.checksum2 

class VFL(object):
    def __init__(self, nand):
        self.nand = nand
        #XXX check
        self.banks_total = nand.nCEs * nand.banks_per_ce_physical
        self.num_ce = nand.nCEs
        self.banks_per_ce = nand.banks_per_ce_physical
        self.blocks_per_ce = nand.blocksPerCE
        self.pages_per_block = nand.pagesPerBlock
        self.pages_per_block_2 = next_power_of_two(self.pages_per_block)
        self.pages_per_sublk = self.pages_per_block * self.banks_per_ce * self.num_ce
        self.blocks_per_bank = self.blocks_per_ce / self.banks_per_ce
        self.blocks_per_bank_vfl = self.blocks_per_ce / self.banks_per_ce
        self.vendorType = nand.vendorType
        self.fs_start_block = 5
        
        #field_4 = 5;
        if not SupportedDevices.has_key(nand.deviceReadId):
            raise Exception("VFL: unsupported device 0x%x" % nand.deviceReadId)
        userSuBlksTotal  = self.userSuBlksTotal = SupportedDevices[nand.deviceReadId][8]#7744
        userPagesTotal = userSuBlksTotal * self.pages_per_sublk
        suBlksTotal = self.blocks_per_ce

        FTLData_field_2 = suBlksTotal - userSuBlksTotal - 28
        print suBlksTotal, userSuBlksTotal, FTLData_field_2
        FTLData_field_4 = FTLData_field_2 + 5
        self.FTLData_field_4 = FTLData_field_4
        #FTLData_sysSuBlks = FTLData_field_2 + 4
        #FTLData_field_6 = 3
        #FTLData_field_8 = 23
        
        self.vflContexts = []
        self.bbt = []
        self.current_version = 0
        self.context = None
        reserved_blocks = 0
        fs_start_block = reserved_blocks+10 #XXX
        for ce in xrange(self.num_ce):
            for b in xrange(reserved_blocks, fs_start_block):
                s, d = nand.readMetaPage(ce, b, 0, _vfl_vsvfl_spare_data)
                if not d:
                    continue
                vflctx = _vfl_vfl_context.parse(d)
                if not vfl_check_checksum(vflctx, _vfl_vfl_context):
                    vflctx = None
                    continue
                break
            MostRecentVFLCxtBlock = -1
            minUsn = 0xFFFFFFFF
            for b in vflctx.vfl_context_block:
                s, d = nand.readMetaPage(ce, b, 0, _vfl_vsvfl_spare_data)
                if not d:
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
                if not d:
                    break
                vflctx = _vfl_vfl_context.parse(d)
                if vfl_check_checksum(vflctx, _vfl_vfl_context):
                    last = vflctx
            if not last:
                raise Exception("VFL open FAIL 1")
            self.vflContexts.append(last)
            if last.version == 1 and last.usn_inc >= self.current_version:
                self.current_version = last.usn_inc
                self.context = last
        if not self.context:
            raise Exception("VFL open FAIL")

        print "VFL context open OK"

    def VFL_get_FTLCtrlBlock(self):
        for ctx in self.vflContexts:
            if ctx.usn_inc == self.current_version:
                return ctx.control_block
    
    def vfl_is_good_block(self, bbt, block):
        if block > self.blocks_per_ce:
            raise Exception("vfl_is_good_block block %d out of bounds" % block)
        index = block/8
        return ((bbt[index / 8] >> (7 - (index % 8))) & 0x1) == 0x1
    
    def virtual_block_to_physical_block(self, ce, pBlock):
        if self.vfl_is_good_block(self.vflContexts[ce].bad_block_table, pBlock):
            return pBlock
        ctx = self.vflContexts[ce]
        for pwDesPbn in xrange(0, ctx.num_reserved_blocks):
            if ctx.reserved_block_pool_map[pwDesPbn] == pBlock:
                if pwDesPbn > self.blocks_per_ce:
                    raise Exception("Destination physical block for remapping is greater than number of blocks per bank!")
                return ctx.reserved_block_pool_start + pwDesPbn
        print "Bad block %d not remapped" % pBlock
        return pBlock
    
    def virtual_page_number_to_virtual_address(self, vpn):
        vbank = vpn % self.num_ce
        vblock = vpn / self.pages_per_sublk
        vpage = (vpn / self.num_ce) % self.pages_per_block
        return vbank, vblock, vpage
        
    def read_single_page(self, vpn, key=None, lpn=None):
        vpn += self.pages_per_sublk * self.FTLData_field_4
        vbank, vblock, vpage = self.virtual_page_number_to_virtual_address(vpn)
        pblock = self.virtual_block_to_physical_block(vbank, vblock)
        #print "VFL read_single_page %d => %d, %d" % (vpn,ce,pPage)
        return self.nand.readPage(vbank, pblock*self.nand.pagesPerBlock + vpage, key, lpn)
