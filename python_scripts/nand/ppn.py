"""
PPNFTL used on newer devices (A5/A6 + iphone 4 rev A)

Weave sequence counter for non-volatile memory systems
http://www.google.com/patents/WO2013040537A1?cl=en
"""

import plistlib
import sqlite3
import struct

from construct import Array
from construct.core import Struct
from construct.macros import ULInt32, String, ULInt8, ULInt16

from crypto.aes import AESdecryptCBC
from util import hexdump

WHIMORY_SIGNATURE_MAGIC = "xrmw"

WHIMORY_SIGNATURE_VER_PPN_CUR = 7

PPNSignature = Struct("PPNSignature",
                      String("magic", 4),
                      ULInt32("f4"),
                      ULInt32("whimory_ver_at_birth"),
                      ULInt32("ftl_major_version"),
                      ULInt32("ftl_minor_version"),
                      ULInt32("xxx"),
                      ULInt32("vfl_major_version"),
                      ULInt32("vfl_minor_version"),
                      ULInt32("f20"),
                      ULInt32("FPart_major"),
                      ULInt32("f22"),
                      ULInt32("f23"),
                      ULInt32("f24"),
                      ULInt32("geometry_num_ce"),
                      )

PPNVFLSpare = Struct("PPNVFLSpare",
                     ULInt8("type"),
                     ULInt8("bank"),
                     ULInt16("index"),
                     ULInt32("ctx_age"),
                     ULInt32("xx"),
                     ULInt32("yy"),
                     )
PPNSpareData = Struct("PPNSpareData",
                    ULInt8("type"),
                    ULInt8("bank"),
                   ULInt32("weaveSeq"),#weaveSeq?
                   ULInt16("unk1"),
                   ULInt32("lpn"),
                   ULInt32("unk2"),
)

PPN_PAGETYPE_DATA = 0x1 #CTX_DIFF?
PPN_PAGETYPE_VFL = 0x20
PPN_PAGETYPE_SFTL_CTX = 0x1F

#S_SB_DATA_CUR = 0,1,2
#S_SB_DATA_GC = 0,1,2
#S_SB_DATA_PENDING_GC = 0,1,2
#S_SB_DATA = 6 ?
S_SB_CXT = 7

PPN_SPECIAL_BLOCK = 0x30

VFL_INDEX = 0xFFFF
WMRX_INDEX = 0xC101
IPCB_INDEX = 0xC104
SYSCFG_INDEX = 0xC105

"""
special blocks at the end of each CAU/bank
between blocks_per_cau-1 and (blocks_per_cau - 5/100 * blocks_per_cau)
"""
SFTL_CTX_SPAN = 4

def ivForPage(page):
    iv = ""
    for _ in xrange(4):
        if (page & 1):
            page = 0x80000061 ^ (page >> 1);
        else:
            page = page >> 1;
        iv += struct.pack("<L", page)
    return iv

#ppn "bruteforce FTL
class PPNFTL(object):
    def __init__(self, nand):
        self.nand = nand
        self.blankPage = self.nand.blankPage
        self.lpnDict = {}
        self.logicalPageSize = self.nand.logicalPageSize
        lbas_per_page = self.nand.pageSize / self.logicalPageSize
        print "PPNFTL: lbas_per_page=%d" % lbas_per_page
        self.spareType = Array(lbas_per_page, PPNSpareData)
        self.bruteforceFTL()

    def bruteforceFTL(self):
        assert self.nand.filename != "remote"

        self.conn = sqlite3.connect(self.nand.filename + ".db")
        self.conn.execute("CREATE TABLE IF NOT EXISTS lpn_to_phys (lpn INTEGER, weaveSeq INTEGER, ce INTEGER, block INTEGER, page INTEGER)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS lpn_idx on lpn_to_phys(lpn)")

        ok = self.conn.execute("SELECT count(*) from lpn_to_phys WHERE lpn=-1").fetchone()[0]
        print "Loading cached Logical->physical map"
        if ok:
            print "Logical->physical db found"
            return

        self.lpnToPhys = {}
        print "Creating logical->physical mapping..."
        for block in xrange(0, self.nand.blocksPerCE):
            for page in xrange(self.nand.pagesPerBlock):
                for ce in xrange(self.nand.nCEs):
                    sp, d = self.nand.readBlockPage(ce, block, page, spareType=self.spareType)
                    if sp and sp[0].type != 1 or not sp:
                        break
                    for s in sp:
                        self.conn.execute("INSERT INTO lpn_to_phys VALUES(?,?,?,?,?)", (s.lpn, s.weaveSeq, ce, block, page))

        self.conn.execute("INSERT INTO lpn_to_phys VALUES(-1,-1,-1,-1,-1)")
        self.conn.commit()

    def findAllVersions(self, lpn):
        return self.conn.execute("SELECT weaveSeq,ce,block,page from lpn_to_phys WHERE lpn=? AND weaveSeq ORDER BY weaveSeq DESC", (lpn,)).fetchall()

    def findPagesInRange(self, low, high):
        return self.conn.execute("SELECT weaveSeq,lpn,ce,block,page from lpn_to_phys WHERE weaveSeq >= ? AND weaveSeq < ? ORDER BY weaveSeq ASC", (low,high)).fetchall()

    def readPage1(self, addr, key, lpn):
        weave, ce, block, page = addr
        #ce, block, page = addr
        s,d = self.nand.readBlockPage(ce, block, page, None, lpn, spareType=self.spareType)

        for i in xrange(len(s)):
            if s[i].lpn == lpn:
                o = i * self.logicalPageSize
                data = d[o:o+self.logicalPageSize]
                if key:
                    data = AESdecryptCBC(data, key, ivForPage(lpn))
                    return data
                return data
        raise Exception("FAIL")

    def readLPN(self, lpn, key=None):
        z = self.conn.execute("SELECT ce,block,page,weaveSeq from lpn_to_phys WHERE lpn=? ORDER BY weaveSeq DESC LIMIT 1", (lpn,)).fetchone()
        if z:
            #weave,ce,block,page = a[-1]
            ce,block,page,weaveSeq = z
        else:
            print "lpn %d => blank" % lpn
            return self.blankPage
        #print "lpn=%d weaveSeq=%d" % (lpn, weaveSeq)

        s,d = self.nand.readBlockPage(ce, block, page, None, lpn, spareType=self.spareType)

        for i in xrange(len(s)):
            if s[i].lpn == lpn:
                o = i * self.logicalPageSize
                data = d[o:o+self.logicalPageSize]
                if key:
                    data = AESdecryptCBC(data, key, ivForPage(lpn))
                return data
        raise Exception("readLPN %d failed" % lpn)

