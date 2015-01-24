from carver import NANDCarver
from construct.core import Struct
from construct.macros import ULInt32, ULInt16, Array, ULInt8, Padding
from pprint import pprint
from structs import SpareData
from util import hexdump
from vfl import VFL
import plistlib

"""
openiboot/plat-s5l8900/ftl.c
openiboot/plat-s5l8900/includes/s5l8900/ftl.h
"""
FTLCxtLog = Struct("FTLCxtLog",
                   ULInt32("usn"),
                   ULInt16("wVbn"),
                   ULInt16("wLbn"),
                   ULInt32("wPageOffsets"),
                   ULInt16("pagesUsed"),
                   ULInt16("pagesCurrent"),
                   ULInt32("isSequential")
                   )

FTLCxtElement2 = Struct("FTLCxtElement2",
                        ULInt16("field_0"),
                        ULInt16("field_2")
                        )

FTLCxt = Struct("FTLCxt",
                ULInt32("usnDec"),
                ULInt32("nextblockusn"),
                ULInt16("wNumOfFreeVb"),
                ULInt16("nextFreeIdx"),
                ULInt16("swapCounter"),
                Array(20, ULInt16("awFreeVb")),
                ULInt16("field_36"),
                Array(18, ULInt32("pages_for_pawMapTable")),
                Array(36, ULInt32("pages_for_pawEraseCounterTable")),
                Array(34, ULInt32("pages_for_wPageOffsets")),
                ULInt32("pawMapTable"),
                ULInt32("pawEraseCounterTable"),
                ULInt32("wPageOffsets"),
                Array(18, FTLCxtLog),
                ULInt32("eraseCounterPagesDirty"),
                ULInt16("unk3"),
                Array(3, ULInt16("FTLCtrlBlock")),
                ULInt32("FTLCtrlPage"),
                ULInt32("clean"),
                Array(36, ULInt32("pages_for_pawReadCounterTable")),
                ULInt32("pawReadCounterTable"),
                Array(5, FTLCxtElement2),
                ULInt32("field_3C8"),
                ULInt32("totalReadCount"),
                ULInt32("page_for_FTLCountsTable"),
                ULInt32("hasFTLCountsTable"),
                Padding(0x420), #, ULInt8("field_3D8")),
                ULInt32("versionLower"),
                ULInt32("versionUpper")
                )

FTL_CTX_TYPE = 0x43
FTL_BLOCK_MAP = 0x44
FTL_ERASE_COUNTER = 0x46
FTL_MOUNTED = 0x47
FTL_CTX_TYPE_MAX = 0x4F
USER_TYPE = 0x40
USER_LAST_TYPE = 0x41   #last user page in superblock?

class FTL(object):
    def __init__(self, nand, vfl):
        self.nand = nand
        self.vfl = vfl
        self.pawMapTable = {}   #maps logical blocks to virtual blocks
        self.pLogs = {}
        if not self.FTL_open():
            self.FTL_restore()
            
    def FTL_open(self):
        minUsnDec = 0xffffffff
        ftlCtrlBlock = 0xffff
        for vb in self.vfl.VFL_get_FTLCtrlBlock():
            s, d = self.vfl.read_single_page(vb * self.vfl.pages_per_sublk)
            if not s:
                continue
            if s.type >= FTL_CTX_TYPE and s.type <= FTL_CTX_TYPE_MAX:
                if s.usn < minUsnDec:
                    ftlCtrlBlock = vb
                    minUsnDec = s.usn
        
        print     ftlCtrlBlock
        self.ftlCtrlBlock = ftlCtrlBlock
        for p in xrange(self.vfl.pages_per_sublk-1,1, -1):
            s, d = self.vfl.read_single_page(ftlCtrlBlock * self.vfl.pages_per_sublk + p)
            if not s:
                continue
            #print s
            #print p
            if s.type == FTL_CTX_TYPE:
                print s.usn
                ctx =  FTLCxt.parse(d)
                if ctx.versionLower == 0x46560001:
                    print ctx
                    assert ctx.FTLCtrlPage == (ftlCtrlBlock * self.vfl.pages_per_sublk + p)
                    break
            else:
                print "Unclean shutdown, last type 0x%x" % s.type
                return False
        self.ctx = ctx
        print "FTL_open OK !"
        return True

    def determine_block_type(self, block):
        maxUSN = 0
        isSequential = True
        for page in xrange(self.vfl.pages_per_sublk-1,1, -1):
            s, _ = self.vfl.read_single_page(block * self.vfl.pages_per_sublk + page)
            if not s:
                continue
            if s.usn > maxUSN:
                maxUSN = s.usn
            if s.lpn % self.vfl.pages_per_sublk != page:
                isSequential = False
                return isSequential, maxUSN 
        return isSequential, maxUSN

    def FTL_restore(self):
        self.pLogs = self.vfl.nand.loadCachedData("pLogs")
        self.pawMapTable = self.vfl.nand.loadCachedData("pawMapTable")
        if self.pLogs and self.pawMapTable:
            print "Found cached FTL restore information"
            return
        self.pawMapTable = {}
        self.pLogs = {}
        ctx = None
        for p in xrange(self.vfl.pages_per_sublk-1,1, -1):
            s, d = self.vfl.read_single_page(self.ftlCtrlBlock * self.vfl.pages_per_sublk + p)
            if not s:
                continue
            if s.type == FTL_CTX_TYPE:
                print s.usn
                ctx =  FTLCxt.parse(d)
                if ctx.versionLower == 0x46560001:
                    print ctx
                    assert ctx.FTLCtrlPage == (self.ftlCtrlBlock * self.vfl.pages_per_sublk + p)
                    print "Found most recent ctx"
                    break
        if not ctx:
            print "FTL_restore fail did not find ctx"
            raise
        blockMap = {}
        self.nonSequential = {}
        print "FTL_restore in progress ..."
        for sblock in xrange(self.vfl.userSuBlksTotal + 23):
            for page in xrange(self.vfl.pages_per_sublk):
                s, d = self.vfl.read_single_page(sblock * self.vfl.pages_per_sublk + page)
                if not s:
                    continue
                if s.type >= FTL_CTX_TYPE and s.type <= FTL_CTX_TYPE_MAX:
                    break
                if s.type != USER_TYPE and s.type != USER_LAST_TYPE:
                    print "Weird page type %x at %x %x" % (s.type, sblock, page)
                    continue
                if s.lpn % self.vfl.pages_per_sublk != page:
                    print "Block %d non sequential" % sblock
                    self.nonSequential[sblock] = 1
                blockMap[sblock] = (s.lpn / self.vfl.pages_per_sublk, s.usn)
                break
        
        z = dict([(i, [(a, blockMap[a][1]) for a in blockMap.keys() if blockMap[a][0] ==i]) for i in xrange(self.vfl.userSuBlksTotal)])
        for k,v in z.items():
            if len(v) == 2:
                print k, v
                vbA, usnA = v[0]
                vbB, usnB = v[1]
                if usnA > usnB: #smallest USN is map block, highest log block
                    self.pawMapTable[k] = vbB
                    self.restoreLogBlock(k, vbA)
                else:
                    self.pawMapTable[k] = vbA
                    self.restoreLogBlock(k, vbB)
            elif len(v) > 2:
                raise Exception("fufu", k, v)
            else:
                self.pawMapTable[k] = v[0][0]
        self.vfl.nand.cacheData("pLogs", self.pLogs)
        self.vfl.nand.cacheData("pawMapTable", self.pawMapTable)
        
    def restoreLogBlock(self, lbn, vbn):
        log = {"wVbn": vbn, "wPageOffsets": {}}
        for page in xrange(self.vfl.pages_per_sublk):
            s, d = self.vfl.read_single_page(vbn * self.vfl.pages_per_sublk + page)
            if not s:
                break
            log["wPageOffsets"][s.lpn % self.vfl.pages_per_sublk] = page
        self.pLogs[lbn] = log
    
    def mapPage(self, lbn, offset):
        if self.pLogs.has_key(lbn):
            if self.pLogs[lbn]["wPageOffsets"].has_key(offset):
                offset = self.pLogs[lbn]["wPageOffsets"][offset]
                #print "mapPage got log %d %d" % (lbn, offset)
                return self.pLogs[lbn]["wVbn"] * self.vfl.pages_per_sublk + offset
        if not self.pawMapTable.has_key(lbn):
            return 0xFFFFFFFF
        return self.pawMapTable[lbn]  * self.vfl.pages_per_sublk + offset

    def readLPN(self, lpn, key=None):
        lbn = lpn / self.vfl.pages_per_sublk
        offset = lpn % self.vfl.pages_per_sublk
        vpn = self.mapPage(lbn, offset)
        if vpn == 0xFFFFFFFF:
            print "lbn not found %d" % lbn
            return "\xFF" * self.nand.pageSize
        s,d = self.vfl.read_single_page(vpn, key, lpn)
        if not s:
            return None
        if s.lpn != lpn:
            raise Exception("FTL translation FAIL spare lpn=%d vs expected %d" % (s.lpn, lpn))
        return d

