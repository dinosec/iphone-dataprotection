from array import array
from construct.core import Struct, Union
from construct.macros import *
from progressbar import ProgressBar
from structs import *
import struct


#https://github.com/iDroid-Project/openiBoot/blob/master/openiboot/ftl-yaftl/yaftl.c
YAFTL_CXT = Struct("YAFTL_CXT",
    String("version", 4),
    ULInt32("unknCalculatedValue0"),
    ULInt32("totalPages"),
    ULInt32("latestUserBlock"),
    ULInt32("cxt_unkn0_usn"),
    ULInt32("latestIndexBlock"),
    ULInt32("maxIndexUsn"),
    ULInt32("blockStatsField4"),
    ULInt32("blockStatsField10"),
    ULInt32("numAllocatedBlocks"),
    ULInt32("numIAllocatedBlocks"),
    ULInt32("unk184_0xA"),
    Array(10, ULInt32("cxt_unkn1")),
    ULInt32("field_58"),
    ULInt16("tocArrayLength"),
    ULInt16("tocPagesPerBlock"),
    ULInt16("tocEntriesPerPage"),
    ULInt16("unkn_0x2A"),
    ULInt16("userPagesPerBlock"),
    ULInt16("unk64"),
    Array(11, ULInt32("cxt_unkn2")),
    ULInt8("unk188_0x63"),
)

TOCStruct = Struct("TOCStruct",
    ULInt32("indexPage"),
    ULInt16("cacheNum"),
    ULInt16("TOCUnkMember2"),
)

BlockStats = Struct("BlockStats",
    ULInt32("numAllocated"),
    ULInt32("field_4"),
    ULInt32("numValidDPages"),
    ULInt32("numIAllocated"),
    ULInt32("field_10"),
    ULInt32("numValidIPages"),
    ULInt32("numFree"),
    ULInt32("field_1C"),
)


class YAFTL(object):
    def __init__(self, vfl, usn=0):
        self.vfl = vfl
        self.lpnToVpn = None
        bytesPerPage = vfl.nand.pageSize
        numBlocks = vfl.context.usable_blocks_per_bank
        self.blankPage = bytesPerPage * "\x00"
        self.numBlocks = numBlocks
        self.tocPagesPerBlock = vfl.pages_per_sublk * 4 / bytesPerPage
        if vfl.pages_per_sublk * 4 % bytesPerPage:
            self.tocPagesPerBlock += 1
        self.tocEntriesPerPage = bytesPerPage / 4
        self.tocArrayLength = CEIL_DIVIDE(vfl.pages_per_sublk * numBlocks * 4, bytesPerPage)
        self.nPagesTocPageIndices = CEIL_DIVIDE(self.tocArrayLength * 4, bytesPerPage)
        self.nPagesBlockStatuses = CEIL_DIVIDE(numBlocks * 1, bytesPerPage)
        self.nPagesBlockReadCounts = CEIL_DIVIDE(numBlocks * 2, bytesPerPage)
        self.nPagesBlockEraseCounts = CEIL_DIVIDE(numBlocks * 4, bytesPerPage)
        self.nPagesBlockValidPagesDNumbers = self.nPagesBlockReadCounts
        self.nPagesBlockValidPagesINumbers = self.nPagesBlockReadCounts
        self.ctrlBlockPageOffset = self.nPagesTocPageIndices \
                                + self.nPagesBlockStatuses \
                                + self.nPagesBlockReadCounts \
                                + self.nPagesBlockEraseCounts \
                                + self.nPagesBlockValidPagesDNumbers \
                                + self.nPagesBlockValidPagesINumbers \
                                + 2 * self.tocPagesPerBlock \
                                + 2
        self.totalPages = (self.numBlocks - 8) * (self.vfl.pages_per_sublk - self.tocPagesPerBlock)# - unknCalculatedValue0
        self.userPagesPerBlock = self.vfl.pages_per_sublk - self.tocPagesPerBlock
        maxUsn = 0
        ftlCtrlBlock = -1
        for b in self.vfl.VFL_get_FTLCtrlBlock():
            s,d = self.YAFTL_readPage(b * self.vfl.pages_per_sublk)
            if not d:
                continue
            if usn and s.usn > usn:
                break
            if s.usn > maxUsn:
                maxUsn = s.usn
                ftlCtrlBlock = b
        if ftlCtrlBlock == -1 or not maxUsn:
            print "ftlCtrlBlock not found, restore needed"
            self.YAFTL_restore()
            return
        i = 0
        maxUsn = 0
        while i < self.vfl.pages_per_sublk - self.ctrlBlockPageOffset:
            s,d = self.YAFTL_readPage(ftlCtrlBlock*self.vfl.pages_per_sublk + i + self.ctrlBlockPageOffset)
            if not d:
                if self.YAFTL_readCxtInfo(ftlCtrlBlock*self.vfl.pages_per_sublk + i):
                    return
                print "YaFTL_readCxtInfo FAIL, restore needed maxUsn=%d" % maxUsn
                self.YAFTL_restore()
                return
            if s and s.usn > maxUsn:
                maxUsn = s.usn
            i += self.ctrlBlockPageOffset + 1
        print "YaFTL open fail"
        self.YAFTL_restore()
        
    def readBTOCPages(self, block, maxVal):
        data = ""
        for i in xrange(self.tocPagesPerBlock):
            s,d = self.YAFTL_readPage((block+1) * self.vfl.pages_per_sublk - self.tocPagesPerBlock + i)
            if not s:
                return None
            data += d
        btoc = array("I",data)
        for i in xrange(len(btoc)):
            if btoc[i] > maxVal:
                btoc[i] = 0xFFFFFFFF
        return btoc
               
    def YAFTL_restore(self):
        self.lpnToVpn = self.vfl.nand.loadCachedData("yaftlrestore")
        if self.lpnToVpn:
            print "Found cached FTL restore information"
            return
        userBlocks = {}
        indexBlocks = {}
        print "FTL restore in progress"
        pbar = ProgressBar(self.numBlocks)
        pbar.start()
        for b in xrange(0, self.numBlocks):
            pbar.update(b)
            #read fist page in block, if empty then block is empty
            s,d = self.YAFTL_readPage(b * self.vfl.pages_per_sublk + 0)
            if not s:
                continue
            if s.type == PAGETYPE_INDEX:
                indexBlocks[s.usn] = b
            elif s.type == PAGETYPE_LBN:
                if userBlocks.has_key(s.usn):
                    print "Two blocks with same USN, something is weird"
                userBlocks[s.usn] = b
            elif s.type == PAGETYPE_FTL_CLEAN:
                pass
        pbar.finish()
        lpnToVpn = {}
        for usn in sorted(userBlocks.keys(), reverse=True):
            b = userBlocks[usn]
            btoc = self.readBTOCPages(b, self.totalPages)
            if btoc:
                for i in xrange(self.userPagesPerBlock-1,-1, -1):
                    if not lpnToVpn.has_key(btoc[i]):
                        lpnToVpn[btoc[i]] = b * self.vfl.pages_per_sublk + i
            else:
                print "BTOC not found for block %d (usn %d), scanning all pages" % (b, usn)
                i = 0
                for p in xrange(self.vfl.pages_per_sublk - self.tocPagesPerBlock -1, -1, -1):
                    s,d = self.YAFTL_readPage(b * self.vfl.pages_per_sublk + p)
                    if s:
                        i+= 1
                    if s and not lpnToVpn.has_key(s.lpn):
                        lpnToVpn[s.lpn] = b * self.vfl.pages_per_sublk + p
                print "%d used pages in block" % i
        self.vfl.nand.cacheData("yaftlrestore", lpnToVpn)
        self.lpnToVpn = lpnToVpn
        return lpnToVpn
            
    def YAFTL_readCxtInfo(self, page):
        s,d = self.YAFTL_readPage(page)
        if not s or s.type != PAGETYPE_FTL_CLEAN:
            return False
        ctx = YAFTL_CXT.parse(d)
        ctx.spareUsn = s.usn
        if ctx.version != "CX01":
            print "Wrong FTL version %s" % ctx.version
            return False
        self.usn = s.usn
        pageToRead = page + 1;
        userTOCBuffer = self.YAFTL_read_n_Page(pageToRead, self.tocPagesPerBlock)
        if not userTOCBuffer:
            raise(Exception("userTOCBuffer"))
        pageToRead += self.tocPagesPerBlock
        indexTOCBuffer = self.YAFTL_read_n_Page(pageToRead, self.tocPagesPerBlock)
        pageToRead += self.tocPagesPerBlock + 1
        tocArrayIndexPages = self.YAFTL_read_n_Page(pageToRead, self.nPagesTocPageIndices)
        self.tocArrayIndexPages = array("I", tocArrayIndexPages)
        assert self.tocArrayIndexPages.itemsize == 4
        self.indexCache = {}
        pageToRead += self.nPagesTocPageIndices
        
        if False: #we don't care, we just want to read
            blockStatuses = self.YAFTL_read_n_Page(pageToRead, self.nPagesBlockStatuses)
            pageToRead += self.nPagesBlockStatuses
            blockReadCounts = self.YAFTL_read_n_Page(pageToRead, self.nPagesBlockReadCounts)
            pageToRead += self.nPagesBlockReadCounts
            blockEraseCounts = self.YAFTL_read_n_Page(pageToRead, self.nPagesBlockEraseCounts)
            pageToRead += self.nPagesBlockEraseCounts
            validPagesINo = self.YAFTL_read_n_Page(pageToRead, self.nPagesBlockValidPagesINumbers)
            pageToRead += self.nPagesBlockValidPagesINumbers
            validPagesDNo = self.YAFTL_read_n_Page(pageToRead, self.nPagesBlockValidPagesDNumbers)
        
        print "YaFTL context OK, version=%s maxIndexUsn=%d context usn=%d" % (ctx.version, ctx.maxIndexUsn, self.usn)
        return True

    def YAFTL_read_n_Page(self, page, n, failIfBlank=False):
        r = ""
        for i in xrange(0, n):
            s,d = self.YAFTL_readPage(page +i)
            if not d:
                if failIfBlank:
                    return
                return r
            r += d
        return r
    
    def YAFTL_readPage(self, page, key=META_KEY, lpn=None):
        return self.vfl.read_single_page(page, key, lpn)
    
    def build_lpn_to_vpn(self):
        lpnToVpn = {}
        for p in xrange(self.totalPages):
            x = self.translateLPNtoVPN(p)
            if x != 0xFFFFFFFF:
                lpnToVpn[p] = x
        self.vfl.nand.cacheData("currentftl", lpnToVpn)
        return lpnToVpn
        
    def translateLPNtoVPN(self, lpn):
        if self.lpnToVpn:
            return self.lpnToVpn.get(lpn, 0xFFFFFFFF)
        tocPageNum = (lpn) / self.tocEntriesPerPage
        indexPage = self.tocArrayIndexPages[tocPageNum]
        if indexPage == 0xffffffff:
            return 0xffffffff
        #print "indexPage %x" % indexPage
        if self.indexCache.has_key(indexPage):
            tocPageBuffer = self.indexCache[indexPage]
        else:
            s,tocPageBuffer = self.YAFTL_readPage(indexPage)
            if not tocPageBuffer:
                print "tocPageBuffer fail"
                return 0xffffffff
            assert s.type == PAGETYPE_INDEX
            tocPageBuffer = array("I", tocPageBuffer)
            self.indexCache[indexPage] = tocPageBuffer
        
        tocEntry = tocPageBuffer[lpn % self.tocEntriesPerPage]
        return tocEntry

    def readLPN(self, lpn, key=None):#, nPages):
        vpn = self.translateLPNtoVPN(lpn)
        if vpn == 0xffffffff:
            return self.blankPage
        #print "tocEntry %d" % tocEntry
        #print "FTL %d => %d" % (lpn, vpn)
        s,d = self.YAFTL_readPage(vpn, key, lpn)
        if d == None:
            return self.blankPage
        if s.lpn != lpn:
            raise Exception("YAFTL translation FAIL spare lpn=%d vs expected %d" % (s.lpn, lpn))
        return d

    def YAFTL_lookup1(self):
        hax = self.vfl.nand.loadCachedData("YAFTL_lookup1")
        if hax:
            print "Found cached FTL lookup table"
            return hax
        userBlocks = {}
        indexBlocks = {}
        print "Building FTL lookup table v1"
        pbar = ProgressBar(self.numBlocks)
        pbar.start()
        for b in xrange(0, self.numBlocks):
            pbar.update(b)
            #read fist page in block, if empty then block is empty
            s,d = self.YAFTL_readPage(b * self.vfl.pages_per_sublk + 0)
            if not s:
                continue
            if s.type == PAGETYPE_INDEX:
                indexBlocks[s.usn] = b
            elif s.type == PAGETYPE_LBN:
                if userBlocks.has_key(s.usn):
                    print "Two blocks with same USN, something is weird"
                userBlocks[s.usn] = b
            elif s.type == PAGETYPE_FTL_CLEAN:
                pass#print b, "ftl block"
        pbar.finish()
        lpnToVpn = {}
        for usn in sorted(userBlocks.keys(), reverse=False):
            b = userBlocks[usn]
            btoc = self.readBTOCPages(b, self.totalPages)
            #print usn, b
            if btoc:
                for i in xrange(self.userPagesPerBlock-1,-1, -1):
                        lpnToVpn.setdefault(btoc[i], []).append(b * self.vfl.pages_per_sublk + i)
            else:
                #print "btoc not found for block %d (usn %d), scanning all pages" % (b, usn)
                i = 0
                usn = -1
                for p in xrange(self.vfl.pages_per_sublk - self.tocPagesPerBlock -1, -1, -1):
                    s,d = self.YAFTL_readPage(b * self.vfl.pages_per_sublk + p)
                    if not s:
                        break
                    i+= 1
                    if usn == -1:
                        usn = s.usn
                    if usn != s.usn:
                        #print "Two usns in same block %d %d" % (usn, s.usn)
                        usn = s.usn
                    lpnToVpn.setdefault(s.lpn, []).append(b * self.vfl.pages_per_sublk + p)
                #print "%d used pages in block" % i
        #self.vfl.nand.cacheData("YAFTL_lookup1", (lpnToVpn, userBlocks))
        return lpnToVpn, userBlocks

    def YAFTL_hax2(self):
        hax = self.vfl.nand.loadCachedData("YAFTL_hax2")
        if hax:
            print "Found cached FTL HAX2 information"
            return hax

        print "FTL hax2 in progress"
        pbar = ProgressBar(self.numBlocks)
        pbar.start()
        lpnToVpn = {}
        for b in xrange(0, self.numBlocks):
            pbar.update(b)
            #read fist page in block, if empty then block is empty (right?)
            s,d = self.YAFTL_readPage(b * self.vfl.pages_per_sublk + 0)
            if not s:
                continue
            if s.type == PAGETYPE_LBN:
                i = 0
                usn = -1
                for p in xrange(0, self.vfl.pages_per_sublk - self.tocPagesPerBlock):
                    s,d = self.YAFTL_readPage(b * self.vfl.pages_per_sublk + p)
                    if not s:
                        break
                    lpnToVpn.setdefault(s.lpn, {}).setdefault(s.usn, []).append(b * self.vfl.pages_per_sublk + p)
                    i+= 1

        pbar.finish()
        self.vfl.nand.cacheData("YAFTL_hax2", lpnToVpn)
        return lpnToVpn

    def block_lpn_to_vpn(self, block):
        res = {}
        for p in xrange(0, self.vfl.pages_per_sublk - self.tocPagesPerBlock):
            s,d = self.YAFTL_readPage(block * self.vfl.pages_per_sublk + p)
            if not s:
                break
            res[s.lpn] = block * self.vfl.pages_per_sublk + p
        return res
