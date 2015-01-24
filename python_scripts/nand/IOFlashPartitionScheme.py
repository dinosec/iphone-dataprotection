import struct

#from http://en.wikipedia.org/wiki/Fletcher's_checksum
def fletcher16(data):
    sum1 = 0xff
    sum2 = 0xff
    _bytes = len(data)
    i = 0

    while (_bytes):
        if _bytes > 20: tlen = 20
        else: tlen = _bytes
        _bytes -= tlen
        for _ in xrange(tlen):
            sum1 += ord(data[i])
            sum2 += sum1
            i += 1
        sum1 = (sum1 & 0xff) + (sum1 >> 8)
        sum2 = (sum2 & 0xff) + (sum2 >> 8)
    #/* Second reduction step to reduce sums to 8 bits */
    sum1 = (sum1 & 0xff) + (sum1 >> 8)
    sum2 = (sum2 & 0xff) + (sum2 >> 8)
    return sum2 << 8 | sum1;

"""
ndrG 
0x4 should_be_zero ;)
0x8 versionMajor
0xC versionMinor = 6 (ios4/5) 9 (ios6)
0x10 generation
0x14 checksumXXX
0x20 factoryBBT[0x1E0] : last_block num_bad + [59* 8 bytes entries]
0x200 ???
0x220
0x224 0xDEADCAFE => cemetary
0x250 spares
0x35c subs
0x400 partition table
0x600 end

boot
2*0x600 ptab
LLB

---
partition table Diff
stored in slack space in nvrm (todo) & plog (closing pages)
ffiD
uint16_t size
uint16_t sequence
uint32_t major  (must match ptable)
uint32_t minor  (must match ptable)
uint32_t generation (must match ptable)
0x20 => up-to-date cemetary

spare
0x40 | (part_idx & 0xF) | 0x0 
"""

kIOFlashPartitionSchemeFakePart = 1 #set for scfg, fbbt, diag that arent managed ?
kIOFlashPartitionSchemeIsSclice     = 2 #wut, new in ios6?
kIOFlashPartitionSchemeIsPool     = 8 #wut, new in ios6?
kIOFlashPartitionSchemeUseSLCBlocks  = 0x100 #sometimes set for plog/nvrm, only if ppn-device
kIOFlashPartitionSchemeUseFullPages  = 0x200 #sometimes set for firm


#TODO: handle partition table Diff
class IOFlashPartitionScheme(object):
    def __init__(self, nand, data):
        self.nand = nand
        self.pagesPerBlock = nand.pagesPerBlock
        self.nCEs = nand.nCEs
        self.cemetary = []
        self.spares = []
        self.subs = []
        self.parts = {}
        self.parts_names = []

        self.validatePartitionTable(data)
        if not self.initCemetery(data[0x224:0x224+42+2]):
            raise Exception("Cemetery is haunted :)")
        self.initSpares(data[0x250:0x35C])
        self.initSubs(data[0x35C:0x400])

        blk_offset = 0
        for idx in xrange(0x400,0x600,0x10):
            name = data[idx:idx+4][::-1]
            if name == "none":
                continue
            a,b,flags = struct.unpack("<LLL", data[idx+4:idx+16])
            if flags & kIOFlashPartitionSchemeIsPool:
                b = (a*b) / self.nCEs
                a = blk_offset
            self.parts[name] = a,b,flags
            blk_offset += b
            self.parts_names.append(name)

    def show(self):
        print "".join(map(lambda x:x.ljust(12), ["Name", "Start block", "Size", "Flags"]))
        for name in self.parts_names:
            start, size, flags = self.parts[name]
            print "".join(map(lambda x:str(x).ljust(12), [name, start, size, "0x%x" % flags]))

    def probe(self, data):
        return False

    def validatePartitionTable(self, data):
        if data[:4] != "ndrG":
            return False
        major = struct.unpack(">L", data[8:12])[0]
        return major == 0

    def initCemetery(self, data):
        gate = struct.unpack("<L", data[0:4])[0]
        if gate != 0xdeadcafe:
            print "Bad cemetery gate %x" % gate
            return False
        guards = struct.unpack("<H", data[42:44])[0]
        if guards != fletcher16(data[:42]):
            print "Bad cemetery guards %x" % guards
            return False
        self.cemetary = map(ord, data[10:42])
        return True

    def initSpares(self, data):
        if data[:4] != "rAps":
            print "Bad spares magic"
            return
        x = fletcher16(data[:0x10A])
        guards = struct.unpack("<H", data[0x10A:0x10C])[0]
        if x != guards:
            print "Bad spares checksum"
            return
        n_spares = struct.unpack("<H", data[4:6])[0]
        assert n_spares < 64
        idx =  10
        for idx in xrange(10, 10+ n_spares*4, 4):
            block = struct.unpack("<L", data[idx:idx+3] + "\x00")[0]
            ce = ord(data[idx+3:idx+4])
            self.spares.append((ce,block))

    def initSubs(self, data):
        if data[:4] != "sbus":
            print "Bad subs magic"
            return
        n_subs = struct.unpack("<H", data[4:6])[0]
        assert n_subs < 64
        self.subs = map(ord, data[10:10+n_subs])

    def isMappedPartition(self, idx):
        n = self.parts_names[idx]
        return n in ["plog","nvrm","firm"]

    def is_bad_vblock(self, vblock):
        x = self.cemetary[vblock / 8]
        return (x & (1 << (vblock % 8))) != 0

    def remap_block(self, ce, block):
        vblock = block * self.nCEs + ce
        try:
            sub = self.subs.index(vblock)
            ce, block = self.spares[sub]
        except:
            pass
        return ce, block, vblock

    def readPartitionBlock(self, name, ce, block):
        if not name in ["boot", "plog","nvrm","firm"]:
            return
        start, end, flags = self.parts[name]
        partition_idx = self.parts_names.index(name)
        block += start

        vblock = block * self.nCEs + ce
        if self.is_bad_vblock(vblock):
            assert vblock in self.subs
            sub = self.subs.index(vblock)
            ce, block = self.spares[sub]
            print "Reading remapped bootloader block %s %d => %d:%d !" % (name, vblock, ce,block)
        elif flags & kIOFlashPartitionSchemeIsPool:
            #print "Partition %s has pool flag, remapping" % name
            sub = self.subs.index(vblock)
            #print "sub ce=%d block=%d vblock=%d sub=%d" % (ce, block, vblock, sub)
            ce, block = self.spares[sub]
            #print "=> ce=%d block=%d" % (ce,block)

        pagesPerBlock = self.pagesPerBlock
        if flags & kIOFlashPartitionSchemeUseSLCBlocks:
            pagesPerBlock = self.nand.slc_pages
            page_bits = self.nand.page_bits
            bits = self.nand.block_bits + self.nand.cau_bits + page_bits
        #print name, block,self.pagesPerBlock, "%x"  %flags
        res = ""
        for i in xrange(pagesPerBlock):
            if flags & kIOFlashPartitionSchemeUseSLCBlocks:
                pageaddr = i | block << page_bits | 1 << bits
            else:
                pageaddr = block*self.pagesPerBlock + i

            if flags & kIOFlashPartitionSchemeUseFullPages: #!!!
                spare, data = self.nand.readPage(ce, pageaddr, spareType=None)
                if spare and ord(spare[0]) ==  0x40 | (partition_idx & 0xF):
                    res += data
                elif spare:
                    print "skipping weird page at %d %d %x" % (block, i, ord(spare[0]))
            else:
                res += self.nand.readBootPage(ce, pageaddr)
        return res

    def readPartition(self, name):
        if not name in ["boot", "plog","nvrm","firm"]:
            return
        start, end, flags = self.parts[name]
        res = ""
        for b in xrange(end):
            res += self.readPartitionBlock(name, 0, b)
        return res

