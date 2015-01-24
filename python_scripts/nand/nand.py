from crypto.aes import AESdecryptCBC
from firmware.img2 import IMG2
from firmware.img3 import Img3, extract_img3s
from firmware.scfg import parse_SCFG
from hfs.emf import EMFVolume
from hfs.hfs import HFSVolume
from image import NANDImageSplitCEs, NANDImageFlat
from IOFlashPartitionScheme import IOFlashPartitionScheme
from keystore.effaceable import check_effaceable_header, EffaceableLockers
from legacyftl import FTL
from partition_tables import GPT_partitions, parse_lwvm, parse_mbr, parse_gpt, \
    APPLE_ENCRYPTED
from ppn import PPNFTL
from progressbar import ProgressBar
from remote import NANDRemote, IOFlashStorageKitClient
from structs import *
from util import sizeof_fmt, write_file, load_pickle, save_pickle, hexdump, \
    makedirs
from util.bdev import FTLBlockDevice
from vfl import VFL
from vsvfl import VSVFL
from yaftl import YAFTL
import math
import os
import plistlib
import struct

def ivForPage(page):
    iv = ""
    for _ in xrange(4):
        if (page & 1):
            page = 0x80000061 ^ (page >> 1);
        else:
            page = page >> 1;
        iv += struct.pack("<L", page)
    return iv

#iOS 3
def getEMFkeyFromCRPT(data, key89B):
    assert data.startswith("tprc")
    z = AESdecryptCBC(data[4:0x44], key89B)
    assert z.startswith("TPRC"), "wrong key89B"
    #last_byte = struct.unpack("<Q", z[4:4+8])[0]
    emf = z[16:16+32]
    return emf
           
class NAND(object):
    H2FMI_HASH_TABLE = gen_h2fmi_hash_table()
    
    def __init__(self, filename, device_infos):
        self.device_infos = device_infos
        self.partition_table = None
        self.lockers = None
        self.iosVersion = 0
        self.hasMBR = False
        self.metadata_whitening = False
        self.filename = filename
        self.encrypted = device_infos["hwModel"] not in ["M68AP", "N45AP", "N82AP", "N72AP"]
        self.initGeometry(device_infos["nand"])
        
        if os.path.basename(filename).startswith("ce_"):
            self.image = NANDImageSplitCEs(os.path.dirname(filename), device_infos["nand"])
        elif filename == "remote":
            self.image = NANDRemote(self.pageSize, self.metaSize, self.pagesPerBlock, self.bfn)
        else:
            self.image = NANDImageFlat(filename, device_infos["nand"])
        
        s, page0 = self.readPage(0,0, boot=True)
        self.nandonly = (page0 != None) and page0.startswith("ndrG")
        if self.nandonly:
            self.encrypted = True
            self.partition_scheme = IOFlashPartitionScheme(self, page0)

        magics = ["DEVICEINFOBBT"]
        nandsig = None
        if page0 and page0[8:14] == "Darwin":
            print "Found old style signature", page0[:8]
            nandsig = page0
        else:
            magics.append("NANDDRIVERSIGN")

        sp0 = {}
        #sp0 = self.readSpecialPages(0, magics)
        #print "Found %s special pages in CE 0" % (", ".join(sp0.keys()))
        if not self.nandonly:
            print "Device does not boot from NAND (=> has a NOR)"
        
        vfltype = '1'   #use VSVFL by default
        if not nandsig:
            nandsig = sp0.get("NANDDRIVERSIGN")
        if not nandsig:
            print "NANDDRIVERSIGN not found, assuming metadata withening = %d" % self.metadata_whitening
        else:
            nSig, flags = struct.unpack("<LL", nandsig[:8])
            #assert nandsig[3] == chr(0x43)
            vfltype = nandsig[1]
            self.metadata_whitening = (flags & 0x10000) != 0
            print "NAND signature 0x%x flags 0x%x withening=%d, epoch=%s" % (nSig, flags, self.metadata_whitening, nandsig[0])

        if self.device_infos.has_key("lockers"):
            self.lockers = EffaceableLockers(self.device_infos.lockers.data)
        if self.nandonly:
            unit = self.findLockersUnit()
            if unit:
                self.lockers = EffaceableLockers(unit[0x40:])
                self.lockers.display()
                self.device_infos.lockers = plistlib.Data(unit[0x40:0x40+960])
                if not self.device_infos.has_key("lockers") or not self.device_infos.has_key("EMF") or self.device_infos.EMF == "00"*32:
                    self.device_infos.lockers = plistlib.Data(unit[0x40:0x40+960])
                    EMF = self.getEMF(device_infos["key89B"].decode("hex"))
                    dkey = self.getDKey(device_infos["key835"].decode("hex"))
                    self.device_infos.EMF = EMF.encode("hex")
                    self.device_infos.DKey = dkey.encode("hex")

            deviceuniqueinfo = sp0.get("DEVICEUNIQUEINFO")
            if not deviceuniqueinfo:
                print "DEVICEUNIQUEINFO not found"
            else:
                scfg = parse_SCFG(deviceuniqueinfo)
                #print "Found DEVICEUNIQUEINFO, serial number=%s" % scfg.get("SrNm","SrNm not found !")

        if self.ppn:
            if filename != "remote":
                print "Using PPN FTL"
                self.ftl = PPNFTL(self)
        elif vfltype == '0':
            print "Using legacy VFL"
            self.vfl = VFL(self)
            self.ftl = FTL(self, self.vfl)
        else:
            print "Using VSVFL"
            self.vfl = VSVFL(self)
            self.ftl = YAFTL(self.vfl)

    def initGeometry(self, d):
        self.metaSize = d.get("meta-per-logical-page", 0)
        if self.metaSize == 0:
            self.metaSize = 12
        dumpedPageSize = d.get("dumpedPageSize", d["#page-bytes"] + self.metaSize + 8)
        self.dump_size=  d["#ce"] * d["#ce-blocks"] * d["#block-pages"] * dumpedPageSize
        self.totalPages = d["#ce"] * d["#ce-blocks"] * d["#block-pages"]
        nand_size = d["#ce"] * d["#ce-blocks"] * d["#block-pages"] * d["#page-bytes"]
        hsize = sizeof_fmt(nand_size)
        self.bfn = d.get("boot-from-nand", False)
        self.ppn = d.get("ppn-device", False)
        self.dumpedPageSize = dumpedPageSize
        self.pageSize = d["#page-bytes"]
        self.bootloaderBytes = d.get("#bootloader-bytes", 1536)
        self.logicalPageSize = d.get("logical-page-size", self.pageSize)
        self.emptyBootloaderPage = "\xFF" * self.bootloaderBytes
        self.blankPage = "\xFF" * self.pageSize
        self.nCEs =d["#ce"]
        self.blocksPerCE = d["#ce-blocks"]
        self.pagesPerBlock = d["#block-pages"]
        self.pagesPerCE = self.blocksPerCE * self.pagesPerBlock
        self.vendorType = d["vendor-type"]
        self.deviceReadId = d.get("device-readid", 0)
        self.banks_per_ce_vfl = d["banks-per-ce"]

        if self.ppn:
            self.slc_pages = d.get("slc-pages", 0)
            self.block_bits =  d.get("block-bits", 0)
            self.cau_bits = d.get("cau-bits", 0)
            self.page_bits = d.get("page-bits", 0)

        if d.has_key("metadata-whitening"):
            self.metadata_whitening = (d["metadata-whitening"].data == "\x01\x00\x00\x00")
        if nand_chip_info.has_key(self.deviceReadId):
            self.banks_per_ce_physical = nand_chip_info.get(self.deviceReadId)[7]
        elif self.ppn:
            self.banks_per_ce_physical = struct.unpack("<L", d["caus-ce"].data)[0]
        else:
            #raise Exception("Unknown deviceReadId %x" % self.deviceReadId)
            print "!!! Unknown deviceReadId %x, assuming 1 physical bank /CE, will probably fail" % self.deviceReadId
            self.banks_per_ce_physical = 1
        print "Chip id 0x%x banks per CE physical %d" % (self.deviceReadId, self.banks_per_ce_physical)
        self.blocks_per_bank = self.blocksPerCE / self.banks_per_ce_physical
        if self.blocksPerCE & (self.blocksPerCE-1) == 0:
            self.bank_address_space = self.blocks_per_bank
            self.total_block_space = self.blocksPerCE
        else:
            bank_address_space = next_power_of_two(self.blocks_per_bank)
            self.bank_address_space = bank_address_space
            self.total_block_space = ((self.banks_per_ce_physical-1)*bank_address_space) + self.blocks_per_bank
        self.bank_mask = int(math.log(self.bank_address_space * self.pagesPerBlock,2))
        print "NAND geometry : %s (%d CEs (%d physical banks/CE) of %d blocks of %d pages of %d bytes data, %d bytes metdata)" % \
            (hsize, self.nCEs, self.banks_per_ce_physical, self.blocksPerCE, self.pagesPerBlock, self.pageSize, d["meta-per-logical-page"])    
    
    def unwhitenMetadata(self, meta, pagenum):
        if len(meta) != 12:
            return None
        s = list(struct.unpack("<LLL", meta))
        for i in xrange(3):
            s[i] ^= NAND.H2FMI_HASH_TABLE[(i+pagenum) % len(NAND.H2FMI_HASH_TABLE)]
        return struct.pack("<LLL", s[0], s[1],s[2])
    
    def readBootPage(self, ce, page):
        s,d=self.readPage(ce, page, boot=True)
        if d:
            return d[:self.bootloaderBytes]
        else:
            #print "readBootPage %d %d failed" % (ce,page)
            return self.emptyBootloaderPage
    
    def readMetaPage(self, ce, block, page, spareType=SpareData):
        return self.readBlockPage(ce, block, page, META_KEY, spareType=spareType)
                
    def readBlockPage(self, ce, block, page, key=None, lpn=None, spareType=SpareData):
        assert page < self.pagesPerBlock
        b = block % self.blocks_per_bank
        bank_offset = self.bank_address_space * (block / self.blocks_per_bank)
        pn = (bank_offset + block % self.blocks_per_bank) * self.pagesPerBlock + page
        return self.readPage(ce, pn, key, lpn, spareType=spareType)
    
    def translateabsPage(self, page):
        return page % self.nCEs, page/self.nCEs
    
    def readAbsPage(self, page, key=None, lpn=None):
        return self.readPage(page % self.nCEs, page/self.nCEs, key, lpn)
    
    def readPage(self, ce, page, key=None, lpn=None, spareType=SpareData, boot=False):
        if ce > self.nCEs or page > self.pagesPerCE:
            #hax physical banking
            pass#raise Exception("CE %d Page %d out of bounds" % (ce, page))
        if self.ppn and self.filename != "remote":
            #undo slc bit
            zz = self.block_bits + self.cau_bits + self.page_bits
            page = page & ((1 << zz) - 1)
        if self.filename != "remote": #undo banking hax
            bank = (page & ~((1 << self.bank_mask) - 1)) >> self.bank_mask
            page2 = (page & ((1 << self.bank_mask) - 1))
            page2 = bank * (self.blocks_per_bank) * self.pagesPerBlock + page2
            spare, data = self.image.readPage(ce, page2, boot)
        else:
            spare, data = self.image.readPage(ce, page, boot)
        if not data:
            return None,None
        if self.metadata_whitening and spare != "\x00"*12 and len(spare) == 12:
            spare = self.unwhitenMetadata(spare, page)
        if spareType:
            spare = spareType.parse(spare)
        if key and self.encrypted:
            if lpn != None: pageNum = lpn#spare.lpn #XXX
            else:           pageNum = page
            return spare, self.decryptPage(data, key, pageNum)
        return spare, data

    def decryptPage(self, data, key, pageNum):
        if key == FILESYSTEM_KEY and self.ppn:
            return data
        return AESdecryptCBC(data, key, ivForPage(pageNum))
    
    def unpackSpecialPage(self, data):
        l = struct.unpack("<L", data[0x34:0x38])[0]
        return data[0x38:0x38 + l]
    
    def readSpecialPages(self, ce, magics):
        print "Searching for special pages..."
        specials = {}
        if self.nandonly:
            magics.append("DEVICEUNIQUEINFO")#, "DIAGCONTROLINFO")
        magics = map(lambda s: s.ljust(16,"\x00"), magics)

        lowestBlock = self.blocksPerCE - (self.blocksPerCE / 100)
        for block in xrange(self.blocksPerCE - 1, lowestBlock, -1):
            if len(magics) == 0:
                break
            #hax for physical banking
            bank_offset = self.bank_address_space * (block / self.blocks_per_bank)
            for page in xrange(self.pagesPerBlock-1,-1,-1):
                page = (bank_offset + block % self.blocks_per_bank) * self.pagesPerBlock + page
                s, data = self.readPage(ce, page)
                if data == None:
                    continue
                if data[:16] in magics:
                    self.encrypted = False
                    magics.remove(data[:16])
                    specials[data[:16].rstrip("\x00")] = self.unpackSpecialPage(data)
                    break
                data = self.decryptPage(data, META_KEY, page)
                #print data[:16]
                if data[:16] in magics:
                    #print data[:16], block, page
                    self.encrypted = True
                    magics.remove(data[:16])
                    specials[data[:16].rstrip("\x00")] = self.unpackSpecialPage(data)
                    break
        return specials

    def readLPN(self, lpn, key):
        return self.ftl.readLPN(lpn, key)
    
    def readVPN(self, vpn, key=None, lpn=None):
        return self.vfl.read_single_page(vpn, key, lpn)
    
    def dumpSystemPartition(self, outputfilename):
        return self.getPartitionBlockDevice(0).dumpToFile(outputfilename)

    def dumpDataPartition(self, emf, outputfilename):
        return self.getPartitionBlockDevice(1, emf).dumpToFile(outputfilename)

    def isIOS5(self):
        self.getPartitionTable()
        return self.iosVersion == 5
        
    def getPartitionTable(self):
        if self.partition_table:
            return self.partition_table
        pt = None
        key = FILESYSTEM_KEY if not self.ppn else None
        for i in xrange(10):
            d = self.readLPN(i, key)
            pt = parse_mbr(d)
            if pt:
                self.hasMBR = True
                self.iosVersion = 3
                break
            gpt = parse_gpt(d)
            if gpt:
                off = gpt.partition_entries_lba - gpt.current_lba
                d = self.readLPN(i+off, key)
                pt = GPT_partitions.parse(d)[:-1]
                self.iosVersion = 4
                break
            pt = parse_lwvm(d, self.logicalPageSize)
            if pt:
                self.iosVersion = 5
                break
        self.partition_table = pt
        return pt
    
    def getPartitionBlockDevice(self, partNum, key=None):
        pt = self.getPartitionTable()
        if self.hasMBR and pt[1].type == APPLE_ENCRYPTED and partNum == 1:
            data = self.readLPN(pt[1].last_lba - 1, FILESYSTEM_KEY)
            key = getEMFkeyFromCRPT(data, self.device_infos["key89B"].decode("hex"))
        if key == None:
            if partNum == 0:
                key = FILESYSTEM_KEY if not self.ppn else None
            elif partNum == 1 and self.device_infos.has_key("EMF"):
                key = self.device_infos["EMF"].decode("hex")
        return FTLBlockDevice(self, pt[partNum].first_lba, pt[partNum].last_lba, key)
    
    def getPartitionVolume(self, partNum, key=None):
        bdev = self.getPartitionBlockDevice(partNum, key)
        if partNum == 0:
            return HFSVolume(bdev)
        elif partNum == 1:
            self.device_infos["dataVolumeOffset"] = self.getPartitionTable()[partNum].first_lba
            return EMFVolume(bdev, self.device_infos)
    
    def findLockersUnit(self):
        if not self.nandonly:
            return
        for ce in xrange(0,self.nCEs):
            for block in xrange(4):#XXX: hax
                plog = self.partition_scheme.readPartitionBlock("plog", ce, block)
                for i in xrange(128):
                    d = plog[i*self.bootloaderBytes:(i+1)*self.bootloaderBytes]

                    if d and check_effaceable_header(d):
                        print "Found effaceable lockers in ce %d block %d (XXX possibly remapped) page %d" % (ce,block,i)
                        return d
   
    def getLockers(self):
        unit = self.findLockersUnit()
        if unit:
            return unit[0x40:0x40+960]

    def getEMF(self, k89b):
        return self.lockers.get_EMF(k89b)

    def getDKey(self, k835):
        return self.lockers.get_DKey(k835)

    def readBootPartition(self, block_start, block_end):
        res = ""
        for i in xrange(block_start*self.pagesPerBlock, block_end*self.pagesPerBlock):
            res += self.readBootPage(0, i)
        return res

    def get_img3s(self):
        if not self.nandonly:
            print "IMG3s are in NOR"
            return []
        blob = self.partition_scheme.readPartition("firm")
        hdr = IMG2.parse(blob[:0x100])
        i = hdr.images_block * hdr.block_size + hdr.images_offset
        img3s = extract_img3s(blob[i:i+hdr.images_length*hdr.block_size])
        
        boot = self.partition_scheme.readPartition("boot")
        img3s = extract_img3s(boot[0xc00:]) + img3s
        return img3s
        
    def extract_img3s(self, outfolder=None):
        if not self.nandonly:
            print "IMG3s are in NOR"
            return
        if outfolder:
            if self.filename != "remote": outfolder = os.path.join(os.path.dirname(self.filename), "img3")
            else: outfolder = os.path.join(".", "img3")
        if outfolder:
            makedirs(outfolder)
            print "Extracting IMG3s to %s" % outfolder
        for img3 in self.get_img3s():
            print img3.sigcheck(self.device_infos.get("key89A").decode("hex"))
            print img3.shortname
            if outfolder:
                write_file(outfolder+ "/%s.img3" % img3.shortname, img3.img3)
        return
        kernel = self.getPartitionVolume(0).readFile("/System/Library/Caches/com.apple.kernelcaches/kernelcache",returnString=True)
        if kernel:
            print "kernel"
            write_file(outfolder + "/kernelcache.img3", kernel)
            
    def extract_shsh(self, outfolder="."):
        if not self.nandonly:
            print "IMG3s are in NOR"
            return
        pass
    
    def getNVRAM(self):
        if not self.nandonly:
            print "NVRAM is in NOR"
            return 
        #TODO
        data = self.partition_scheme.readPartition("nvrm")

    def cacheData(self, name, data):
        if self.filename == "remote":
            return None
        save_pickle(self.filename + "." + name, data)
    
    def loadCachedData(self, name):
        try:
            if self.filename == "remote":
                return None
            return load_pickle(self.filename + "." + name)
        except:
            return None
        
    def dump(self, p):
        ioflash = IOFlashStorageKitClient()
        ioflash.dump_nand(p)
