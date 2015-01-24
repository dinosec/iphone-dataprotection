from crypto.aes import AESdecryptCBC, AESencryptCBC
from hfs.emf import cprotect_xattr, EMFVolume
from hfs.hfs import HFSVolume, hfs_date, HFSFile
from hfs.journal import carveBtreeNode, isDecryptedCorrectly
from hfs.structs import *
from util import sizeof_fmt, makedirs, hexdump
import hashlib
import os
import struct

class PPNCarver(object):
    def __init__(self, volume, image, outputdir=None):
        self.volume = volume
        self.image = image
        self.nand = image
        self.ftlhax = False
        self.userblocks = None
        self.lpnToVpn = None
        self.files = {}
        self.keys = {}
        self.encrypted = image.encrypted and hasattr(volume, "emfkey")
        self.encrypted = hasattr(volume, "cp_root") and volume.cp_root != None
        if outputdir == None:
            if image.filename != "remote": outputdir = os.path.join(os.path.dirname(image.filename), "undelete")
            else: outputdir = os.path.join(".", "undelete")
        print "Carver output %s" % outputdir
        self.outputdir = outputdir
        self.okfiles = 0
        self.first_lba = self.volume.bdev.lbaoffset
        self.pageSize = image.logicalPageSize
        self.blankPage = "\xDE\xAD\xBE\xEF" * (self.pageSize/4)
        self.emfkey = None
        self.fileIds = None
        self.fastMode = False
        if hasattr(volume, "emfkey"):
            self.emfkey = volume.emfkey
    
    def carveFile(self, hfsfile, callback, lbas=None, filter_=None):
        for e in hfsfile.extents:
            if e.blockCount == 0:
                break
            for i in xrange(e.startBlock, e.startBlock+e.blockCount):
                if lbas and not i in lbas:
                    continue
                if i % 2:
                    continue
                #HAX btree nodeSize > logicalBlockSize
                hax = self.nand.ftl.findAllVersions(self.first_lba+i+1)
                allvers = self.nand.ftl.findAllVersions(self.first_lba+i)
                for j in xrange(len(allvers)):
                    addr = allvers[j]
                    if j >= len(hax):
                        continue
                    d = self.nand.ftl.readPage1(addr, self.emfkey, self.first_lba+i)
                    #print addr[0], hax[j][0]
                    d2 = self.nand.ftl.readPage1(hax[j], self.emfkey, self.first_lba+i+1)
                    callback(d+d2, addr[0], filter_)

    def _catalogFileCallback(self, data, usn, filter_):
        for k,v in carveBtreeNode(data,HFSPlusCatalogKey, HFSPlusCatalogData):
            if v.recordType != kHFSPlusFileRecord:
                continue
            if filter_ and not filter_(k,v):
                continue
            name = getString(k)
            #if not self.filterFileName(name):
            #if not name.startswith("IMG"):
            #    continue
            h = hashlib.sha1(HFSPlusCatalogKey.build(k)).digest()
            if self.files.has_key(h):
                continue
            if not self.fileIds.has_key(v.data.fileID):
                try:
                    print "Found deleted file record", v.data.fileID, name, "created", hfs_date(v.data.createDate)
                    print "weave %d" % usn
                except:
                    print "fu " + name.encode("hex")
                self.files[h] = (name,v, usn)               
    
    def _attributesFileCallback(self, data, usn, filter_):
        for k,v in carveBtreeNode(data,HFSPlusAttrKey, HFSPlusAttrData):
            if getString(k) != "com.apple.system.cprotect":
                continue
            if self.fileIds.has_key(k.fileID):
                continue
            filekeys = self.keys.setdefault(k.fileID, [])
            try:
                cprotect = cprotect_xattr.parse(v.data)
            except:
                continue
            if cprotect.key_size == 0:
                continue
            filekey = self.volume.keybag.unwrapKeyForClass(cprotect.persistent_class, cprotect.persistent_key, False)
            if filekey and not filekey in filekeys:
                #print "Found key for file ID ", k.fileID
                filekeys.append(filekey)
    
    def carveCatalog(self, lbas=None, filter_=None):
        return self.carveFile(self.volume.catalogFile, self._catalogFileCallback, lbas, filter_)
    
    def carveKeys(self, lbas=None):
        return self.carveFile(self.volume.xattrFile, self._attributesFileCallback, lbas)

    def decryptFileBlock(self, pn, filekey, lbn, decrypt_offset):
        s, ciphertext = self.nand.ftl.YAFTL_readPage(pn, None, lbn)
        if not self.encrypted:
            return ciphertext
        if not self.image.isIOS5():
            return AESdecryptCBC(ciphertext, filekey, self.volume.ivForLBA(lbn))
        clear = ""
        ivkey = hashlib.sha1(filekey).digest()[:16]
        for i in xrange(len(ciphertext)/0x1000):
            iv =  self.volume.ivForLBA(decrypt_offset, False)
            iv = AESencryptCBC(iv, ivkey)
            clear += AESdecryptCBC(ciphertext[i*0x1000:(i+1)*0x1000], filekey, iv)
            decrypt_offset += 0x1000
        return clear

    def writeUndeletedFile(self, filename, data):
        knownExtensions = (".m4a", ".plist",".sqlite",".sqlitedb", ".jpeg", ".jpg", ".png", ".db",".json",".xml",".sql")
        #windows invalid chars  \/:*?"<>|
        filename = str(filename.encode("utf-8")).translate(None, "\\/:*?\"<>|,")
        folder = self.outputdir
        if self.outputdir == "./":
            folder = folder + "/undelete"
        elif filename.lower().endswith(knownExtensions):
            ext = filename[filename.rfind(".")+1:]
            folder = folder + "/" + ext.lower()
        makedirs(folder)
        open(folder + "/" + filename, "wb").write(data)
    
    def filterFileName(self, filename):
        return filename.lower().endswith(".jpg")

    def getExistingFileIDs(self):
        print "Collecting existing file ids"
        self.fileIds = self.volume.listAllFileIds()
        print "%d file IDs" % len(self.fileIds.keys())

    def carveDeletedFiles_fast(self, catalogLBAs=None, filter_=None, limit=0):
        self.fastMode = True
        self.files = {}
        if not self.fileIds:
            self.getExistingFileIDs()
        print "Carving catalog file"
        #catalogLBAs = None
        self.carveCatalog(catalogLBAs, filter_)

        #keysLbas = []
        #for name, vv, usn in self.files.values():
        #    for i in xrange(vv.data.fileID, vv.data.fileID + 100):
        #       if self.volume.xattrTree.search((i, "com.apple.system.cprotect")):
        #            keysLbas.extend(self.volume.xattrTree.getLBAsHax())
        #            break
        
        #print "keysLbas", keysLbas
        if self.encrypted and len(self.keys) == 0:
            print "Carving attribute file for file keys"
            #self.carveKeys(keysLbas)
            self.carveKeys()

        self.okfiles = 0
        total = 0
        print "%d files, %d keys" % (len(self.files), len(self.keys))
        for name, vv, usn in self.files.values():
            if not self.keys.has_key(vv.data.fileID):
                print "No file key for %s" % name
            keys = set(self.keys.get(vv.data.fileID, [self.emfkey]))
            print "%s" % name
            if self.readFileHax(name, vv.data, keys):
                total += 1

        print "Carving done, recovered %d deleted files, %d are most likely OK" % (total, self.okfiles)
           
    def readFileHax(self, filename, filerecord, filekeys):
        lba0 = self.first_lba + filerecord.dataFork.HFSPlusExtentDescriptor[0].startBlock
        filekey = None
        good_usn = None
        first_usn = 0
        lba0_versions = self.nand.ftl.findAllVersions(lba0)
        print "%d versions for first lba" % len(lba0_versions)
        for k in filekeys:
            for addr in lba0_versions:
                ciphertext = self.nand.ftl.readPage1(addr, key=None, lpn=lba0)
                if not ciphertext:
                    continue
                d = self.decryptFileBlock2(ciphertext, k, lba0, 0)
                if isDecryptedCorrectly(d):
                    hexdump(d[:16])
                    filekey = k
                    weaveSeq = addr[0]
                    break
        if not filekey:
            return False
        logicalSize = filerecord.dataFork.logicalSize
        missing_pages = 0
        file_pages = []
        lbns = []
        for extent in self.volume.getAllExtents(filerecord.dataFork, filerecord.fileID):
            for bn in xrange(extent.startBlock, extent.startBlock + extent.blockCount):
                lbns.append(self.first_lba + bn)
        datas = {}
        
        first_block = True
        done = False
        for weaveSeq,lbn,ce,block,page in self.nand.ftl.findPagesInRange(weaveSeq, weaveSeq+50000):
            if not lbn in lbns:
                continue
            idx = lbns.index(lbn)
            ciphertext = self.nand.ftl.readPage1((weaveSeq,ce,block,page), key=None, lpn=lbn)
            if not ciphertext:
                continue
            ciphertext = self.decryptFileBlock2(ciphertext, filekey, lbn, idx*self.pageSize)
            if idx == 0:
                if not isDecryptedCorrectly(ciphertext):
                    continue
            datas[idx*self.pageSize] = (ciphertext, lbn - self.first_lba)
            #if idx == len(lbns):
            if len(datas) == len(lbns):
                done=True
                break
            if done:
                break
        cleartext = ""
        decrypt_offset = 0
        for i in xrange(0,logicalSize, self.pageSize):
            if datas.has_key(i):
                ciphertext, lbn = datas[i]
                cleartext += ciphertext
            else:
                cleartext += self.blankPage
                missing_pages += 1
            decrypt_offset += self.pageSize

        print "Recovered %d:%s %d missing pages, size %s, created %s, contentModDate %s" % \
            (filerecord.fileID, filename.encode("utf-8"), missing_pages, sizeof_fmt(logicalSize), hfs_date(filerecord.createDate), hfs_date(filerecord.contentModDate))
        filename =  "%d_%d_%s" % (filerecord.fileID, first_usn, filename)
        if missing_pages == 0:
            filename = "OK_" + filename
            self.okfiles += 1
        if True:#exactSize:
            cleartext = cleartext[:logicalSize]
        self.writeUndeletedFile(filename, cleartext)
        return True
     
    def decryptFileBlock2(self, ciphertext, filekey, lbn, decrypt_offset):
        if not self.encrypted:
            return ciphertext
        if not self.image.isIOS5():
            return AESdecryptCBC(ciphertext, filekey, self.volume.ivForLBA(lbn, add=False))
        clear = ""
        ivkey = hashlib.sha1(filekey).digest()[:16]
        for i in xrange(len(ciphertext)/0x1000):
            iv =  self.volume.ivForLBA(decrypt_offset, False)
            iv = AESencryptCBC(iv, ivkey)
            clear += AESdecryptCBC(ciphertext[i*0x1000:(i+1)*0x1000], filekey, iv)
            decrypt_offset += 0x1000
        return clear

