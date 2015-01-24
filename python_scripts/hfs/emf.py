from construct import Struct, ULInt16, ULInt32, String
from construct.macros import ULInt64, Padding, If
from crypto.aes import AESencryptCBC, AESdecryptCBC
from hfs import HFSVolume, HFSFile
from keystore.keybag import Keybag
from structs import HFSPlusVolumeHeader, kHFSPlusFileRecord, getString, \
    kHFSRootParentID
from util import search_plist
from util.bruteforce import loadKeybagFromVolume
import hashlib
import os
import plistlib
import struct

"""
iOS >= 4 raw images
http://opensource.apple.com/source/xnu/xnu-1699.22.73/bsd/hfs/hfs_cprotect.c
http://opensource.apple.com/source/xnu/xnu-1699.22.73/bsd/sys/cprotect.h
"""

cp_root_xattr = Struct("cp_root_xattr",
    ULInt16("major_version"),
    ULInt16("minor_version"),
    ULInt64("flags"),
    ULInt32("reserved1"),
    ULInt32("reserved2"),
    ULInt32("reserved3"),
    ULInt32("reserved4")
)

cprotect_xattr = Struct("cprotect_xattr",
    ULInt16("xattr_major_version"),
    ULInt16("xattr_minor_version"),
    ULInt32("flags"),
    ULInt32("persistent_class"),
    ULInt32("key_size"),
    If(lambda ctx: ctx["xattr_major_version"] >= 4, Padding(20)),
    String("persistent_key", length=lambda ctx: ctx["key_size"])
)
NSProtectionNone = 4

PROTECTION_CLASSES={
    1:"NSFileProtectionComplete",
    2:"NSFileProtectionCompleteUnlessOpen",
    3:"NSFileProtectionCompleteUntilFirstUserAuthentication",
    4:"NSFileProtectionNone",
    5:"NSFileProtectionRecovery?"
}

#HAX: flags set in finderInfo[3] to tell if the image was already decrypted
FLAG_DECRYPTING = 0x454d4664  #EMFd big endian
FLAG_DECRYPTED = 0x454d4644  #EMFD big endian

class EMFFile(HFSFile):
    def __init__(self, volume, hfsplusfork, fileID, filekey, deleted=False):
        super(EMFFile,self).__init__(volume, hfsplusfork, fileID, deleted)
        self.filekey = filekey
        self.ivkey = None
        self.decrypt_offset = 0
        if volume.cp_major_version == 4:
            self.ivkey = hashlib.sha1(filekey).digest()[:16]

    def processBlock(self, block, lba):
        iv = self.volume.ivForLBA(lba)
        ciphertext = AESencryptCBC(block, self.volume.emfkey, iv)
        if not self.ivkey:
            clear = AESdecryptCBC(ciphertext, self.filekey, iv)
        else:
            clear = ""
            for i in xrange(len(block)/0x1000):
                iv = self.volume.ivForLBA(self.decrypt_offset, False)
                iv = AESencryptCBC(iv, self.ivkey)
                clear += AESdecryptCBC(ciphertext[i*0x1000:(i+1)*0x1000], self.filekey,iv)
                self.decrypt_offset += 0x1000
        return clear
    
    def decryptFile(self):
        self.decrypt_offset = 0
        bs = self.volume.blockSize
        for extent in self.extents:
            for i in xrange(extent.blockCount):
                lba = extent.startBlock+i
                data = self.volume.readBlock(lba)
                if len(data) == bs:
                    clear = self.processBlock(data, lba)
                    self.volume.writeBlock(lba, clear)


class EMFVolume(HFSVolume):
    def __init__(self, bdev, device_infos, **kwargs):
        super(EMFVolume,self).__init__(bdev, **kwargs)
        volumeid = self.volumeID().encode("hex")

        if not device_infos:
            dirname = os.path.dirname(bdev.filename)
            device_infos = search_plist(dirname, {"dataVolumeUUID":volumeid})
            if not device_infos:
                raise Exception("Missing keyfile")
        try:
            self.emfkey = None
            if device_infos.has_key("EMF"):
                self.emfkey = device_infos["EMF"].decode("hex")
            self.lbaoffset = device_infos["dataVolumeOffset"]
            self.keybag = Keybag.createWithPlist(device_infos)
        except:
            raise #Exception("Invalid keyfile")
        
        self.decrypted = (self.header.finderInfo[3] == FLAG_DECRYPTED) 
        rootxattr =  self.getXattr(kHFSRootParentID, "com.apple.system.cprotect")
        self.cp_major_version = None
        self.cp_root = None
        if rootxattr == None:
            print "(No root com.apple.system.cprotect xattr)"
        else:
            self.cp_root = cp_root_xattr.parse(rootxattr)
            ver = self.cp_root.major_version
            print "cprotect version : %d" % ver
            assert self.cp_root.major_version == 2 or self.cp_root.major_version == 4
            self.cp_major_version = self.cp_root.major_version
        self.keybag = loadKeybagFromVolume(self, device_infos)
            
    def ivForLBA(self, lba, add=True):
        iv = ""
        if add:
            lba = lba + self.lbaoffset
        lba &= 0xffffffff
        for _ in xrange(4):
            if (lba & 1):
                lba = 0x80000061 ^ (lba >> 1);
            else:
                lba = lba >> 1;
            iv += struct.pack("<L", lba)
        return iv
    
    def getFileKeyForCprotect(self, cp):
        if self.cp_major_version == None:
            self.cp_major_version = struct.unpack("<H", cp[:2])[0]
        cprotect = cprotect_xattr.parse(cp)
        return self.keybag.unwrapKeyForClass(cprotect.persistent_class, cprotect.persistent_key)
    
    def getFileKeyForFileId(self, fileid):
        cprotect = self.getXattr(fileid, "com.apple.system.cprotect")
        if cprotect == None:
            return None
        return self.getFileKeyForCprotect(cprotect)

    def readFile_old_api(self, path, outFolder="./", returnString=False):
        k,v = self.catalogTree.getRecordFromPath(path)
        if not v:
            print "File %s not found" % path
            return
        assert v.recordType == kHFSPlusFileRecord
        cprotect = self.getXattr(v.data.fileID, "com.apple.system.cprotect")
        if cprotect == None or not self.cp_root or self.decrypted:
            #print "cprotect attr not found, reading normally"
            return super(EMFVolume, self).readFile(path, returnString=returnString)
        filekey = self.getFileKeyForCprotect(cprotect)
        if not filekey:
            print "Cannot unwrap file key for file %s protection_class=%d" % (path, cprotect_xattr.parse(cprotect).persistent_class)
            return
        f = EMFFile(self, v.data.dataFork, v.data.fileID, filekey)
        if returnString:
            return f.readAllBuffer()
        output = open(outFolder + os.path.basename(path), "wb")
        f.readAll(output)
        output.close()
        return True

    def readFileByRecord(self, key, record, output):
        assert record.recordType == kHFSPlusFileRecord
        cprotect = self.getXattr(record.data.fileID, "com.apple.system.cprotect")
        if cprotect == None or not self.cp_root or self.decrypted:
            #print "cprotect attr not found, reading normally"
            return super(EMFVolume, self).readFileByRecord(key, record, output)
        filekey = self.getFileKeyForCprotect(cprotect)
        if not filekey:
            print "Cannot unwrap file key for file %d protection_class=%d" % (record.data.fileID, cprotect_xattr.parse(cprotect).persistent_class)
            return
        f = EMFFile(self, record.data.dataFork, record.data.fileID, filekey)
        f.readAll(output)
        return True
    
    def flagVolume(self, flag):
        self.header.finderInfo[3] = flag
        h = HFSPlusVolumeHeader.build(self.header)
        return self.bdev.write(0x400, h)
        
    def decryptAllFiles(self):
        if self.header.finderInfo[3] == FLAG_DECRYPTING:
            print "Volume is half-decrypted, aborting (finderInfo[3] == FLAG_DECRYPTING)"
            return
        elif self.header.finderInfo[3] == FLAG_DECRYPTED:
            print "Volume already decrypted (finderInfo[3] == FLAG_DECRYPTED)"
            return
        self.failedToGetKey = []
        self.notEncrypted = []
        self.decryptedCount = 0
        self.flagVolume(FLAG_DECRYPTING)
        self.catalogTree.traverseLeafNodes(callback=self.decryptFile)
        self.flagVolume(FLAG_DECRYPTED)
        print "Decrypted %d files" % self.decryptedCount
        print "Failed to unwrap keys for : ", self.failedToGetKey
        print "Not encrypted files : %d" % len(self.notEncrypted)

    def decryptFile(self, k,v):
        if v.recordType == kHFSPlusFileRecord:
            filename = getString(k).encode("utf-8")
            cprotect = self.getXattr(v.data.fileID, "com.apple.system.cprotect")
            if not cprotect:
                self.notEncrypted.append(filename)
                return
            fk = self.getFileKeyForCprotect(cprotect)
            if not fk:
                self.failedToGetKey.append(filename)
                return
            print "Decrypting", filename
            f = EMFFile(self, v.data.dataFork, v.data.fileID, fk)
            f.decryptFile()
            self.decryptedCount += 1

    def list_protected_files(self):
        self.protected_dict = {}
        self.xattrTree.traverseLeafNodes(callback=self.inspectXattr)
        for k in self.protected_dict.keys():
            print k
            for v in self.protected_dict[k]: print "\t",v
            print ""
            
    def inspectXattr(self, k, v):
        if getString(k) == "com.apple.system.cprotect" and k.fileID != kHFSRootParentID:
            c = cprotect_xattr.parse(v.data)
            if c.persistent_class != NSProtectionNone:
                #desc = "%d %s" % (k.fileID, self.getFullPath(k.fileID))
                desc = "%s" % self.getFullPath(k.fileID)
                self.protected_dict.setdefault(PROTECTION_CLASSES.get(c.persistent_class),[]).append(desc)
                #print k.fileID, self.getFullPath(k.fileID), PROTECTION_CLASSES.get(c.persistent_class)
