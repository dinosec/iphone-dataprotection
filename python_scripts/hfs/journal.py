from crypto.aes import AESencryptCBC, AESdecryptCBC
from emf import cprotect_xattr, EMFFile
from structs import *
from util import write_file, sizeof_fmt
import hashlib

"""
Implementation of the following paper :
Using the HFS+ Journal For Deleted File Recovery. Aaron Burghardt, Adam Feldman. DFRWS 2008
http://www.dfrws.org/2008/proceedings/p76-burghardt.pdf
http://www.dfrws.org/2008/proceedings/p76-burghardt_pres.pdf
"""

def carveBtreeNode(node, kClass, dClass):
    try:
        btnode = BTNodeDescriptor.parse(node)
       
        if btnode.kind == kBTLeafNode:
            off = BTNodeDescriptor.sizeof()
            recs = []
            offsets = Array(btnode.numRecords, UBInt16("off")).parse(node[-2*btnode.numRecords:])
            for i in xrange(btnode.numRecords):
                off = offsets[btnode.numRecords-i-1]
                k = kClass.parse(node[off:])
                off += 2 + k.keyLength
                d = dClass.parse(node[off:])
                recs.append((k,d))
            return recs
        return []
    except:
        return []

"""
for standard HFS volumes
"""
def carveHFSVolumeJournal(volume):
    journal = volume.readJournal()
    hdr = journal_header.parse(journal)
    sector_size = hdr.jhdr_size
    nodeSize = volume.catalogTree.nodeSize
    
    f={}
    for i in xrange(0,len(journal), sector_size):
        for k,v in carveBtreeNode(journal[i:i+nodeSize],HFSPlusCatalogKey, HFSPlusCatalogData):
            if v.recordType == kHFSPlusFileRecord:
                name = getString(k)
                h = hashlib.sha1(HFSPlusCatalogKey.build(k)).digest()
                if f.has_key(h):
                    continue
                if volume.catalogTree.searchByCNID(v.data.fileID) == (None, None):
                    if volume.isBlockInUse(v.data.dataFork.HFSPlusExtentDescriptor[0].startBlock) == False:
                        print "deleted file", v.data.fileID, name
                        fileid = v.data.fileID
                        f[h]=(name, v)
    return f.values()


magics=["SQLite", "bplist", "<?xml", "\xFF\xD8\xFF", "\xCE\xFA\xED\xFE", "\x89PNG", "\x00\x00\x00\x1CftypM4A",
        "\x00\x00\x00\x14ftypqt"]
"""
HAX: should do something better like compute entropy or something
"""
def isDecryptedCorrectly(data):
    for m in magics:
        if data.startswith(m):
            return True
    return False

"""
carve the journal for deleted cprotect xattrs and file records
"""
def carveEMFVolumeJournal(volume):
    journal = volume.readJournal()
    print "Journal size : %s" % sizeof_fmt(len(journal))
    hdr = journal_header.parse(journal)
    sector_size = hdr.jhdr_size
    nodeSize = volume.catalogTree.nodeSize
    print "Collecting existing file ids"
    fileIds = volume.listAllFileIds()
    print "%d file IDs" % len(fileIds.keys())
    files = {}
    keys = {}
    
    for i in xrange(0,len(journal),sector_size):
        for k,v in carveBtreeNode(journal[i:i+nodeSize],HFSPlusCatalogKey, HFSPlusCatalogData):
            if v.recordType == kHFSPlusFileRecord:
                name = getString(k)
                h = hashlib.sha1(HFSPlusCatalogKey.build(k)).digest()
                if files.has_key(h):
                    continue
                if not fileIds.has_key(v.data.fileID):
                    #we only keep files where the first block is not marked as in use
                    if volume.isBlockInUse(v.data.dataFork.HFSPlusExtentDescriptor[0].startBlock) == False:
                        print "Found deleted file record", v.data.fileID, name
                        files[h] = (name,v)
        for k,v in carveBtreeNode(journal[i:i+nodeSize],HFSPlusAttrKey, HFSPlusAttrData):
            if getString(k) == "com.apple.system.cprotect":
                if not fileIds.has_key(k.fileID):
                    filekeys = keys.setdefault(k.fileID, [])
                    try:
                        cprotect = cprotect_xattr.parse(v.data)
                    except:
                        continue
                    #assert cprotect.xattr_major_version == 2
                    filekey = volume.keybag.unwrapKeyForClass(cprotect.persistent_class, cprotect.persistent_key)
                    if filekey and not filekey in filekeys:
                        print "Found key for file", k.fileID
                        filekeys.append(filekey)
    
    return files.values(), keys

"""
"bruteforce" method, tries to decrypt all unallocated blocks with provided file keys
this is a hack, don't expect interesting results with this
"""
def carveEMFemptySpace(volume, file_keys, outdir):
    for lba, block in volume.unallocatedBlocks():
        iv = volume.ivForLBA(lba)
        for filekey in file_keys:
            ciphertext = AESencryptCBC(block, volume.emfkey, iv)
            clear = AESdecryptCBC(ciphertext, filekey, iv)
            if isDecryptedCorrectly(clear):
                print "Decrypted stuff at lba %x" % lba
                open(outdir+ "/%x.bin" % lba, "wb").write(clear)


def do_emf_carving(volume, carveokdir, carvenokdir):
    deletedFiles, filekeys = carveEMFVolumeJournal(volume)

    print "Journal carving done, trying to extract deleted files"
    n = 0
    for name, vv in deletedFiles:
        for filekey in filekeys.get(vv.data.fileID, []):
            ff = EMFFile(volume,vv.data.dataFork, vv.data.fileID, filekey, deleted=True)
            data = ff.readAllBuffer()
            if isDecryptedCorrectly(data):
                write_file(carveokdir + "%d_%s" % (vv.data.fileID, name.replace("/","_")),data)
                n += 1
            else:
                write_file(carvenokdir + "%d_%s" % (vv.data.fileID, name.replace("/","_")),data)
        if not filekeys.has_key(vv.data.fileID):
            print "Missing file key for", name
        else:
            del filekeys[vv.data.fileID]
    
    print "Done, extracted %d files" % n

    if False:
        fks = set(reduce(lambda x,y: x+y, filekeys.values()))
        print "%d file keys left, try carving empty space (slow) ? CTRL-C to exit" % len(fks)
        raw_input()
        carveEMFemptySpace(volume, fks)