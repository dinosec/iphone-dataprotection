import os
import struct
import sys

"""
row-by-row dump
page = data + spare metadata + iokit return code + iokit return code 2
"""
class NANDImageFlat(object):
    def __init__(self, filename, geometry):
        flags =  os.O_RDONLY
        if sys.platform == "win32":
            flags |= os.O_BINARY
        self.fd = os.open(filename, flags)
        self.nCEs = geometry["#ce"]
        self.ppn = geometry.get("ppn-device", False)
        self.pageSize = geometry["#page-bytes"]
        self.metaSize = geometry.get("meta-per-logical-page", 12)
        if self.metaSize == 0: self.metaSize = 12
        self.dumpedPageSize = geometry.get("dumpedPageSize", self.pageSize + self.metaSize + 8)
        self.hasIOKitStatus = True
        if self.dumpedPageSize  ==  self.pageSize + geometry["#spare-bytes"] + 8:
            self.metaSize = geometry["#spare-bytes"]
        if self.dumpedPageSize  ==  self.pageSize + geometry["#spare-bytes"] or self.dumpedPageSize == self.pageSize + self.metaSize:
            self.hasIOKitStatus = False
            self.blankPage = "\xFF" * self.pageSize
            self.blankSpare = "\xFF" * self.metaSize
        self.imageSize = os.path.getsize(filename)
        expectedSize = geometry["#ce"] * geometry["#ce-blocks"] * geometry["#block-pages"] * self.dumpedPageSize
        if self.imageSize < expectedSize:
            raise Exception("Error: image appears to be truncated, expected size=%d" % expectedSize)
        print "Image size matches expected size, looks ok"
        
    def _readPage(self, ce, page):
        i = page * self.nCEs + ce
        off = i * self.dumpedPageSize
        os.lseek(self.fd, off, os.SEEK_SET)
        return os.read(self.fd, self.dumpedPageSize)

    def readPage(self, ce, page, boot=False):
        d = self._readPage(ce, page)
        if not d or len(d) != self.dumpedPageSize:
            return None,None
        if self.hasIOKitStatus and not self.ppn:#ppn iokit codes are bogus
            r1,r2 = struct.unpack("<LL", d[self.pageSize+self.metaSize:self.pageSize+self.metaSize+8])
            if r1 != 0x0:
                return None, None
        data = d[:self.pageSize]
        spare = d[self.pageSize:self.pageSize+self.metaSize]
        if not self.hasIOKitStatus and data == self.blankPage and spare == self.blankSpare:
            return None,None
        return spare, data 

"""
iEmu NAND format
one file for each CE, start with chip id (8 bytes) then pages
page = non-empty flag (1 byte) + data + spare metadata (12 bytes)
"""
class NANDImageSplitCEs(object):
    def __init__(self, folder, geometry):
        flags =  os.O_RDONLY
        if sys.platform == "win32":
            flags |= os.O_BINARY
        self.fds = []
        self.nCEs = geometry["#ce"]
        self.pageSize = geometry["#page-bytes"]
        self.metaSize = 12
        self.npages = 0
        self.dumpedPageSize = 1 + self.pageSize + self.metaSize
        for i in xrange(self.nCEs):
            fd = os.open(folder + "/ce_%d.bin" % i, flags)
            self.fds.append(fd)
            self.npages += os.fstat(fd).st_size / self.dumpedPageSize

    def _readPage(self, ce, page):
        fd = self.fds[ce]
        off = 8 + page * self.dumpedPageSize    #skip chip id
        os.lseek(fd, off, os.SEEK_SET)
        return os.read(fd, self.dumpedPageSize)

    def readPage(self, ce, page):
        d = self._readPage(ce, page)
        if not d or len(d) != self.dumpedPageSize:
            return None,None
        if d[0] != '1' and d[0] != '\x01':
            return None,None
        data = d[1:1+self.pageSize]
        spare = d[1+self.pageSize:1+self.pageSize+self.metaSize]
        return spare, data 
