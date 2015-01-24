from progressbar import ProgressBar
from usbmux import usbmux
from util import hexdump, sizeof_fmt
import datetime
import hashlib
import struct
import os

CMD_DUMP = 0
CMD_PROXY = 1
kIOFlashStorageOptionRawPageIO  = 0x002
kIOFlashStorageOptionBootPageIO = 0x100

class IOFlashStorageKitClient(object):
    def __init__(self, udid=None, host="localhost", port=2000):
        self.host = host
        self.port = port
        self.connect(udid)
        
    def connect(self, udid=None):
        mux = usbmux.USBMux()
        mux.process(1.0)
        if not mux.devices:
            print "Waiting for iOS device"
            while not mux.devices:
                mux.process(1.0)
        if not mux.devices:
            print "No device found"
            return
        dev = mux.devices[0]
        try:
            self.s = mux.connect(dev, self.port)
        except:
            raise Exception("Connexion to device %s port %d failed" % (dev.serial, self.port))
    
    def send_command(self, cmd):
        return self.s.send(struct.pack("<L", cmd))
    
    def dump_nand(self, filename):
        f = open(filename, "wb")
        self.send_command(CMD_DUMP)
        zz = self.s.recv(8)
        totalSize = struct.unpack("<Q", zz)[0]
        recvSize = 0
        print "Dumping %s NAND to %s" % (sizeof_fmt(totalSize), filename)
        pbar = ProgressBar(totalSize)
        pbar.start()
        h = hashlib.sha1()
        while recvSize < totalSize:
            pbar.update(recvSize)
            d = self.s.recv(8192*2)
            if not d or len(d) == 0:
                break
            h.update(d)
            f.write(d)
            recvSize += len(d)
        pbar.finish()
        f.close()
        print "NAND dump time : %s" % str(datetime.timedelta(seconds=pbar.seconds_elapsed))
        print "SHA1: %s" % h.hexdigest()
        if recvSize != totalSize:
            print "dump_nand FAIL"
            
class NANDRemote(object):
    def __init__(self, pageSize, spareSize, pagesPerBlock, bfn):
        self.spareSize = spareSize
        self.pageSize = pageSize
        self.pagesPerBlock = pagesPerBlock
        self.bootFromNand = bfn
        self.client = IOFlashStorageKitClient()
        self.client.send_command(CMD_PROXY)
    
    def readPage(self, ce, page, boot=False):
        options = 0
        spareSize = self.spareSize
        if self.bootFromNand and boot:
            options = kIOFlashStorageOptionBootPageIO
            spareSize = 0
        d = struct.pack("<LLLL", ce, page, spareSize, options)
        
        self.client.s.send(d)
        
        torecv = self.pageSize+8+spareSize
        d = ""
        while len(d) != torecv:
            zz = self.client.s.recv(torecv)
            if not zz:
                break
            d += zz
        pageData = d[:self.pageSize]
        spareData = d[self.pageSize:self.pageSize+spareSize]
        r1,r2 = struct.unpack("<LL", d[self.pageSize+spareSize:self.pageSize+spareSize+8])

        if r1 == 0xe00002e5:
            return None, None
        #print ce, page, "%x" % r1, r2, pageData[:0x10].encode("hex"), spareData[:0x10].encode("hex")
        if spareData == "":
            spareData = "\xFF" * self.spareSize
        return spareData, pageData
