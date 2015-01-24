#!/usr/bin/python
from cmd import Cmd
from firmware.img3 import Img3
from hfs.emf import cprotect_xattr, PROTECTION_CLASSES
from hfs.hfs import hfs_date
from keystore.keybag import Keybag, PROTECTION_CLASSES
from nand.carver import NANDCarver
from nand.ppn_carver import PPNCarver
from nand.nand import NAND
from optparse import OptionParser
from util import hexdump, makedirs, write_file, parsePlist, sizeof_fmt,\
    readPlist
from util.bruteforce import bruteforcePasscode
from util.ramdiskclient import RamdiskToolClient
import os
import plistlib
import sqlite3
import struct
import sys
from pprint import pprint
from keychain import keychain_load
from nand.remote import IOFlashStorageKitClient

DEVICES_NAMES = {"m68ap": "iPhone 2G",
           "n82ap": "iPhone 3G",
           "n88ap": "iPhone 3GS",
           "n90ap": "iPhone 4 GSM",
           "n92ap": "iPhone 4 CDMA",
           "n72ap": "iPod Touch 2G",
           "n18ap": "iPod Touch 3G",
           "n81ap": "iPod Touch 4G",
           "k48ap": "iPad 1",
           }

def print_device_infos(d):
    print "Device model:", DEVICES_NAMES.get(d["hwModel"].lower(), d["hwModel"])
    print "UDID:", d["udid"]
    print "ECID:", d.get("ECID")
    print "Serial number:", d["serialNumber"]
    for k in ["key835", "key89B"]:
        if d.has_key(k): print "%s: %s" % (k, d[k])
        
def grab_system_version(system, device_infos):
    SystemVersion = system.readFile("/System/Library/CoreServices/SystemVersion.plist", returnString=True)
    if SystemVersion:
        SystemVersion = plistlib.readPlistFromString(SystemVersion)
        print "iOS version: ", SystemVersion.get("ProductVersion")

def get_device_name(dataVolume):
    preferences = dataVolume.readFile("/preferences/SystemConfiguration/preferences.plist", returnString=True)
    if preferences:
        preferences = parsePlist(preferences)
        return preferences.get("System", {}).get("System", {}).get("ComputerName", "[device name found]")
    return "[device name not found]"

def jailbreak_check(system):
    #lazy jailbreak check
    binsh = system.readFile("/bin/sh",returnString=True)
    if binsh:
        print "Device is probably jailbroken"
    #fstab = system.readFile("/etc/fstab",returnString=True)
    #XXX follow symlinks
    #if fstab.count("rw") != 1:
    #    print "Device is probably jailbroken"

def check_kernel(system, device_infos):
    kernel = system.readFile("/System/Library/Caches/com.apple.kernelcaches/kernelcache",returnString=True)
    if not kernel: return
    k3 = Img3("kernel", kernel)
    if k3.sigcheck(device_infos.get("key89A","").decode("hex")):
        print "Kernel signature check OK"
    if kernel[0x40:0x50].startswith("complzss"):
        print "Kernel is decrypted, probably jailbroken with redsn0w/pwnage tool"

class ExaminerShell(Cmd):
    def __init__(self, image, completekey='tab', stdin=None, stdout=None):
        Cmd.__init__(self, completekey=completekey, stdin=stdin, stdout=stdout)
        self.curdir = "/"
        self.rdisk = None
        if image.filename == "remote":
            self.rdisk = RamdiskToolClient.get()
        self.device_infos = image.device_infos
        self.complete_open = self._complete
        self.complete_xattr = self._complete
        self.complete_cprotect = self._complete
        self.complete_ls = self._complete
        self.complete_cd = self._complete
        self.complete_plist = self._complete
        self.complete_xxd = self._complete
        self.image = image
        if image.ppn and image.filename == "remote":
            self.savepath = "."
            print "Remote PPN device, use nand_dump + save, other commands will fail"
            return
        self.system = image.getPartitionVolume(0)
        self.data = image.getPartitionVolume(1)
        self.volume = None
        self.volname = ""
        grab_system_version(self.system, self.device_infos)
        print "Keybag state: %slocked" % (int(self.data.keybag.unlocked) * "un")
        self.deviceName = get_device_name(self.data)
        self.do_data("")
        self.savepath = os.path.join(os.path.dirname(image.filename), "%s.plist" % self.device_infos.udid[:10])
        #if image.iosVersion > 3 and not image.device_infos.has_key("passcode"):
        #    print "No passcode found in plist file, bruteforce required to access protected data"
        
        self.carver = None
    
    def set_partition(self, name, vol):
        self.volume = vol
        self.do_cd("/")
        self.volname = name
        self.prompt = "(%s-%s) %s " % (self.deviceName, self.volname, self.curdir)
    
    def do_info(self, p):
        pprint(self.device_infos)
        
    def do_save(self, p):
        print "Save device information plist to [%s]:" % self.savepath,
        path2 = raw_input()
        if path2: self.savepath = path2
        if os.path.exists(self.savepath):
            print "File already exists, overwrite ? [y/n]:",
            if raw_input() != "y":
                return
        plistlib.writePlist(self.device_infos, self.savepath)
        
    def do_system(self, p):
        self.set_partition("system", self.system)
    
    def do_data(self, p):
        self.set_partition("data", self.data)
    
    def do_pix(self, p):
        self.do_data("")
        self.do_cd("/mobile/Media/DCIM/100APPLE")
        
    def do_keychain(self, p):
        #self.data.readFile("/Keychains/keychain-2.db")
        self._pull__and_open_sqlitedb("/Keychains/keychain-2.db")
        keychain = keychain_load("keychain-2.db", self.data.keybag, self.image.device_infos["key835"].decode("hex"))
        keychain.print_all(False)
    
    def do_keychain_cert(self, p):
        t = p.split()
        id = int(t[0])
        if len(t) == 2: filename = t[1]
        else: filename = ""
        keychain = keychain_load("keychain-2.db", self.data.keybag, self.image.device_infos["key835"].decode("hex"))
        keychain.cert(id, filename)
    
    def do_keychain_key(self, p):
        t = p.split()
        id = int(t[0])
        if len(t) == 2: filename = t[1]
        else: filename = ""
        keychain = keychain_load("keychain-2.db", self.data.keybag, self.image.device_infos["key835"].decode("hex"))
        keychain.key(id, filename)
    
    def do_exit(self, p):
        return True
    
    def do_quit(self, p):
        return self.do_exit(p)

    def do_reboot(self, p):
        if not self.rdisk:
            self.rdisk = RamdiskToolClient.get()
        self.rdisk.reboot()
        return self.do_exit(p)
    
    def do_pwd(self, p):
        print self.curdir
            
    def do_cd(self, p):
        if len(p) == 0: p = "/"
        if not p.startswith("/"):
            new = self.curdir + p
        else:
            new = p
        if not p.endswith("/"): new = new + "/"
        d = self.volume.ls(new)
        if d != None:
            self.curdir = new
            self.prompt = "(%s-%s) %s " % (self.deviceName, self.volname, new)
        else:
            print "%s not found/is not a directory" % new
            
    def get_path(self, p):
        path = p
        if not path.startswith("/"):
            path = self.curdir + path
        return path
   
    def _complete(self, text, line, begidx, endidx):
        filename = text.split("/")[-1]
        dirname = "/".join(text.split("/")[:-1])
        if text.startswith("/"):
            contents = self.volume.ls(dirname)
        else:
            contents = self.volume.ls(self.curdir + dirname)
        if not contents:
            return []
        if dirname != "" and not dirname.endswith("/"):
            dirname += "/"
        res = [dirname + x for x in contents.keys() if x.startswith(filename)]
        return res
    
    #TODO if size==0 check if compressed
    def do_ls(self, p):
        dirDict = self.volume.ls((self.curdir + "/" + p).replace("//","/")) 
        if not dirDict:
            return
        for name in sorted(dirDict.keys()):
            size = ""
            protection_class = ""
            record = dirDict[name]
            if hasattr(record, "fileID"):
                size = sizeof_fmt(record.dataFork.logicalSize)
                cprotect = self.volume.getXattr(record.fileID, "com.apple.system.cprotect")
                if cprotect:
                    protection_class = PROTECTION_CLASSES[struct.unpack("<L", cprotect[8:12])[0]]
            print "%s\t%s\t%s\t%s" % (name[:30].ljust(30), size.ljust(10), hfs_date(record.createDate), protection_class)
    
    def do_undelete(self, p):
        if not self.data.keybag.unlocked:
            print "Warning, keybag is not unlocked, some files will be inaccessible"
        if not self.carver:
            if self.image.ppn:
                self.carver = PPNCarver(self.data, self.image)
            else:
                self.carver = NANDCarver(self.data, self.image)
        if False:#len(p):
            z =  self.volume.catalogTree.getLBAsHax()
            v = self.volume.getFileRecordForPath(self.curdir)
            folderId = v.folderID
            f = lambda k,v: k.parentID == folderId
        else:
            z = None
            f = None
        self.carver.carveDeletedFiles_fast(z, f)
        #self.carver.carveDeleteFiles_slow(z, f)
    
    def do_xattr(self, p):
        xattr = self.volume.listXattrs(self.get_path(p))
        if not xattr:
            return
        for name, value in xattr.items():
            print name, value.encode("hex")

    def do_protected_files(self, p):
        self.data.list_protected_files()
        
    def do_cprotect(self, p):
        id = self.volume.getFileIDByPath(self.get_path(p))
        if not id:
            return
        
        cprotect = self.volume.getXattr(id, "com.apple.system.cprotect")
        if not cprotect:
            return
        cp = cprotect_xattr.parse(cprotect)
        print cp
        print "Protection class %d => %s" % (cp.persistent_class, PROTECTION_CLASSES.get(cp.persistent_class))
        if not cp.persistent_key:
            return
        fk = self.volume.getFileKeyForCprotect(cprotect)
        if fk:
            print "Unwrapped file key : %s" % fk.encode("hex")
        else:
            print "Cannot decrypt file key"


    def do_open(self, p):
        path = self.get_path(p)
        if self.volume.readFile(path):
            os.startfile(os.path.basename(path))

    def do_xxd(self, p):
        t = p.split()
        path = self.get_path(t[0])
        data = self.volume.readFile(path, returnString=True)
        if not data:
            return
        if len(t) > 1:
            hexdump(data[:int(t[1])])
        else:
            hexdump(data[:0x200])
            if len(data) > 0x200:
                print "Output truncated to %d bytes" % 0x200
    
    def do_effaceable(self, p):
        print "Effaceable Lockers"
        for k,v in self.image.lockers.lockers.items():
            print "%s: %s" % (k, v.encode("hex"))
    
    def do_BAG1(self, p):
        print "BAG1 locker from effaceable storage"
        bag1 = self.image.lockers.get("BAG1")
        hexdump(bag1)
        print "IV:", bag1[4:20].encode("hex")
        print "Key:", bag1[20:].encode("hex")
    
    def do_keybag(self, p):
        self.data.keybag.printClassKeys()
        
    def do_plist(self, p):
        d = None
        data = self.volume.readFile(self.get_path(p), returnString=True)
        if data:
            d = parsePlist(data)
            pprint(d)
        else:
            try:
                d = readPlist(p)
                if d: pprint(d)
            except:
                pass
        if d and d.has_key("_MKBIV"):
            print "=>System keybag file"
            print "_MKBPAYLOAD: encrypted"
            print "_MKBIV: %s" % d["_MKBIV"].data.encode("hex")
            print "_MKBWIPEID: 0x%x (%s)" % (d["_MKBWIPEID"], ("%x"%(d["_MKBWIPEID"])).decode("hex"))
    
    def do_bruteforce(self, p):
        if bruteforcePasscode(self.image.device_infos, self.data):
            print "Keybag state: %slocked" % (int(self.data.keybag.unlocked) * "un")
            self.do_save("")
    
    def do_ptable(self, p):
        pt = self.image.getPartitionTable()
        print "Block device partition table"
        print "".join(map(lambda x:x.ljust(12), ["Index", "Name", "Start LBA", "End LBA", "Size"]))
        for i in xrange(len(pt)):
            p = pt[i]
            print "".join(map(lambda x:str(x).ljust(12), [i, p.name, p.first_lba, p.last_lba, sizeof_fmt((p.last_lba - p.first_lba)*self.image.pageSize)])) 

    def do_nand_dump(self, p):
        if len(p)==0:
            print "Usage: nand_dump my_nand.bin"
            return
        self.image.dump(p)

    def do_dd(self, p):
        if len(p)==0:
            print "Usage: dd output_file.dmg"
            return
        self.volume.bdev.dumpToFile(p.split()[0])
        
    def do_img3(self, p):
        self.image.extract_img3s("./")
    
    def do_shsh(self, p):
        self.image.extract_shsh()

    def _pull__and_open_sqlitedb(self, path):
        outdir = "/tmp/"
        self.volume.readFile(path, outdir)
        self.volume.readFile(path + "-shm", outdir)
        if self.volume.readFile(path + "-wal", outdir):
            if sqlite3.sqlite_version < "3.7":
                print "Python sqlite3 version %s < 3.7" % (sqlite3.sqlite_version)
                print "Please update python sqlite dll to use this feature on iOS 6+ images (WAL)"
                return
        dbpath = os.path.join(outdir, os.path.basename(path))
        print dbpath
        return sqlite3.connect(dbpath)

    def do_sms(self, p):
        conn = self._pull__and_open_sqlitedb("/mobile/Library/SMS/sms.db")
        if not conn: return
        #http://linuxsleuthing.blogspot.fr/2012/10/whos-texting-ios6-smsdb.html
        z = conn.execute("""SELECT
            DATETIME(date + 978307200, 'unixepoch', 'localtime') as Date,
              h.id as "Phone Number",
                CASE is_from_me
                WHEN 0 THEN "Received"
                WHEN 1 THEN "Sent"
                ELSE "Unknown"
                  END as Type,
              text as Text
              FROM message m, handle h
              WHERE h.rowid = m.handle_id
              ORDER BY Date ASC;""")

        print " ".join(["Date".ljust(20), "To/From".ljust(12), "Text"])
        for row in z.fetchall():
            print row[0].ljust(21) + row[1].ljust(13) + row[3][:80]

    def do_contacts(self, p):
        conn = self._pull__and_open_sqlitedb("/mobile/Library/AddressBook/AddressBook.sqlitedb")
        if not conn: return
        #https://gist.github.com/laacz/1180765
        conn = sqlite3.connect("AddressBook.sqlitedb")
        z = conn.execute("""select ABPerson.first,
                                 ABPerson.last,
                                 ABPerson.Organization as organization,
                                 (select value from ABMultiValue where property = 4 and record_id = ABPerson.ROWID LIMIT 1) as email
                                 from ABPerson
                                order by ABPerson.ROWID;""")

        print "".join(["First name".ljust(15), "Last name".ljust(15), "Organization".ljust(15), "Email"])
        for row in z.fetchall():
            row = map(str, row)
            print row[0].ljust(15) + row[1].ljust(15) + row[2].ljust(15) + row[3]

    def do_email(self, p):
        conn = self._pull__and_open_sqlitedb("/mobile/Library/Mail/Protected Index")
        #conn = self._pull__and_open_sqlitedb("/mobile/Library/Mail/Envelope Index")
        z = conn.execute("SELECT message_id, sender, _to, subject from messages")
        print "  ".join(map(lambda x:x.ljust(40), ["From", "To", "Subject"]))
        for row in z.fetchall():
            print "  ".join(map(lambda x:x.ljust(40)[:40], row[1:]))

    def do_debug(self,p):
        from IPython.Shell import IPShellEmbed
        ipshell = IPShellEmbed()
        ipshell(local_ns=locals())
   
def main():
    parser = OptionParser(usage="%prog [options] nand_image.bin device_infos.plist")
    (options, args) = parser.parse_args()

    if sys.platform == "darwin":
        import readline
        import rlcompleter
        #fix tab complete on osx
        if readline.__doc__ and "libedit" in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

    if len(args) >= 2:
        plistname = args[1]
        nandimagename = args[0]
        device_infos = plistlib.readPlist(plistname)
        print "Loading device information from %s" % plistname
    else:
        nandimagename ="remote"
        client = RamdiskToolClient.get()
        device_infos = client.device_infos
    print_device_infos(device_infos)
    image = NAND(nandimagename, device_infos)

    ExaminerShell(image).cmdloop("")
    
if __name__ == "__main__":
    main()
