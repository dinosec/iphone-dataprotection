import os
import re
import sqlite3
import plistlib

from Crypto.Cipher import AES

from util import readPlist, makedirs, parsePlist

def warn(msg):
    print "WARNING: %s" % msg

MASK_SYMBOLIC_LINK = 0xa000
MASK_REGULAR_FILE = 0x8000
MASK_DIRECTORY = 0x4000

class MBFile(object):
    def __init__(self, domain, relative_path, flags, file_blob):
        self.domain = domain
        self.relative_path = relative_path
        self.flags = flags
        self.file_info = parsePlist(str(file_blob))

        self._parse_file_info()

    def _parse_file_info(self):
        self.file_hash = None
        if isinstance(self.file_info['$objects'][3], plistlib.Data):
            self.file_hash = self.file_info['$objects'][3]
        self.protection_class = 0
        self.encryption_key = None
        self.protection_class = self.file_info['$objects'][1]['ProtectionClass']
        self.file_size = self.file_info['$objects'][1]['Size']
        self.mode = self.file_info['$objects'][1]['Mode']
        if len(self.file_info['$objects']) >= 5 and type(self.file_info['$objects'][4]) == dict:
            if self.file_info['$objects'][4].has_key('NS.data'):
                self.encryption_key = self.file_info['$objects'][4]['NS.data'].data

        self.target = None
        if self.is_symbolic_link() and isinstance(self.file_info['$objects'][3], str):
            self.target  = self.file_info['$objects'][3]
        # print self.encryption_key
        # print self.file_size
        # print "is regular file", " yes" if self.is_regular_file() else "no"

        if self.is_symbolic_link():
            print self.relative_path
            print self.target


    def type(self):
        return self.mode & 0xf000

    def is_symbolic_link(self):
        return self.type() == MASK_SYMBOLIC_LINK

    def is_regular_file(self):
        return self.type() == MASK_REGULAR_FILE

    def is_directory(self):
        return self.type() == MASK_DIRECTORY

class ManifestDB(object):
    def __init__ (self, path):
        self.files = {}
        self.backup_path = path
        self.keybag = None

        conn = sqlite3.connect(os.path.join(path,'Manifest.db'))

        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            for record in cursor.execute("SELECT fileID, domain, relativePath, flags, file FROM Files"):
                filename = record[0]
                domain = record[1]
                relative_path = record[2]
                flags = record[3]
                file_blob = record[4]
                self.files[filename] = MBFile(domain, relative_path, flags, file_blob)

        finally:
            conn.close()


    def extract_backup(self, output_path):
        for mbfile in self.files.itervalues():
            if mbfile.is_directory():
                record_path = re.sub(r'[:|*<>?"]', "_", mbfile.relative_path)
                path = os.path.join(output_path, mbfile.domain, record_path)
                if not os.path.exists(path):
                    os.makedirs(path)

        for filename, mbfile in self.files.iteritems():
            if mbfile.is_regular_file() or mbfile.is_symbolic_link():
                self._extract_file(filename, mbfile, output_path)

    def _extract_file(self, filename, record, output_path):
         # adjust output file name
        if record.is_symbolic_link():
            out_file = record.target
        else:
            out_file = record.relative_path

        try:
            f1 = file(os.path.join(self.backup_path, filename[:2] ,filename), 'rb')

        except:
            warn("File %s (%s) has not been found" % (os.path.join(filename[:2] ,filename), record.relative_path))
            return


        # write output file
        out_file = re.sub(r'[:|*<>?"]', "_", out_file)
        output_path = os.path.join(output_path, record.domain, out_file)
        print("Writing %s" % output_path)
        f2 = file(output_path, 'wb')

        aes = None

        if record.encryption_key is not None and self.keybag: # file is encrypted!
            key = self.keybag.unwrapKeyForClass(record.protection_class, record.encryption_key[4:])
            if not key:
                warn("Cannot unwrap key")
                return
            aes = AES.new(key, AES.MODE_CBC, "\x00"*16)

        while True:
            data = f1.read(8192)
            if not data:
                break
            if aes:
                data2 = data = aes.decrypt(data)
            f2.write(data)

        f1.close()
        if aes:
            c = data2[-1]
            i = ord(c)
            if i < 17 and data2.endswith(c*i):
                f2.truncate(f2.tell() - i)
            else:
                warn("Bad padding, last byte = 0x%x !" % i)

        f2.close()
