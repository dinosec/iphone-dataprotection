import os
import re
import sqlite3
import plistlib

from Crypto.Cipher import AES

from util import readPlist, makedirs, parsePlist
from util import bplist

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
        objects = self.file_info['$objects']
        if objects[1].has_key('Digest'):
            if isinstance(objects[1]['Digest'], plistlib.Data):
                self.file_hash = objects[1]['Digest']
            elif isinstance(objects[1]['Digest'], bplist.BPListUID) and len(objects) >= objects[1]['Digest'].uid:
                p = objects[objects[1]['Digest'].uid]
                if isinstance(p, plistlib.Data):
                    self.file_hash = p.data
                elif isinstance(p, dict) and p.has_key('NS.data'):
                    self.file_hash = p['NS.data']

        self.protection_class = 0
        self.encryption_key = None
        self.protection_class = objects[1]['ProtectionClass']
        self.file_size = objects[1]['Size']
        self.mode = objects[1]['Mode']
        self.encryption_key = None

        if objects[1].has_key('EncryptionKey'):
            if isinstance(objects[1]['EncryptionKey'], plistlib.Data):
                self.encryption_key = objects[1]['EncryptionKey']
            elif isinstance(objects[1]['EncryptionKey'], bplist.BPListUID) and len(objects) >= objects[1]['EncryptionKey'].uid:
                p = objects[objects[1]['EncryptionKey'].uid]
                if isinstance(p, plistlib.Data):
                    self.encryption_key = p.data
                elif isinstance(p, dict) and p.has_key('NS.data'):
                    self.encryption_key = p['NS.data'].data

        self.target = None
        if objects[1].has_key('Target'):
            if isinstance(objects[1]['Target'], str):
                self.target = objects[1]['Target']
            elif isinstance(objects[1]['Target'], bplist.BPListUID) and len(objects) >= objects[1]['Target'].uid:
                p = objects[objects[1]['Target'].uid]
                if isinstance(p, str):
                    self.target = p
                elif isinstance(p, dict) and p.has_key('NS.string'):
                    self.target = p['NS.string']


    def type(self):
        return self.mode & 0xf000

    def is_symbolic_link(self):
        return self.type() == MASK_SYMBOLIC_LINK

    def is_regular_file(self):
        return self.type() == MASK_REGULAR_FILE

    def is_directory(self):
        return self.type() == MASK_DIRECTORY


class ManifestDB(object):
    def __init__ (self, path, key=None):
        self.files = {}
        self.backup_path = path
        self.keybag = None

        mdb_path = os.path.join(path,'Manifest.db')

        #If a key is provided, try to decrypt the DB
        if key:
            mdb_path_encrypted = mdb_path
            mdb_path = os.path.join(path,'Manifest.db-decrypted')
            self.decrypt_manifest_db(mdb_path_encrypted, mdb_path, key)

        conn = sqlite3.connect(mdb_path)

        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            for record in cursor.execute("SELECT fileID, domain, relativePath, flags, file FROM Files"):
                filename = record[0]
                domain = record[1]
                relative_path = record[2]
                flags = record[3]
                file_blob = record[4]
                if flags == 16:
                    warn("Flags == 16 for {0} {1} ({2})".format(domain, relative_path, file_blob))
                else:
                    self.files[filename] = MBFile(domain, relative_path, flags, file_blob)

        finally:
            conn.close()

    @staticmethod
    def decrypt_manifest_db(path_in, path_out, key):
        """
        Will decrypt the Manifest.db file using the provided key.

        TODO: merge with method _extract_file
        """
        aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
        
        f_in = file(path_in, 'rb')
        f_out = file(path_out, 'wb')
        
        while True:
            data = f_in.read(8192)
            if not data:
                break

            data2 = data = aes.decrypt(data)
            f_out.write(data)
        
        f_in.close()

        c = data2[-1]
        i = ord(c)

        if i < 17 and data2.endswith(c*i):
            f_out.truncate(f_out.tell() - i)

        else:
            print "Bad padding, last byte = 0x%x !" % i

        f_out.close()

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

        try:
            f2 = file(output_path, 'wb')
        
        except:
            warn("File %s could not be created (path too long?)" % output_path)
            return

        aes = None

        if record.encryption_key is not None and self.keybag: # file is encrypted!
            key = self.keybag.unwrapKeyForClass(record.protection_class, record.encryption_key[4:])
            if not key:
                warn("Cannot unwrap key for {0}".format(out_file))
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
