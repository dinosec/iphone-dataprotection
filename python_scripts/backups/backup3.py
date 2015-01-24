from crypto.PBKDF2 import PBKDF2
from crypto.aes import AESdecryptCBC
from util import read_file, write_file, makedirs, readPlist
from util.bplist import BPlistReader
import hashlib
import struct
import glob
import sys
import os
import re

"""
decrypt iOS 3 backup blob (metadata and file contents)
"""

def decrypt_blob(blob, auth_key):
    len = struct.unpack(">H", blob[0:2])[0]
    if len != 66:
        print "blob len != 66"
    magic = struct.unpack(">H", blob[2:4])[0]
    if magic != 0x0100:
        print "magic != 0x0100"
    iv = blob[4:20]
    
    blob_key = AESdecryptCBC(blob[20:68], auth_key, iv)[:32]

    return AESdecryptCBC(blob[68:], blob_key, iv, padding=True)

def decrypt_backup3(backupfolder, outputfolder, passphrase):
    auth_key = None
    manifest = readPlist(backupfolder + "/Manifest.plist")
        
    if manifest["IsEncrypted"]:
        manifest_data = manifest["Data"].data
    
        authdata = manifest["AuthData"].data
    
        pkbdf_salt = authdata[:8]
        iv = authdata[8:24]
        key = PBKDF2(passphrase,pkbdf_salt,iterations=2000).read(32)
    
        data = AESdecryptCBC(authdata[24:], key, iv)
        auth_key = data[:32]
    
        if hashlib.sha1(auth_key).digest() != data[32:52]:
            print "wrong auth key (hash mismatch) => wrong passphrase"
            return
    
        print "Passphrase seems OK"

    for mdinfo_name in glob.glob(backupfolder + "/*.mdinfo"):

        mddata_name = mdinfo_name[:-7] + ".mddata"
        mdinfo = readPlist(mdinfo_name)
        metadata = mdinfo["Metadata"].data
        if mdinfo["IsEncrypted"]:
            metadata = decrypt_blob(metadata, auth_key)
        metadata = BPlistReader.plistWithString(metadata)
            
        print metadata["Path"]
        
        filedata = read_file(mddata_name)
        if mdinfo["IsEncrypted"]:
            filedata = decrypt_blob(filedata, auth_key)
        
        filename = re.sub(r'[:|*<>?"]', "_", metadata["Path"])
        makedirs(outputfolder + "/" + os.path.dirname(filename))
        write_file(outputfolder + "/" + filename, filedata)
