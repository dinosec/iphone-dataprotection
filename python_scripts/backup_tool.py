#!/usr/bin/python
from backups.backup3 import decrypt_backup3
from backups.backup4 import MBDB
from keystore.keybag import Keybag
from util import readPlist, makedirs
import os
import sys
import plistlib

showinfo = ["Device Name", "Display Name", "Last Backup Date", "IMEI",
            "Serial Number", "Product Type", "Product Version", "iTunes Version"]

def extract_backup(backup_path, output_path, password=""):
    if not os.path.exists(backup_path + "/Manifest.plist"):
        print "Manifest.plist not found"
        return
    manifest = readPlist(backup_path + "/Manifest.plist")
    
    info = readPlist( backup_path + "/Info.plist")
    for i in showinfo:
        print i + " : " + unicode(info.get(i, "missing"))
    
    print "Extract backup to %s ? (y/n)" % output_path
    if raw_input() == "n":
        return
    
    print "Backup is %sencrypted" % (int(not manifest["IsEncrypted"]) * "not ")
    
    if manifest["IsEncrypted"] and password == "":
        print "Enter backup password : "
        password = raw_input()
    
    if not manifest.has_key("BackupKeyBag"):
        print "No BackupKeyBag in manifest, assuming iOS 3.x backup"
        decrypt_backup3(backup_path, output_path, password)
    else:    
        mbdb = MBDB(backup_path)
    
        kb = Keybag.createWithBackupManifest(manifest, password)
        if not kb:
            return
        manifest["password"] = password
        makedirs(output_path)
        plistlib.writePlist(manifest, output_path + "/Manifest.plist")
       
        mbdb.keybag = kb
        mbdb.extract_backup(output_path)
        
        print "You can decrypt the keychain using the following command : "
        print "python keychain_tool.py -d \"%s\" \"%s\"" % (output_path + "/KeychainDomain/keychain-backup.plist", output_path + "/Manifest.plist")

def extract_all():
    if sys.platform == "win32":
        mobilesync = os.environ["APPDATA"] + "/Apple Computer/MobileSync/Backup/"
    elif sys.platform == "darwin":
        mobilesync = os.environ["HOME"] + "/Library/Application Support/MobileSync/Backup/"
    else:
        print "Unsupported operating system"
        return
    print "-" * 60
    print "Searching for iTunes backups"
    print "-" * 60
    
    for udid in os.listdir(mobilesync):
        extract_backup(mobilesync + "/" + udid, udid + "_extract")

def main():
    if len(sys.argv) < 2:
        print "Usage: %s <backup path> [output path]" % sys.argv[0]
        return
    backup_path = sys.argv[1]
    output_path = os.path.dirname(backup_path) + "_extract"
    if len(sys.argv) >= 3:
        output_path = sys.argv[2]

    if backup_path == "icloud":
        from icloud.backup import download_backup
        print "Downloading iCloud backup"
        download_backup(None, None, output_path)
    else:
        extract_backup(backup_path, output_path)

if __name__ == "__main__":
    main()
