#!/usr/bin/env python

# Script to take a dictionary of passwords and try them against an encrypted backup
#
# Uses code created at https://code.google.com/archive/p/iphone-dataprotection/ 
# speficically the python_scripts/backup_tool.py and its dependancies
# Referenced from http://stackoverflow.com/questions/1498342/how-to-decrypt-an-encrypted-apple-itunes-iphone-backup
#

# System imports
from crypto.PBKDF2 import PBKDF2
from crypto.aeswrap import AESUnwrap
from Crypto.Hash import SHA256
from keystore.keybag import Keybag, BACKUP_KEYBAG, OTA_KEYBAG, WRAP_DEVICE, WRAP_PASSCODE
from util import readPlist
import os
import sys

def main():
  # Get the arguments
  if len(sys.argv) != 3:
    print "Usage: backup_passwd_guess.py iOS_Backup_Dir Password_Dictionary"
    sys.exit(1)
  backup = sys.argv[1]
  pwddict = sys.argv[2]

  # Open the manifest plist
  manifest_loc = backup + "/Manifest.plist"
  if not os.path.exists(manifest_loc):
    print "Can't find Manifest.plist - bad backup?"
    sys.exit(1)
  manifest = readPlist(manifest_loc)

  # Open the dictionary
  if not os.path.exists(pwddict):
    print "Can't find dictionary"
    sys.exit(1)
  dictfile = open(pwddict)

  # Get the backup information
  info = readPlist(backup + "/Info.plist")
  print "Backup Details:"
  print "  Device:   %s" % (info['Product Name'])
  print "  Serial:   %s" % (info['Serial Number'])
  print "  Firmware: %s" % (info['Product Version'])
  print ""

  # Make sure the backup is encrypted
  if not manifest["IsEncrypted"]:
    print "Backup is not encrypted"
    sys.exit(1)

  # Determine if we have the new format of the backup encryption
  iosFlag = False
  if 'ManifestKey' in manifest:
    print "***** Backup is encrypted using newer algorithm. Time per try is now minutes instead of seconds *****"
    print ""
    iosFlag = True

  # Get the keybag
  kb = Keybag(manifest["BackupKeyBag"].data)
  kb.deviceKey = None
  if kb.type != BACKUP_KEYBAG and kb.type != OTA_KEYBAG:
    print "Backup does not contain a backup keybag"
    sys.exit(1)
  salt = kb.attrs["SALT"]
  iter = kb.attrs["ITER"]
  if iosFlag:
    dpsl = kb.attrs["DPSL"]
    dpic = kb.attrs["DPIC"]

  # Loop through the passwords in the file
  while True:
    password = dictfile.readline()
    if password == "":
      break
    password = password[:-1]
    opassword = password
    print "Trying %s" % (opassword)

    # Check the password
    if iosFlag:
      password = PBKDF2(password, dpsl, iterations = dpic, digestmodule=SHA256).read(32)
    code = PBKDF2(password, salt, iterations=iter).read(32)
    success = 0
    for classkey in kb.classKeys.values():
      k = classkey["WPKY"]
      if classkey["WRAP"] & WRAP_PASSCODE:
        k = AESUnwrap(code, classkey["WPKY"])
        if not k:
          success = 1
          break
      if classkey["WRAP"] & WRAP_DEVICE:
        if not kb.deviceKey:
          continue
        k = AESdecryptCBC(k, kb.deviceKey)
    if success == 0:
      print "Password found - ",opassword
      break

if __name__ == "__main__":
  main()
