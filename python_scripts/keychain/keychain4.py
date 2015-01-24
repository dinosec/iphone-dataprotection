from crypto.aes import AESdecryptCBC
import struct
from pyasn1.codec.der.decoder import decode as der_decode

"""
    iOS 4 keychain-2.db data column format

    version     0x00000000
    key class   0x00000008
                kSecAttrAccessibleWhenUnlocked                      6
                kSecAttrAccessibleAfterFirstUnlock                  7
                kSecAttrAccessibleAlways                            8
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly        9
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly    10
                kSecAttrAccessibleAlwaysThisDeviceOnly              11
    wrapped AES256 key 0x28 bytes  (passed to kAppleKeyStoreKeyUnwrap)
    encrypted data (AES 256 CBC zero IV)
"""
from keychain import Keychain
from crypto.gcm import gcm_decrypt
from util.bplist import BPlistReader

KSECATTRACCESSIBLE = {
    6: "kSecAttrAccessibleWhenUnlocked",
    7: "kSecAttrAccessibleAfterFirstUnlock",
    8: "kSecAttrAccessibleAlways",
    9: "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    10: "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    11: "kSecAttrAccessibleAlwaysThisDeviceOnly"
}

class Keychain4(Keychain):
    def __init__(self, filename, keybag):
        if not keybag.unlocked:
            print "Keychain object created with locked keybag, some items won't be decrypted"
        Keychain.__init__(self, filename)
        self.keybag = keybag

    def decrypt_item(self, row):
        version, clas = struct.unpack("<LL", row["data"][0:8])
        clas &= 0xF
        if self.keybag.isBackupKeybag():
            if clas >= 9 and not self.keybag.deviceKey:
                return {}
        if version >= 2:
            dict = self.decrypt_blob(row["data"])
            if not dict:
                return {"clas": clas, "rowid": row["rowid"]}
            if dict.has_key("v_Data"):
                try:
                  dict["data"] = dict["v_Data"].data
                except AttributeError:
                  dict["data"] = dict["v_Data"]
            else:
                dict["data"] = ""
            dict["rowid"] = row["rowid"]
            dict["clas"] = clas
            return dict
        row["clas"] = clas
        return Keychain.decrypt_item(self, row)

    def decrypt_data(self, data):
        data = self.decrypt_blob(data)
        if type(data) == dict:
            return data["v_Data"].data
        return data

    def decrypt_blob(self, blob):
        if blob == None:
            return ""
        
        if len(blob) < 48:
            print "keychain blob length must be >= 48"
            return

        version, clas = struct.unpack("<LL",blob[0:8])
        clas &= 0xF
        self.clas=clas
        if version == 0:
            wrappedkey = blob[8:8+40]
            encrypted_data = blob[48:]
        elif version == 2:
            l = struct.unpack("<L",blob[8:12])[0]
            wrappedkey = blob[12:12+l]
            encrypted_data = blob[12+l:-16]
        elif version == 3:
          l = struct.unpack("<L",blob[8:12])[0]
          wrappedkey = blob[12:12+l]
          encrypted_data = blob[12+l:-16]
        else:
            raise Exception("unknown keychain verson ", version)
            return
        
        unwrappedkey = self.keybag.unwrapKeyForClass(clas, wrappedkey, False)
        if not unwrappedkey:
            return

        if version == 0:
            return AESdecryptCBC(encrypted_data, unwrappedkey, padding=True)
        elif version == 2:
            binaryplist = gcm_decrypt(unwrappedkey, "", encrypted_data, "", blob[-16:])
            return BPlistReader(binaryplist).parse()
        elif version == 3:
            der = gcm_decrypt(unwrappedkey, "", encrypted_data, "", blob[-16:])
            stuff = der_decode(der)[0]
            rval = {}
            for k,v in stuff:
              k = str(k)
              # NB - this is binary and may not be valid UTF8 data
              v = str(v)
              rval[k] = v
            return rval

