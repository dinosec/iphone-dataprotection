from keychain import Keychain
from crypto.aes import AESdecryptCBC, AESencryptCBC
import hashlib

class Keychain3(Keychain):
    def __init__(self, filename, key835=None):
        Keychain.__init__(self, filename)
        self.key835 = key835
        
    def decrypt_data(self, data):
        if data == None:
            return ""
        data = str(data)
        
        if not self.key835:
            print "Key 835 not availaible"
            return ""
        
        data = AESdecryptCBC(data[16:], self.key835, data[:16], padding=True)
        
        #data_column = iv + AES128_K835(iv, data + sha1(data))
        if hashlib.sha1(data[:-20]).digest() != data[-20:]:
            print "data field hash mismatch : bad key ?"
            return "ERROR decrypting data : bad key ?"

        return data[:-20]
    
    def change_key835(self, newkey):
        tables = {"genp": "SELECT rowid, data FROM genp",
                  "inet": "SELECT rowid, data FROM inet",
                  "cert": "SELECT rowid, data FROM cert",
                  "keys": "SELECT rowid, data FROM keys"}
        
        for t in tables.keys():
            for row in self.conn.execute(tables[t]):
                rowid = row["rowid"]
                data = str(row["data"])
                iv = data[:16]
                data = AESdecryptCBC(data[16:], self.key835, iv)
                data = AESencryptCBC(data, newkey, iv)
                data = iv + data
                data = buffer(data)
                self.conn.execute("UPDATE %s SET data=? WHERE rowid=?" % t, (data, rowid))
        self.conn.commit()