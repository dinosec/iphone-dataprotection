import plistlib
import sqlite3
import struct
from util import readPlist

class KeychainStore(object):
    def __init__(self):
        pass
    
    def convertDict(self, d):
        return d
    
    def returnResults(self, r):
        for a in r:
            yield self.convertDict(a)
    
    def get_items(self, table):
        return []

class SQLiteKeychain(KeychainStore):
    def __init__(self, filename):
        self.conn = sqlite3.connect(filename)
        self.conn.row_factory = sqlite3.Row
        
    def convertDict(self, row):
        d = dict(row)
        for k,v in d.items():
            if type(v) == buffer:
                d[k] = str(v)
        return d
    
    def get_items(self, table):
        sql = {"genp": "SELECT rowid, data, svce, acct, agrp FROM genp",
               "inet": "SELECT rowid, data, acct, srvr, port, agrp FROM inet",
               "cert": "SELECT rowid, data, pkhh, agrp FROM cert",
               "keys": "SELECT rowid, data, klbl, agrp FROM keys"}
        return self.returnResults(self.conn.execute(sql[table]))
        
class PlistKeychain(KeychainStore):
    def __init__(self, filename):
        self.plist = readPlist(filename)

    def convertDict(self, d):
        for k, v in d.items():
            if isinstance(v, plistlib.Data):
                if k == "v_Data":
                    d["data"] = v.data
                elif k == "v_PersistentRef":
                    #format tablename (4 chars) + rowid (64 bits)
                    d["rowid"] = struct.unpack("<Q", v.data[-8:])[0]
                else:
                    d[k] = v.data
        return d
    
    def get_items(self, table):
        return self.returnResults(self.plist.get(table, []))
