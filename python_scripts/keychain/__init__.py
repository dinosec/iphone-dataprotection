import sqlite3
from keychain3 import Keychain3
from keychain4 import Keychain4

def keychain_load(filename, keybag, key835):
    version = sqlite3.connect(filename).execute("SELECT version FROM tversion").fetchone()[0]
    #print "Keychain version : %d" % version
    if version == 3:
        return Keychain3(filename, key835)
    elif version >= 4:
        return Keychain4(filename, keybag)
    raise Exception("Unknown keychain version %d" % version)
