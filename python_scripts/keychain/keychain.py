from store import PlistKeychain, SQLiteKeychain
from util import write_file
from util.asciitables import print_table
from util.bplist import BPlistReader
from util.cert import RSA_KEY_DER_to_PEM, CERT_DER_to_PEM
try: import M2Crypto
except: M2Crypto = None
import hashlib
import plistlib
import sqlite3
import string
import struct

KSECATTRACCESSIBLE = {
    6: "kSecAttrAccessibleWhenUnlocked",
    7: "kSecAttrAccessibleAfterFirstUnlock",
    8: "kSecAttrAccessibleAlways",
    9: "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    10: "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    11: "kSecAttrAccessibleAlwaysThisDeviceOnly"
}
printset = set(string.printable)

def render_password(p):
    data = p["data"]
    if data != None and data.startswith("bplist") and data.find("\x00") != -1:
        pl = BPlistReader.plistWithString(p["data"])
        filename = "%s_%s_%d.plist" % (p["svce"],p["acct"],p["rowid"])
        plistlib.writePlist(pl, filename)
        #write_file("bin_"+filename, p["data"])
        data = filename

    if p.has_key("srvr"):
        return "%s:%d;%s;%s" % (p["srvr"],p["port"],p["acct"],data)
    else:
        return "%s;%s;%s" % (p["svce"],p["acct"],data)

def get_CN_from_der_cert(der):
    if not M2Crypto:
        return ""
    cert = M2Crypto.X509.load_cert_der_string(der)
    subject = cert.get_subject().as_text()
    common_name = cert.get_subject().get_entries_by_nid(M2Crypto.X509.X509_Name.nid['CN'])
    if len(common_name):
        return str(common_name[0].get_data())
    else:
        return ""

class Keychain(object):
    def __init__(self, filename):
        magic = open(filename, "rb").read(16)
        if magic.startswith("SQLite"):
            self.store = SQLiteKeychain(filename)
        elif magic.startswith("bplist"):
            self.store = PlistKeychain(filename)
        else:
            raise Exception("Unknown keychain format for %s" % filename)
        self.bsanitize = True
        self.items = {"genp": None, "inet": None, "cert": None, "keys": None}
        
    def decrypt_data(self, data):
        return data #override this method

    def decrypt_item(self, res):
        res["data"] = self.decrypt_data(res["data"])
        if not res["data"]:
            return {}             
        return res

    def get_items(self, table):
        if self.items[table]:
            return self.items[table]
        self.items[table] = filter(lambda x:x!={}, map(self.decrypt_item, self.store.get_items(table)))
        return self.items[table]

    def get_passwords(self):
        return self.get_items("genp")

    def get_inet_passwords(self):
        return self.get_items("inet")

    def get_keys(self):
        return self.get_items("keys")

    def get_cert(self):
        return self.get_items("cert")

    def get_certs(self):
        certs = {}
        pkeys = {}
        if not M2Crypto:
            print "M2Crypto missing for get_certs"
            return certs, pkeys
        keys = self.get_keys()
        for row in self.get_cert():
            subject = get_CN_from_der_cert(row["data"])
            if not subject:
                subject = "cn_unknown_%d" % row["rowid"]
            certs[subject+ "_%s" % row["agrp"]] = cert
            
            #print subject
            #print "Access :\t" + KSECATTRACCESSIBLE.get(row["clas"])
            
            for k in keys:
                if k["agrp"] == row["agrp"] and k["klbl"] == row["pkhh"]:
                    pkey_der = k["data"]
                    pkey_der = RSA_KEY_DER_to_PEM(pkey_der)
                    pkeys[subject + "_%s" % row["agrp"]] = pkey_der
                    break

        return certs, pkeys


    def save_passwords(self):
        passwords = "\n".join(map(render_password,  self.get_passwords()))
        inetpasswords = "\n".join(map(render_password,  self.get_inet_passwords()))
        print "Writing passwords to keychain.csv"
        write_file("keychain.csv", "Passwords;;\n"+passwords+"\nInternet passwords;;\n"+ inetpasswords)

    def save_certs_keys(self):
        certs, pkeys = self.get_certs()
        for c in certs:
            filename = c + ".crt"
            print "Saving certificate %s" % filename
            certs[c].save_pem(filename)
        for k in pkeys:
            filename = k + ".key"
            print "Saving key %s" % filename
            write_file(filename, pkeys[k])

    def sanitize(self, pw):
        if pw.startswith("bplist"):
            return "<binary plist data>"
        elif not set(pw).issubset(printset):
            pw = ">"+ pw.encode("hex")
            #pw = "<binary data> : " + pw.encode("hex")
        if self.bsanitize:
            return pw[:2] + ("*" * (len(pw) - 2))
        return pw

    def print_all(self, sanitize=True):
        self.bsanitize = sanitize
        headers = ["Service", "Account", "Data", "Access group", "Protection class"]
        rows = []
        for p in self.get_passwords():
            row = [p.get("svce","?"),
                   str(p.get("acct","?"))[:40],
                   self.sanitize(p.get("data","?"))[:20],
                   p.get("agrp","?"),
                   KSECATTRACCESSIBLE.get(p["clas"])[18:]]
            rows.append(row)
        
        print_table("Passwords", headers, rows)

        headers = ["Server", "Account", "Data", "Access group", "Protection class"]
        rows = []

        for p in self.get_inet_passwords():
            addr = "?"
            if p.has_key("srvr"):
                addr = p["srvr"] + ":" + str(p["port"])
            row = [addr,
                   str(p.get("acct","?")),
                   self.sanitize(p.get("data","?"))[:20],
                   p.get("agrp","?"),
                   KSECATTRACCESSIBLE.get(p["clas"])[18:]]
            rows.append(row)

        print_table("Internet Passwords", headers, rows)

        headers = ["Id", "Common Name", "Access group", "Protection class"]
        rows = []
        c  = {}

        for row in self.get_cert():
            subject = "?"
            if row.has_key("data"):
                subject = get_CN_from_der_cert(row["data"])
                if not subject:
                    subject = "cn_unknown_%d" % row["rowid"]
                c[hashlib.sha1(str(row["pkhh"])).hexdigest() + row["agrp"]] = subject
            row = [str(row["rowid"]), 
                   subject[:81],
                   row.get("agrp","?")[:31],
                   KSECATTRACCESSIBLE.get(row["clas"])[18:]
                   ]
            rows.append(row)
        
        print_table("Certificates", headers, rows)
        
        headers = ["Id", "Label", "Common Name", "Access group", "Protection class"]
        rows = []
        for row in self.get_keys():
            subject = ""
            if row.has_key("klbl"):
                subject = c.get(hashlib.sha1(str(row["klbl"])).hexdigest() + row["agrp"], "")
            row = [str(row["rowid"]), row.get("labl", "?")[:30], subject[:39], row.get("agrp","?")[:31],
                KSECATTRACCESSIBLE.get(row["clas"])[18:]]
            rows.append(row)
        print_table("Keys", headers, rows)

    def get_push_token(self):
        for p in self.get_passwords():
            if p["svce"] == "push.apple.com":
                return p["data"]
    
    def get_managed_configuration(self):
        for p in self.get_passwords():
            if p["acct"] == "Private" and p["svce"] == "com.apple.managedconfiguration" and p["agrp"] == "apple":
                return BPlistReader.plistWithString(p["data"])
    
    def _diff(self, older, res, func, key):
        res.setdefault(key, []) 
        current = func(self)  
        for p in func(older):
            if not p in current and not p in res[key]:
                res[key].append(p)

    def diff(self, older, res):
        self._diff(older, res, Keychain.get_passwords, "genp")
        self._diff(older, res, Keychain.get_inet_passwords, "inet")
        self._diff(older, res, Keychain.get_cert, "cert")
        self._diff(older, res, Keychain.get_keys, "keys")

    def cert(self, rowid, filename=""):
        for row in self.get_cert():
            if row["rowid"] == rowid:
                blob = CERT_DER_to_PEM(row["data"])
                if filename:
                    write_file(filename, blob)
                if not M2Crypto: continue
                cert = M2Crypto.X509.load_cert_der_string(row["data"])
                print cert.as_text()
                return

    def key(self, rowid, filename=""):
        for row in self.get_keys():
            if row["rowid"] == rowid:
                blob =  RSA_KEY_DER_to_PEM(row["data"])
                if filename:
                    write_file(filename, blob)
                #k = M2Crypto.RSA.load_key_string(blob)
                print blob
                return

