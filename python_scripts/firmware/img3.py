from crypto.aes import AESdecryptCBC
from util import read_file, write_file
from util.ramdiskclient import RamdiskToolClient
try: import M2Crypto
except: M2Crypto = None
import struct
import hashlib
import os
import sys

def decryptGID(data):
    try:
        client = RamdiskToolClient.get()
    except:
        return None
    r = client.aesGID(data)
    if r and r.has_key("data"):
        return r.data.data
    return None

def decryptPseudoGID(data):
    pseudogid = "5F650295E1FFFC97CE77ABD49DD955B3".decode("hex")
    return AESdecryptCBC(data, pseudogid, padding=False)

def dword(s,i):
    return struct.unpack("<L", s[i:i+4])[0]

def extract_img3s(blob):
    i = 0
    res = []
    while i < len(blob):
        if blob[i:i+4] != "3gmI":
            break
        TYPE = blob[i+16:i+20][::-1]
        l = struct.unpack("<L", blob[i+4:i+8])[0]
        data = blob[i:i+l]
        img3 = Img3(TYPE, data)
        res.append(img3)
        i += l
    return res

class Img3:
    INT_FIELDS =  ["SEPO", "SDOM", "BORD", "CHIP", "PROD"]
    
    rootCert = None
    def __init__(self, filename, data=None):
        self.filename = filename
        self.shortname = os.path.basename(filename)
        self.certs = None
        if not data:
            img3 = read_file(filename)
        else:
            img3 = data
        self.img3 = img3
        self.ecidoffset = 0
        
        if img3[0:4] != '3gmI':
            print "Magic 3gmI not found in " + filename
            return

        fullSize = dword(img3, 4)
        sizeNoPack = dword(img3, 8)
        sigCheckArea = dword(img3, 12)

        self.sha1 = hashlib.sha1(img3)
        self.fileHash = hashlib.sha1(img3[12:20+sigCheckArea])

        i = 20
      
        sections = {}

        while i < fullSize:
            tag = img3[i:i+4][::-1] #reverse fourcc tag
            total_length = dword(img3, i+4)
            data_length = dword(img3, i+8)

            if tag == "DATA":
                self.datalen = data_length
                data = img3[i+12:i+total_length]
            else:
                data = img3[i+12:i+12+data_length]
                
            if tag in Img3.INT_FIELDS:
                data = struct.unpack("<L", data)[0]
            elif tag == "VERS":
                data = data[4:]
            elif tag == "TYPE":
                data = data[::-1]
            elif tag == "ECID":
                self.ecidoffset = i
            #print "%s offset=%x len=%x" % (tag,i, data_length)
            if tag != "KBAG" or dword(data,0) == 1:
                sections[tag] = data

            i += total_length

        self.sections = sections
        self.leaf_cert = None
        self.sig = None
        self.key = ""
        self.iv = ""
        self.extractCertificates()
    #self.sigcheck()

    def isEncrypted(self):
        return self.sections.has_key("KBAG")
        
    @staticmethod
    def setRootCert(filename):
        try:
            Img3.rootCert = M2Crypto.X509.load_cert_der_string(open(filename,"rb").read())
        except:
            print "IMG3.setRootCert failed loading %s" % filename

    def extractCertificates(self):
        if not self.sections.has_key("CERT"):
            return
        
        certs = {}
        i = 0
        
        while i < len(self.sections["CERT"]):
            data = self.sections["CERT"][i:]
            cert = M2Crypto.X509.load_cert_der_string(data)
            name = cert.get_subject().as_text()
            #name = name[name.find("CN=")+3:]
            #print name
            certs[name] = cert
            i += len(cert.as_der())
            
            #XXX nested Img3 in leaf cert 1.2.840.113635.100.6.1.1
            #CFTypeRef kSecOIDAPPLE_EXTENSION_APPLE_SIGNING = CFSTR("1.2.840.113635.100.6.1.1");
            z = data.find("3gmI")
            if z != -1:
                zz = Img3("cert", data[z:])
                self.sections.update(zz.sections)
        
        #assume leaf cert is last    
        self.certs = certs
        self.leaf_cert = cert
        self.leaf_name = name
    
    def writeCerts(self):
        if not self.certs:
            self.extractCertificates()

        for key, cert in self.certs.items():
            cert_data = cert.as_der()
            cert_sha1 = hashlib.sha1(cert_data).hexdigest()
            write_file("%s_%s.crt" % (key, cert_sha1), cert_data)

    """
    Decrypt SHSH section with leaf certificate public key
    output should be the SHA1 of img3[12:20+sigCheckArea]
    """
    def sigcheck(self, k89A=None):
        if not self.sections.has_key("SHSH"):
            print "[x] FAIL sigcheck %s : no SHSH section" % self.shortname
            return False

        if not self.leaf_cert:
            #print "Extracting certificates"
            self.extractCertificates()
        cert = self.leaf_cert
        #print "Leaf cert subject: %s" % cert.get_subject()
        certChainOk = False
        while True:
            issuer = cert.get_issuer().as_text()
            #print "issuer: %s" % issuer
            if not self.certs.has_key(issuer):
                if not Img3.rootCert:
                    print "Cert chain stops at %s" % issuer
                    certChainOk = False
                    break
                #print "Verifying cert.",
                certChainOk = cert.verify(Img3.rootCert.get_pubkey())
                break
            issuer = self.certs[issuer]
            if not cert.verify(issuer.get_pubkey()):
                print "%s is not signed by %s (verify fail)" % (cert.get_subject().as_text(), issuer.get_subject().as_text())
                return False
            cert = issuer
        shsh = self.sections["SHSH"]
        print "Got SHSH"
            
        try:
            sig =  self.leaf_cert.get_pubkey().get_rsa().public_decrypt(shsh, M2Crypto.RSA.pkcs1_padding)
        except:
            if k89A == None:
                print "SHSH RSA decrypt FAIL, IMG3 must be personalized (SHSH encrypted with k89A)"
                return False
            try:
                shsh = AESdecryptCBC(shsh, k89A)
                sig =  self.leaf_cert.get_pubkey().get_rsa().public_decrypt(shsh, M2Crypto.RSA.pkcs1_padding)
            except:
                raise
                return False
       
        #DigestInfo SHA1 http://www.ietf.org/rfc/rfc3447.txt
        sha1_digestInfo = "3021300906052b0e03021a05000414".decode("hex")
        if sig[:len(sha1_digestInfo)] == sha1_digestInfo:
            pass#print "DigestInfo SHA1 OK"

        self.sig = sig = sig[len(sha1_digestInfo):]
        
        ok = sig == self.fileHash.digest()
        
        if ok:
            print "%s : signature check OK (%s)" % (self.shortname, self.leaf_name)
        else:
            print "Signature check for %s failed" % self.shortname
            print "Decrypted SHA1 " + sig.encode("hex")
            print "Sigcheck area SHA1 " + self.fileHash.hexdigest()
        return ok

    def ticketHash(self):
        #sigchecklen = struct.unpack("<L", self.img3[12:16])[0]
        tohash = struct.pack("<L", self.ecidoffset - 20) + self.img3[16:12 + self.ecidoffset - 20+8]
        return hashlib.sha1(tohash).digest()
        
    def setIvAndKey(self, iv, key):
        self.iv = iv
        self.key = key
        
    def decryptKBAG(self):
        if self.iv and self.key:
            print "No need to decrypt KBAG"
            return
        if not self.sections.has_key("KBAG"):
            print "FAIL: decrypt_kbag no KBAG section for %s" % self.filename
            return
            
        kbag = self.sections["KBAG"]

        cryptState = dword(kbag,0)
        
        if cryptState != 1:
            print "FAIL: cryptState = %d" % cryptState

        aesType = dword(kbag,4)

        if aesType != 128 and aesType != 192 and aesType != 256:
            print "FAIL: aesType = %d" % aesType

        keySize = aesType / 8
        #print "KBAG keySize = " + str(keySize)
        #print "KBAG = %s" % kbag.encode("hex")
        #kbag_dec = decryptPseudoGID(kbag[8:8+16+keySize])
        kbag_dec = decryptGID(kbag[8:8+16+keySize])
        if not kbag_dec:
            return False

        self.iv = kbag_dec[:16]
        self.key = kbag_dec[16:]
        return True
    
    def isValidDecryptedData(self, data):
        if len(data) > 16 and data.startswith("complzss"):
            return "kernel"
        if len(data) > 0x800 and data[0x400:0x400+2] == "H+":
            return "ramdisk"
        if len(data) > 0x300 and data[0x280:0x285] == "iBoot":
            return "bootloader";
        if data.find("serial-number") != -1:
            return "devicetree"
        if data.startswith("iBootIm"):
            return "bootlogo"
        
    def getRawData(self):
        return self.sections["DATA"][:self.datalen]

    def decryptData(self, key=None, iv=None):
        if not self.sections.has_key("KBAG"):
            return self.getRawData()
        
        if not key or not iv:
            if not self.decryptKBAG():
                return
            key = self.key
            iv = self.iv

        data =  AESdecryptCBC(self.sections["DATA"], key, iv)
        x = self.isValidDecryptedData(data)
        if not x:
            print >> sys.stderr, "%s : Decrypted data seems invalid"  % self.shortname
            print >> sys.stderr, data[:50].encode("hex")
            return False
        print "%s : decrypted OK (%s)" % (self.shortname, x)
        return data[:self.datalen]
    
if __name__ == "__main__":
    img3 = Img3(sys.argv[1])
    img3.sigcheck()
