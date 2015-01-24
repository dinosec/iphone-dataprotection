"""
0
1:MCSHA256DigestWithSalt
2:SecKeyFromPassphraseDataHMACSHA1
"""
from crypto.PBKDF2 import PBKDF2
import plistlib
import hashlib

SALT1 = "F92F024CA2CB9754".decode("hex")

hashMethods={
    1: (lambda p,salt:hashlib.sha256(SALT1 + p)),
    2: (lambda p,salt:PBKDF2(p, salt, iterations=1000).read(20))
    }

def bruteforce_old_pass(h):
    salt = h["salt"].data
    hash = h["hash"].data
    f = hashMethods.get(h["hashMethod"])

    if f:
        print "Bruteforcing hash %s (4 digits)" % hash.encode("hex")
        for i in xrange(10000):
            p = "%04d" % (i % 10000)
            if f(p,salt) == hash:
                return p
