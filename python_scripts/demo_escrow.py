import os
import plistlib
from keystore.keybag import Keybag
from util.ramdiskclient import RamdiskToolClient

"""
this wont work on iOS 5 unless the passcode was already bruteforced
"""
def escrow():
    client = RamdiskToolClient()
    di = client.getDeviceInfos()
    key835 = di.get("key835").decode("hex")
    
    plist = os.environ["ALLUSERSPROFILE"] + "/Apple/Lockdown/%s.plist" % di["udid"]
    lockdown = plistlib.readPlist(plist)    
    kb = Keybag.createWithDataSignBlob(lockdown["EscrowBag"].data, key835)
    
    keybags = di.setdefault("keybags", {})
    kbuuid = kb.uuid.encode("hex")
    if not keybags.has_key(kbuuid):
        print lockdown["HostID"]
        res = client.getEscrowRecord(lockdown["HostID"])
        bagkey = res.get("BagKey")
        print "Bag key" + bagkey.data.encode("hex")
        res = client.getPasscodeKey(lockdown["EscrowBag"].data, bagkey)
        print res
        passcodeKey = res["passcodeKey"].decode("hex")
        keybags[kbuuid] = {"KeyBagKeys": lockdown["EscrowBag"],
                            "passcode": bagkey,
                            "passcodeKey": passcodeKey.encode("hex")}
        pl.update(keybags[kbuuid])
    else:
        passcodeKey = keybags[kbuuid].get("passcodeKey").decode("hex")

    print kb.unlockWithPasscodeKey(passcodeKey)
    kb.printClassKeys()

escrow()