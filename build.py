#!/usr/bin/env python

import os,sys

REDSNOW_URL="https://sites.google.com/a/iphone-dev.com/files/home/redsn0w_mac_0.9.15b3.zip"

IPSWs = {
    #"iphone2g": "http://appldnld.apple.com.edgesuite.net/content.info.apple.com/iPhone/061-7481.20100202.4orot/iPhone1,1_3.1.3_7E18_Restore.ipsw",
    #"iphone3g": "http://appldnld.apple.com/iPhone4/061-9853.20101122.Vfgt5/iPhone1,2_4.2.1_8C148_Restore.ipsw",

    "iphone3gs": "http://appldnld.apple.com/iPhone4/041-8356.20111012.SQRDT/iPhone2,1_5.0_9A334_Restore.ipsw",
    #"iphone3gs": "http://appldnld.apple.com/iOS6/Restore/041-7173.20120919.sDDMh/iPhone2,1_6.0_10A403_Restore.ipsw",
    "ipad1":     "http://appldnld.apple.com/iPhone4/041-8357.20111012.DTOrM/iPad1,1_5.0_9A334_Restore.ipsw",
    "iphone4":   "http://appldnld.apple.com/iPhone4/041-8358.20111012.FFc34/iPhone3,1_5.0_9A334_Restore.ipsw",
    #"iphone4":   "http://appldnld.apple.com/iOS6/Restore/041-7175.20120919.wvv7Y/iPhone3,1_6.0_10A403_Restore.ipsw",

    "iphone4gsmA": "http://appldnld.apple.com/iOS6/Restore/041-7177.20120919.xqoqs/iPhone3,2_6.0_10A403_Restore.ipsw",
    "iphone4cdma": "http://appldnld.apple.com/iPhone4/041-9743.20111012.vjhfp/iPhone3,3_5.0_9A334_Restore.ipsw",
    "iphone4cdma": "http://appldnld.apple.com/iOS6/Restore/041-7179.20120919.bDw4g/iPhone3,3_6.0_10A403_Restore.ipsw",

    "ipt2":        "http://appldnld.apple.com/iPhone4/061-9855.20101122.Lrft6/iPod2,1_4.2.1_8C148_Restore.ipsw"
}

def usage():
    print "Usage: %s %s" % (sys.argv[0], "|".join(sorted(IPSWs.keys())))
    exit(0)

def run_command(cmd):
    print "Running %s" % cmd
    os.system(cmd)

def check_deps():
    if not os.path.exists("/Applications/Xcode.app") or not os.path.exists("/usr/bin/codesign"):
        print "Xcode missing, install and run the Xcode app to agree to the Xcode and iOS SDK License Agreement"
        return

    redsn0w_folder = os.path.basename(REDSNOW_URL).replace(".zip","")
    if not os.path.exists(redsn0w_folder):
        if raw_input("%s folder missing, download ? [y/n] " % redsn0w_folder) == "y":
            os.system("curl -L -O %s" % REDSNOW_URL)
            os.system("unzip %s" % os.path.basename(REDSNOW_URL))
        else:
            return
    if not os.path.exists("Keys.plist"):
        os.system("cp %s/redsn0w.app/Contents/MacOS/Keys.plist ." % redsn0w_folder)
    return True

def build(arg):
    if arg.endswith(".ipsw") and os.path.exists(arg):
        ipsw = arg
    elif IPSWs.has_key(arg):
        basename = os.path.basename(IPSWs[arg])
        ipsw = "data/ipsw/" + basename
        if not os.path.exists(ipsw):
            if raw_input("IPSW %s missing, download ? [y/n] " % ipsw) == "y":
                url = IPSWs[arg]
                print "Downloading %s" % url
                os.system("cd data/ipsw && curl -O %s" % url)
            else:
                print "Place %s in data/ispw/ and try again" % basename
                return
        if arg in ["ipt2", "iphone2g", "iphone3g"]:
            print "Setting ARCH to armv6 for device %s" % arg
            os.putenv("ARCH", "armv6")
    else:
        usage()
    
    print "Using %s" % ipsw

    if not check_deps():
        return
    
    if os.system("python python_scripts/kernel_patcher.py %s" % ipsw):
        print "Kernel patcher failed !"
        return
    if os.system("./build_ramdisk_v2.sh data/boot/ramdisk_%s.dmg" % basename.replace("_Restore.ipsw", "")):
        print "build ramdisk failed"
        return
    return True

def main():
    if sys.platform != "darwin":
        print "Script for Mac OS X only"
        return
    
    if len(sys.argv) != 2:
        usage()
    arg = sys.argv[1]

    if build(arg):
        print "Build OK, running boot.py"
        os.system("./boot.py")

if __name__ == "__main__":
    main()
