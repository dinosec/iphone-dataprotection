iOS forensics tools

Supported devices
    (iPhone 2G)
    iPhone 3G
    iPhone 3GS
    iPad 1
    iPhone 4 GSM
    iPhone 4 GSM rev A
    iPhone 4 CDMA
    Newer devices are NOT supported

Requirements
    Mac OS X 10.8/10.9
    Xcode with iOS SDK (open Xcode to accept the license agreement)
    redsn0w_mac_0.9.15b3 (downloaded by build.py)
    Supported IPSW for the target device in data/ipsw (downloaded by build.py)

Building a custom ramdisk
    Run ./build.py DEVICE_NAME to create the patched kernel + custom ramdisk
        IPSW wont match the installed iOS version on the device, this is normal
    Use ./boot.py to start redsn0w with the correct parameters, then place the device in DFU mode

    ./build_ramdisk_v2.sh can be used to recompile ramdisk_tools and update existing ramdisks (data/boot/*.dmg)

SSH access
    Boot using ./boot.py wait for "OK" on screen
    Run ./tcprelay.sh in a new terminal window
    Run ssh -p 2222 root@localhost
        root password is alpine

Python scripts
    Install dependencies
       sudo easy_install M2crypto construct progressbar setuptools pyasn1 protobuf
       sudo ARCHFLAGS='-arch i386 -arch x86_64' easy_install pycrypto
    M2Crypto for OS X 10.9
        curl -O http://chandlerproject.org/pub/Projects/MeTooCrypto/M2Crypto-0.21.1-py2.7-macosx-10.9-intel.egg
        sudo easy_install M2Crypto-0.21.1-py2.7-macosx-10.9-intel.egg

