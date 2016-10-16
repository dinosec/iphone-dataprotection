
iphone-dataprotection:

iPhone Data Protection Tools cloned from https://code.google.com/p/iphone-dataprotection on January 24, 2015.

Code slightly changed for OS X Yosemite (v 10.10.x) with Xcode 6.1.x:
- "build_tools.sh": SDK references point to 10.10
- "demo_bruteforce.py" patched to obtain the three files used for the keychain-2.db in iOS 7.x

By Raul Siles

- References:

Check https://github.com/dinosec/iphone-dataprotection-xcode5 for OS X Yosemite (v 10.10.x) with Xcode 5.1.1.

(The project reference for iphone-dataprotection in OS X El Capitan (v 10.11.x), with Xcode 7.3.x, has been removed, as the passcode bypass capabilities do not work in that version - without doing further analysis)

The iTunes backup format has significantly changed from iOS 9 to iOS 10 (and the associated iTunes versions). The old iphone-dataprotection tools (cloned from the original version in this GitHub project) do not support the new iOS 10 format, unless someone decides to update them ;)
