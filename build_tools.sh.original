#!/bin/bash

if [ ! $(uname) == "Darwin" ]
then
    echo "Script for Mac OS X only"
    exit
fi

for VER in 5.0 5.1 6.0 6.1 7.0 7.1
do
    if [ -d "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS$VER.sdk/" ];
    then
        SDKVER=$VER
        SDKPATH="/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS$VER.sdk/"
        echo "Found iOS SDK at $SDKPATH"
        break
    fi
done

if [ "$SDKVER" == "" ]; then
    echo "iOS SDK not found, make sure Xcode is installed"
    exit -1
fi

if [ "$ARCH" == "armv6" ] && [ `echo "$VER >= 7.0" | bc` == "1" ]; then
    echo "Need iOS 6 SDK for armv6 target"
    exit -1
fi

if [ ! -f "$SDKPATH/System/Library/Frameworks/IOKit.framework/Headers/IOKitLib.h" ]; then
    echo "IOKit headers missing"

    IOKIT_HDR="/System/Library/Frameworks/IOKit.framework/Headers"
    IOKIT_HDR_109="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/System/Library/Frameworks/IOKit.framework/Headers"

    if [ -d $IOKIT_HDR_109 ]; then
        echo "Symlinking headers"
        set -x
        sudo ln -s $IOKIT_HDR_109 "$SDKPATH/System/Library/Frameworks/IOKit.framework/Headers"
        sudo ln -s "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/usr/include/libkern/OSTypes.h" "$SDKPATH/usr/include/libkern/OSTypes.h"
        set +x
    elif [ -d $IOKIT_HDR ]; then
        echo "Symlinking headers"
        set -x
        sudo ln -s $IOKIT_HDR "$SDKPATH/System/Library/Frameworks/IOKit.framework/Headers"
        set +x
    fi
fi

if [ ! -f "$SDKPATH/System/Library/Frameworks/IOKit.framework/IOKit" ]; then
    echo "IOKit binary missing"

    if [ -f "$SDKPATH/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit" ]; then
        echo "Creating IOKit symlink for iOS 7.0 SDK"
        set -x
        sudo ln -s "$SDKPATH/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit" "$SDKPATH/System/Library/Frameworks/IOKit.framework/IOKit"
        set +x
    fi
fi

if     [ -f "$SDKPATH/System/Library/Frameworks/IOKit.framework/Headers/IOKitLib.h" ] \
    && [ -f "$SDKPATH/System/Library/Frameworks/IOKit.framework/IOKit" ]; then
    export SDKVER
    export ARCH
    make -C ramdisk_tools clean
    make -C ramdisk_tools
fi
