#!/bin/bash

if [ ! $(uname) == "Darwin" ]
then
    echo "Script for Mac OS X only"
    exit
fi

function build_ramdisk {

RAMDISK=$1

RD_SIZE=$(du -h $RAMDISK  | cut -f 1)

if [ ! $RD_SIZE == "20M" ]
then
    echo "resizing ramdisk..."
    echo "hdiutil will segfault if ramdisk was already resized, thats ok"
    hdiutil resize -size 20M $RAMDISK
fi

if [ -d /Volumes/ramdisk ]
then
    echo "Unmount /Volumes/ramdisk then try again"
    exit -1
fi

echo "Attaching ramdisk"

hdiutil attach $RAMDISK
rm -rf /Volumes/ramdisk/usr/local/standalone/firmware/*
rm -rf /Volumes/ramdisk/usr/share/progressui/

if [ ! -f /Volumes/ramdisk/sbin/sshd ]
then
    echo "Unpacking ssh.tar.gz on ramdisk..."
    tar -C /Volumes/ramdisk/ -xzkP <  data/ssh.tar.gz
    echo "^^ This tar error message is okay"
fi

if [ ! -f /Volumes/ramdisk/usr/lib/libncurses.5.4.dylib ]
then
    echo "Adding libncurses..."
    cp data/libncurses.5.dylib /Volumes/ramdisk/usr/lib/libncurses.5.4.dylib
fi

echo "Adding/updating ramdisk_tools binaries on ramdisk..."
cp ramdisk_tools/restored_external /Volumes/ramdisk/usr/local/bin/
cp ramdisk_tools/ioflashstoragekit ramdisk_tools/bruteforce ramdisk_tools/device_infos /Volumes/ramdisk/var/root/
cp ramdisk_tools/scripts/* /Volumes/ramdisk/var/root/
chmod +x /Volumes/ramdisk/var/root/*

cp data/bin/* /Volumes/ramdisk/bin/


ls -laht /Volumes/ramdisk/var/root/

#if present, copy ssh public key to ramdisk
if [ -f ~/.ssh/id_rsa.pub ] && [ ! -d /Volumes/ramdisk/var/root/.ssh ]
then
    mkdir /Volumes/ramdisk/var/root/.ssh
    cp ~/.ssh/id_rsa.pub /Volumes/ramdisk/var/root/.ssh/authorized_keys
    chmod 0600 /Volumes/ramdisk/var/root/.ssh/authorized_keys
fi

hdiutil eject /Volumes/ramdisk
}

echo "Rebuilding ramdisk_tools"

./build_tools.sh || exit -1

#compiling in a vmware shared folder can produce binaries filled with zeroes !
if [ ! -f ramdisk_tools/restored_external ] || [ "$(file -b ramdisk_tools/restored_external)" == "data" ]
then
    echo "ramdisk_tools/restored_external not found or invalid, check compilation output for errors"
    exit -1
fi

#show armv6/armv7
lipo -info ramdisk_tools/restored_external

if [ $# -eq 1 ]
then
    build_ramdisk $1
else
    shopt -s nullglob
    for RAMDISK in data/boot/*.dmg
    do
        echo "Updating $RAMDISK"
        build_ramdisk $RAMDISK
    done
fi


