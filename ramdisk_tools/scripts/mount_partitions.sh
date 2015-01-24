#!/bin/sh

if [ -a /dev/disk0s1s2 ]; then # test for iOS 5 data partition
    mount_hfs /dev/disk0s1s1 /mnt1 2>/dev/null
    mount_hfs /dev/disk0s1s2 /mnt2 2>/dev/null
elif [ -a /dev/disk0s2s1 ]; then # test for iOS 4 data partition
    mount_hfs /dev/disk0s1 /mnt1 2>/dev/null
    mount_hfs /dev/disk0s2s1 /mnt2 2>/dev/null
elif [ -a /dev/disk0s2 ]; then
    mount_hfs /dev/disk0s1 /mnt1 2>/dev/null
    mount_hfs /dev/disk0s2 /mnt2 2>/dev/null
else
    echo "Error mounting partitions. Please try it manually"
fi