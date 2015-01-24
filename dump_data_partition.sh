#!/bin/sh
SSHOPTS="-p 2222 -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null"

UDID=`ssh $SSHOPTS root@localhost "./device_infos udid"`

if [ "$UDID" == "" ]; then
    exit
fi

echo "Device UDID : $UDID"

mkdir -p $UDID

DATE=`date +"%Y%m%d-%H%M"`
OUT=$UDID/data_$DATE.dmg

echo "Dumping data partition in $OUT ..."

ssh $SSHOPTS root@localhost "dd if=/dev/rdisk0s2s1  bs=8192 || dd if=/dev/rdisk0s1s2  bs=8192" > $OUT
