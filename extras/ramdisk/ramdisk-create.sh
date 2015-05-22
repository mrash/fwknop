#!/bin/sh -x
#
# This script creates a ramdisk and clones the fwknop git repository
# into it. This is meant for AFL fuzzing cycles.
#

RSIZE=768M
RAMDISK=/tmp/afl-ramdisk

if [ -d $RAMDISK ]
then
    echo "[*] $RAMDISK directory already exists"
    exit 1
fi

if [ -f extras/ramdisk/ramdisk-create.sh ]
then
    mkdir $RAMDISK && chmod 777 $RAMDISK
    mount -t tmpfs -o size=$RSIZE tmpfs $RAMDISK
    git clone . $RAMDISK/fwknop.git
else
    echo "[*] Run this script from the top level fwknop sources directory"
    exit 1
fi

exit $?
