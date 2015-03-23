#!/bin/sh -x

RAMDISK=/tmp/afl-ramdisk
mkdir $RAMDISK && chmod 777 $RAMDISK
mount -t tmpfs -o size=768M tmpfs $RAMDISK

git clone . $RAMDISK/fwknop.git
exit $?
