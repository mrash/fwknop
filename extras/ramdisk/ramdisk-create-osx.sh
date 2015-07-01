#!/bin/sh -x
#
# This script creates a ramdisk and clones the fwknop git repository
# into it. This is meant for AFL fuzzing cycles.
#

### 1GB
RSIZE=2097152
LABEL="ramdisk-for-fwknop"
RAMDISK=/Volumes/$LABEL

if [ -d $RAMDISK ]
then
    echo "[*] $RAMDISK mount point already exists"
    exit 1
fi

if [ -f extras/ramdisk/ramdisk-create-osx.sh ]
then
    diskutil erasevolume HFS+ "$LABEL" `hdiutil attach -nomount ram://$RSIZE`
    git clone . $RAMDISK/fwknop.git
else
    echo "[*] Run this script from the top level fwknop sources directory"
    exit 1
fi

exit $?
