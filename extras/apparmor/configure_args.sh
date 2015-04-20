#!/bin/sh -x

#
# This is a convenience script to run ./configure with the command line args
# that the AppArmor policy expects (sets up binary locations, sysconfdir,
# etc.).  Execute this script from the top level fwknop sources directory.
#

if [ -x ./configure ]; then
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/run $@
else
    echo "[*] Execute from the fwknop top level sources directory"
fi
