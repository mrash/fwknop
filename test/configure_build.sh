#!/bin/sh -x

#
# This is a convenience script to run ./configure with the command line args
# that the test suite needs (sets up binary locations, sysconfdir,
# etc.). Execute this script from the top level fwknop sources directory, and
# then run the test-fwknop.pl script from the test/ directory.
#

if [ -x ./configure ]; then
    ./configure --prefix=/usr --sysconfdir=`pwd`/test/conf --localstatedir=`pwd`/test/run $@
else
    echo "[*] Execute from the fwknop top level sources directory"
fi
