#!/bin/sh -x

#
# This is a convenience script to run ./configure with the command line args
# that are designed for fuzzing and test coverage support
#

if [ -x ./configure ]; then
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --enable-profile-coverage --enable-fuzzing-interfaces --enable-libfiu-support --enable-c-unit-tests $@
else
    echo "[*] Execute from the fwknop top level sources directory"
fi
