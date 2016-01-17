#!/bin/sh

if [ -x ./configure ]; then
    make clean
    scan-build ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/run $@
    script -c 'scan-build make'
else
    echo "[*] Execute from the fwknop top level sources directory"
fi

exit 0
