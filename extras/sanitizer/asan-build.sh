#!/bin/sh -x

#
# In some cases when enabling Google's Address Sanitizer, errors like the
# following can be generated. This script provides a workaround.
#
# fwknop-spa_comm.o: In function `send_spa_packet_http':
# /home/mbr/git/fwknop.git/client/spa_comm.c:516: undefined reference to `rpl_malloc'
# ../lib/.libs/libfko.so: undefined reference to `rpl_realloc'
#

if [ -x ./configure ]; then
    export ac_cv_func_malloc_0_nonnull=yes
    export ac_cv_func_realloc_0_nonnull=yes
    ./autogen.sh
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/run --enable-asan-support $@
    make clean
    make
else
    echo "[*] Execute from the fwknop top level sources directory"
fi
