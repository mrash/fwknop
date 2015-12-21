#!/bin/sh -x
#
# Enabling Google's UndefinedBehaviorSanitizer
#

if [ -x ./configure ]; then
    export ac_cv_func_malloc_0_nonnull=yes
    export ac_cv_func_realloc_0_nonnull=yes
    ./autogen.sh
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/run --enable-ubsan-support $@
    make clean
    make
else
    echo "[*] Execute from the fwknop top level sources directory"
fi
