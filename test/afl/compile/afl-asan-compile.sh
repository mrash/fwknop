#!/bin/sh -x

. ./compile/fcns

### set either afl-gcc or afl-clang (defaults to afl-gcc)
set_afl_cc

cd ../../

AFL_USE_ASAN=1 CC=$AFL_CC ./extras/apparmor/configure_args.sh --enable-afl-fuzzing --without-gpgme --enable-32bit-mode --enable-asan-support $@

if [ $? -ne 0 ]
then
    echo "[*] autogen configure script failure, exiting"
    exit 1
fi

make clean
AFL_HARDEN=1 make
cd test/afl
exit $?
