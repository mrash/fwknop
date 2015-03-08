#!/bin/sh -x

cd ../../
CC=afl-gcc ./extras/apparmor/configure_args.sh --enable-afl-fuzzing $@
make clean
AFL_HARDEN=1 make
cd test/afl
exit $?
