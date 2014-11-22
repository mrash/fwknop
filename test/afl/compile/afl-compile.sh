#!/bin/sh -x

cd ../../
CC=afl-gcc ./extras/apparmor/configure_args.sh --enable-afl-fuzzing $@
make clean
make
cd test/afl
exit
