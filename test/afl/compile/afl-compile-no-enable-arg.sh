#!/bin/sh -x

# this is for the fuzzing-wrappers/client-rc.sh script

cd ../../
CC=afl-gcc ./extras/apparmor/configure_args.sh $@
make clean
AFL_HARDEN=1 make
cd test/afl
exit $?
