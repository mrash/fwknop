#!/bin/sh -x

OLD_DIR=afl-out-archive
OUT_DIR=afl-fuzzing.out

[ ! -d $OLD_DIR ] && mkdir $OLD_DIR
TS=`date +"%m%d%y%H%M%S"`
[ -d $OUT_DIR ] && mv $OUT_DIR "$OLD_DIR/$OUT_DIR-$TS"
mkdir $OUT_DIR

### make sure that a basic SPA packet to stdin in fwknopd -A mode works
./fwknopd-stdin-test.sh || exit

LD_LIBRARY_PATH=../../lib/.libs afl-fuzz -i afl-fuzzing.in -o $OUT_DIR ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t

exit
