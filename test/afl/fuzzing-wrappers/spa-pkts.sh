#!/bin/sh -x

TOP_DIR="fuzzing-output"
FDIR="spa-pkts.out"
ARCHIVE_DIR="$TOP_DIR/archive"
OUT_DIR="$TOP_DIR/$FDIR"
IN_DIR="test-cases/spa-pkts"

SERVER="../../server/.libs/fwknopd"
LIB_DIR="../../lib/.libs"

[ ! -d $ARCHIVE_DIR ] && mkdir -p $ARCHIVE_DIR
TS=`date +"%m%d%y%H%M%S"`
[ -d $OUT_DIR ] && mv $OUT_DIR "$ARCHIVE_DIR/$FDIR-$TS"
mkdir $OUT_DIR

### make sure that a basic SPA packet to stdin in fwknopd -A mode works
./fuzzing-wrappers/helpers/fwknopd-stdin-test.sh || exit

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz -t 1000 -i $IN_DIR -o $OUT_DIR $SERVER -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t

exit
