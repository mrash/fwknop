#!/bin/sh -x

TOP_DIR="fuzzing-output"
FDIR="server-conf.out"
ARCHIVE_DIR="$TOP_DIR/archive"
OUT_DIR="$TOP_DIR/$FDIR"
IN_DIR="test-cases/server-conf"

SERVER="../../server/.libs/fwknopd"
LIB_DIR="../../lib/.libs"

[ ! -d $ARCHIVE_DIR ] && mkdir -p $ARCHIVE_DIR
TS=`date +"%m%d%y%H%M%S"`
[ -d $OUT_DIR ] && mv $OUT_DIR "$ARCHIVE_DIR/$FDIR-$TS"
mkdir $OUT_DIR

### make sure that parsing the fwknopd.conf file works
./fuzzing-wrappers/helpers/fwknopd-parse-conf.sh || exit

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz -t 1000 -i $IN_DIR -o $OUT_DIR -f $OUT_DIR/afl_fwknopd.conf $SERVER -c $OUT_DIR/afl_fwknopd.conf -a $OUT_DIR/afl_access.conf -A -f -t --exit-parse-config -D

exit
