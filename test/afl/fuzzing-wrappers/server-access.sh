#!/bin/sh -x

TOP_DIR="fuzzing-output"
FDIR="server-access.out"
ARCHIVE_DIR="$TOP_DIR/archive"
OUT_DIR="$TOP_DIR/$FDIR"
IN_DIR="test-cases/server-access"

SERVER="../../server/.libs/fwknopd"
LIB_DIR="../../lib/.libs"

[ ! -d $ARCHIVE_DIR ] && mkdir -p $ARCHIVE_DIR
TS=`date +"%m%d%y%H%M%S"`
[ -d $OUT_DIR ] && mv $OUT_DIR "$ARCHIVE_DIR/$FDIR-$TS"
mkdir $OUT_DIR

### make sure that parsing the access.conf file works
./fuzzing-wrappers/helpers/fwknopd-parse-access.sh || exit $?

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz -t 1000 -i $IN_DIR -o $OUT_DIR -f $OUT_DIR/afl_access.conf $SERVER -c ../conf/ipt_snat_fwknopd.conf -a $OUT_DIR/afl_access.conf -A -f -t --exit-parse-config -D

exit $?
