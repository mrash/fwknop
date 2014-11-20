#!/bin/sh -x

TOP_DIR="fuzzing-output"
FDIR="client-rc.out"
ARCHIVE_DIR="$TOP_DIR/archive"
OUT_DIR="$TOP_DIR/$FDIR"
IN_DIR="test-cases/client-rc"

CLIENT="../../client/.libs/fwknop"
LIB_DIR="../../lib/.libs"

[ ! -d $ARCHIVE_DIR ] && mkdir -p $ARCHIVE_DIR
TS=`date +"%m%d%y%H%M%S"`
[ -d $OUT_DIR ] && mv $OUT_DIR "$ARCHIVE_DIR/$FDIR-$TS"
mkdir $OUT_DIR

### make sure the client can handle the rc file
./fuzzing-wrappers/fwknop-rc-test.sh || exit

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz -t 1000 -i $IN_DIR -o $OUT_DIR -f $OUT_DIR/fwknoprc $CLIENT --rc-file $OUT_DIR/fwknoprc -T -a 1.1.1.1 -n testhost.com

exit
