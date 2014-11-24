#!/bin/sh -x

#
# Fuzz SPA packet encoding/decoding
#

. ./fuzzing-wrappers/fcns

FDIR="spa-pkts.out"
ARCHIVE_DIR="$TOP_DIR/archive"
OUT_DIR="$TOP_DIR/$FDIR"
IN_DIR="test-cases/spa-pkts"

### build up our afl-fuzz text banner
TSTR="fwknopd,SPA,encode/decode"
GIT_STR=''
git_banner GIT_STR
BANNER="$TSTR$GIT_STR"

### set up directories
dir_init $ARCHIVE_DIR $FDIR $OUT_DIR

### make sure that a basic SPA packet to stdin in fwknopd -A mode works
./fuzzing-wrappers/helpers/fwknopd-stdin-test.sh || exit $?

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz -T $BANNER -t 1000 -i $IN_DIR -o $OUT_DIR $SERVER -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t

exit $?
