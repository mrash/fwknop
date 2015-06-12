#!/bin/sh -x

#
# Fuzz SPA packet encoding/decoding
#

. ./fuzzing-wrappers/fcns

FDIR="enc-pkts.out"
OUT_DIR="$TOP_DIR/$FDIR"
PREV_OUT_DIR=''
IN_DIR="test-cases/enc-pkts"

### build up our afl-fuzz text banner
TSTR="fwknopd,SPA,encrypt/decrypt"
GIT_STR=''
git_banner GIT_STR
BANNER="$TSTR$GIT_STR"

### set up directories
dir_init $ARCHIVE_DIR $FDIR $OUT_DIR PREV_OUT_DIR

### support resuming from a previous run
if [ $@ ] && [ "$1" = "resume" ]
then
    IN_DIR=$PREV_OUT_DIR
fi

### make sure that reading a packet works (this is expected to error
### out though since base64 decoding is short-circuited when AFL
### support is compiled in).
./fuzzing-wrappers/helpers/fwknopd-enc-pkt-file.sh

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz \
    -m $MEM_LIMIT -T $BANNER -t $TIMEOUT -i $IN_DIR \
    -o $OUT_DIR -f $OUT_DIR/afl_enc_pkt.data $SERVER \
    -c ../conf/default_fwknopd.conf \
    -a ../conf/default_access.conf \
    -O ../conf/override_no_digest_tracking_fwknopd.conf \
    -A --afl-pkt-file $OUT_DIR/afl_enc_pkt.data \
    -f -t -v -v -v -r `pwd`/run

exit $?
