#!/bin/sh -x

#
# Fuzz fwknopd config file parsing (fwknopd.conf)
#

. ./fuzzing-wrappers/fcns

FDIR="server-conf.out"
OUT_DIR="$TOP_DIR/$FDIR"
PREV_OUT_DIR=''
IN_DIR="test-cases/server-conf"

### build up our afl-fuzz text banner
TSTR="fwknopd,fwknopd.conf"
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

### make sure that parsing the fwknopd.conf file works
./fuzzing-wrappers/helpers/fwknopd-parse-conf.sh || exit $?

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz -T $BANNER -t 1000 -i $IN_DIR \
    -o $OUT_DIR -f $OUT_DIR/afl_fwknopd.conf $SERVER \
    -c $OUT_DIR/afl_fwknopd.conf \
    -a $OUT_DIR/afl_access.conf \
    -O ../conf/override_no_digest_tracking_fwknopd.conf \
    -A -f -t --exit-parse-config

exit $?
