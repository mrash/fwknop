#!/bin/sh -x

#
# Fuzz the fwknopd digest tracking file
#

. ./fuzzing-wrappers/fcns

FDIR="server-digest-cache.out"
OUT_DIR="$TOP_DIR/$FDIR"
PREV_OUT_DIR=''
IN_DIR="test-cases/server-digest-cache"

### build up our afl-fuzz text banner
TSTR="fwknopd,digest.cache"
GIT_STR=''
git_banner GIT_STR
BANNER="$TSTR$GIT_STR"

### set up directories
dir_init $ARCHIVE_DIR $FDIR $OUT_DIR PREV_OUT_DIR

### make sure that parsing the access.conf file works
./fuzzing-wrappers/helpers/fwknopd-digest-cache.sh || exit $?

### support resuming from a previous run
if [ $@ ] && [ "$1" = "resume" ]
then
    IN_DIR=$PREV_OUT_DIR
fi

### run afl-fuzz
LD_LIBRARY_PATH=$LIB_DIR afl-fuzz \
    -T $BANNER -t 1000 -i $IN_DIR \
    -o $OUT_DIR -f $OUT_DIR/afl_digest_cache.conf $SERVER \
    -c ../conf/ipt_snat_fwknopd.conf \
    -a ../conf/default_access.conf \
    -d $OUT_DIR/afl_digest_cache.conf \
    -f -t --exit-parse-config -r `pwd`/run

exit $?
