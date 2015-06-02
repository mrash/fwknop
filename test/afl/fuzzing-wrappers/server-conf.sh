#!/bin/sh -x

#
# Fuzz fwknopd config file parsing (fwknopd.conf)
#

. ./fuzzing-wrappers/fcns

FDIR="server-conf.out"
OUT_DIR="$TOP_DIR/$FDIR"
PREV_OUT_DIR=''
IN_DIR_BASE="test-cases/server-conf"
IN_DIR=''
FUZZ_FILE=$OUT_DIR/afl_fwknopd.conf

### build up our afl-fuzz text banner
TSTR="fwknopd,fwknopd.conf"
GIT_STR=''
git_banner GIT_STR
BANNER="$TSTR$GIT_STR"

### point to the appropriate test cases (iptables vs. firewalld)
fw_type $IN_DIR_BASE IN_DIR

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
    -o $OUT_DIR -f $FUZZ_FILE $SERVER \
    -O ../conf/override_no_digest_tracking_fwknopd.conf \
    -a ../conf/default_access.conf \
    -c $FUZZ_FILE \
    -A -f -t --exit-parse-config -v -v -v -r `pwd`/run

exit $?
