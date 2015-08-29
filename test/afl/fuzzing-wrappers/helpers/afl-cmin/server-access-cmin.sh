#!/bin/sh -x

. ./fuzzing-wrappers/fcns

### generate test corpus directly from the main test suite
### config files
CONF_DIR=../conf
IN_DIR=$CONF_DIR
OUT_DIR="test-cases/server-access.cmin"
FUZZ_FILE=access_tmp.conf

LD_LIBRARY_PATH=../../lib/.libs afl-cmin -i $IN_DIR \
    -f $FUZZ_FILE -o $OUT_DIR $SERVER \
    -c $CONF_DIR/ipt_snat_fwknopd.conf \
    -a $FUZZ_FILE -O $CONF_DIR/override_no_digest_tracking_fwknopd.conf \
    -A -f -t --exit-parse-config -v -v -v -r `pwd`/run

exit $?
