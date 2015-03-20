#!/bin/sh -x

. ./fuzzing-wrappers/fcns
IN_DIR="test-cases/spa-pkts"
OUT_DIR=${IN_DIR}.cmin
CONF_DIR=../conf

LD_LIBRARY_PATH=../../lib/.libs afl-cmin -i $IN_DIR \
    -o ${IN_DIR}.cmin $SERVER -c ../conf/default_fwknopd.conf \
    -a $CONF_DIR/default_access.conf -A -f -t

exit $?
