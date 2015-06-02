#!/bin/sh -x

. ./fuzzing-wrappers/fcns

IN_DIR_BASE="test-cases/server-conf"
IN_DIR=''
CONF_FILE="/fwknopd.conf"
fw_type $IN_DIR_BASE IN_DIR

FWKNOPD_CONF_FILE="$IN_DIR$CONF_FILE"

if [ $@ ]
then
    FWKNOPD_CONF_FILE=$@
fi

LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd \
    -c $FWKNOPD_CONF_FILE \
    -a ../conf/default_access.conf \
    -O ../conf/override_no_digest_tracking_fwknopd.conf \
    -A -f -t --exit-parse-config -v -v -v -r `pwd`/run

exit $?
