#!/bin/sh -x

FWKNOPD_CONF_FILE="test-cases/server-conf/fwknopd.conf"

if [ $@ ]
then
    FWKNOPD_CONF_FILE=$@
fi

LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd \
    -c $FWKNOPD_CONF_FILE \
    -a ../conf/default_access.conf \
    -O ../conf/override_no_digest_tracking_fwknopd.conf \
    -f -t --exit-parse-config -v -v -v -r `pwd`/run

exit $?
