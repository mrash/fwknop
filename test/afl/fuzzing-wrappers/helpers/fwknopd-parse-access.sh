#!/bin/sh -x

ACCESS_FILE="../conf/default_access.conf"

if [ $@ ]
then
    ACCESS_FILE=$@
fi

LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd \
    -c ../conf/ipt_snat_fwknopd.conf \
    -O ../conf/override_no_digest_tracking_fwknopd.conf \
    -a $ACCESS_FILE \
    -A -f -t --exit-parse-config -v -v -v

exit $?
