#!/bin/sh -x

DIGEST_FILE="./test-cases/server-digest-cache/digest.cache"

if [ $@ ]
then
    DIGEST_FILE=$@
fi

LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd \
    -c ../conf/ipt_snat_fwknopd.conf \
    -a ../conf/default_access.conf \
    -d $DIGEST_FILE \
    -f -t --exit-parse-config -v -v -v -r `pwd`/run

exit $?
